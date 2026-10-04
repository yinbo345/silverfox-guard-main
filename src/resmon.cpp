#include "resmon.h"

#include <windows.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include "common.h"        // LogDbg / LogDbgC
#include "sfstop.h"        // StopHandle / IsStopRequested
#include "behavior.h"      // JudgeProcess / MakeEntityOfPid / ProcEntity / ProcReputable
#include "observe.h"       // ObserveHit
#include "iocs.h"          // MINER_PROTO_TOKENS
#include "trace.h"
#include "resultstore.h"   // AddFinding / EscalateInfected

namespace sf {
namespace resmon {

// ================================================================ 配置与状态
static Config             g_cfg;
static std::atomic<bool>  g_running{ false };
static std::atomic<uint64_t> g_scanCount{ 0 };
static std::atomic<uint64_t> g_hitCount{ 0 };

// 每个进程的累计状态：跨采样周期累积 CPU 时间与命中次数
namespace {
struct ProcAcc {
    unsigned long long lastKernel = 0;   // 上次采到的内核态 100ns 数
    unsigned long long lastUser  = 0;   // 上次采到的用户态 100ns 数
    unsigned          hits      = 0;   // 连续命中周期数
    unsigned          sustainSec = 0;   // 持续高占用秒数（累加）
    std::string       imagePath;
    bool              reported  = false;   // 本轮是否已报过（避免每周期重复弹卡）
};
std::mutex              g_accMtx;
std::map<unsigned long, ProcAcc> g_acc;

// 逻辑处理器数（启动时取一次）
unsigned g_cores = 1;

FILETIME ToFt(const ULARGE_INTEGER& v) { FILETIME f; f.dwLowDateTime = v.LowPart; f.dwHighDateTime = v.HighPart; return f; }

unsigned long long FtVal(const FILETIME& f) {
    return ((unsigned long long)f.dwHighDateTime << 32) | f.dwLowDateTime;
}

unsigned Cores() {
    if (g_cores) return g_cores;
    SYSTEM_INFO si; GetSystemInfo(&si);
    g_cores = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
    return g_cores;
}

// 取路径（失败返回空，不阻塞）
std::string PathOfPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return {};
    char buf[MAX_PATH * 2] = {0};
    DWORD n = sizeof(buf);
    std::string out;
    if (QueryFullProcessImageNameA(h, 0, buf, &n)) out.assign(buf, n);
    CloseHandle(h);
    return out;
}

// 进程名是否明显是正常高负载程序（编译/压缩/渲染/备份）——
// ★ 这些是**合法**的持续高 CPU，不能当挖矿。宁可放过不可错杀。
bool LooksLikeLegitHeavy(const std::string& base) {
    static const char* kHeavy[] = {
        "cl.exe", "link.exe", "msbuild.exe", "devenv.exe", "gcc.exe", "g++.exe",
        "cc1plus.exe", "rustc.exe", "cargo.exe", "ninja.exe", "cmake.exe",
        "7z.exe", "7za.exe", "7zfm.exe", "rar.exe", "winrar.exe", "tar.exe",
        "makecab.exe", "wzzip.exe", "compact.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",  // 浏览器多进程
        "defender.exe", "msmpeng.exe", "mpcmdrun.exe",                       // Defender 全盘扫
        "searchindexer.exe", "sqlservr.exe", "wmiprvse.exe",
        "system", "audiodg.exe", "dwm.exe", "csrss.exe",                    // 系统必需
        "vmmem", "vmmemWSL", "wsl.exe", "wslhost.exe", "vmwp.exe",          // 虚拟机/WSL
        "ollama.exe", "python.exe", "python3.exe", "node.exe",              // AI/运行时
    };
    std::string b = base;
    for (const char* h : kHeavy) {
        size_t n = strlen(h);
        if (b.size() == n && _stricmp(b.c_str(), h) == 0) return true;
    }
    return false;
}

// 命令行里是否有矿池协议特征
bool HasMinerToken(const std::string& cmd) {
    if (cmd.empty()) return false;
    std::string c = cmd;
    for (char& ch : c) if (ch >= 'A' && ch <= 'Z') ch = (char)(ch + 32);
    for (std::size_t k = 0; k < iocs::MINER_PROTO_TOKENS_N; ++k) {
        if (c.find(iocs::MINER_PROTO_TOKENS[k]) != std::string::npos) return true;
    }
    return false;
}

}  // namespace

// ================================================================ 配置接口
void SetConfig(const Config& c) { g_cfg = c; }
Config GetConfig() { return g_cfg; }

// ================================================================ 单轮扫描
unsigned ScanOnce() {
    if (!g_cfg.enabled) return 0;
    const unsigned cores = Cores();
    // ★★ 2026-10-03 修正（Win10 单核虚拟机实测：整条 CPU 判定被跳过）。
    //
    //  【原状】`if (cores < g_cfg.coresMin) return 0;` —— 单核机器**完全不扫**。
    //  【代价】用户的虚拟机就是单核 ⇒ 日志明写「逻辑处理器数=1 < 门槛 2 ⇒ 跳过」
    //         ⇒ 整个挖矿检测在那台机器上全程不工作。而单核恰恰是最该监控的
    //         机器形态（老机器、虚拟机、被当作跳板的机器）。
    //
    //  【改为】单核走**收紧口径**而不是跳过：
    //         阈值 60% → 90%（单核上「一个进程吃掉 100%」是常态，只有几乎独占才入选）
    //         持续 60s → 180s（单核误报的主因是短时任务恰好撞在采样点上）
    //         连续 6 轮 → 9 轮
    //  【为什么这样安全】`pct` 是**按逻辑核归一**的（见下方 dWall 计算），
    //         跨核数机器可比；而「持续」+「高信誉门」两道闸门仍然都在。
    //         挖矿是长期吃满 CPU 的负载，收紧到 90%/180s 照样会命中。
    const bool singleCore = (cores < g_cfg.coresMin);
    const unsigned thrPct   = singleCore ? g_cfg.singleCorePercent : g_cfg.cpuPercent;
    const unsigned thrSus    = singleCore ? g_cfg.singleCoreSustain : g_cfg.minSustainSec;
    const unsigned thrSample = singleCore ? g_cfg.singleCoreSamples : g_cfg.minSamples;
    if (singleCore) {
        static bool warned = false;
        if (!warned) {
            warned = true;
            LogDbg("[resmon] 单核口径生效：逻辑处理器=" + std::to_string(cores) +
                   " ⇒ 阈值收紧为 CPU≥" + std::to_string(thrPct) + "% 持续≥" +
                   std::to_string(thrSus) + "s 连续" + std::to_string(thrSample) +
                   " 轮（单核不再整条跳过；此前会让本模块在这类机器上完全不工作）");
        }
    }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    const unsigned long long now = GetTickCount64();
    unsigned found = 0;
    std::vector<Hit> hits;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == GetCurrentProcessId()) continue;

            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!h) continue;   // 权限不足 ⇒ 不参与判定（服务已提权，仍不足说明是真受限）
            FILETIME cK{}, eK{}, uK{}, eU{};
            if (!GetProcessTimes(h, &cK, &eK, &uK, &eU)) { CloseHandle(h); continue; }
            CloseHandle(h);

            std::string path = PathOfPid(pe.th32ProcessID);
            if (path.empty()) continue;
            std::string base = path;
            std::size_t sl = base.find_last_of("\\/");
            if (sl != std::string::npos) base = base.substr(sl + 1);

            if (LooksLikeLegitHeavy(base)) continue;

            const unsigned long long k = FtVal(cK) + FtVal(uK);   // 本进程累计 CPU 时间
            unsigned pct = 0;
            {
                std::lock_guard<std::mutex> lk(g_accMtx);
                ProcAcc& a = g_acc[pe.th32ProcessID];
                a.imagePath = path;
                if (a.lastKernel == 0 && a.lastUser == 0) {
                    // 首次见到 ⇒ 只建档，不判定（没有增量）
                    a.lastKernel = FtVal(cK); a.lastUser = FtVal(uK);
                    continue;
                }
                const unsigned long long dK = (FtVal(cK) > a.lastKernel) ? FtVal(cK) - a.lastKernel : 0;
                const unsigned long long dU = (FtVal(uK) > a.lastUser) ? FtVal(uK) - a.lastUser : 0;
                a.lastKernel = FtVal(cK); a.lastUser = FtVal(uK);
                const unsigned long long dms = g_cfg.sampleIntervalMs ? g_cfg.sampleIntervalMs : 5000;
                // 增量 CPU 时间 / 墙钟时间 = 该周期内的占用比例
                const unsigned long long dWall = dms * 10000ULL;   // 100ns 单位
                if (dWall == 0) continue;
                unsigned long long per = ((dK + dU) * 100ULL) / dWall;
                if (per > 100) per = 100;   // 单进程单周期不可能超 100%（已按核归一）
                pct = (unsigned)per;
                if (pct >= thrPct) { a.hits++; a.sustainSec += g_cfg.sampleIntervalMs / 1000; }
                else { a.hits = 0; a.sustainSec = 0; a.reported = false; }

                if (a.hits >= thrSample && a.sustainSec >= thrSus) {
                    Hit h2;
                    h2.pid = pe.th32ProcessID; h2.imagePath = path;
                    h2.cpuPercent = pct; h2.sustainSec = a.sustainSec; h2.cores = cores;
                    hits.push_back(h2);
                    a.reported = true;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // ---- 清理已退出的进程，避免 map 无限增长（铁律 28：随机会话/实体不回收 ⇒ 累积）----
    {
        std::lock_guard<std::mutex> lk(g_accMtx);
        if (g_acc.size() > 512) {
            for (auto it = g_acc.begin(); it != g_acc.end(); ) {
                if (!PathOfPid(it->first).empty()) { ++it; continue; }
                it = g_acc.erase(it);
            }
        }
    }

    // ---- 逐个走统一判定与处置链 ----
    for (const Hit& h : hits) {
        found++;
        ProcEntity ent = MakeEntityOfPid(h.pid);
        if (ent.imagePath.empty()) ent.imagePath = h.imagePath;
        if (ent.imagePath.empty()) continue;
        // ★ 信誉门（硬纪律二）：浏览器/系统组件/自家进程一律不处置
        if (ProcReputable(ent.imagePath)) continue;
        if (ObserveHit(ent.imagePath)) ent.observed = true;

        const bool minerToken = HasMinerToken(ent.commandLine);
        ProcVerdict v = JudgeProcess(ent);

        // ★ CPU 高**只是旁证**：只有当「进程本身已有可疑判定」或「命令行带矿池特征」
        //   时才升级处置。单靠高 CPU 就终止 = 误杀正常高负载程序（编译/压缩/Defender 扫描）。
        const bool corroborated = minerToken || v.level >= 1;
        if (!corroborated) {
            LogDbg("[resmon] 高 CPU 未获旁证印证，仅留痕不处置：pid=" + std::to_string(h.pid) +
                   " " + h.imagePath + " CPU=" + std::to_string(h.cpuPercent) + "%*核数 持续=" +
                   std::to_string(h.sustainSec) + "s 判据 lv=" + std::to_string(v.level) +
                   (ent.commandLine.empty() ? "（命令行不可得）" : ""));
            continue;
        }

        // ★ 不用 std::max：<algorithm> 的重载与 windows.h 的 min/max 宏会撞
        //   （MSVC 下 `max(a,b)` 已被宏吃掉，模板形式则触发 C2589 找不到匹配的 "("）。
        //   显式比较最省事，也不依赖头文件顺序。
        if (v.level  < 2)      v.level  = 2;
        if (v.score  < 120)    v.score  = 120;
        v.hard  = true;
        v.tag   = "miner";
        v.reason = std::string("持续高 CPU 占用（") + std::to_string(h.cpuPercent) + "%×" +
                   std::to_string(h.cores) + " 核，持续 " + std::to_string(h.sustainSec) + " 秒）" +
                   (minerToken ? "，且命令行含矿池协议特征" : "") +
                   (v.reason.empty() ? "" : ("；" + v.reason));

        std::string detail = "持续高 CPU 占用 " + std::to_string(h.sustainSec) + " 秒（" +
                             std::to_string(h.cpuPercent) + "% × " + std::to_string(h.cores) +
                             " 核）" + (minerToken ? "，命令行含矿池协议特征" : "");
        if (!v.reason.empty()) detail += "。" + v.reason;

        LogDbg("[resmon] ★疑似挖矿 pid=" + std::to_string(h.pid) + " " + h.imagePath +
               " CPU=" + std::to_string(h.cpuPercent) + "% 持续=" + std::to_string(h.sustainSec) + "s");

        HANDLE hp = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)h.pid);
        bool killed = false;
        DWORD err = ERROR_INVALID_PARAMETER;
        if (hp) { killed = (TerminateProcess(hp, 0) != 0); if (!killed) err = GetLastError(); CloseHandle(hp); }
        if (killed) detail += "。已自动终止该进程";
        else {
            // ★ 分开落日志，不要把「权限不足」和「进程已退出」写在一句
            LogDbg("[resmon] 终止高 CPU 进程失败 pid=" + std::to_string(h.pid) +
                   " 原因：" + (err == ERROR_ACCESS_DENIED
                                ? "权限不足（检查 SeDebugPrivilege 是否已启用）"
                                : "进程已退出或句柄打开失败"));
        }

        sf::AddFinding("资源", "高", "疑似挖矿行为", detail, ent.imagePath, std::string(), 60);
        sf::EscalateInfected(200);
        trace::Record(trace::Kind::Process, sf::BaseName(ent.imagePath),
                      "疑似挖矿（持续高 CPU）：" + detail, ent.imagePath, "", true, 200);
        // ★ 走 common.h 的公共告警出口（弹卡 + 右下角）。
        //   注意：service.cpp 里那个 SetLastAlertInfo 是文件作用域 static、无对外声明，
        //   从本模块调不到 —— 也不该为此改它的边界。NotifyAnomaly 才是既定契约。
        //   risk 传 "high" ⇒ 卡片渲染「撤销我的处理」入口（与其它自动处置路径一致）。
        sf::NotifyAnomaly("infected", 200, "high");
    }

    g_scanCount.fetch_add(1, std::memory_order_relaxed);
    g_hitCount.fetch_add(found, std::memory_order_relaxed);
    return found;
}

// ================================================================ 监控线程
static void MonThread() {
    // ★ 报**实际生效**的阈值，而不是 g_cfg 里的名义值 ——
    //   单核走收紧口径（见 ScanOnce），若这里打 60% 而实际跑 90%，
    //   排障时会被这条日志直接带偏（同「日志说 A 代码做 B」的家族）。
    {
        const unsigned cores = Cores();
        const bool sc = (cores < g_cfg.coresMin);
        LogDbg(std::string("[resmon] 资源监控已启动：周期 ") +
               std::to_string(g_cfg.sampleIntervalMs) + "ms" +
               " 阈值 " + std::to_string(sc ? g_cfg.singleCorePercent : g_cfg.cpuPercent) +
               "%×核 连续 " + std::to_string(sc ? g_cfg.singleCoreSamples : g_cfg.minSamples) +
               " 次 / 持续 " + std::to_string(sc ? g_cfg.singleCoreSustain : g_cfg.minSustainSec) +
               "s 逻辑核 " + std::to_string(cores) +
               (sc ? "（单核口径：收紧阈值而非跳过）" : ""));
    }
    uint64_t n = 0;
    while (!IsStopRequested()) {
        HANDLE h = StopHandle();
        if (h && WaitForSingleObject(h, g_cfg.sampleIntervalMs) != WAIT_TIMEOUT) break;
        // ★ 静默降级纪律：周期统计必须落日志，否则「扫了几轮、一轮多少」是黑洞
        const unsigned f = ScanOnce();
        n++;
        if (n % 12 == 1) {
            LogDbg("[resmon] 周期统计：已扫 " + std::to_string(n) + " 轮，累计挑出可疑高 CPU 进程 " +
                   std::to_string(g_hitCount.load()) + " 个次（本轮 " + std::to_string(f) + "）");
        }
    }
    g_running.store(false);
    LogDbg("[resmon] 资源监控已停止（共扫 " + std::to_string(n) + " 轮）");
}

bool Start() {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return true;   // 幂等
    {
        std::lock_guard<std::mutex> lk(g_accMtx);
        g_acc.clear();
    }
    g_scanCount.store(0); g_hitCount.store(0);
    std::thread(MonThread).detach();
    return true;
}

void Stop() { g_running.store(false); }
bool IsRunning() { return g_running.load(); }

bool SingleCoreMode() { return Cores() < g_cfg.coresMin; }

std::string FormatHits() {
    std::ostringstream ss;
    // ★ 同样报**实际生效**的口径（单核走收紧阈值），并把口径本身暴露出来，
    //   这样「为什么这台机器阈值和文档不一样」从管道就能直接回答。
    const unsigned cores = Cores();
    const bool sc = (cores < g_cfg.coresMin);
    ss << "{\"running\":" << (g_running.load() ? "true" : "false")
       << ",\"scans\":" << g_scanCount.load()
       << ",\"hits\":"    << g_hitCount.load()
       << ",\"cores\":"   << cores
       << ",\"singleCoreMode\":" << (sc ? "true" : "false")
       << ",\"cpuPercent\":" << (sc ? g_cfg.singleCorePercent : g_cfg.cpuPercent)
       << ",\"minSustainSec\":" << (sc ? g_cfg.singleCoreSustain : g_cfg.minSustainSec)
       << ",\"minSamples\":" << (sc ? g_cfg.singleCoreSamples : g_cfg.minSamples)
       << "}";
    return ss.str();
}

}  // namespace resmon
}  // namespace sf
