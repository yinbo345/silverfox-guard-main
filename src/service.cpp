// service.cpp — 银狐主防服务：SCM 控制 / 守护循环 / 命名管道 / 自保 / 安装
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <sddl.h>
#include <shlobj.h>
#include <thread>
#include <atomic>
#include <mutex>
#include <wbemidl.h>
#include <unordered_map>
#include <map>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>   // std::sort（隔离区列表按时间倒序）
#include <ctime>       // time()（隔离区索引时间戳）

#include "scanner.h"
#include "common.h"
#include "hashverdict.h"   // 病毒库点查（原 static HashDbVerdict，2026-09-27 提升为公共实现）
#include "cleaner.h"
#include "compute.h"
#include "probe.h"
#include "rollback.h"
#include "service.h"
#include "behavior.h"   // 实时防护判定核心：JudgeProcess / MakeEntityOfPid / ProcEntity
#include "sfcompat.h"    // 2026-10-03 Win10 适配：SeDebugPrivilege / 版本口径 / 多策略命令行
#include "observe.h"     // 放行后监控灰名单：ObserveAdd / ObserveHit
#include "bootguard.h"  // MBR 引导扇区防护（基线 + 5 秒级监视 + 自动拦截 + 可撤销）
#include "trace.h"      // 行为链记录（弹窗「查看病毒行为图」的数据源，2026-09-21）
#include "netwatch.h"   // 网络外联采集（第四个实时防护事件源，2026-09-22）
#include "resmon.h"      // 进程资源监控（第八个实时防护事件源，2026-10-03，挖矿兜底）
#include "guardcheck.h"   // 能力看门狗（2026-10-03，C1）
#include "errhold.h"     // 无结论文件的用户决策待决表（2026-10-03，errdecide 管道命令）
#include "crashlog.h"   // 崩溃留证（2026-10-03，无条件装未捕获异常过滤器）
#include "packscan.h"   // 压缩包落地深度检测（异步解包 + 内容判定，2026-09-22）
#include "sandbox.h"    // 动态分析沙箱（异步送检队列 + 结果回调，2026-09-27）
#include "iocs.h"       // 已知 C2 表（C2_IPS / C2_PORTS）—— 与全盘扫描同源，口径一致
#include "resultstore.h"// 扫描结果写入契约（消除 4 处重复的写样板）
#include "sfstop.h"     // 停止信号契约（StopHandle）
#include "sfutils.h"    // 路径/字符串工具（NowStr 等）
#include "module.h"     // 主干式架构：分体契约 + 托管器（2026-09-22）
#include "etwproc.h"    // ETW 进程创建订阅（实时防护第一事件源）
#include "iowatch.h"    // 文件/注册表写操作采集（第六个实时防护事件源，2026-09-25）
#include "auditapi.h"    // 跨进程注入/内存加载采集（第七个实时防护事件源，2026-09-30）
#include "sfthread.h"   // 线程双层兜底（RunThreadGuarded，主干与分体共用）
#include "aiobserve.h"  // ★ 影子模式投递（只投事实、不做 I/O；契约见该文件头）
#include "hashshare.h"  // ★ 云端哈希库查询（病毒库点查；契约与"为什么不给指针"见该文件头）
#include "pehash.h"     // 文件 SHA-256 / imphash（与 hashq 命令同一套算法）

#include <bcrypt.h>     // BCryptGenRandom：隔离区可逆编码的每文件随机密钥（2026-09-26）
#pragma comment(lib, "bcrypt.lib")
#include <aclapi.h>     // SetNamedSecurityInfoW：还原产物 ACL 归还给父目录继承（2026-09-26）
#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "advapi32.lib")

namespace sf {

SERVICE_STATUS        g_svcStatus{};
SERVICE_STATUS_HANDLE g_svcHandle = NULL;
HANDLE                g_stopEvent = NULL;
std::atomic<bool>     g_stop{false};

static void WmiProcessWatch();   // 定义见 GuardThread 之后（ETW 失败时的兜底订阅）
static void ProcessWatch();      // 实时事件订阅线程：ETW 优先，失败回退 WMI
static void RegRunWatch();       // 注册表自启动项实时监控（第二个实时防护事件源）
static void LandedAlertWatch();  // 落地捕获消费线程（第三个实时防护事件源，2026-09-19）
static void NetWatch();          // 网络外联监听（第四个实时防护事件源，2026-09-22）
static void PersistWatch();      // 持久化面全覆盖（第五个实时防护事件源，2026-09-24）
static void IoWatch();           // 文件/注册表写操作采集（第六个实时防护事件源，2026-09-25）
static void ApiWatch();           // 跨进程注入/内存加载采集（第七个实时防护事件源，2026-09-30）
static void ResMonWatch();        // 进程资源监控（第八个实时防护事件源，2026-10-03，挖矿兜底）
static void GuardCheckWatch();    // 能力看门狗（C1，2026-10-03：任一事件源降级/停摆即显式报出）
static std::string TasksRootDir();   // 计划任务目录（UniversalUndo 的 kind=40 也要用）

// ---------------------------------------------------------------------------
//  ⚠️ 线程级异常兜底已抽为公共契约 sf::RunThreadGuarded（实现见 sfthread.cpp）。
//
//  为什么不留在本文件：分体模块（由 module.cpp 托管的 mod_*.cpp 线程）也必须
//  享受同样的双层兜底（SEH + C++ 异常）。原实现是本文件的 static 函数，外部
//  用不到 —— 会造成分体线程比主干线程更脆弱的不对称，是事故温床。
//  抽成公共契约后，主干线程与所有分体线程走同一条兜底路径。
//
//  历史背景（旧架构的致命缺失）：过去 ServiceMain 起线程后直接
//  WaitForSingleObject(INFINITE)，**假设只要服务没被停止、进程就永远活着**。
//  但 C++ 异常（bad_alloc / 越界 / 第三方 COM 抛出）从任一工作线程逃逸，CRT 会
//  直接 std::terminate() → 进程静默死亡，日志干净地断掉、退出码为 0，服务管理器
//  只会按 sc failure 策略重启它 —— 用户看到的是莫名其妙重启，无从追查。
// ---------------------------------------------------------------------------

// 普通清除（cmd=clean）后仍失败的目标清单，供「高级清除（cmd=clean_adv）」阶段消费
static std::vector<std::string> g_failedTargets;
static std::mutex               g_failedMtx;

// rescan 去重：全盘扫描 ~20 秒，用户连点「立即检查」会连发多个 rescan。
// exchange=true 表示已有全盘在跑，后到的 rescan 直接回缓存结果，不再排队重扫。
static std::atomic<bool> g_rescanBusy{ false };

// ★★ C2 处置闭环断言的累计计数（2026-10-03）
//   语义：**累计发生过的「判定了却一件都没处置」次数**。
//   正常应恒为 0。非 0 即表示某条处置分支与判定链脱节（今天实测查出过三处：
//   注入侧只打日志、error 结论无条件放行、送检副本不带依赖）。
//   刻意不按分钟重置 —— 半通故障是要回溯的，跨轮累计才有意义。
static std::atomic<unsigned long long> g_halfOpen{ 0 };


// 前置声明：衍生物清除联动要落历史（定义见清除历史段）
static void AppendCleanHistory(const char* mode, const CleanReport& rep);

// ---------------------------------------------------------------------------
//  ★ 衍生物清除联动（2026-09-20 新增）
//
//  实时拦截的三条路径（进程终止 / 落地隔离 / 自启移除）处置的都是「当前那一个对象」，
//  但银狐从不只释放一个文件——它一次落地多份随机名副本（互相当备份），
//  还会在 Temp/ProgramData/Users\Public 里埋伴生 DLL。只处理当前对象，
//  结果是「拦了一个，另一个把它拉回来」，用户视角就是"清不干净"。
//
//  故三条路径在处置完成后统一调此函数收尾。安全约束（全部在 cleaner.cpp 内实现）：
//    · 目录白名单（IsNeverCleanPath）：反作弊 / Program Files / 系统目录一律不动
//    · 自保：我方程序文件不动
//    · 上限 24 个文件，避免实时路径被扫盘拖慢
//    · 只做轻量删除，删不掉就跳过（不硬删、不夺权、不重启登记）——
//      实时路径绝不自作主张扩大破坏面，顽固文件留给用户显式点「一键清除」
//
//  同一进程名 60 秒内只清一次，避免同一载荷反复拉起时疯狂扫盘。
// ---------------------------------------------------------------------------
static void SweepDerivativesFor(const std::string& seedPath, const char* tag) {
    if (seedPath.empty()) return;
    {
        static std::mutex m;
        static std::unordered_map<std::string, std::chrono::steady_clock::time_point> seen;
        auto now = std::chrono::steady_clock::now();
        std::string key = sf::BaseName(seedPath);
        for (auto& c : key) c = (char)tolower((unsigned char)c);
        if (key.empty()) return;
        std::lock_guard<std::mutex> lk(m);
        auto it = seen.find(key);
        if (it != seen.end() && now - it->second < std::chrono::seconds(60)) return;
        seen[key] = now;
        if (seen.size() > 2048) seen.clear();
    }
    CleanReport rep;
    int n = 0;
    try { n = sf::SweepDerivatives({ seedPath }, &rep, false); } catch (...) { return; }
    if (n <= 0) return;
    LogDbg(std::string("[deriv] 衍生物清除（") + tag + "）：种子=" + seedPath +
           " 清除=" + std::to_string(n) +
           "（requested=" + std::to_string(rep.requested) +
           " failed=" + std::to_string(rep.failed) + "）");
    AppendCleanHistory("deriv", rep);
}

void RequestStop() { g_stop.store(true); if (g_stopEvent) SetEvent(g_stopEvent); }
bool IsStopRequested() { return g_stop.load(); }

// ---- 停止信号契约的访问器（见 sfstop.h）----
// 拆分巨型文件时，service.cpp 之外的模块（netwatch / watch_* / 未来的子模块）
// 不该再直接摸 g_stopEvent 这个全局 —— 它属于 SERVICE_STATUS 生命周期，
// 由 ServiceMain 创建、HandlerEx 触发、ServiceMain 末尾关闭。
// 统一通过本函数读取，句柄所有权仍留在 service.cpp。
HANDLE StopHandle() { return g_stopEvent; }

// ---------------------------------------------------------------------------
//  清除历史（NDJSON 追加写）：扩展端「清除记录」卡片的数据源。
//  每行一条 JSON 记录；读取时取最后 50 行，避免无限增长。
// ---------------------------------------------------------------------------
static std::wstring HistoryPathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\clean_history.ndjson";
}

static std::string NowStr() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::ostringstream os;
    os << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return os.str();
}

// 每次清除（普通 / 高级）完成后追加一条记录
static void AppendCleanHistory(const char* mode, const CleanReport& rep) {
    std::string line = "{\"time\":\"" + NowStr() + "\",\"mode\":\"" + mode + "\"";
    line += ",\"requested\":" + std::to_string(rep.requested);
    line += ",\"deleted\":"   + std::to_string(rep.deleted);
    line += ",\"deferred\":"  + std::to_string(rep.deferred);
    line += ",\"failed\":"    + std::to_string(rep.failed);
    line += ",\"killed\":"    + std::to_string(rep.killed);
    line += ",\"extraDlls\":" + std::to_string(rep.extraDlls);
    line += ",\"items\":[";
    for (size_t i = 0; i < rep.items.size(); ++i) {
        if (i) line += ",";
        line += "{\"path\":" + JsonString(rep.items[i].path);
        line += ",\"action\":" + JsonString(rep.items[i].action);
        line += ",\"reason\":" + JsonString(rep.items[i].reason) + "}";
    }
    line += "]}\n";
    HANDLE h = CreateFileW(HistoryPathW().c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr);
    CloseHandle(h);
}

// 供 cmd=history：读 NDJSON 最后 50 行，拼成扩展可直接渲染的响应帧
static std::string BuildHistoryJson() {
    std::vector<std::string> lines;
    std::ifstream f(HistoryPathW());
    if (f) {
        std::string ln;
        while (std::getline(f, ln)) {
            if (!ln.empty()) lines.push_back(ln);
            if (lines.size() > 200) lines.erase(lines.begin());   // 防超大文件读爆内存
        }
    }
    size_t start = lines.size() > 50 ? lines.size() - 50 : 0;
    std::string s = "{\"type\":\"clean_history\",\"records\":[";
    for (size_t i = start; i < lines.size(); ++i) {
        if (i > start) s += ",";
        s += lines[i];
    }
    s += "]}";
    return s;
}

// ---------------------------------------------------------------------------
//  服务控制处理
// ---------------------------------------------------------------------------
static DWORD WINAPI HandlerEx(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            g_svcStatus.dwCurrentState = SERVICE_STOP_PENDING;
            SetServiceStatus(g_svcHandle, &g_svcStatus);
            RequestStop();
            break;
        case SERVICE_CONTROL_INTERROGATE:
        default: break;
    }
    SetServiceStatus(g_svcHandle, &g_svcStatus);
    return NO_ERROR;
}

// ---------------------------------------------------------------------------
//  正经杀软模式的统一处置/撤销层（2026-09-19，银泊指示）
// ---------------------------------------------------------------------------
//  撤销 token 统一 10 位 hex：前 2 位是类型码，后 8 位是事件 id ——
//  NotifyAnomaly 对 undoToken 做 [0-9a-f] 白名单过滤（命令行是外部可写边界），
//  所以类型码必须编码进 hex 而不是用 "boot:" 这类带冒号前缀。
//    10xxxxxx = 引导扇区（撤销 = 写回隔离副本）   → boot::UndoIntercept
//    20xxxxxx = 自启动项（撤销 = 写回注册表原值）
//    30xxxxxx = 落地隔离（撤销 = 把文件移回原位）
//    其余     = 勒索回滚（撤销 = 反向回滚）        → rb::UndoLastRollback
struct UndoRec {
    int kind = 0;               // 2=自启动项 3=落地隔离
    std::string a, b, c, d;     // kind=2: hive|keypath|valueName|data  kind=3: 隔离路径|原路径
};
static std::mutex g_undoMtx;
static std::map<std::string, UndoRec> g_undoMap;   // id(hex) → 记录

static std::string NewUndoId() {
    char b[16];
    snprintf(b, sizeof(b), "%08x", (unsigned)(GetTickCount() & 0xFFFFFFFE) | 1);
    return b;
}

// 右下角自动拦截卡的数据源：toast 卡 JS 加载时经管道取 lastalert 回填
// 「某某程序正在干嘛」的归因文本（卡片 HTML 是静态的，进程名不能走命令行 —— 注入面）。
static std::mutex g_lastAlertMtx;
static std::string g_lastAlertJson = "{}";
static void SetLastAlertInfo(const std::string& title, const std::string& sub,
                             const std::string& proc) {
    std::string js = "{\"title\":" + sf::JsonString(title);
    js += ",\"sub\":"  + sf::JsonString(sub);
    js += ",\"proc\":" + sf::JsonString(proc) + "}";
    std::lock_guard<std::mutex> lk(g_lastAlertMtx);
    g_lastAlertJson = js;
}
static std::string LastAlertJson() {
    std::lock_guard<std::mutex> lk(g_lastAlertMtx);
    return g_lastAlertJson;
}

// ---------------------------------------------------------------------------
//  ★ 隔离区硬化（2026-09-21，银泊要求：「放进隔离区里的文件，要保证它完全不能运行」）
// ---------------------------------------------------------------------------
//  为什么必须做：旧的隔离只用 MoveFileW 把文件挪到
//  C:\ProgramData\SilverFoxGuard\quarantine\l_<id>.qtn，**一点权限收紧都没有**。
//  而 ProgramData\SilverFoxGuard 继承来的 DACL 是
//      BUILTIN\Users:(OI)(CI)(RX)              ← 读 + 执行
//      BUILTIN\Users:(CI)(WD,AD,WEA,WA)        ← 还能建文件/改属性
//  也就是说隔离后的样本，普通用户双击照样能跑；攻击者也能往隔离目录里再扔东西。
//  "隔离"名不副实。
//
//  四道锁（缺一不可，全部在 MoveFileW 之前/之后落地）：
//    锁 1  容器 ACL：隔离目录改成只有 SYSTEM + Administrators，
//          并 **关掉继承**（D 前缀的 SDDL 不带 (I) 项）——否则 Users 的权限会
//          从 ProgramData 一路继承下来，给目录级锁形同虚设。
//    锁 2  文件 ACL：文件本身也显式设成仅 SYSTEM/Admins 可读，
//          Everyone 连读都不给（不给执行位是底线，连读都不给更彻底）。
//    锁 3  ▲ 去执行结构：把 PE 头里的 `MZ` 起步区域抹成 `QT`（Quarantine Truncated），
//          并毁掉 `e_lfanew` 指向的 `PE\0\0` 签名。
//          → 即使前两道锁被管理员权限攻破、文件被复制出去，**它也不再是一个
//            合法的可执行映像**，双击只会报"不是有效的 Win32 应用程序"。
//          这是唯一能防住"提权绕过 ACL"的一道锁。
//    锁 4  扩展名 .qtn（不是 .exe/.dll/.scr）—— 防的是"用户自己去隔离目录
//          里翻出来双击"这种最朴素的人为失误；不指望它防攻击者。
//
//  撤销（还原）时：先去执行结构**无法自动还原**（MZ 已被抹），
//  所以隔离文件必须能"失败还原"而不是"假装还原成功"。
//  处理方式：还原前检查头部，若是被截断过的，还原后**明确告知用户文件已不可执行**，
//  需要重新下载/重新获取原文件。宁可如实说，不假装能用。
// ---------------------------------------------------------------------------

// 隔离目录（宽字符）+ 确保存在且已硬化。
// 每次调用都重新收紧一次：用户/其他程序可能把权限改回去。
static std::wstring QuarantineDirW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard\\quarantine";
    else dir = L"C:\\ProgramData\\SilverFoxGuard\\quarantine";
    return dir;
}

// 把目录 DACL 设为「仅 SYSTEM + Administrators」，并断开继承。
// SDDL 说明：
//   D:            → DACL
//   PA            → 保护（P = Protected，阻断从父容器继承）★ 关键
//   (A;;FA;;;SY)  → Allow 完全控制 给 SYSTEM
//   (A;;FA;;;BA)  → Allow 完全控制 给 Builtin Administrators
//   (A;;0x1200a9;;;OW) → 给 Owner 读+执行（便于用户自己看隔离了什么）
// 注意：**不给 Users 组任何权限** —— 普通用户不应当直接接触隔离区，
// 浏览隔离区走服务管道（service 代读），而不是文件系统直读。
static bool HardenQuarantineDir(const std::wstring& dir) {
    // ○ SDDL_REVISION_1 + 显式 PA 前缀：PA 会写入 SE_DACL_PROTECTED，
    //   阻断从 ProgramData 继承下来的 Users:(RX) 与 Users:(WD,AD,...)。
    //   同时 P 与 AI 并存，既有子项的继承 ACE 会被重算掉。
    const wchar_t* sddl =
        L"D:PAI"
        L"(A;OICI;FA;;;SY)"        // SYSTEM 完全控制（含子项）
        L"(A;OICI;FA;;;BA)"        // Administrators 完全控制（含子项）
        L"(A;OICI;0x1200a9;;;OW)"; // CREATOR OWNER 读+执行（目录所有者）
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    // SetFileSecurity 直接附着这一个 SD（自带 PROTECTED 语义）；
    // 比 SetNamedSecurityInfo 少一个 aclapi.h 依赖，行为一致。
    BOOL ok = SetFileSecurityW(dir.c_str(),
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok != 0;
}

// 把单个隔离文件的 DACL 设为「仅 SYSTEM + Administrators 读取」，Everyone 一律拒绝。
// 显式带一条 Deny(Everyone) —— 就算将来有人往隔离目录加了权限，
// Deny ACE 优先级高于 Allow，仍能挡住。
static bool HardenQuarantineFile(const std::wstring& file) {
    const wchar_t* sddl =
        L"D:PAI"
        L"(D;;FRFX;;;WD)"        // ★ Deny Everyone：读/执行全拒（Deny 优先）
        L"(A;;FA;;;SY)"          // SYSTEM 完全控制（服务要能删/还原/读）
        L"(A;;FA;;;BA)"          // Administrators 完全控制
        L"(A;;FR;;;OW)";         // CREATOR OWNER（服务账户）只读
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    BOOL ok = SetFileSecurityW(file.c_str(),
                               DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok != 0;
}

// ★ 锁 3b：脚本类正文破坏。
//   为什么单列一道锁：cmd.exe / wscript / powershell / python 这些宿主是
//   **逐行读文本**执行的，完全不看 PE 头。抹 PE 头对 .bat/.ps1 天然无效 ——
//   实测确认：把一个真 PE 改名 .bat 后双击，cmd.exe 会把 'QT...' 当命令逐行解析
//   （虽然全是乱码命令、不会真的执行恶意逻辑，但"能启动"这件事本身说明
//    扩展名与抹头都不构成硬保证）。所以脚本类必须**破坏正文**：
//   把文件内容整体覆写为 0x00（保持文件大小不变，便于事后取证"原本多大"）。
//   覆写为 0 而非删除：① 还原时能判断"这文件被破坏过"；② 不改变 inode 语义，
//   元数据（时间戳/占用簇）仍可分析。
//   返回：true = 正文已被破坏（或文件为空，无需处理）。
static bool WipeScriptBody(const std::wstring& file) {
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        sf::LogDbg("[quarantine] 脚本正文破坏失败：无法以写方式打开");
        return false;
    }
    LARGE_INTEGER sz = {0};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    if (sz.QuadPart == 0) { CloseHandle(h); return true; }   // 空文件本就不能执行

    // 分块覆写，避免为超大样本分配内存（上限 8MB，超出只覆写前 8MB +
    // 截掉尾部剩余内容是无法保证的，所以超限时改用"截断到 0"策略）
    const LONGLONG kMax = 8LL * 1024 * 1024;
    bool ok = false;
    if (sz.QuadPart <= kMax) {
        static const DWORD kChunk = 64 * 1024;
        unsigned char zero[kChunk];
        memset(zero, 0, sizeof(zero));
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        LONGLONG left = sz.QuadPart;
        ok = true;
        while (left > 0) {
            DWORD want = (DWORD)((left > (LONGLONG)kChunk) ? (LONGLONG)kChunk : left);
            DWORD wr = 0;
            if (!WriteFile(h, zero, want, &wr, nullptr) || wr != want) { ok = false; break; }
            left -= wr;
        }
        if (ok) FlushFileBuffers(h);
    } else {
        // 超大脚本样本极少见；截断为 0 同样能达到"无法运行"的目的
        SetFilePointer(h, 0, nullptr, FILE_BEGIN);
        if (SetEndOfFile(h)) { FlushFileBuffers(h); ok = true; }
    }
    CloseHandle(h);
    return ok;
}

// 判断是否为「靠宿主逐行解释执行的脚本类」文件。
// 依据扩展名 —— 这不是"用扩展名当安全措施"，而是**选择用哪种破坏手段**：
// PE 抹头 vs 正文覆写，两者都做才是完整覆盖。
static bool IsScriptLikeExt(const std::wstring& file) {
    size_t dot = file.rfind(L'.');
    if (dot == std::wstring::npos) return false;
    std::wstring e = file.substr(dot);
    for (size_t i = 0; i < e.size(); ++i) e[i] = (wchar_t)towlower(e[i]);
    static const wchar_t* kExts[] = {
        L".bat", L".cmd", L".js", L".jse", L".vbs", L".vbe", L".wsf", L".wsh",
        L".ps1", L".psm1", L".psd1", L".py", L".pyw", L".pl", L".rb", L".php",
        L".hta", L".lnk", L".scf", L".inf", L".reg", L".sh", L".jar", L".scr",
        L".msi", L".cpl", L".dll", L".sys", L".ocx", nullptr
    };
    for (int i = 0; kExts[i]; ++i) if (e == kExts[i]) return true;
    return false;
}

// ★ 锁 3：去执行结构。把 PE 头部抹掉，使文件不再是合法可执行映像。
//   做法（不改文件大小，不加密，不破坏"能不能看出它是什么"）：
//     ① 开头 2 字节 MZ → QT   （所有加载器第一关就不过）
//     ② e_lfanew(0x3C) 处的 "PE\0\0" → "QU\0\0"
//     ③ 文件属性加 FILE_ATTRIBUTE_READONLY（防手滑覆盖）
//   为何不加密：加密后"还原"要解密，解密逻辑本身是攻击面；
//   而且加密后的文件在磁盘上仍可能被误当数据执行。抹头更直接、不可逆、可自证。
//   也**不做**任何"重命名成 .txt 就以为安全"的事 —— 扩展名挡不住任何人。
//
//   ★ 两道分支（缺一不可，实测得出）：
//     · 有 MZ 头 → 抹 PE 头。加载器实测 LoadLibrary 返回 193「不是有效的 Win32 应用程序」，
//       且**只改 MZ 或只改 PE 签名任意一处**都足以让加载器拒绝。
//     · 无 MZ 头（脚本/文本/数据）→ 破坏正文。cmd.exe 等宿主逐行读文本，
//       不看 PE 头，抹头对它们无效；覆写正文为 0 才能彻底堵死。
//   两种破坏都做，而不是"按扩展名选一种"：扩展名可以随便改，内容才作数。
//   返回：true = 已确认文件不再可执行。
static bool StripExecutableHeader(const std::wstring& file) {
    bool isScript = IsScriptLikeExt(file);
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        sf::LogDbg("[quarantine] 去执行结构失败：无法以写方式打开（文件可能被占用）");
        return false;
    }
    unsigned char hdr[64] = {0};
    DWORD got = 0;
    bool ok = false;
    if (ReadFile(h, hdr, sizeof(hdr), &got, nullptr) && got >= 2) {
        if (!(hdr[0] == 'M' && hdr[1] == 'Z')) {
            // ---- 非 PE 分支：正文破坏 ----
            CloseHandle(h);
            h = INVALID_HANDLE_VALUE;
            bool wiped = WipeScriptBody(file);
            if (wiped) {
                sf::LogDbg(std::string("[quarantine] 非 PE 文件已破坏正文（覆写为 0）：") +
                           (isScript ? "脚本类，正文覆写后宿主无法解释执行"
                                     : "数据类，内容已清空"));
                ok = true;
            } else {
                sf::LogDbg("[quarantine] ⚠ 非 PE 文件正文破坏失败，仅 ACL 与扩展名生效");
                ok = false;
            }
        } else {
            // ---- PE 分支：抹头 ----
            // ① 抹 MZ
            hdr[0] = 'Q'; hdr[1] = 'T';
            // ② 抹 e_lfanew 处的 PE 签名（e_lfanew 位于偏移 0x3C，4 字节小端）
            DWORD peOff = 0;
            if (got >= 0x40) {
                peOff = (DWORD)hdr[0x3C] | ((DWORD)hdr[0x3D] << 8) |
                        ((DWORD)hdr[0x3E] << 16) | ((DWORD)hdr[0x3F] << 24);
            }
            SetFilePointer(h, 0, nullptr, FILE_BEGIN);
            DWORD wr = 0;
            WriteFile(h, hdr, 64, &wr, nullptr);
            // ② 单独定位 PE 签名再抹一次（PE 头通常远在 64 字节之后）
            if (peOff > 0 && peOff < 0x1000000) {
                SetFilePointer(h, (LONG)peOff, nullptr, FILE_BEGIN);
                unsigned char sig[4] = {'Q', 'U', 0, 0};
                DWORD w2 = 0;
                WriteFile(h, sig, 4, &w2, nullptr);
            }
            FlushFileBuffers(h);
            ok = true;
            // ★ 扩展名声称是脚本、实际是 PE（伪装样本）：两道破坏都做，
            //   防止攻击者把 PE 改名 .bat 后由别的宿主加载。
            if (isScript) {
                CloseHandle(h);
                h = INVALID_HANDLE_VALUE;
                if (!WipeScriptBody(file))
                    sf::LogDbg("[quarantine] ⚠ 伪脚本 PE 的正文破坏失败（PE 头已抹）");
            }
        }
    }
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    if (ok) {
        SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY);
        sf::LogDbg("[quarantine] 已去除可执行结构（PE 抹头 / 非 PE 破坏正文），该文件无法再被加载运行");
    }
    return ok;
}

// 判断一个隔离文件是否已被去除可执行结构（还原时要如实告知用户）。
//   1 = 已抹 PE 头（QT 开头）        → 还原后无法作为可执行映像运行
//   0 = 完整 PE（MZ 开头）           → 还原后可用
//   2 = 非 PE，但正文已被覆写为 0     → 还原后是空壳，脚本类也无法执行
//   3 = 非 PE，正文仍在               → 还原后仍可能被宿主解释执行（旧版本隔离的遗留）
//  -1 = 读不到（已被 ACL 挡住或不存在）
static int QuarantineStrippedState(const std::wstring& file) {
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return -1;   // 读不到（已被 ACL 挡住或不存在）
    unsigned char b[2] = {0}; DWORD got = 0;
    bool rd = ReadFile(h, b, 2, &got, nullptr) && got == 2;
    LARGE_INTEGER sz = {0};
    bool gotSize = GetFileSizeEx(h, &sz) != 0;
    CloseHandle(h);
    if (!rd) {
        // 读不到头 2 字节：可能是 0 字节文件（正文已破坏的一种形态）
        return (gotSize && sz.QuadPart == 0) ? 2 : -1;
    }
    if (b[0] == 'Q' && b[1] == 'T') return 1;    // 已去 PE 头
    if (b[0] == 'M' && b[1] == 'Z') return 0;    // 完整 PE
    if (b[0] == 0 && b[1] == 0) return 2;        // 非 PE 且正文已清零（我们的破坏痕迹）
    return 3;                                     // 非 PE，正文仍在
}

// ===========================================================================
//  ★ 隔离区可逆编码（2026-09-26，银泊方案：记录改动 + 按记录还原）
// ===========================================================================
//  【为什么改】旧实现隔离时不可逆破坏（PE 抹头 / 非 PE 覆 0），「撤销还原」
//  还原回来的是坏文件（实测：NOBELIUM.zip 还原后 7-Zip 打不开、哈希全变）——
//  「隔离 ≠ 删除、可还原」的承诺被实现打破了。
//
//  【新机制】Move 进隔离区后，对副本做**整文件 XOR 每文件随机 32 字节密钥**：
//    · 防御目的达成：编码后头部既非 MZ 也非 QT，PE 加载器拒绝；正文对脚本宿主
//      是乱码命令；zip/文档打开也是乱码 —— 与旧破坏等效的「无法再被加载运行」。
//    · 可逆：还原时按台账记录的密钥**再次 XOR**（自逆）→ 逐字节恢复原文。
//    · 开源无碍：算法公开没关系，安全来自 ①隔离目录/文件的 SYSTEM-only ACL，
//      ②每文件随机密钥（BCryptGenRandom）—— 拿到密钥的前提是先突破 SYSTEM，
//      那时攻击者早已为所欲为，隔离区不是最后防线。
//    · 台账记录 = 「改了什么」的完整文档：keyHex + origSha16 + origSize
//      （QuarEntry 扩列，见上）。还原后按 origSha16 对账，还原错了能发现。
// ===========================================================================
static bool GenQuarKeyHex(std::string& outHex) {
    unsigned char key[32];
    if (FAILED(BCryptGenRandom(nullptr, key, sizeof(key),
                               BCRYPT_USE_SYSTEM_PREFERRED_RNG))) return false;
    static const char* kHex = "0123456789abcdef";
    outHex.resize(64);
    for (int i = 0; i < 32; ++i) {
        outHex[i * 2]     = kHex[key[i] >> 4];
        outHex[i * 2 + 1] = kHex[key[i] & 0x0F];
    }
    return true;
}

// XOR 编码/解码一体（自逆）。分块 4MB 流式处理，不为大样本分配整块内存。
// 成功后设只读属性（与旧抹头一致，防手滑覆盖）。失败时文件内容可能已部分
// 改写 —— 调用方（还原路径）遇到失败必须中止还原并保留隔离副本，绝不半还原。
static bool XorQuarFileWithKey(const std::wstring& file, const unsigned char key[32]) {
    HANDLE h = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        sf::LogDbg("[quarantine] 编码/解码失败：无法以读写方式打开（ACL/占用）");
        return false;
    }
    static const DWORD kChunk = 4 * 1024 * 1024;
    std::vector<unsigned char> buf(kChunk);
    uint64_t off = 0;
    bool ok = true;
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), kChunk, &got, nullptr)) { ok = false; break; }
        if (got == 0) break;
        for (DWORD i = 0; i < got; ++i) buf[i] ^= key[(off + i) & 31];
        DWORD wr = 0;
        // 回退到本块起点再写回：ReadFile 顺序读后指针在块尾，写回必须回到块头。
        // 用相对定位（FILE_CURRENT）避开 64 位高低位拼 PLONG 的样板与踩坑。
        LONG back = -((LONG)got);
        SetFilePointer(h, back, nullptr, FILE_CURRENT);
        if (!WriteFile(h, buf.data(), got, &wr, nullptr) || wr != got) { ok = false; break; }
        off += got;
        if (got < kChunk) break;
    }
    if (ok) FlushFileBuffers(h);
    CloseHandle(h);
    if (ok) SetFileAttributesW(file.c_str(), FILE_ATTRIBUTE_READONLY);
    return ok;
}

// hex 密钥 → 32 字节。非法输入返回 false（还原路径据此拒绝，绝不瞎解）。
static bool QuarKeyHexToBytes(const std::string& hex, unsigned char out[32]) {
    if (hex.size() != 64) return false;
    for (int i = 0; i < 64; ++i) {
        char c = hex[i];
        unsigned char v;
        if (c >= '0' && c <= '9')      v = (unsigned char)(c - '0');
        else if (c >= 'a' && c <= 'f') v = (unsigned char)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') v = (unsigned char)(c - 'A' + 10);
        else return false;
        out[i / 2] = (i % 2 == 0) ? (unsigned char)(v << 4) : (unsigned char)(out[i / 2] | v);
    }
    return true;
}

// ---------------------------------------------------------------------------
//  ★ 隔离区索引（2026-09-20 新增）
//
//  为什么必须落盘：隔离记录原本只存在内存里的 g_undoMap（Process 级），
//  且 size()>64 就整体 clear() —— 服务一重启，隔离区里躺着的文件就**彻底失联**：
//  用户能看到 C:\ProgramData\SilverFoxGuard\quarantine\ 里有一堆 .qtn，
//  但没人知道它们原本叫什么、从哪来、为什么被隔离、还原后还能不能用。
//  「看不到隔离区」这个反馈的根因就在这里 —— GUI 没页面只是表象，
//  真正缺的是这份**可以重建展示的元数据**。
//
//  落盘格式：每行一条制表符分隔（TSV），列序固定：
//      id \t origin(UTF-8 path) \t atMs \t reason \t state
//  行内不出现制表符与换行（path 里的制表符极罕见，写入前统一替换为空格）。
//  索引文件本身也在隔离目录里，靠目录级 ACL（仅 SYSTEM/Admins）保护。
// ---------------------------------------------------------------------------
struct QuarEntry {
    std::string id;       // 8 位 hex（撤销 token 的后 8 位）
    std::string origin;   // 原始路径（UTF-8）
    uint64_t    atMs = 0; // 隔离时刻
    std::string reason;   // 命中原因（落盘捕获 / 实时判定）
    int         state = -1;  // 还原可用性档位（QuarantineStrippedState）
    // ★ 2026-09-26 可逆编码记录（银泊方案）：
    //   隔离不再不可逆破坏内容，改为「整文件 XOR 每文件随机密钥」——副本既不可
    //   直接执行/打开（防御目的与旧抹头/覆0 等效），又能按记录**逐字节还原**。
    //   这三项就是银泊说的「程序到底改了这个文件的什么」的完整记录：
    //     keyHex    = 本次编码的 32 字节随机密钥（64 hex）。算法随开源代码公开
    //                 无妨（Kerckhoffs 原则：安全来自隔离目录 ACL + 每文件随机
    //                 密钥，不来自算法保密）；拿到密钥的前提是先突破 SYSTEM 权限。
    //     origSha16 = 编码前原始内容的 SHA-256 前 16 hex —— 还原后校验用，
    //                 「按文档还原」必须有对账凭证，否则还原错了也不知道。
    //     origSize  = 编码前原始字节数（十进制）。
    //   旧版本隔离的记录（5 列 TSV）这三项为空 → 还原走旧档位逻辑（如实告知不可用）。
    std::string keyHex;
    std::string origSha16;
    std::string origSize;
};

static std::mutex          g_qidxMtx;
static std::vector<QuarEntry> g_qidx;
static bool                g_qidxLoaded = false;

static std::wstring QuarantineIndexPathW() {
    return QuarantineDirW() + L"\\index.tsv";
}

// 读索引（懒加载；首次调用时把 index.tsv 全量读进内存）
static void LoadQuarantineIndexLocked() {
    if (g_qidxLoaded) return;
    g_qidxLoaded = true;
    g_qidx.clear();
    std::ifstream f(QuarantineIndexPathW().c_str(), std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // 切列（2026-09-26 扩为 8 列；旧版 5 列行兼容 —— 后三列缺省为空）
        std::vector<std::string> c;
        size_t p = 0;
        for (int i = 0; i < 7; ++i) {
            size_t q = line.find('\t', p);
            if (q == std::string::npos) break;
            c.push_back(line.substr(p, q - p));
            p = q + 1;
        }
        c.push_back(line.substr(p));
        if (c.size() < 5) continue;
        QuarEntry e;
        e.id     = c[0];
        e.origin = c[1];
        e.atMs   = (uint64_t)_strtoui64(c[2].c_str(), nullptr, 10);
        e.reason = c[3];
        e.state  = atoi(c[4].c_str());
        if (c.size() > 5) e.keyHex    = c[5];
        if (c.size() > 6) e.origSha16 = c[6];
        if (c.size() > 7) e.origSize  = c[7];
        g_qidx.push_back(e);
    }
}

// 整表回写（改一条就重写全表：条目数量级是几十，全写比增量改更不容易写坏）
static void SaveQuarantineIndexLocked() {
    std::wstring dir = QuarantineDirW();
    CreateDirectoryW(dir.c_str(), nullptr);
    // 先写临时文件再原子替换 —— 避免写到一半掉电留下半个索引，
    // 那种情况下用户会看到"隔离区空了"，比索引旧一点严重得多。
    std::wstring tmp = QuarantineIndexPathW() + L".tmp";
    {
        std::ofstream f(tmp.c_str(), std::ios::binary | std::ios::trunc);
        if (!f) return;
        for (const auto& e : g_qidx) {
            std::string o = e.origin, r = e.reason;
            for (char& ch : o) if (ch == '\t' || ch == '\n' || ch == '\r') ch = ' ';
            for (char& ch : r) if (ch == '\t' || ch == '\n' || ch == '\r') ch = ' ';
            f << e.id << '\t' << o << '\t' << e.atMs << '\t' << r << '\t' << e.state
              << '\t' << e.keyHex << '\t' << e.origSha16 << '\t' << e.origSize << "\r\n";
        }
    }
    MoveFileExW(tmp.c_str(), QuarantineIndexPathW().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

// 登记一条隔离记录（QuarantineLanded 成功后调用）
static void AddQuarantineRecord(const std::string& id, const std::string& origin,
                                const std::string& reason, int state,
                                const std::string& keyHex = std::string(),
                                const std::string& origSha16 = std::string(),
                                const std::string& origSize = std::string()) {
    std::lock_guard<std::mutex> lk(g_qidxMtx);
    LoadQuarantineIndexLocked();
    for (auto& e : g_qidx) {          // 同 id 覆盖（理论上不会重）
        if (e.id == id) { e.origin = origin; e.reason = reason; e.state = state;
                          e.keyHex = keyHex; e.origSha16 = origSha16; e.origSize = origSize;
                          e.atMs = GetTickCount64(); SaveQuarantineIndexLocked(); return; }
    }
    QuarEntry e;
    e.id = id; e.origin = origin; e.reason = reason; e.state = state;
    e.keyHex = keyHex; e.origSha16 = origSha16; e.origSize = origSize;
    e.atMs = (uint64_t)time(nullptr) * 1000ull;
    g_qidx.push_back(e);
    SaveQuarantineIndexLocked();
    LogDbg("[quarantine] 已登记隔离记录 id=" + id + " origin=" + origin +
           " state=" + std::to_string(state));
}

// 删除一条隔离记录（还原 / 删除后调用）
static void RemoveQuarantineRecord(const std::string& id) {
    std::lock_guard<std::mutex> lk(g_qidxMtx);
    LoadQuarantineIndexLocked();
    for (size_t i = 0; i < g_qidx.size(); ++i) {
        if (g_qidx[i].id == id) { g_qidx.erase(g_qidx.begin() + (ptrdiff_t)i); break; }
    }
    SaveQuarantineIndexLocked();
}

static std::wstring QuarantineFilePathW(const std::string& id) {
    std::wstring dir = QuarantineDirW();
    return dir + L"\\l_" + std::wstring(id.begin(), id.end()) + L".qtn";
}

// 隔离区列表 JSON（含逐条还原可用性档位）。
// 同时做一件事：**校验磁盘上的 .qtn 是否还在** —— 用户可能手工删过，
// 索引里却还留着记录。孤儿记录要标出来，不能让界面显示"可还原"却点不动。
static std::string BuildQuarantineListJson() {
    std::vector<QuarEntry> copy;
    {
        std::lock_guard<std::mutex> lk(g_qidxMtx);
        LoadQuarantineIndexLocked();
        copy = g_qidx;
    }
    // 按隔离时刻倒序：用户最关心"刚才隔离了什么"
    std::sort(copy.begin(), copy.end(),
              [](const QuarEntry& a, const QuarEntry& b) { return a.atMs > b.atMs; });

    // 顺手也扫一遍目录，把「有文件但索引里没记录」的孤儿捡回来
    // （历史版本隔离的文件、或索引被清过的情况）
    {
        std::vector<std::string> known;
        for (const auto& e : copy) known.push_back(e.id);
        std::wstring dir = QuarantineDirW();
        std::wstring pat = dir + L"\\l_*.qtn";
        WIN32_FIND_DATAW fd{};
        HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                std::wstring name = fd.cFileName;
                if (name.size() < 6) continue;
                std::string id(name.begin() + 2, name.end() - 4);   // 去 "l_" 与 ".qtn"
                bool dup = false;
                for (const auto& k : known) if (k == id) { dup = true; break; }
                if (dup) continue;
                QuarEntry e;
                e.id = id;
                e.origin = "（未知来源 · 早期版本隔离）";
                e.atMs = ((uint64_t)fd.ftLastWriteTime.dwHighDateTime << 32) |
                         fd.ftLastWriteTime.dwLowDateTime;
                e.atMs = e.atMs / 10000ull - 11644473600000ull;    // FILETIME → Unix ms
                e.reason = "历史遗留条目（本次启动扫描目录时补录）";
                e.state = QuarantineStrippedState(dir + L"\\" + name);
                copy.push_back(e);
            } while (FindNextFileW(hf, &fd));
            FindClose(hf);
        }
    }

    uint64_t nowMs = (uint64_t)time(nullptr) * 1000ull;
    std::ostringstream os;
    std::wstring dir = QuarantineDirW();
    os << "{\"ok\":true,\"dir\":" << sf::JsonString(std::string(dir.begin(), dir.end()))
       << ",\"count\":" << copy.size() << ",\"items\":[";
    size_t n = 0, liveCount = 0;
    for (const auto& e : copy) {
        if (n >= 300) break;      // 与快照列表一致：上限防止管道消息过大
        std::wstring wp = QuarantineFilePathW(e.id);
        bool exists = GetFileAttributesW(wp.c_str()) != INVALID_FILE_ATTRIBUTES;
        // state=4（可逆编码）只有我们能写、且无法从文件内容推断（编码后头部随机）
        // → 直接信台账；其余档位维持内容自证（旧记录兼容、防手工篡改）。
        int  st = exists ? (e.state == 4 ? 4 : QuarantineStrippedState(wp)) : -1;
        if (exists) ++liveCount;
        if (n) os << ",";
        os << "{\"id\":"      << sf::JsonString(e.id)
           << ",\"origin\":"  << sf::JsonString(e.origin)
           << ",\"at\":"      << e.atMs
           << ",\"ageMs\":"   << (nowMs > e.atMs ? (nowMs - e.atMs) : 0)
           << ",\"reason\":"  << sf::JsonString(e.reason)
           << ",\"state\":"   << st
           << ",\"exists\":"  << (exists ? "true" : "false");
        // 还原后能不能用 —— 界面上必须如实写出来，不能让用户还原完才发现文件坏了
        const char* usability =
              (st == 4) ? "encoded"      // 可逆编码存储 → 还原后完整可用
            : (st == 1) ? "stripped"     // 已抹 PE 头 → 还原后不可运行
            : (st == 2) ? "wiped"        // 正文已清零 → 还原后是空壳
            : (st == 0) ? "usable"       // 完整 PE → 可正常使用
            : (st == 3) ? "script"       // 非 PE 正文仍在 → 可能被宿主解释执行
                        : "unknown";     // 读不到
        os << ",\"usability\":" << sf::JsonString(usability);
        // 这个文件当初是不是我们自动隔离的（有索引记录）还是历史补录的
        os << ",\"tracked\":" << (e.origin.rfind("（未知来源", 0) == 0 ? "false" : "true") << "}";
        ++n;
    }
    os << "],\"shown\":" << n << ",\"live\":" << liveCount << "}";
    return os.str();
}

// 隔离区还原：先放开 ACL 再 Move（文件被设成 Deny Everyone，不解锁搬不出来），
// 并按档位如实告知「还原后能不能运行」。
static std::string QuarantineRestore(const std::string& id) {
    std::string origin;
    std::string keyHex, origSha16, origSizeS;   // ★ 可逆编码记录（2026-09-26）
    int storedState = -1;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_qidxMtx);
        LoadQuarantineIndexLocked();
        for (const auto& e : g_qidx)
            if (e.id == id) { origin = e.origin; found = true;
                              keyHex = e.keyHex; origSha16 = e.origSha16;
                              origSizeS = e.origSize; storedState = e.state; break; }
    }
    if (!found)
        return "{\"ok\":false,\"reason\":\"找不到该隔离记录（索引可能已被清理）。\"}";

    std::wstring wsrc = QuarantineFilePathW(id);
    if (GetFileAttributesW(wsrc.c_str()) == INVALID_FILE_ATTRIBUTES) {
        RemoveQuarantineRecord(id);
        return "{\"ok\":false,\"reason\":\"隔离文件已不在磁盘上（可能已被手工删除），记录已清除。\"}";
    }
    // 还原前先记录档位 —— 放开 ACL 之后就读不出来了（不是内容变了，是权限流程）。
    // state=4（可逆编码）无法从内容推断（编码后头部随机）→ 信台账存档。
    const int st = (storedState == 4) ? 4 : QuarantineStrippedState(wsrc);

    int w2 = MultiByteToWideChar(CP_UTF8, 0, origin.c_str(), -1, nullptr, 0);
    std::wstring wdst(w2 > 0 ? w2 - 1 : 0, L'\0');
    if (w2 > 1) MultiByteToWideChar(CP_UTF8, 0, origin.c_str(), -1, &wdst[0], w2);

    // 目标目录可能已被删 → 逐级重建（CreateDirectoryW 不建父级）
    {
        size_t pos = wdst.find_last_of(L"\\/");
        if (pos != std::wstring::npos) {
            std::wstring d = wdst.substr(0, pos);
            if (GetFileAttributesW(d.c_str()) == INVALID_FILE_ATTRIBUTES) {
                std::wstring cur;
                for (size_t i = 0; i < d.size(); ++i) {
                    cur += d[i];
                    if (d[i] == L'\\' || d[i] == L'/') CreateDirectoryW(cur.c_str(), nullptr);
                }
                CreateDirectoryW(d.c_str(), nullptr);
            }
        }
    }

    // ★ 放开 ACL：必须在 Move 之前。文件 DACL 是 Deny Everyone(FRFX)，
    //   连读都拒，MoveFileW 会被自己的 Deny ACE 挡回 ERROR_ACCESS_DENIED。
    {
        const wchar_t* sddl = L"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &sd, nullptr)) {
            SetFileSecurityW(wsrc.c_str(),
                             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
            LocalFree(sd);
        }
        SetFileAttributesW(wsrc.c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    // ★ 可逆解码（2026-09-26，银泊方案）：按台账记录的密钥再次 XOR（自逆），
    //   逐字节恢复原文；origSha16 非空时**必须对账** —— 解码产物与隔离时记录的
    //   原始哈希不符，说明记录与文件错位（手工替换/台账损坏），此时**绝不 Move**，
    //   保留隔离副本让问题可查。失败/校验不过都中止还原，绝不半还原。
    bool decodeOk = true;
    std::string decodeErr;
    if (st == 4) {
        unsigned char qk[32];
        if (!QuarKeyHexToBytes(keyHex, qk)) {
            decodeOk = false;
            decodeErr = "编码记录缺失或损坏（台账中无有效密钥），无法安全解码。";
        } else if (!XorQuarFileWithKey(wsrc, qk)) {
            decodeOk = false;
            decodeErr = "解码失败：隔离副本无法以读写方式打开。";
        } else if (!origSha16.empty()) {
            // 对账：解码产物整文件 SHA-256 前 16 位必须等于隔离时记录的原始指纹
            int n8 = WideCharToMultiByte(CP_UTF8, 0, wsrc.c_str(), -1,
                                         nullptr, 0, nullptr, nullptr);
            std::string srcU8;
            if (n8 > 1) { srcU8.resize(n8 - 1);
                         WideCharToMultiByte(CP_UTF8, 0, wsrc.c_str(), -1, &srcU8[0], n8, nullptr, nullptr); }
            std::string shaFull;
            if (sf::pehash::FileSha256Cached(srcU8, shaFull, nullptr) &&
                shaFull.compare(0, 16, origSha16) != 0) {
                decodeOk = false;
                decodeErr = "解码校验不符：还原产物与隔离时记录的原始指纹不一致"
                            "（记录与文件可能错位）。副本保留在隔离区待查。";
                LogDbg("[quarantine] ⚠ 解码对账失败 id=" + id +
                       " 记录=" + origSha16 + " 实得=" + shaFull.substr(0, 16));
            }
        }
        if (decodeOk)
            LogDbg("[quarantine] 已按编码记录解码 id=" + id +
                   (origSha16.empty() ? std::string() : (" sha16=" + origSha16 + " 对账通过")));
    }

    bool ok = false;
    DWORD err = 0;
    if (decodeOk) {
        ok = MoveFileW(wsrc.c_str(), wdst.c_str()) != FALSE;
        err = ok ? 0 : GetLastError();
    }
    if (ok) {
        // ★ 归还正常权限（2026-09-26 修复「还原后拒绝访问」）：同卷 Move 保留
        //   文件的显式 DACL（现值=仅 SY/BA 的受保护 DACL）。用户进程以非提升
        //   令牌运行时 Administrators ACE 不授权（deny-only）→ 双击/7-Zip 全部
        //   ERROR_ACCESS_DENIED。此处清掉显式 DACL 并解除保护，让文件从
        //   **目标父目录**（Desktop/Downloads 等）继承正常用户权限——
        //   「还原」的正确语义就是文件像从没被隔离过一样。
        //   失败只记日志不回滚：文件已移回，权限可手工 icacls /reset 补救。
        DWORD siRc = SetNamedSecurityInfoW(
            const_cast<LPWSTR>(wdst.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr);
        if (siRc != ERROR_SUCCESS)
            LogDbg("[quarantine] ⚠ 还原产物 ACL 重置失败 err=" + std::to_string(siRc) +
                   "（可 icacls /reset 手工修复）→ " + origin);
        RemoveQuarantineRecord(id);
        LogDbg("[quarantine] 已还原：" + origin);
    } else {
        LogDbg(decodeOk ? ("[quarantine] 还原失败 err=" + std::to_string(err) + " → " + origin)
                        : ("[quarantine] 还原中止（解码未通过）→ " + origin));
    }

    std::string why;
    if (!decodeOk) {
        why = "还原中止：" + decodeErr;
    } else if (!ok) {
        why = (err == ERROR_ALREADY_EXISTS || err == ERROR_FILE_EXISTS)
                ? "还原失败：目标位置已存在同名文件，未覆盖。请先处理该文件再重试。"
                : "还原失败：目标路径不可写（可能被占用、或被系统保护）。错误码 " + std::to_string(err);
    } else if (st == 4) {
        why = "文件已按隔离记录完整解码还原" +
              (origSha16.empty() ? std::string("。")
                                 : ("，SHA-256 指纹对账一致，内容与隔离前逐字节一致。可正常使用。"));
    } else if (st == 1) {
        why = "文件已移回原位。注意：该文件在隔离时已被移除可执行结构（PE 头），"
              "还原后**无法运行**，如需使用请重新获取原始文件。";
    } else if (st == 2) {
        why = "文件已移回原位。注意：该文件在隔离时内容已被清空，"
              "还原后是空文件、**无法运行**，如需使用请重新获取原始文件。";
    } else if (st == 0) {
        why = "文件已移回原位，可正常使用。";
    } else {
        why = "文件已移回原位。该文件非可执行映像（脚本/数据），"
              "还原后仍可能被其宿主程序解释执行，请谨慎打开。";
    }
    std::ostringstream os;
    os << "{\"ok\":" << (ok ? "true" : "false")
       << ",\"origin\":" << sf::JsonString(origin)
       << ",\"state\":" << st
       << ",\"reason\":" << sf::JsonString(why) << "}";
    return os.str();
}

// 隔离区删除：彻底销毁一份隔离文件（不可撤销）
static std::string QuarantineDelete(const std::string& id) {
    std::wstring wp = QuarantineFilePathW(id);
    bool exists = GetFileAttributesW(wp.c_str()) != INVALID_FILE_ATTRIBUTES;
    if (exists) {
        // 同样先放开 ACL，否则删除也会被自己的 Deny ACE 挡回
        const wchar_t* sddl = L"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
        PSECURITY_DESCRIPTOR sd = nullptr;
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SDDL_REVISION_1, &sd, nullptr)) {
            SetFileSecurityW(wp.c_str(),
                             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
            LocalFree(sd);
        }
        SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_NORMAL);
    }
    bool ok = exists ? (DeleteFileW(wp.c_str()) != FALSE) : true;
    if (ok) {
        RemoveQuarantineRecord(id);
        LogDbg("[quarantine] 已彻底删除隔离文件 id=" + id);
    }
    return std::string("{\"ok\":") + (ok ? "true" : "false") +
           ",\"reason\":" + sf::JsonString(ok ? "该隔离文件已从磁盘彻底删除，不可恢复。"
                                              : "删除失败：文件被占用或权限不足。") + "}";
}

// 隔离区清空：删除目录下全部 .qtn（索引同步清空）
static std::string QuarantineClear() {
    std::wstring dir = QuarantineDirW();
    int total = 0, done = 0;
    std::wstring pat = dir + L"\\l_*.qtn";
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            ++total;
            std::wstring wp = dir + L"\\" + fd.cFileName;
            const wchar_t* sddl = L"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
            PSECURITY_DESCRIPTOR sd = nullptr;
            if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl, SDDL_REVISION_1, &sd, nullptr)) {
                SetFileSecurityW(wp.c_str(),
                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
                LocalFree(sd);
            }
            SetFileAttributesW(wp.c_str(), FILE_ATTRIBUTE_NORMAL);
            if (DeleteFileW(wp.c_str())) ++done;
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    {
        std::lock_guard<std::mutex> lk(g_qidxMtx);
        g_qidx.clear();
        g_qidxLoaded = true;
        SaveQuarantineIndexLocked();
    }
    LogDbg("[quarantine] 已清空隔离区：删除 " + std::to_string(done) + "/" +
           std::to_string(total));
    return std::string("{\"ok\":") + (done == total ? "true" : "false") +
           ",\"deleted\":" + std::to_string(done) +
           ",\"total\":"   + std::to_string(total) +
           ",\"reason\":"  +
           sf::JsonString(done == total ? ("已清除全部 " + std::to_string(total) + " 份隔离文件。")
                                        : ("部分删除失败：" + std::to_string(done) + "/" +
                                           std::to_string(total) + "，剩余文件可能被占用。")) + "}";
}

// UTF-8 字符串 → 宽字符路径。
// ★ 为什么必须用它而不是 GetFileAttributesA：
//   本工程的路径字符串**统一是 UTF-8**（ETW/WMI/管道都按 UTF-8 传），
//   而 GetFileAttributesA 按**当前 ANSI 代码页**解释入参。中文用户名
//   （C:\Users\银泊\…）在 UTF-8 字节流里是非法的 GBK 序列 →
//   调用直接失败返回 INVALID_FILE_ATTRIBUTES，于是"文件存在性检查"永远为假，
//   隔离/删除之类的动作被**静默跳过**（而且日志上看不出原因）。
//   凡是拿 UTF-8 路径去问 Windows API，一律先转宽字符。
static std::wstring Utf8PathW(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 1) return std::wstring();
    std::wstring w((size_t)(n - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

// 落地载荷自动隔离：移入隔离目录 + 四道锁，可撤销还原。返回撤销 id（失败返回空）。
// reason 用于隔离区索引（在界面上解释「这份文件为什么被隔离」）。
static std::string QuarantineLanded(const std::string& path,
                                    const std::string& reason = "落地前置捕获：高危目录 + 可疑载荷特征",
                                    bool autoAddToLocalDb = true) {
    std::wstring dir = QuarantineDirW();
    CreateDirectoryW(dir.c_str(), nullptr);
    // ★ 锁 1：先硬化容器。放在建文件之前 —— 否则文件会带着继承 ACE 被创建出来。
    HardenQuarantineDir(dir);

    std::string id = NewUndoId();
    // ★ 本地恶意库：隔离前先取**原始文件** SHA-256（用于高危隔离自动入库，独立于云库）
    std::string localSha;
    sf::pehash::FileSha256(path, localSha);
    // 同名碰撞：id 带时间与自增位，冲突时简单放弃（概率可忽略）
    std::wstring dst = dir + L"\\l_" + std::wstring(id.begin(), id.end()) + L".qtn";
    int needed = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    std::wstring wsrc(needed > 0 ? needed - 1 : 0, L'\0');
    if (needed > 1) MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &wsrc[0], needed);
    if (!MoveFileW(wsrc.c_str(), dst.c_str())) return "";

    // ★ 锁 3（2026-09-26 可逆编码改造，银泊方案）：Move 之后对副本做**可逆编码**
    //   （整文件 XOR 每文件随机密钥），不再不可逆破坏。旧抹头/覆 0 会把「撤销
    //   还原」变成还原出一个坏文件（实测 NOBELIUM.zip 还原后 7-Zip 打不开）。
    //   编码后防御目的等效（加载器拒绝 + 脚本宿主读到乱码 + 压缩包打不开），
    //   而撤销从此真正可用 —— 台账记下密钥/原始哈希/原始大小，还原按记录逆变换。
    //   编码失败才退回旧破坏路径（有总比没有强），state 相应降档如实告知。
    std::string encKey, origSha16, origSizeS;
    {
        // 编码前先取原始指纹（还原对账凭证；超限/失败则留空，还原时不做哈希校验）
        std::string dstU8;
        {
            int n = WideCharToMultiByte(CP_UTF8, 0, dst.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (n > 1) { dstU8.resize(n - 1);
                         WideCharToMultiByte(CP_UTF8, 0, dst.c_str(), -1, &dstU8[0], n, nullptr, nullptr); }
        }
        uint64_t osize = 0;
        std::string shaFull;
        if (sf::pehash::FileSha256Cached(dstU8, shaFull, &osize)) {
            origSha16 = shaFull.substr(0, 16);
            origSizeS = std::to_string(osize);
        }
    }
    unsigned char qk[32];
    bool encoded = false;
    if (GenQuarKeyHex(encKey) && QuarKeyHexToBytes(encKey, qk) &&
        XorQuarFileWithKey(dst, qk)) {
        encoded = true;
        sf::LogDbg("[quarantine] 已按随机密钥编码存储（可逆，撤销可完整还原）sha16=" +
                   (origSha16.empty() ? std::string("（超限未记）") : origSha16));
    } else {
        if (!StripExecutableHeader(dst)) {
            sf::LogDbg("[quarantine] ⚠ 警告：文件已隔离但未能去执行结构（ACL 仍生效）：" +
                       std::string(dst.begin(), dst.end()));
        }
    }
    // ★ 锁 2：文件级 ACL（编码之后设，避免 READONLY 属性挡住写入）
    HardenQuarantineFile(dst);

    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoMap.size() > 64) g_undoMap.clear();
    UndoRec r; r.kind = 3; r.a = std::string(dst.begin(), dst.end()); r.b = path;
    g_undoMap[id] = r;

    // ★ 落盘索引：撤销记录只活到服务重启或 64 条，索引才是隔离区的"户口本"。
    //   state=4 表示「可逆编码存储」—— 还原按台账密钥解码后完整可用。
    AddQuarantineRecord(id, path, reason, encoded ? 4 : QuarantineStrippedState(dst),
                        encKey, origSha16, origSizeS);
    // ★ 高危隔离即入库：把样本 SHA-256 写入本地恶意库（独立 local\ 目录，云库更新不触达）
    //   ★★★ 2026-10-03：**仅高置信形态**才入库（银泊裁定）。理由：
    //     入库是**永久性**事实（local\local_malicious.txt 只增不减），而"行为分
    //     推定"是可错的概率结论。一旦把误判写进库，用户点「撤销」还原后，文件
    //     会立刻再次命中本地库 → 再隔离 → 死循环（2026-10-02 实证：被误杀的
    //     Python 出现在 local_malicious.txt 第 5 条）。故：纯分数推定 → 只隔离、不入库。
    if (!localSha.empty()) {
        if (autoAddToLocalDb) {
            sf::hashshare::AddLocalMaliciousSha256(localSha);
        } else {
            sf::LogDbg("[quarantine] 结论为行为分推定（非高置信）→ 本次**不入本地恶意库**，"
                       "避免误判经库传播成死循环 sha16=" + localSha.substr(0, 16));
        }
    }
    return id;
}


// ---------------------------------------------------------------------------
//  无结论（verdict=error）文件的用户决策 · 执行侧（2026-10-03 银泊裁定）
// ---------------------------------------------------------------------------
// 【三个动作，语义各不相同】
//   删掉    = 先进隔离区留底 → 再彻底删（"误删的代价是去隔离区捞回来"）
//   不删除  = 解锁放行 + 登记 observe 名单（此后行为可疑即自动升危）
//   知道了  = 不动作，**继续锁着**（用户看到了但没选 ⇒ 不替他做决定）
//   超时    = 等价于「删掉」，但日志里必须能区分是超时还是用户点的
//
// 【★ 关于"删原件不需要先解锁"——银泊指正后核实】
//   MakeHold 拿的是 GENERIC_READ + FILE_SHARE_DELETE，即"我允许别人删除它"。
//   所以删除从来不受封锁影响。**曾误记为「必须先 DropHold」，那是把删副本的
//   约束错记到了原件上**（副本确实要先关句柄，但副本不是处置对象）。
//   ⇒ 删前可以直接 QuarantineLanded 搬走：它走 MoveFileW，而 Move 需要
//     DELETE 访问 —— 我们恰好给了别人 DELETE 权限，所以**锁定期间照样搬得走**
//     （MakeHold 处注释已实测记录过这一点）。
//
// 【★ 隔离留底为什么必要】删除不可撤销。若程序判错（error 只说明"我们不知道"，
//   不说明"它有问题"），用户点完就永久没了。留底把不可撤销降级为"多一步"。
static void ErrHoldDeleteNow(const std::string& origPath, const char* whyTag) {
    // ★ 必须走 Utf8PathW：origPath 是 UTF-8，直接交给 GetFileAttributesW 会被
    //   按 ANSI 解释 → 中文路径下"文件不存在"恒为真 → 每次都走"视为已删除"分支
    //   → 用户点的「删掉」变成**什么都没做却报成功**（铁律 4 同族）。
    if (GetFileAttributesW(Utf8PathW(origPath).c_str()) == INVALID_FILE_ATTRIBUTES) {
        // 已被用户自己删掉 —— 视为达成目标，但必须留痕（不能静默当成功）
        LogDbg(std::string("[errhold] 文件已不存在，视为已删除：") + origPath +
               "（" + whyTag + "）");
        return;
    }
    // ① 先隔离留底（可撤销还原）。失败**不阻断删除**：
    //    用户已明确要求删除（银泊裁定），留底只是额外保险，
    //    保险失败不该把正事也拖掉 —— 但必须打日志说明"没留底成功"。
    const std::string qid = QuarantineLanded(
        origPath, "沙箱未测出结论：" + std::string(whyTag) + "（删除前留底）");
    if (qid.empty()) {
        LogDbg("[errhold] ★留底失败（隔离未成功），但仍按用户要求删除：" + origPath +
               " —— 此文件删除后**无法找回**");
    } else {
        LogDbg("[errhold] 已留底到隔离区 id=" + qid + "（可在隔离区还原）：" + origPath);
    }
    // ② 彻底删掉隔离区里的那份。隔离是中间态不是最终态 ——
    //    用户要的是删除，隔离区留一份就等于"没删干净"。
    if (!qid.empty()) {
        const std::string rep = QuarantineDelete(qid);
        LogDbg(std::string("[errhold] 隔离留底已清除（真正删除完成）：") + rep);
    }
    // ③ 副本目录：走公开的 ReleaseHold（先 CloseHandle 再清空目录）。
    //    **必须放在最后**：删原件不需要解锁，但清副本目录需要先关掉
    //    我们自己开着的句柄（否则那些文件仍被占用，删不掉）。
    sandbox::ReleaseHold(origPath);
}

// 超时执行器（注入 errhold::SetTimeoutHandler）
static void OnErrHoldTimeout(const std::string& token, const std::string& origPath) {
    LogDbg("[errhold] ★★ 决策超时（用户未在 30 秒内选择）⇒ **自动删除**："
           + origPath + "（令牌 " + token.substr(0, 6) + "…）");
    ErrHoldDeleteNow(origPath, "决策超时自动删除");
}

// 用户点「不删除」：解锁 + 登记 observe
static void ErrHoldReleaseNow(const std::string& origPath) {
    sandbox::ReleaseHold(origPath);
    // 银泊裁定「放行并持续监控其行为」：登记 observe 后，该文件再次启动且
    // 行为暴露可疑 ⇒ 判定层自动升为高危处置（e.observed 提权路径）。
    // 窗口取 3600 秒：比沙箱放行档的 600 秒长得多 —— 那一份是"刚验过所以盯一会"，
    // 这一份是"没验过但用户选择信任"，风险更高 ⇒ 盯更久。
    sf::ObserveAdd(origPath, 3600);
    LogDbg("[errhold] 用户选择不删除 ⇒ 已解锁放行 + 登记放行后监控（3600s）：" + origPath +
           "（该文件再次运行时若行为可疑，将自动升为高危处置）");
}


// 可疑自启动项自动移除：删除注册表值（原值记录在案，可撤销写回）。返回撤销 id。
static std::string RemoveAutorunValue(const std::string& loc) {
    // loc 格式（RegRunWatch collect 产出）："HKLM|path|valueName" / "HKCU|..." / "HKU|sid\path|name"
    size_t p1 = loc.find('|');
    size_t p2 = loc.rfind('|');
    if (p1 == std::string::npos || p2 == std::string::npos || p2 <= p1) return "";
    std::string hive = loc.substr(0, p1);
    std::string keyp = loc.substr(p1 + 1, p2 - p1 - 1);
    std::string name = loc.substr(p2 + 1);
    HKEY root = (hive == "HKLM") ? HKEY_LOCAL_MACHINE
              : (hive == "HKCU") ? HKEY_CURRENT_USER : HKEY_USERS;
    // 先读原值（撤销要用）
    char data[8192] = {0}; DWORD ds = sizeof(data) - 1, type = 0;
    std::string orig;
    {
        HKEY hk;
        if (RegOpenKeyExA(root, keyp.c_str(), 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            if (RegQueryValueExA(hk, name.c_str(), nullptr, &type, (LPBYTE)data, &ds) == ERROR_SUCCESS)
                orig = std::string(data, ds ? ds - 1 : 0);
            RegCloseKey(hk);
        }
    }
    HKEY hk;
    if (RegOpenKeyExA(root, keyp.c_str(), 0, KEY_SET_VALUE, &hk) != ERROR_SUCCESS) return "";
    LSTATUS st = RegDeleteValueA(hk, name.c_str());
    RegCloseKey(hk);
    if (st != ERROR_SUCCESS) return "";
    std::string id = NewUndoId();
    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoMap.size() > 64) g_undoMap.clear();
    UndoRec r; r.kind = 2; r.a = hive; r.b = keyp; r.c = name; r.d = orig;
    g_undoMap[id] = r;
    return id;
}

// 统一撤销入口：rollbackundo 管道命令按 token 前缀分发到这里/回滚引擎。
// 返回 report JSON（与 BuildUndoResultHtml 的解析格式对齐）。
static std::string UniversalUndo(const std::string& token) {
    if (token.size() == 10) {
        std::string kind = token.substr(0, 2);
        std::string id   = token.substr(2);
        if (kind == "10") {
            bool ok = boot::UndoIntercept(id);
            if (ok) LogDbg("[undo] 引导扇区拦截已撤销（token=" + token + "）");
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                   (ok ? "引导记录已写回隔离副本，并重立基线。"
                       : "撤销失败：隔离副本不存在或写入被拒。") + "\"}";
        }
        if (kind == "20") {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            auto it = g_undoMap.find(id);
            if (it == g_undoMap.end())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,\"reason\":\"记录已失效（服务重启后撤销窗口失效）。\"}");
            const UndoRec& r = it->second;
            HKEY root = (r.a == "HKLM") ? HKEY_LOCAL_MACHINE
                      : (r.a == "HKCU") ? HKEY_CURRENT_USER : HKEY_USERS;
            HKEY hk;
            bool ok = false;
            if (RegOpenKeyExA(root, r.b.c_str(), 0, KEY_SET_VALUE, &hk) == ERROR_SUCCESS) {
                ok = RegSetValueExA(hk, r.c.c_str(), 0, REG_SZ, (const BYTE*)r.d.c_str(),
                                    (DWORD)(r.d.size() + 1)) == ERROR_SUCCESS;
                RegCloseKey(hk);
            }
            if (ok) g_undoMap.erase(it);
            if (ok) LogDbg("[undo] 自启动项已撤销移除：" + r.a + "|" + r.b + "|" + r.c);
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                   (ok ? "自启动项已写回注册表。"
                       : "写回注册表失败（权限不足或键已失效）。") + "\"}";
        }
        if (kind == "30") {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            auto it = g_undoMap.find(id);
            if (it == g_undoMap.end())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,\"reason\":\"隔离记录已失效。\"}");
            const UndoRec& r = it->second;
            int w1 = MultiByteToWideChar(CP_UTF8, 0, r.a.c_str(), -1, nullptr, 0);
            std::wstring wsrc(w1 > 0 ? w1 - 1 : 0, L'\0');
            if (w1 > 1) MultiByteToWideChar(CP_UTF8, 0, r.a.c_str(), -1, &wsrc[0], w1);
            int w2 = MultiByteToWideChar(CP_UTF8, 0, r.b.c_str(), -1, nullptr, 0);
            std::wstring wdst(w2 > 0 ? w2 - 1 : 0, L'\0');
            if (w2 > 1) MultiByteToWideChar(CP_UTF8, 0, r.b.c_str(), -1, &wdst[0], w2);
            // ★ 还原前先看这个文件当初有没有被"去执行结构"。
            //   若被抹过（'QT'）或被破坏过正文，还原回去的是一个**不能运行**的文件 ——
            //   必须如实告诉用户，不能让他双击后自己发现"文件坏了"。
            const int st = QuarantineStrippedState(wsrc);
            // 还原前先放开 ACL：文件被设成 Deny Everyone + READONLY，
            // 不先解除就 MoveFileW 不出来（读/移动权限都被自己的 Deny 挡掉）。
            {
                const wchar_t* sddl = L"D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
                PSECURITY_DESCRIPTOR sd = nullptr;
                if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddl, SDDL_REVISION_1, &sd, nullptr)) {
                    SetFileSecurityW(wsrc.c_str(),
                                     DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, sd);
                    LocalFree(sd);
                }
                SetFileAttributesW(wsrc.c_str(), FILE_ATTRIBUTE_NORMAL);
            }
            bool ok = MoveFileW(wsrc.c_str(), wdst.c_str()) != FALSE;
            if (ok) g_undoMap.erase(it);
            if (ok) LogDbg("[undo] 落地隔离已撤销，文件已移回原位：" + r.b);
            std::string why;
            const bool destroyed = (st == 1 || st == 2);   // 内容已被破坏，还原后不可用
            if (!ok) {
                why = "移回失败：目标位置被占用或文件已失。";
            } else if (st == 1) {
                why = "文件已移回原位。注意：该文件在隔离时已被移除可执行结构（PE 头），"
                      "还原后**无法运行**，如需使用请重新获取原始文件。";
            } else if (st == 2) {
                why = "文件已移回原位。注意：该文件在隔离时内容已被清空，"
                      "还原后是空文件、**无法运行**，如需使用请重新获取原始文件。";
            } else if (st == 0) {
                why = "文件已移回原位，可正常使用。";
            } else {
                why = "文件已移回原位。该文件非可执行映像（脚本/数据），"
                      "还原后仍可能被其宿主程序解释执行，请谨慎打开。";
            }
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"stripped\":" +
                   (destroyed ? "true" : "false") +
                   ",\"state\":" + std::to_string(st) +
                    ",\"reason\":" + sf::JsonString(why) + "}";
        }
        // ---- kind=40：持久化项（计划任务）----
        // 与 10/20/30 三类并列：撤销 = 把备份的计划任务 XML 写回 Tasks 目录。
        // ⚠️ 逐级重建父目录 —— CreateDirectoryA **不建父级**（隔离区还原踩过同一个坑）。
        if (kind == "40") {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            auto it = g_undoMap.find(id);
            if (it == g_undoMap.end())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,"
                                   "\"reason\":\"持久化撤销记录已失效（服务重启后撤销窗口失效）。\"}");
            const UndoRec& r = it->second;
            if (r.a != "task")
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,"
                                   "\"reason\":\"该类持久化项不支持自动撤销。\"}");
            const std::string root = TasksRootDir();
            if (root.empty())
                return std::string("{\"ok\":false,\"restored\":0,\"failed\":0,"
                                   "\"reason\":\"找不到系统计划任务目录。\"}");
            const std::string dst = root + "\\" + r.b;
            for (size_t i = root.size() + 1; i < dst.size(); ++i) {
                if (dst[i] != '\\') continue;
                CreateDirectoryA(dst.substr(0, i).c_str(), nullptr);
            }
            const bool ok = (CopyFileA(r.c.c_str(), dst.c_str(), FALSE) != FALSE);
            if (ok) g_undoMap.erase(it);
            if (ok) LogDbg("[undo] 计划任务已写回：" + r.b);
            return std::string("{\"ok\":") + (ok ? "true" : "false") +
                   ",\"restored\":0,\"failed\":0,\"reason\":" +
                   sf::JsonString(ok
                       ? "计划任务已写回（计划任务服务会在数秒内重新加载该任务）。"
                       : "写回失败：备份文件已丢失或目标目录权限不足。") + "}";
        }
    }
    return rb::UndoLastRollback(token);
}

// ---------------------------------------------------------------------------
//  MBR 告警回调（bootguard 监视线程内执行）：写 findings + 右下角弹专用卡。
//  弹卡去重：自动拦截卡弹一次就够（引导已恢复，用户可不理会）；被动告警
//  （无归因，等用户决定）30 分钟未处理重提一次，避免"弹一次就石沉大海"。
// ---------------------------------------------------------------------------
static std::mutex g_bootAlertMtx;
static bool       g_bootActive = false;
static ULONGLONG  g_bootLastTick = 0;

// ---------------------------------------------------------------------------
//  清除"引导告警活跃"标志（供 mod_boot 分体调用）
//
//  为什么做成函数而不是把 g_bootActive 暴露出去：
//  这个标志属于**服务层状态**（决定弹窗卡是否还要询问用户），不该让分体
//  直接摸全局变量。收敛成一个具名函数后，"谁能改它"在代码里是可检索的。
// ---------------------------------------------------------------------------
void ClearBootAlertActive() {
    std::lock_guard<std::mutex> lk(g_bootAlertMtx);
    g_bootActive = false;
}

static void OnBootAlert(const boot::BootAlert& al) {
    {
        std::lock_guard<std::mutex> lk(g_bootAlertMtx);
        if (g_bootActive) {
            if (al.autoHandled) return;                                   // 自动拦截不重复弹
            if (GetTickCount64() - g_bootLastTick < 30ull * 60 * 1000) return;
        }
        g_bootActive = true;
        g_bootLastTick = GetTickCount64();
    }
    std::string procName = al.procPath.empty() ? "" : sf::BaseName(al.procPath);
    std::string title, sub;
    if (al.autoHandled) {
        title = "已自动拦截 · 引导扇区修改";
        sub   = "「" + (procName.empty() ? "可疑程序" : procName) +
                "」正在修改系统引导扇区（MBR），已自动终止该进程" +
                (al.terminated ? "" : "（进程可能已退出）") +
                "并用基线恢复引导记录。若这是你亲手运行的磁盘/引导工具，可点「撤销拦截」还原。";
    } else {
        title = "引导扇区被修改";
        sub   = "检测到系统引导代码区（MBR）与安装基线不一致。若你近期没有安装系统或引导管理工具，"
                "这可能是 bootkit 正在建立开机持久化，建议「恢复引导」；磁盘工具的合法改动请选「信任此变更」。";
    }
    if (!al.cr.reason.empty()) sub += "\n" + al.cr.reason;
    SetLastAlertInfo(title, sub, procName);

    // ---- 行为链记录（弹窗「查看病毒行为图」的数据源）----
    //  引导扇区是链条的**最后一环**（终极持久化）。这条事实记进去后，
    //  行为图能把它和前面"落地 → 自启 → 进程行为"串成完整链条 ——
    //  而这正是旧弹窗看不到的东西（用户只看到"引导区被改了"）。
    trace::Record(trace::Kind::Boot,
                  procName.empty() ? "未知进程" : procName,
                  al.autoHandled
                      ? ("正在修改系统引导扇区（MBR），已自动终止该进程并用基线恢复引导记录"
                         + std::string(al.terminated ? "" : "（进程可能已自行退出）"))
                      : "系统引导代码区（MBR）与安装基线不一致，可能是 bootkit 建立的持久化",
                  al.procPath,
                  al.autoHandled ? ("10" + al.undoToken) : std::string(),
                  al.autoHandled, 200);

    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        g_result.findings.push_back({"引导防护", "高", title, sub + "\n" + al.procPath,
                                     procName, al.procPath});
        g_result.status = "infected";
        if (g_result.score < 200) g_result.score = 200;
        g_result.timestamp = NowStr();
    }
    // token 前缀 "10"（hex），NotifyAnomaly 的 [0-9a-f] 过滤可原样放行
    sf::NotifyAnomaly("infected", 200, "mbr",
                      al.autoHandled ? ("10" + al.undoToken) : std::string(),
                      al.autoHandled);
}

// 快扫节奏的 MBR 兜底校验：监视线程意外退出或错过边沿时，
// 仍保证"最多 3 分钟必有人看一次引导扇区"。
static void BootScanTick() {
    boot::CheckResult cr = boot::CheckNow();
    if (cr.status != 1) return;
    boot::BootAlert a;
    a.cr = cr;
    OnBootAlert(a);   // 被动告警路径（无归因，弹询问卡）
}

// ---------------------------------------------------------------------------
//  压缩包落地命中回调（2026-09-22，在 packscan 的消费者线程上执行）
//
//  为什么需要它：probe.cpp 早已具备完整的递归解包 + 逐层内容判定能力，
//  但那套能力过去**只在用户手动右键查杀时**才被调用。压缩包落到磁盘那一刻，
//  落地捕获（LandedAlertWatch）的 QuickProbeExecutable 只认 PE/脚本，
//  `.zip` 到那一行就 return 0 —— 于是「下载了一个恶意压缩包」在实时防护里
//  是完全静默的。本回调把那套能力接到实时链上。
//
//  处置对象是**归档本体**：包内文件还没落地，隔离包即阻断整条链。
//  隔离走 QuarantineLanded（与落地载荷同一条链，含四道锁 + 索引落盘 + 可撤销）。
//
//  ⚠️ 本函数运行在 packscan 的消费者线程上，**不在** 5 秒轮询的实时路径里 ——
//     所以这里可以放心做隔离这类耗时动作，不会拖慢后续落地事件。
// ---------------------------------------------------------------------------
static void OnPackHit(const std::string& path, int level,
                      const std::string& title, const std::string& detail) {
    if (path.empty()) return;

    std::string quarantineId = QuarantineLanded(path);
    boot::NoteSuspicion(0, path);

    std::string sub = title.empty() ? std::string("压缩包内含高危文件") : title;
    if (!quarantineId.empty()) {
        SweepDerivativesFor(path, "pack");
        sub += "\n已隔离该压缩包（误判可在卡片上点「撤销」移回原位）。";
    } else {
        sub += "\n自动隔离失败（文件被占用或权限不足），请手动处理。";
    }

    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        bool dup = false;
        for (const auto& f : g_result.findings) if (f.path == path) { dup = true; break; }
        if (!dup)
            g_result.findings.push_back({ "压缩包检测", "高",
                                          "压缩包内含高危文件",
                                          sub + "\n" + path,
                                          sf::BaseName(path), path });
        g_result.status = "infected";
        if (g_result.score < 200) g_result.score = 200;
        g_result.timestamp = NowStr();
    }

    // 行为链：压缩包落地是投递链的**起点**（"下载 → 落盘"），比包内文件落地更早
    trace::Record(trace::Kind::Landed, sf::BaseName(path),
                  "压缩包落地即检出内含高危文件：" + sub,
                  path, quarantineId.empty() ? std::string() : ("30" + quarantineId),
                  true, 200);

    SetLastAlertInfo("压缩包已拦截",
                     "「" + sf::BaseName(path) + "」" + sub,
                     sf::BaseName(path));

    if (!quarantineId.empty())
        sf::NotifyAnomaly("infected", 200, "landed", "30" + quarantineId, true);
    else
        sf::NotifyAnomaly("infected", 200);

    LogDbg("[packscan] 命中已处置 level=" + std::to_string(level) + " " + path +
           (quarantineId.empty() ? " [隔离失败]" : " [已隔离]"));
}

// ===========================================================================
//  沙箱送检结果回调（2026-09-27 新增）—— 在**沙箱消费线程**上调用
// ===========================================================================
//  【它补的是哪一段断链】
//    沙箱模块自己会把结果推给界面卡片（NotifySandboxResult），但**判定链
//    看不到它**。于是会出现一种最难被发现的半通故障：
//        卡片告诉用户"这是恶意样本"，而那个文件仍然躺在磁盘上可以双击运行
//        —— 判定发生了，处置没发生，两边都以为对方在做。
//    本回调就是把"判定"接上"处置"的那根线（同型先例：packscan 的
//    level>=2 若不回调 OnPackHit，压缩包被扫出高危也只是一个数字）。
//
//  【口径（银泊 2026-09-27 拍板）】
//    送检来源 = 落地捕获的 lv==1 旁证档（静态初筛判"拿不准"的那批）
//    处置权限 = 报告 + **malicious 一律自动隔离**；其余四档只出报告
//
//  【★ 为什么隔离的是"原始样本"，不是 box 内的落地物】
//    box 内的落地物是样本**释放出来的衍生物**，随一次性 box 一起销毁，留着无用。
//    真正有威胁的是**用户磁盘上那个原始样本** —— 它才是能被双击执行、
//    能被下次开机再拉起的东西。所以这里 quarantine 的是 rep.file。
//
//  【★ 为什么 malicious 才动手，suspicious 不】
//    与 lv>=2 才隔离同一条纪律：**动作要能被解释**。malicious 有两个来源，
//    两者都够格动手且隔离可撤销：
//      (a) 沙箱内落地物命中**病毒库**（字节同一性，结论确凿）
//      (b) 行为分 ≥120（形态推定，结论是概率 —— 阈值本来就是照这个定的）
//    而 suspicious（60~119 分）只是"像"，不够格替用户决定，只记账不越权。
//
//  【★ 为什么必须先排除"我方产物"】
//    沙箱送检会把压缩包解压到 %TEMP%\SilverFoxSandbox\，那些是**我们自己造的**
//    临时文件。若无条件对 rep.file 动手，就可能把自家临时解压物隔离掉
//    （隔离一个几秒后就要被删的副本，留下垃圾台账）；更糟的是自喂循环。
//    rollback.cpp 的 IsExcluded 已排除该前缀（落地捕获看不到它），这里再加
//    一道**独立**闸门 —— 两条链各自的入口都要自己把关，不能指望对方。
// ===========================================================================
static bool IsSandboxSampleAllowed(const std::string& path) {
    if (path.empty()) return false;
    std::string low = path;
    for (auto& c : low) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    static const char* kDeny[] = {
        "\\programdata\\silverfoxguard\\",   // 自身数据目录（含隔离区、快照缓存）
        "\\silverfoxsandbox\\",              // 沙箱自己的临时解压目录
        "\\temp\\sf_stash\\",                // 部署脚本暂存区
        "\\temp\\samples\\",                 // 测试样本仓库
    };
    for (const char* d : kDeny)
        if (low.find(d) != std::string::npos) return false;
    // 文件必须还在（可能已被其它链路隔离/用户删除）
    DWORD a = GetFileAttributesA(path.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return false;
    if (a & FILE_ATTRIBUTE_DIRECTORY) return false;
    return true;
}

static void OnSandboxReport(const sf::sandbox::Report& rep) {
    if (rep.file.empty()) return;

    const std::string path = rep.file;
    const std::string name = sf::BaseName(path);
    const bool mal = (rep.verdict == "malicious");
    const bool sus = (rep.verdict == "suspicious");

    // ---- 放行档（clean / suspicious）进入「放行后监控」灰名单 ----
    //   这两档都是「没确认恶意、但也没完全信任」。真机运行时若暴露恶意行为
    //   （反沙箱逃逸），由实时防护判定层提权处置。监控窗口 600 秒，过期自动移出。
    //   malicious 不进名单（已被隔离，无需再盯）。
    //
    // ★★★ 2026-10-03 修正（真样本轮实测暴露）：原判据是 `if (!mal)`，
    //   那会把 **error / not_applicable 也一起塞进灰名单**。而 error 时刻
    //   文件正被我们**锁着**、等用户在决策卡上选「删掉 / 不删除」——
    //   它连"能不能运行"都还没定，**根本不在"放行"语义里**。
    //   后果是两条互斥结论同时成立（实测同一秒内两条日志都打了）：
    //       21:45:36.905 [sandbox] ★★ 维持封锁，处置权交回用户（令牌 3e7e6b…）
    //       21:45:37.113 [sandbox] 送检结论 error → 进入放行后监控灰名单（600s）
    //   ⇒ 卡片在问"删不删"，同时名单在准备"盯着它跑"。若用户随后选「不删除」，
    //     就会**叠加两个不同窗口的监控**（600s + 3600s），而日志会让人以为
    //     只有一份 —— 又一处「拿不到/做不了就静默降级」的错位。
    //   正确判据：**只有 clean / suspicious 才是"放行"**。
    //   error / not_applicable 由各自路径处理（error 走 errhold 决策，
    //   not_applicable 本来就无需观察）。
    const bool releaseable = (rep.verdict == "clean" || rep.verdict == "suspicious");
    if (releaseable) {
        sf::ObserveAdd(path, 600);
        LogDbg("[sandbox] 送检结论 " + rep.verdict + " → 进入放行后监控灰名单（600s）：" + path);
    }

    // ---- ① 只记日志的档位：不给用户添噪音，但必须在日志里留痕 ----
    //   error          = 沙箱流程本身出错，本次结果**不具参考价值**（≠干净）
    //   not_applicable = 观察根本不适用（零信息量）
    //   clean          = 看了没看出来（★ 不等于安全，逐字见 rep.summary）
    //   ★ 这三档都**不动手**、也**不写 finding**：它们不是"发现"，
    //     只是"这次没结论"。把它们写成 finding 会让扫描结果列表里塞满
    //     "未发现问题"这种零信息条目。
    if (!mal && !sus) {
        LogDbg("[sandbox] 送检结论 " + rep.verdict + "（不处置，仅监控）：" + path +
               (rep.err.empty() ? "" : " / " + rep.err));
        return;
    }

    // ---- ② 我方产物闸门 ----
    if (!IsSandboxSampleAllowed(path)) {
        LogDbg("[sandbox] ★送检结论 " + rep.verdict + " 但路径属我方产物或已不存在，"
               "不做处置：" + path);
        return;
    }

    std::string quarantineId;
    std::string detail = rep.summary;

    if (mal) {
        // ---- ③ 自动隔离原始样本 ----
        //  reason 会写进隔离区台账（用户点「撤销」时能看到"为什么被隔离"）
        quarantineId = QuarantineLanded(
            path,
            std::string("沙箱动态分析判定恶意：") + rep.verdict +
            (rep.hashHit ? "（沙箱内落地物命中病毒库）" : "（行为特征累计达恶意阈值）"),
            /*autoAddToLocalDb=*/rep.verdictStrong);
        boot::NoteSuspicion(0, path);   // MBR 归因登记

        detail += quarantineId.empty()
            ? "\n自动隔离失败（文件被占用或权限不足），请手动处理。"
            : "\n已自动隔离该文件（先处置，误判可点「撤销」移回）。";
        if (!quarantineId.empty()) SweepDerivativesFor(path, "sandbox");
    }

    // ---- ④ 写扫描结果（findings）----
    //  ★ detail 必须带上沙箱的原始摘要：用户要能看出"这条结论是**跑出来的**，
    //    不是静态特征猜的"，否则无从判断该不该信。
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        bool dup = false;
        for (const auto& f : g_result.findings) if (f.path == path) { dup = true; break; }
        if (!dup)
            g_result.findings.push_back({
                "沙箱动态分析",
                mal ? "高" : "中",
                mal ? (rep.hashHit ? "沙箱检出已知恶意样本"
                                   : "沙箱检出恶意行为（行为推定）")
                    : "沙箱观察到可疑行为（建议人工确认）",
                detail + "\n" + path,
                name, path });
        if (mal) {
            g_result.status = "infected";
            if (g_result.score < 200) g_result.score = 200;
        }
        g_result.timestamp = NowStr();
    }

    LogDbg("[sandbox] 送检结论已处置：" + rep.verdict +
           " score=" + std::to_string(rep.score) +
           " hashHit=" + std::string(rep.hashHit ? "1" : "0") +
           (quarantineId.empty() ? "" : " [已隔离]") + " " + path);

    // ---- ⑤ 弹卡（仅恶意档：suspicious 不打扰用户，只进结果列表）----
    if (!mal) return;

    // ★★ 两类命中的口径必须分开（与落地捕获同一纪律）：
    //   库中命中 = **字节同一性**，结论确凿，用户动作只有一个：清掉；
    //   行为推定 = **形态可疑**，结论是概率，用户动作是"看一眼再决定"。
    //   混成一张卡，用户就分不出「确凿」与「疑似」，也就无从判断该不该点「撤销」
    //   —— 而把确凿样本恢复回去等于主动放行已知恶意。
    //   risk 值在三个地方有白名单/映射，这里**刻意复用既有值**（hashlanded / landed）
    //   而不新增，避免再引入一处"三副本不同步"的静默失效面：
    //     toast.cpp BuildHtml（WebView2 路径）
    //     toast-app/resources/app/main.js parseArgs（Electron 路径）
    //     toast-app/resources/app/index.html deriveFlags（Electron 渲染）
    const std::string riskKey = rep.hashHit ? "hashlanded" : "landed";
    SetLastAlertInfo(rep.hashHit ? "沙箱验证：已知恶意样本已自动隔离"
                                 : "沙箱验证：恶意行为已自动隔离",
                     "「" + name + "」" + detail,
                     name);
    // ---- 行为链记录 ----
    //  ★ kind 刻意复用 Landed（不新增枚举值）：它记录的确实是「这个落地物
    //    后续被判定为恶意」这一事实，与既有 landed 节点是同一条链上的延续；
    //    而新增 Kind 要同步 trace.cpp 的 KindName/order 与两份 graph.html 的
    //    prio/typeClass —— 那是另一件事（行为图加独立节点），不该混在本次改动里。
    trace::Record(trace::Kind::Landed, name,
                  std::string("沙箱动态分析（") +
                    (rep.hashHit ? "库命中" : "行为推定") + "，用时 " +
                    std::to_string(rep.elapsedSec) + " 秒）判定恶意并自动隔离：" + detail,
                  path, quarantineId.empty() ? std::string() : ("30" + quarantineId),
                  !quarantineId.empty(), 200);

    if (!quarantineId.empty())
        sf::NotifyAnomaly("infected", 200, riskKey, "30" + quarantineId, true);
    else
        sf::NotifyAnomaly("infected", 200);   // 隔离失败 → 普通告警卡（清除威胁）
}

static void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_svcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwCurrentState     = SERVICE_START_PENDING;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_svcStatus.dwWin32ExitCode    = 0;
    g_svcStatus.dwServiceSpecificExitCode = 0;
    g_svcStatus.dwCheckPoint = 0;
    g_svcStatus.dwWaitHint   = 3000;

    g_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    g_svcHandle = RegisterServiceCtrlHandlerExW(SVC_NAME, HandlerEx, NULL);
    if (!g_svcHandle) { if (g_stopEvent) CloseHandle(g_stopEvent); return; }

    g_svcStatus.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_svcHandle, &g_svcStatus);

    // ---- ★ 崩溃留证（2026-10-03）：必须早于任何工作线程 ----
    //  无条件装未捕获异常过滤器。原因：崩溃现场的价值恰恰在于
    //  「出事那一刻你不会想到去开它」—— 要开关就会漏开 ⇒ 又一次静默失效。
    //  同时若发现上次的 crash-*.txt 会打一行日志（否则「服务莫名重启」永远查无对证）。
    sf::crashlog::Install();

    // ---- 无结论决策的执行器装配（2026-10-03）----
    //  必须在任何送检入队**之前**：errhold 到期时要靠它做「隔离留底 + 强删」，
    //  而那两样能力都在本文件（QuarantineLanded / QuarantineDelete）。
    //  漏装的后果不是「少一个功能」，而是「到期的文件被**无限期永久锁住**」
    //  （句柄是我们自己持有的，唯一解锁路径就是这个回调）—— 已立为硬要求。
    sf::errhold::SetTimeoutHandler(&OnErrHoldTimeout);

    // ---- ★ 2026-10-03 Windows 10 适配：先提权 + 打兼容性自检，再起任何线程 ----
    //
    //  ① 启用 SeDebugPrivilege（★ 本次最关键的一处修复）
    //     服务以 LocalSystem 运行，**默认持有但未启用** SeDebugPrivilege。
    //     未启用时 OpenProcess(PROCESS_TERMINATE) 对其它用户/受保护进程返回
    //     ERROR_ACCESS_DENIED ⇒ 我们的「已自动终止高危进程」永远失败，而日志只写
    //     「终止进程失败（权限不足或进程已退出）」—— **把权限问题伪装成进程已退出**，
    //     排障时会被带偏（实测 innoextract 事件里连续 5 次处置失败）。
    //     ★ 必须放在**所有工作线程启动之前**：处置发生在各线程里，
    //       线程令牌是进程级，进程级提权对已创建的线程同样生效，但顺序上先提权最干净。
    const bool dbgOk = sf::compat::EnableDebugPrivilege();
    if (!dbgOk) {
        LogDbg("[compat] ★★ SeDebugPrivilege 未启用 —— 高危进程自动终止将对受保护进程失败"
               "（日志会误报成「进程已退出」，排障注意）");
    }

    //  ② 兼容性自检：把「这台机器上哪几处不工作」变成日志里可读的事实，
    //     而不是等线上出问题再猜。Win10 与 Win11 的差异点集中在这里。
    LogDbg("[compat] " + sf::compat::CompatDiag());

    // 三个工作线程全部经 RunThreadGuard 包裹：任何异常/结构化异常都就地吞掉并记日志，
    // 绝不允许从线程逃逸出去把服务进程带走（旧架构的致命缺失，见 RunThreadGuard 注释）。
    std::thread guard([] { sf::RunThreadGuarded("guard", GuardThread); });
    std::thread pipe([] { sf::RunThreadGuarded("pipe", PipeServerThread); });
    std::thread evtsub([] { sf::RunThreadGuarded("evtsub", ProcessWatch); });   // ETW 优先，WMI 兜底
    std::thread regrun([] { sf::RunThreadGuarded("regrun", RegRunWatch); });
    // 落地捕获消费线程：把回滚引擎的"落盘初筛结果"接到进程判定链上
    // （银狐链条「下载→落盘→自启」的**第二步**就被捕获，早于进程创建事件）
    std::thread landed([] { sf::RunThreadGuarded("landed", LandedAlertWatch); });
    // 网络外联监听（第四个事件源）：银狐/VALLEYRAT/挖矿/银行木马的共同出口 ——
    // 「下载 → 落盘 → 自启」之后的「连出去想干什么」。只订阅 id=10（TCP 连接建立）。
    std::thread net([] { sf::RunThreadGuarded("net", NetWatch); });
    // 持久化面全覆盖（第五个事件源，2026-09-24）：计划任务 / 系统服务 / IFEO / WMI 订阅。
    // 虚拟机实战暴露：RegRunWatch 只盯 Run 键，而银狐现在更常用计划任务与服务 ——
    // 四条路径一条都不碰 Run 键，于是"持久化"这一环在实时防护里完全静默。
    std::thread persist([] { sf::RunThreadGuarded("persist", PersistWatch); });
    // ★ 文件/注册表写操作采集（第六个事件源，2026-09-25，银泊指示补订阅）。
    //   前五个事件源覆盖「进程出生 / 网络外联 / 目录出现新文件 / 引导扇区 / 持久化面」，
    //   唯独"文件被改写与被改名"从来没有看到过 —— 那正是勒索的画像动作，也是
    //   银狐载荷落地后改名/自删/写配置的那一段。本线程订阅 Kernel-File +
    //   Kernel-Registry 把这段补上（**只采集不处置**，处置判断留给后续模型与上层）。
    std::thread iowatch([] { sf::RunThreadGuarded("iowatch", IoWatch); });
    // ★ 跨进程注入 / 内存加载采集（第七个事件源，2026-09-30，preview4「功能做完整」）。
    //   此前"卡片之间做的事"——注入、进程镂空、跨进程终止、无文件加载——完全空白。
    //   本线程订阅 Microsoft-Windows-Kernel-Audit-API-Calls（GUID 本机实测确认；
    //   keyword=0 收 keyword=0 事件），补上这一盲区。只采集 + 与进程台账 join +
    //   评分层加权，不直接处置（自动终止链路待与银泊联调）。
    std::thread auditapi([] { sf::RunThreadGuarded("auditapi", ApiWatch); });
    // ★★ 进程资源监控（第八个事件源，2026-10-03）：**挖矿检测的最后一道兜底**。
    //   虚拟机真样本那一轮暴露的断链有四环，本线程补的是第四环 ——
    //   全工程此前**没有任何进程 CPU 监控**（GetProcessTimes 只在 sandbox.cpp 用过，
    //   且量的是沙箱自身进程）。挖矿的 CPU 高占用是最稳的特征：攻击者可以换矿池、
    //   改端口、用 HTTPS 隧道（让 IOC 与外联判据全部失效），但挖矿的本质是持续做
    //   哈希运算，**CPU 必然长期占用**，换不掉。
    //   判据要「持续」而非「瞬时」（正常程序高 CPU 是突发的，挖矿是持续的），
    //   且**高 CPU 只是旁证**，必须与进程自身可疑判定叠加才处置（resmon.cpp 内部把关）。
    std::thread resmonthr([] { sf::RunThreadGuarded("resmon", ResMonWatch); });

    // ---- 能力看门狗（2026-10-03，C1）----
    // 放在 resmon 之后：它要等各源起来才能有意义，但**不依赖任何一源成功**——
    // 恰恰是「某源没起来」时它才最该说话，所以不能挂在某源的成败上。
    std::thread guardcheckthr([] { sf::RunThreadGuarded("guardcheck", GuardCheckWatch); });

    // ---- MBR 引导扇区防护（2026-09-19 新增，银泊指示"要像正经杀软一样"）----
    // 基线加载/首建 → 注册告警回调 → 启动 5 秒级监视线程。
    // 监视线程发现引导代码区被改且近 10 分钟有可疑进程活动 → 自动终止 + 恢复引导 +
    // 弹卡（可撤销）；无归因 → 弹卡询问（恢复引导 / 信任此变更）。
    boot::SetStopEvent(g_stopEvent);
    boot::SetAlertCallback(&OnBootAlert);
    if (boot::Init()) boot::StartWatch();

    // ---- 勒索回滚引擎（对齐卡巴 System Watcher 的写前快照 + 回滚）----
    // 与扫描线程并行独立运行：扫描是"事后体检"（分钟级），回滚是"实时拦截"
    // （毫秒级），两者的时间尺度差三个数量级，必须分线程。
    rb::SetStopEvent(g_stopEvent);     // 让监控线程能随服务一起退出
    // 注入告警回调：引擎只管"判定 + 回滚"，展示（写扫描结果 + 弹窗）由服务层负责
    //
    // ---- 三层处置模型的上报端（详见 rollback.h 的说明）----
    //  高风险：引擎**已经**自动终止进程 + 自动回滚（不等用户确认 —— 勒索爆发时
    //          每等一秒就多一批文件被加密）。这里只把结果写进扫描结果并弹窗
    //          **告知**，同时标记"本次处置可撤销"——判定可能误伤（备份软件批量
    //          操作等），必须留反悔通道。
    //  可疑：引擎未动手，弹窗询问用户是否处理（前端走 rollbackdo 命令）。
    rb::SetDetectionCallback([](const rb::DetectionInfo& info) {
        bool highRisk = (info.risk == rb::Risk::High);
        bool didRollback = (info.restored > 0);   // 覆盖写是否真的发生过
        std::string detail;
        if (highRisk && info.autoHandled) {
            detail = info.trigger + "。已自动终止并回滚恢复 " +
                     std::to_string(info.restored) + " 个文件";
            if (info.unrecoverable)
                detail += "，另有 " + std::to_string(info.unrecoverable) +
                          " 个文件因无可用快照未能恢复";
            detail += "。";
            if (info.undoable)
                detail += "若判断有误，可在右下角通知卡点「撤销我的处理」还原。";
        } else {
            detail = info.trigger + "。已拦截该操作，等待你确认是否还原文件。";
        }
        if (!info.processPath.empty())
            detail += "肇事进程：" + info.processPath + "（PID " + std::to_string(info.pid) + "）";
        {
            std::lock_guard<std::mutex> lk(g_resultMutex);
            std::string sev = info.unrecoverable ? "中" : "高";
            bool dup = false;
            for (const auto& f : g_result.findings)
                if (f.category == "勒索回滚") { dup = true; break; }
            if (!dup)
                g_result.findings.push_back({ "勒索回滚", sev,
                                              highRisk ? "勒索行为已拦截并回滚" : "检测到疑似勒索操作",
                                              detail, info.processPath, info.processPath, 90 });
            // 无论是否已有一条，都置为异常状态 —— 勒索是**进行中的破坏**，
            // 不像普通可疑项可以留在"预警"档观察。
            g_result.status = "infected";
            if (g_result.score < 200) g_result.score = 200;
            g_result.timestamp = NowStr();
        }
        LogDbg("[rollback] 告警已上报: " + detail);
        // 弹窗参数：
        //   risk=high + 真的覆盖写过 → 带上撤销凭据，弹窗会渲染「撤销我的处理」按钮
        //   risk=high + 未覆盖写   → 无须撤销，只告知
        //   risk=suspect            → 弹窗询问用户是否处理
        //   rolling 标志：回滚动作会**写回**大批文件，扩展端在窗口期内看到的状态是
        //   "正在恢复中"；这里传出窗口剩余毫秒，让卡片上的说明与实际进度对得上，
        //   而不是弹窗刚出来就宣称"已恢复正常"（那是撤回报文与磁盘状态不一致的旧 bug）。
        {
            std::string riskStr = highRisk ? "high" : "suspect";
            std::string undo = (info.undoable && didRollback) ? info.undoToken : std::string();

            // ---- 行为链记录：回滚是链条的"处置"环节 ----
            //  拆成两条事实记录，因为它们在行为图上语义不同：
            //    · Key   —— 勒索前兆：检测到批量改写（用户需要知道"它想干什么"）
            //    · Rollback —— 已还原（用户需要知道"我们做了什么、有没有救回来"）
            //  只有真的发生过覆盖写（didRollback）才记 Rollback，否则图上会出现
            //  "已还原 0 个文件"这种自相矛盾的节点。
            std::string culprit = info.processPath.empty() ? std::string("未知进程")
                                                          : sf::BaseName(info.processPath);
            if (didRollback || highRisk) {
                trace::Record(trace::Kind::Key, culprit,
                              info.trigger + (highRisk ? "（已判定为勒索行为）"
                                                       : "（疑似批量改写，等待确认）"),
                              info.processPath, "", highRisk && info.autoHandled, 200);
            }
            if (didRollback) {
                std::string rdet = "已从快照还原 " + std::to_string(info.restored) + " 个文件";
                if (info.unrecoverable)
                    rdet += "，" + std::to_string(info.unrecoverable) +
                            " 个文件因无可用快照不可恢复（诚实上报）";
                else
                    rdet += "，无不可恢复文件";
                trace::Record(trace::Kind::Rollback, culprit, rdet,
                              info.processPath, info.undoable ? info.undoToken : std::string(),
                              true, 200);
            }

            NotifyAnomaly("infected", 200, riskStr, undo, didRollback);
        }
    });
    rb::Start();

    // GPU 加速开关若已打开（注册表 gpu_scan=1），启动后自动把「特征地图」载入显存，
    // 与「打开开关即加载」保持一致（加载进度可经管道命令 gpuprog 查询）。
    if (compute::IsGpuEnabled()) compute::LoadMapAsync();

    // ---- 动态分析沙箱的结果出口（2026-09-27）----
    //  为什么在这里：处置回调 OnSandboxReport 需要服务层的 QuarantineLanded /
    //  SweepDerivativesFor / g_result / trace，这些不对外暴露 —— 与 packscan 同型。
    //
    //  ★★ 顺序有硬要求：必须在 mod::StartAll() **之前**注册。
    //     沙箱的消费线程正是由 StartAll 拉起的（分体 kModule_sandbox 的 Run）。
    //     回调晚一步就位，就存在"线程已开始取任务、sink 还是空"的窗口 ——
    //     落进那个窗口的报告会被**静默丢弃**，也就是本次要修的那种半通故障：
    //     判定做了、处置没做，两边都以为对方在做。
    //     与其论证"这个窗口只有几微秒"，不如让顺序本身没有歧义。
    //
    //  ★ 沙箱的消费线程由分体框架托管（RunThreadGuarded 双层兜底 + 停止时 join），
    //    所以这里只注册回调，**不 Start 线程**（与 packscan 的差别正在于此）。
    sandbox::SetSink(&OnSandboxReport);

    // ---- ★ 主干式架构：挂载全部分体（2026-09-22）----
    //  放在最后的原因：分体可能依赖上面已装配好的基础设施（回滚引擎、引导防护、
    //  显存地图）。StartAll 内部逐个 Init —— 某个分体初始化失败只跳过它自己，
    //  其余照常挂载（这是刻意的语义，见 module.h 约束 1）。
    {
        std::string issues = mod::SelfCheck();
        if (!issues.empty())
            LogDbg("[mod] ★ 自检发现问题（分体可能静默失效）：" + issues);
        mod::StartAll();
    }

    // ---- 压缩包落地深度检测（2026-09-22）----
    //  它刻意**不做成分体**：命中回调 OnPackHit 需要服务层的 QuarantineLanded /
    //  SweepDerivativesFor / trace 记录等内部能力，这些不对外暴露。
    //  即便做成"分体 + 由 service 注入回调"，service 仍要参与装配，收益为零、
    //  却多一层间接。它属于**服务层能力**，不是"可插拔检测模块"。
    //  分体的判据是"能否独立 Init/Run/Stop 且不依赖服务内部状态"—— 它不满足。
    packscan::SetSink(&OnPackHit);
    packscan::Start();

    WaitForSingleObject(g_stopEvent, INFINITE);
    if (guard.joinable()) guard.join();
    if (pipe.joinable()) pipe.join();
    if (evtsub.joinable()) evtsub.join();
    if (regrun.joinable()) regrun.join();
    if (landed.joinable()) landed.join();
    if (net.joinable()) net.join();
    if (persist.joinable()) persist.join();

    // 压缩包检测：先停止并 join 消费者线程（它可能正在解包，必须等在途任务收尾）
    packscan::Stop();

    // 服务停止：先停分体（逆序 join + Stop），再停回滚引擎与引导防护 ——
    // 分体可能持有引擎资源的引用，必须比引擎先停。
    mod::StopAll();

    // 服务停止：先停回滚引擎（保留已建立的快照，供下次启动继续使用），
    // 再释放显存中的地图与全部 GPU 资源
    rb::Stop();
    compute::UnloadMap();

    g_svcStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_svcHandle, &g_svcStatus);
}

void RunService() {
    // 进程级单实例：防止服务被重复拉起（重复实例会争抢命名管道）
    HANDLE hMutex = CreateMutexW(NULL, FALSE, L"Global\\SilverFoxGuardService");
    if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return;   // 已有实例在后台运行，直接退出
    }
    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)SVC_NAME, (LPSERVICE_MAIN_FUNCTIONW)ServiceMain },
        { NULL, NULL }
    };
    StartServiceCtrlDispatcherW(table);
    if (hMutex) CloseHandle(hMutex);
}

// ---------------------------------------------------------------------------
//  守护循环（后台定期扫描）
//
//  ⚠️ 2026-09-18 架构修正（用户实测「每 3 分钟全盘扫描 + 弹窗」的真因）
//
//  旧实现：启动自检跑一次【快扫 + 全盘扫】，然后每 180 秒又跑一次【全盘扫】。
//  全盘扫一轮要遍历 10000+ 文件（含 GPU 深度内容扫描 200000 候选预算），单轮
//  实测 40~90 秒 —— 也就是说**一半以上的时间都在扫盘**，用户观感就是"它一直在扫"。
//
//  更糟的是：全盘扫恰好是 GPU 崩溃的触发点（nvwgf2umx.dll 0xC0000005）。崩了
//  → SCM 按 sc failure 策略 60 秒后重启 → 启动自检又立刻跑一遍快扫+全盘扫
//  → 又崩。用户看到的就是"每 3 分钟扫描一次 + 弹窗"，实际是崩溃重启循环。
//
//  新架构：**分层调度**——重活（全盘扫）降到 6 小时一次并与启动错开，轻活
//  （快扫：只看系统目录与可疑落点）保持 3 分钟一次。这样实时性不丢，CPU/IO
//  占用下降两个数量级，也把 GPU 崩溃的暴露面从"每 3 分钟一次"降到"每 6 小时一次"。
// ---------------------------------------------------------------------------
// 快扫间隔：只扫常规落点 + 已知样本父目录，秒级完成（实时性靠它）
static const DWORD QUICK_SCAN_INTERVAL_MS = 180000;      // 3 分钟
// 全盘精扫间隔：遍历全盘可写目录，分钟级（完整性靠它）
static const DWORD FULL_SCAN_INTERVAL_MS  = 6 * 3600 * 1000;   // 6 小时
// 启动后延迟多久才做首轮全盘精扫：避开开机高峰，也让快扫先出结果
static const DWORD FULL_SCAN_STARTUP_DELAY_MS = 120000;  // 2 分钟

// 状态切换去重：仅当本次状态与上次通知状态不同才弹通知，避免每轮扫描刷屏。
// 首启若为 normal 不弹；之后任何切换（含由异常恢复正常）都弹一次。
//
// ⚠️ 双重去抖（2026-09-18 加固，用户实测「每 3 分钟弹一次」）：
//   ① 状态基线：g_lastToastStatus 跨轮次记忆，同状态不重复弹。
//   ② 升级即时 / 降级滞回：normal→warning/infected 立即弹（风险要马上告知）；
//      warning↔normal 这类「降级」必须连续 DEGRADE_CONFIRM 轮保持才认账并弹，
//      避免单个间歇性发现项（如短暂的高熵临时文件）让状态来回抖动、每轮都弹窗。
//
// ⚠️ 基线持久化（2026-09-18 新增，架构级修复）
//
// 旧实现把基线放在【进程内静态变量】里，服务一重启就清空 → 重启后第一轮扫描
// 必然被当成"新变化"而弹窗。这本身不算错（首启 normal 会跳过），但只要有任何
// 残留发现项（如桌面自建工具被标旁证），每次重启都会弹一次 —— 用户观感就是
// "它老是弹窗"。而服务重启是**常态**：SCM 故障恢复、安装更新、手动重启、
// 崩溃拉起都会触发。所以基线必须落盘。
//
// 落盘文件：<ProgramData>\SilverFoxGuard\toast_state.txt，单行纯文本存上一个
// 已通知过的状态。写入用原子替换（先写 .tmp 再 MoveFileEx）避免半截文件。
static std::string g_lastToastStatus;
static std::string g_pendingStatus;      // 待确认的降级目标状态（连续命中才认账）
static int         g_pendingCount = 0;
static const int   DEGRADE_CONFIRM = 2;  // 降级需连续保持的轮数

static std::wstring ToastStatePathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\toast_state.txt";
}

static void SaveToastBaseline(const std::string& status) {
    std::wstring path = ToastStatePathW();
    std::wstring tmp  = path + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wn = 0;
    WriteFile(h, status.data(), (DWORD)status.size(), &wn, nullptr);
    CloseHandle(h);
    // 原子替换：避免读到写了一半的文件
    MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING);
}

static std::string LoadToastBaseline() {
    std::string s;
    HANDLE h = CreateFileW(ToastStatePathW().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return s;   // 首次运行：无基线
    char buf[64] = { 0 };
    DWORD got = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got > 0) s.assign(buf, got);
    CloseHandle(h);
    // 清掉可能的空白/换行
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ')) s.pop_back();
    return s;
}

// 上一轮扫描的**时间戳**（用于判断"距离上次扫描过了多久"，决定重启后该不该补扫）。
// 存在同一文件里更省事，但为保持格式简单，单独记一个文件。
static std::wstring LastScanPathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\last_scan.txt";
}
static void SaveLastScanTime() {
    auto now = std::chrono::system_clock::now();
    long long sec = (long long)std::chrono::system_clock::to_time_t(now);
    std::string s = std::to_string(sec);
    std::wstring tmp = LastScanPathW() + L".tmp";
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wn = 0;
    WriteFile(h, s.data(), (DWORD)s.size(), &wn, nullptr);
    CloseHandle(h);
    MoveFileExW(tmp.c_str(), LastScanPathW().c_str(), MOVEFILE_REPLACE_EXISTING);
}
static long long LoadLastScanTime() {
    HANDLE h = CreateFileW(LastScanPathW().c_str(), GENERIC_READ, FILE_SHARE_READ,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    char buf[32] = { 0 };
    DWORD got = 0;
    long long v = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got > 0) v = _atoi64(buf);
    CloseHandle(h);
    return v;
}

// 是否为「降级」迁移（风险等级下降：infected→warning→normal）
static int RiskRank(const std::string& s) {
    if (s == "infected") return 2;
    if (s == "warning")  return 1;
    return 0;   // normal / 空
}

static void CheckAndNotify() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    if (g_result.status == g_lastToastStatus) {
        g_pendingStatus.clear();
        g_pendingCount = 0;
        LogDbg("[check] skip: status unchanged (" + g_result.status + ")");
        return;
    }
    // 复读卡防护（2026-09-19）：回滚引擎判定时**已经直弹过卡**（SetDetectionCallback
    // 里的 NotifyAnomaly），它写进 g_result 的 infected 状态若再被周期体检发现，
    // 就会对同一事件弹第二张「环境异常」卡。检测到当前异常来自引擎写入的
    // 「勒索回滚」发现项时，这里只同步基线、不再弹窗。
    bool fromLiveEngine = false;
    for (const auto& f : g_result.findings)
        if (f.category == "勒索回滚") { fromLiveEngine = true; break; }
    if (fromLiveEngine && g_result.status != "normal") {
        g_lastToastStatus = g_result.status;
        SaveToastBaseline(g_lastToastStatus);
        LogDbg("[check] skip: 异常状态来自回滚引擎实时处置（已弹过卡），仅同步基线");
        return;
    }
    const std::string prev = g_lastToastStatus;
    const bool isDowngrade = !prev.empty() &&
                             RiskRank(g_result.status) < RiskRank(prev);
    if (isDowngrade) {
        // 降级滞回：连续 DEGRADE_CONFIRM 轮看到同一目标状态才认账，
        // 期间只要回升（或又变了）就重置计数，不弹窗。
        if (g_pendingStatus == g_result.status) {
            ++g_pendingCount;
        } else {
            g_pendingStatus = g_result.status;
            g_pendingCount  = 1;
        }
        if (g_pendingCount < DEGRADE_CONFIRM) {
            LogDbg("[check] hold: downgrade pending " + prev + " -> " + g_result.status +
                   " (" + std::to_string(g_pendingCount) + "/" + std::to_string(DEGRADE_CONFIRM) + ")");
            return;
        }
    }
    g_pendingStatus.clear();
    g_pendingCount = 0;
    g_lastToastStatus = g_result.status;
    SaveToastBaseline(g_lastToastStatus);   // 落盘：服务重启后基线不丢
    if (prev.empty() && g_result.status == "normal") {
        LogDbg("[check] skip: first-run normal");
        return;   // 首启即正常：不打扰
    }
    LogDbg("[check] trigger toast: status=" + g_result.status + " score=" + std::to_string(g_result.score));
    sf::NotifyAnomaly(g_result.status, g_result.score);
}

// 只同步「上次已通知状态」而不弹窗。用于清除成功后立刻重扫的场景：
// 清理结果由发起方（弹窗卡片 / 扩展面板）自行呈现，不该再额外弹一次「环境已恢复正常」；
// 但若不同步基线，下一轮定时扫描又会把这次变化判成新变化而弹窗。
static void SyncLastToastStatus() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    g_lastToastStatus = g_result.status;
    SaveToastBaseline(g_lastToastStatus);
    LogDbg("[check] sync baseline: " + g_result.status);
}

// 清除报告 → JSON 片段（不含外层大括号，供并入扫描结果帧）
static std::string BuildCleanJson(const CleanReport& rep) {
    std::string s = "\"clean\":{";
    s += "\"requested\":" + std::to_string(rep.requested) + ",";
    s += "\"deleted\":"   + std::to_string(rep.deleted)   + ",";
    s += "\"deferred\":"  + std::to_string(rep.deferred)  + ",";
    s += "\"failed\":"    + std::to_string(rep.failed)    + ",";
    s += "\"skipped\":"   + std::to_string(rep.skipped)   + ",";
    s += "\"killed\":"    + std::to_string(rep.killed)    + ",";
    s += "\"extraDlls\":" + std::to_string(rep.extraDlls) + ",";
    s += "\"killedNames\":[";
    for (size_t i = 0; i < rep.killedNames.size(); ++i) {
        if (i) s += ",";
        s += JsonString(rep.killedNames[i]);
    }
    s += "],\"items\":[";
    for (size_t i = 0; i < rep.items.size(); ++i) {
        if (i) s += ",";
        s += "{\"path\":"   + JsonString(rep.items[i].path)   + ",";
        s += "\"action\":"  + JsonString(rep.items[i].action) + ",";
        s += "\"reason\":"  + JsonString(rep.items[i].reason) + "}";
    }
    s += "]}";
    return s;
}

// P3 主动防御：WMI 实时进程创建监听。银狐落地「发现即处置」——
// 用 __InstanceCreationEvent 订阅 Win32_Process 创建事件，对新进程走**双路判定**：
//   ① 文件启发式 QuickProbeExecutable(path)      —— 抓「随机名落地 / 可疑路径 / PE 异常」
//   ② 行为判定   sf::JudgeProcess(MakeEntityOfPid) —— 抓「命令行 / 父子链 / 白利用 / 注入」
// 任一命中即写 g_result.findings（扩展面板实时可见，无需等下一轮定时扫描）。
//
// ⚠️ 2026-09-19 增强（原实现只做 ①，检测面过窄）：
//   旧版仅取 ExecutablePath 调 QuickProbeExecutable，实测 `[real-time]` 命中 **0 次** ——
//   因为银狐的投递链特征是「正常名宿主进程 + 恶意命令行」（如
//   `mshta.exe javascript:...` / `rundll32.exe javascript:...` / `regsvr32.exe /s /u /i:http://...`），
//   或「Office/WPS 拉起 powershell」这类父子链异常 —— **ExecutablePath 永远是白文件**，
//   只看路径必然全漏。现补齐 CommandLine + ParentProcessId + 父子链三路输入。
// ---------------------------------------------------------------------------
//  ★ 病毒库点查（原 HashDbVerdict）已于 2026-09-27 提升为公共实现：
//        sf::hashverdict::MaliciousVerdict()  —— 见 hashverdict.h
//    为什么搬走：沙箱模块要对"沙箱内落地产物"做**同一套**判定。若各自实现一份，
//    两条链路的口径会**悄悄漂移** —— 出现"实时防护判恶意、沙箱判干净"这类
//    无法解释的不一致，且漂移不会有任何报错。本项目铁律：同一条判据只能有
//    一个实现（唯一推导入口）。返回值语义（0 = 无意见 ≠ 干净）见 hashverdict.h。
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
//  ★ 实时进程判定管线（2026-09-23 从 WmiSink 抽出，ETW / WMI 双路径共用）
// ---------------------------------------------------------------------------
//  ETW（首选，毫秒级）与 WMI（兜底，最多 3 秒延迟 + 60 秒重建盲窗）两条采集
//  路径最终都汇到这里，判定与处置口径完全一致：
//    文件启发式 → 行为判定（命令行/父子链/签名）→ 5 秒去抖 → 信誉门 → 分级处置。
//  pathHint：WMI 给完整路径；ETW 的 ImageFileName 只有文件名 —— 统一在开头
//  用 sf::MakeEntityOfPid(pid) 补齐（服务是 LocalSystem，可读绝大多数进程）。
static void HandleNewProcess(unsigned long pid, const std::string& pathHint) {
    // ★★ 路径补齐 + 不静默丢弃（2026-09-23 修复「ETW 路径下样本跑完毫无反应」）
    //
    //  ETW 的 ProcessStart 在进程对象**刚创建**时触发，比 WMI（WITHIN 3 秒轮询）
    //  早得多 —— 此时镜像往往还没映射完，MakeEntityOfPid 可能拿不到 imagePath。
    //  旧实现「拿不到完整路径就 return」= 静默丢弃：样本 7 步全没反应、
    //  日志一行都不打（实测踩到，最难查的那种）。
    //
    //  现在两处改进：
    //   ① 短暂重试补齐（最多 5 次 × 40ms ≈ 160ms）——只对少数拿不到路径的事件生效，
    //      不会拖慢消费队列；
    //   ② 仍拿不到就用文件名继续走**行为判定**（命令行 / 父子链），
    //      只跳过依赖完整路径的两项（文件启发式、签名信誉门）。
    //  ★ 重试条件必须**同时看 imagePath 与 commandLine**（2026-09-23 二次修复）：
    //    ETW 事件在进程创建瞬间推送，两个字段就绪时刻不同 ——
    //    实测 `cmd /c "echo vssadmin delete shadows & ping …"` 时 imagePath 已就绪、
    //    而 commandLine 还是空 → 旧条件（只看 imagePath）当场跳出重试 →
    //    拿着空命令行去判定 → 规则全是"命令行子串匹配" → 一律 0 分 → 静默漏报。
    //  （现象：同一批样本里有的拦住有的漏，因为就绪时序随机。）
    sf::ProcEntity ent;
    for (int attempt = 0; attempt < 6; ++attempt) {   // 6 × 40ms ≈ 240ms 上限
        try { ent = sf::MakeEntityOfPid(pid); } catch (...) {}
        if (!ent.imagePath.empty() && !ent.commandLine.empty()) break;
        Sleep(40);
    }
    // ★★ 2026-10-02 路径归一化（根因修复，**勿删、勿"顺手简化"**）：
    //
    //   现象：反沙箱逃逸样本（fake_antisbx）经确认在**真机**上跑起来并暴露了行为
    //   （释放伪装副本 + 写 Run 键 + 拉起子进程），但主防**一行都没打** ——
    //   「放行后监控」（observe 灰名单升档）整条链死掉。
    //
    //   根因：ETW 的 `ImageName` 是 **NT 设备路径**（`\Device\HarddiskVolume2\Users\x\a.exe`），
    //   而全系统（iowatch 文件事件 / 沙箱报告 / 隔离区 / 放行后监控名单）统一用**盘符路径**。
    //   文件链路一直在 iowatch 里归一化，**进程链路从来没归一化过**（service.cpp 旧注释
    //   还写着"ETW 的 ImageFileName 只有文件名"，与实测不符 —— 实测给的是完整设备路径）。
    //   后果不是报错，而是**静默失效**：
    //     · `sf::ObserveHit` 是**精确匹配**，拿设备路径查盘符名单**永远查不中**
    //       ⇒ 放行后监控 100% 失效（这正是反沙箱逃逸能全身而退的原因）；
    //     · `havePath` 判据只看 `ent.imagePath`，于是 ETW 给出的**完整设备路径被当成
    //       "没拿到路径"** ⇒ 病毒库点查 / 文件启发式 / 新鲜度判定在**首选路径（ETW）下
    //       被整段跳过**（短命进程连路径都拿不到时更甚）。
    //
    //   修法：复用 iowatch 的**唯一实现**（`iowatch.h` 明确写着"也对外暴露，供上层复用"），
    //   对盘符路径**幂等**，不改变任何判定语义；并让 `havePath` 改判**归一化之后**的 p ——
    //   这使 ETW 与 WMI 两条路径的口径重新一致（本函数开头的设计契约就是"口径完全一致"）。
    //
    //   ★ 这已是"路径形态击穿判定"家族在本工程的**第三次**现身（前两次：rollback 的签名
    //     前缀比较、scanner 的 HasCatalogSignature）。共性：路径形态不一致 ⇒ 精确比较恒假
    //     ⇒ **不报错、只是静默不生效**。故此处加注释钉死，避免将来又被"简化"掉。
    ent.imagePath = sf::iowatch::NormalizeFilePath(ent.imagePath);
    std::string p = ent.imagePath.empty() ? sf::iowatch::NormalizeFilePath(pathHint)
                                          : ent.imagePath;
    if (p.empty()) return;                     // 连文件名都拿不到 → 放弃
    // havePath：归一化**之后**再判"是否真的拿到了完整路径"（含目录分隔符）。
    //   裸文件名（无 `\`）仍视为没有路径 → 保持"不凭文件名猜路径"的原有克制。
    const bool havePath = p.find('\\') != std::string::npos;

    if (ent.commandLine.empty()) {
        // 拿不到命令行 → 所有「命令行子串」规则都无从判定，等于漏报。
        // 打节流日志（否则排查时是黑洞；这正是「样本跑完毫无反应」的真实原因之一）。
        //
        // ★ 2026-10-03 Win10 适配：补上 **读取策略号 + 累计计数**。
        //   cmdStrategy：0=完全失败 1=直读 PEB 命中 2=走 Ldr 链表兜底命中
        //   （2 也可能返回空 —— 走到了兜底但命令行仍不可得，属于布局差异）
        //   计数用于验收：「这台机器上命令行读取成功率是多少」必须可量化，
        //   否则「规则没生效」与「命令行没取到」永远分不清（铁律 41）。
        static std::atomic<int> s_noCmdLog{ 0 };
        static std::atomic<int> s_noCmdTotal{ 0 };
        const int n = s_noCmdTotal.fetch_add(1) + 1;
        if (s_noCmdLog.fetch_add(1) < 20)
            LogDbg("[real-time] 事件进程 " + std::to_string(pid) + " 命令行暂不可得（image=" +
                   pathHint + "，策略=" + std::to_string(ent.cmdStrategy) +
                   "）→ 无法做行为判定  [累计失败 " + std::to_string(n) + "]");
        else if (n % 500 == 0)
            // ★ 周期性汇总：命令行读取失败率是 Win10 适配的核心指标，
            //   静默只打前 20 条会让它变成看不见的黑洞。
            LogDbg("[real-time] ★命令行读取累计失败 " + std::to_string(n) +
                   " 次（最近一次 pid=" + std::to_string(pid) +
                   " 策略=" + std::to_string(ent.cmdStrategy) + "）");
    }

    if (!havePath) {
        // 诊断日志（节流前 20 条）：路径拿不到时不再静默 —— 否则排查时是黑洞
        static std::atomic<int> s_noPathLog{ 0 };
        if (s_noPathLog.fetch_add(1) < 20)
            LogDbg("[real-time] 事件进程 " + std::to_string(pid) +
                   " 路径暂不可得（image=" + pathHint + "）→ 仅走行为判定");
    }

        // ---- 判定结果汇总 ----
        int  lv     = 0;      // 0=正常 1=可疑 2=高危
        std::string sev, title, detail;
        std::string tag;
        // ★ 判定理由（2026-09-24）：此前只记 tag 不记理由，导致误报无法回溯 ——
        //   例如「tag=rat 但命令行与家族特征都不命中」时完全无从下手。
        std::string reason;
        // ★ 是否"硬规则命中"（behavior.cpp 的 v.hard）。
        // 只有硬规则命中才允许直接终止进程 —— 见下方终止段落的说明。
        bool hardHit = false;
        // ★ ④ 落地档案是否命中（2026-09-24）：供「高危文件是否收进隔离区」判断 ——
        //   只有"确实是刚落地就被拉起"的文件才隔离，避免把用户的老程序搬走。
        bool landedHit = false;
        // ★ 影子模式（2026-09-25）：下面这两个原本是第 ④ 步块内的局部变量，
        //   现在提到这里 —— 因为投递 ObserveEvent 需要它们，而投递点在第 ④ 步**之后**。
        //   ⚠️ 不要为了"少两个变量"把它们又挪回块内：那样投递到的 softLanded* 会恒为 0/false，
        //      而特征 36~41 组（时间与落地）会静默退化成"没有落地旁证" —— 不报错、只是学错。
        int  slLv  = 0;
        bool slSys = false;
        // ★ 行为判定的原始分数（v.score）。此前只在块内用，现在要投递给影子模式 ——
        //   它是训练里的**对照基准**（AI 分数 vs 规则分数），丢了这条整个对照就没意义。
        int  vScore = 0;

        // ⓪ ★★ 病毒库点查（整文件 SHA-256 + imphash）—— **必须先跑**
        //    理由与返回值语义见 hashverdict.h（2026-09-27 已提升为公共实现）。一句话：
        //    它是"同一性"判定而非"相似性"推测，命中即定案，
        //    且命中后就没必要再花一次整文件深度学习判定（下面会跳过）。
        std::string hashWhy;
        const bool hashHit = havePath && (sf::hashverdict::MaliciousVerdict(p, &hashWhy) >= 2);

        // ① 文件启发式（随机名落地 / 可疑路径 / PE 形态）
        //    ★ 需要完整路径；只有文件名时跳过（否则会把 cmd.exe 这类正常名误判）
        int fileLv = hashHit ? 2 : (havePath ? QuickProbeExecutable(p) : 0);
        // ★ 2026-09-24：内容判定补位（消除与全盘扫描链路的判定口径差）。
        //   **只在文件"刚落地"时才跑** —— 完整引擎要读整文件（含递归解包），
        //   对每个新进程都跑会拖垮 ETW 消费线程。银狐的投毒节奏是"落盘后几秒
        //   内执行"，5 分钟窗口足以覆盖；而正常软件被启动时文件早已是老文件
        //   → 天然不触发。这道门同时把开销从"每进程"压到"每新文件"。
        std::string deepNote;
        if (fileLv == 0 && havePath && IsFreshlyCreated(p, 300)) {
            std::string dTitle; int dScore = 0;
            int dl = DeepProbeExecutable(p, &dTitle, &dScore);
            if (dl > fileLv) {
                fileLv = dl;
                deepNote = "内容判定命中：" + dTitle + "（" + std::to_string(dScore) + " 分）";
            }
        }
        if (fileLv > 0) {
            lv    = fileLv;
            sev   = (fileLv >= 2) ? "高" : "中";
            if (hashHit) {
                // 病毒库命中：文案必须说清"是已知样本"，而不是"看起来可疑"——
                // 用户看到"可疑"会以为我们在猜，看到"已知恶意样本"才知道我们有据。
                tag    = "hashdb";
                reason = hashWhy;
                title  = "实时拦截已知恶意文件";
                detail = "进程 " + p + " 正在启动，" + hashWhy +
                         "。该文件与已收录样本字节一致，判定为已知恶意程序。";
            } else {
                title = (fileLv >= 2) ? "实时发现随机名落地文件" : "实时发现疑似随机名落地文件（旁证）";
                detail = "进程 " + p + " 正在启动，命中随机名落地启发式" +
                         (fileLv >= 2 ? "（PE 形态异常/盘根）" : "（PE 正常）") + "，疑似银狐载荷被拉起。";
                if (!deepNote.empty()) {
                    title  = "实时拦截可疑载荷进程";
                    detail = "进程 " + p + " 正在启动，" + deepNote + "。";
                }
                tag = "heuristic";
            }
        }

        // ② 行为判定（命令行 / 父子链 / 白利用）—— 仅当 ① 未定档时补充，
        //    或 ① 只判「中危」而行为判定给出「高危」时升级。
        //    ★ 复用开头已查询到的 ent（旧实现在这里又查了一次，纯浪费）
        try {
            // ★★ 2026-10-03 修正：此处补路径归一化。**上一行注释说「传入的是已归一化的
            //   ent.imagePath」，而实际并非如此** —— 注释与代码不符，正好害我以为
            //   「三处调用点口径已一致、不用改」（又一次「读过了 ≠ 记住了」）。
            //
            //  【为什么必须在这里做，而不是在三处 ObserveHit 调用点】
            //    `ent.imagePath` 的来源有两个：
            //      ① `MakeEntityOfPid` → `ImagePathOfPid` → `QueryFullProcessImageNameW`
            //         返回的**本来就是盘符路径**（C:\...），不需要归一；
            //      ② 本行的兜底 `= p` —— 而 `p` 来自 **ETW 事件**，是**设备路径**
            //         （\Device\HarddiskVolume3\...）。
            //    灰名单里存的是盘符形态 ⇒ 拿设备路径去查**永远查不中** ⇒
            //    放行后监控在「命令行读不到、只能靠事件路径」的那批进程上 100% 失效。
            //  ⇒ 在**唯一的汇合点**归一一次，三处消费方自动一致（改三处 = 迟早漏一处）。
            if (ent.imagePath.empty()) ent.imagePath = sf::iowatch::NormalizeFilePath(p);
            else                        ent.imagePath = sf::iowatch::NormalizeFilePath(ent.imagePath);
            // ★ 2026-10-02：放行后监控打标 —— **必须留日志**。
            //   这一行此前是**静默**的，于是"没命中"与"命中了但没用上"在日志里
            //   长得一模一样，白排查两轮（铁律 38：日志正常 ≠ 功能生效）。
            //   打一行，一眼可辨。注意传入的是**已归一化**的 ent.imagePath
            //   —— 名单里存的是盘符形态，拿设备路径来查永远查不中。
            if (sf::ObserveHit(ent.imagePath)) {
                ent.observed = true;
                LogDbg("[observe] ★放行后监控命中（进程创建）：" + ent.imagePath);
            }
            sf::ProcVerdict v = sf::JudgeProcess(ent);
            if (v.level > lv) {
                lv     = v.level;
                sev    = (v.level >= 2) ? "高" : "中";
                title  = (v.level >= 2) ? "实时拦截可疑进程行为" : "实时发现可疑进程行为（旁证）";
                detail = std::string("进程 ") + (ent.imagePath.empty() ? p : ent.imagePath) +
                         " 命中行为判定：\n" + v.reason +
                         (ent.parentImagePath.empty() ? "" : ("\n父进程：" + ent.parentImagePath));
                tag = v.tag;
                reason = v.reason;
            }
            hardHit = v.hard;   // 硬规则命中标记（独立于是否升级了 lv）
            vScore  = v.score;  // ★ 供影子模式做对照基准（见上方声明处说明）
        } catch (...) { /* 行为判定异常不影响文件启发式结论 */ }

        // ③ 进程出生卡（2026-09-24 新增）—— 与命令行内容**完全无关**的通用判据。
        //   【为什么必须有一条不看命令行的判据】
        //   虚拟机实战：银狐载荷的命令行"很干净"（随机名 exe、无参数），
        //   于是所有基于命令行的特征规则集体失效。攻击者能随意改写命令行，
        //   但改不了三件事：文件有多新、有没有签名、谁把它拉起来的。
        //   三者组合才判高危（见 scanner.cpp 的 BirthCardLevel 说明）。
        //   ★ 2026-09-24 误报压制：把本步之前已经拿到的 `lv` 作为「独立旁证等级」
        //     传进去 —— 解释器父链（powershell/7z/python/node/chrome/微信…）
        //     **单独不再判高危**，必须叠加另一条互不相干的判据才处置。
        //     那 40 多个宿主全是日常操作的父进程，原来的"命中即高危"必然天天误杀。
        if (havePath) {
            std::string bcReason;
            int bc = 0;
            try { bc = BirthCardLevel(p, ent.parentImagePath, &bcReason, lv); }
            catch (...) { bc = 0; }
            if (bc > 0) {
                if (reason.empty()) reason = bcReason;
                if (bc > lv) {
                    lv     = bc;
                    sev    = (bc >= 2) ? "高" : "中";
                    title  = (bc >= 2) ? "实时拦截新落地载荷进程"
                                       : "实时发现新落地可疑进程（旁证）";
                    detail = "进程 " + p + " 正在启动。\n" + bcReason;
                    tag    = "birthcard";
                }
                if (bc > 0)
                    LogDbg("[real-time] 进程出生卡命中（" + std::to_string(bc) + "级）: " +
                           p + " —— " + bcReason);
            }
        }

        // ④ 落地→执行 组合升档（2026-09-24 新增）
        //   【这一条补的是什么盲区】
        //   ③ 出生卡用"文件有多新"（IsFreshlyCreated 300s）判；若载荷落地后
        //   **隔十几分钟才被拉起**（银狐常见的延时执行节奏），新鲜度门就失效。
        //   本步改用回滚引擎在**落地那一刻**登记下来的档案做匹配 ——
        //   时效窗口放宽到 10 分钟，且完全不看文件时间戳（攻击者可篡改）。
        //   【为什么只认 sysZone】
        //   Temp / AppData / ProgramData / Users\Public / 启动文件夹 是**软件
        //   自己写的**区域，用户不会主动往那里放 exe；而 Downloads / 桌面 是
        //   用户主动落点（下载安装包再双击 = 正常行为），不参与组合，
        //   否则普通安装包会被大面积误伤。
        //   【为什么还要加签名门】
        //   组合成立后再要求**无有效签名**才升档：正规安装包绝大多数已签名，
        //   这道门把"用户下载的无签名绿软"挡在外面，只留真正的投递链画像。
        if (havePath && lv < 2) {
            // ⚠️ 这里**不能**再写 `int slLv = 0; bool slSys = false;` ——
            //    那会遮蔽外层同名变量，导致影子模式投递过去的 softLanded* 恒为 0/false。
            //    这种遮蔽编译器只会给 C4456（/W4 才报，本项目是 /W3）→ 完全静默。
            std::string slWhy;
            bool landed = false;
            try { landed = rb::QuerySoftLanded(p, 10u * 60u * 1000u, &slLv, &slSys, &slWhy); }
            catch (...) { landed = false; }
            landedHit = (landed && slSys);   // 供终止后「是否把文件收进隔离区」判断
            if (landed && slSys) {
                // ★ 2026-09-24 误报压制：升档前先过三道豁免门。
                //   本判据（软件自写区落地 + 10 分钟内执行 + 无签名）的画像与
                //   「正常软件的安装器/更新器把自己的子程序释放到 AppData\Local\Temp
                //   再运行」**完全重合** —— 这是本轮误报的主要来源之一。
                //   三道门互不依赖，任一成立即不升档（不处置、不弹卡；本步之前若已有
                //   1 级旁证，那段记录仍然保留）：
                //     E1 有有效 Authenticode 签名（原有门）
                //     E2 有厂商版本资源 —— 不依赖签名，救回"无签名但完全正常"的绿软 /
                //        自更新器 / 开源工具（它们的 PE 里总有 CompanyName/ProductName，
                //        而银狐 stub 载荷一个字段都没有）
                //     E3 父进程是用户交互外壳（explorer / taskmgr…）—— 人类自己按的，
                //        按投递链处置没有依据
                //   【唯一的例外】slLv >= 2：**落地那一刻**内容引擎就已经把它判成高危。
                //     此时 E2/E3 不再构成豁免 —— 内容证据强于身份证据。但 E1 仍生效：
                //     正规签名的文件交给扫描链路与行为规则处理，不在实时链路动刀。
                const bool sigOk  = IsFileSignatureTrusted(p);
                const bool vendor = HasVendorInfo(p);
                const bool human  = IsUserInteractiveHost(ent.parentImagePath);
                const bool strong = (slLv >= 2);
                const bool exempt = (!strong) && (vendor || human);
                if (!sigOk && !exempt) {
                    lv     = 2;
                    sev    = "高";
                    title  = "实时拦截「刚落地即被执行」的可疑程序";
                    detail = "进程 " + p + " 正在启动。\n"
                             "该文件是不久前落在软件自写目录（Temp / AppData / ProgramData 等）"
                             "的可执行文件，落地后短时间内被执行，且**没有有效数字签名、"
                             "也没有任何厂商版本信息**。\n"
                             "落地判定：" + slWhy;
                    if (!deepNote.empty()) detail += "\n" + deepNote;
                    if (strong) detail += "\n旁证：落地那一刻的内容引擎已判定其为高危。";
                    tag    = "landed-exec";
                    if (reason.empty()) reason = "落地后随即执行且无签名：" + slWhy;
                    LogDbg("[real-time] 落地→执行 组合命中: " + p + " —— " + slWhy +
                           (strong ? "（落地时内容引擎已判高危）" : ""));
                } else {
                    LogDbg("[real-time] 落地→执行 组合成立但已豁免、不升档: " + p +
                           "（签名=" + (sigOk ? "有" : "无") +
                           "／厂商信息=" + (vendor ? "有" : "无") +
                           "／用户交互父进程=" + (human ? "是" : "否") +
                           "／落地内容等级=" + std::to_string(slLv) + "）—— " + slWhy);
                }
            }
        }

        // =====================================================================
        //  ⑤ ★ 放行后监控「统一收口」（2026-10-02 新增）—— 反沙箱逃逸的最后一道阀
        // =====================================================================
        //  【为什么必须单独有个收口，而不能继续写在 JudgeProcess 里面】
        //   反沙箱逃逸样本（fake_antisbx 这类银狐 stub）有两条硬特征：
        //     ① 命令行**空**（随机名 exe、无参数）⇒ 行为判定只能给 level 0；
        //     ② 刚落地 ⇒ 真正命中它的判据是 **③ 出生卡** / ④ 落地→执行。
        //   而 `observed` 升档原先**只写在 behavior.cpp 的 JudgeProcessInner 内部**，
        //   且前提是 `level>=1` —— stub 恰好不满足 ⇒ **升档永远轮不到它**。
        //   实测（2026-10-02 20:09:54 真机复测）：进灰名单 ✅、出生卡判 1 级 ✅，
        //   但最终 tag 是 `heuristic` 而非 `observed-escalate` ⇒ **升档没发生**。
        //   ⇒ 结论：升档必须挂在「lv 已被**任一**判据算完」之后，
        //     而不是挂在某一条判据的内部 —— 否则换个判据命中就整条链失效。
        //  【为什么放在 ④ 之后、影子投递之前】
        //   到这里 lv/tag/reason 已经是四个判据的**最终结果**，升档才能覆盖全部形态；
        //   又必须在影子投递之前 —— 否则喂给 AI 的规则等级与实际处置等级不一致。
        //  【语义纪律】只升 `lv>=1` 的；`lv==0` 的正常行为**绝不**升档
        //   —— 与 behavior.cpp:1237 同一条纪律，不给普通程序新增任何误报面。
        if (ent.observed && lv >= 1 && lv < 2) {
            std::string base = reason.empty()
                ? std::string("该程序在放行后监控期内暴露了可疑行为")
                : reason;
            std::string tagBefore = tag.empty() ? std::string("(空)") : tag;
            std::string prevDetail = detail;
            lv     = 2;
            sev    = "高";
            title  = "实时拦截「放行后监控」期间暴露行为的程序";
            reason = "[放行后监控升级] " + base +
                     "（该程序沙箱初判未确认恶意、处于放行后监控期，真机行为触发即升级处置）";
            detail = "进程 " + p + " 正在启动。\n" + reason;
            if (!prevDetail.empty()) detail += "\n原始判据：" + prevDetail;
            tag    = tag.empty() ? "observed-escalate" : (tag + "+observed");
            LogDbg("[observe] ★放行后监控升级 → 2 级：" + p +
                   "（守候前判据 tag=" + tagBefore + "，理由：" + base + "）");
        } else if (ent.observed) {
            // 命中灰名单、但本次**未**升档 —— 也要留痕。
            //   否则将来排查时"没升档"与"压根没命中"长得一模一样。
            LogDbg("[observe] 已命中放行后监控但未升档（lv=" + std::to_string(lv) +
                   "，升档要求 1<=lv<2，lv=0 属正常行为不升）：" + p);
        }

        // ---- ★ 影子模式投递（2026-09-25）------------------------------------
        // 【为什么放在这里】四个判据（①文件启发式 ②行为判定 ③出生卡 ④落地→执行）
        //   到此**全部**算完 → 才能把"原始事实 + 规则引擎当时怎么判的"一次性投出去。
        //
        // 【★ 为什么必须在 `if (lv > 0)` **外面】** —— 这是本段最容易改错的地方：
        //   `if (lv > 0)` 是"要不要处置"的分支。把投递放进去，采到的就**只有恶意样本**
        //   （lv>=1 的），良性样本一条都没有。而训练一个二分类模型，
        //   只有正样本等于完全无法训练 —— 更糟的是**它不报错**：日志显示"已写入 N 条"，
        //   表面上一切正常，直到训练时才发现模型只会说"是恶意"。
        //   所以：lv==0（干净进程）也必须投，它们才是样本里最有价值的那一半。
        //
        // 【为什么先判 ObserveEnabled()】影子模式关掉时，下面的 ObserveEvent
        //   构造要拷 3 个字符串（含分配）。关着还付这个钱没有意义 ——
        //   进程创建是实时链路的既有路径，能省则省。
        //   ⚠️ 副作用：`aiobstat` 的 droppedOff 从此只在"通过检查之后、入队之前
        //      恰好被关掉"这种竞态窗口里增长，正常恒为 0。这是**刻意**的：
        //      要判断"为什么没样本"，看 ObserveStat.enabled 就够了，不需要一个
        //      天天在涨的计数器来重复同一件事。
        //
        // 【这一段允许做什么】只搬内存里已有的东西（ent 的几个字段 + 刚算出的
        //   lv/vScore/tag/hardHit + slLv/slSys），**一次磁盘都不碰**。
        //   签名/版本资源/ADS/文件年龄/文件大小全部由 mod_ai 的观察线程现取 ——
        //   分工的理由见 aiobserve.h 文件头（热路径有延迟预算）。
        if (sf::ai::ObserveEnabled()) {
            sf::ai::ObserveEvent oe;
            oe.pid             = pid;
            oe.atUnixMs        = sf::ai::NowUnixMs();
            oe.imagePath       = p;
            oe.commandLine     = ent.commandLine;      // 拿不到就是空串，规则引擎同样只看到空串
            oe.parentImagePath = ent.parentImagePath;
            oe.ruleLevel       = lv;
            oe.ruleScore       = vScore;
            oe.ruleHard        = hardHit;
            oe.ruleTag         = tag;
            oe.softLandedLv      = slLv;
            oe.softLandedSysZone = slSys;
            sf::ai::ObservePush(oe);
        }

        if (lv > 0) {
            // 5 秒去抖：同一路径只报一次
            static std::mutex m; static std::unordered_map<std::string, std::chrono::steady_clock::time_point> seen;
            auto now = std::chrono::steady_clock::now();
            bool skip = false;
            { std::lock_guard<std::mutex> lk(m);
              auto it = seen.find(p);
              if (it != seen.end() && now - it->second < std::chrono::seconds(5)) skip = true;
              else { seen[p] = now; if (seen.size() > 4096) seen.clear(); } }
            if (!skip) {
                // ---- ★ 分级终止（2026-09-19 新增，修复"拦截太软"）----
                //
                // 【为什么现在才加】旧实现命中 lv>=2 只写 findings + 弹窗，
                // **一行终止都没有** —— 银狐载荷该跑还是在跑。对比同一个程序里
                // 勒索引擎的动作（rollback.cpp 的 RollbackVictims 里有
                // TerminateSuspect），会发现两套标准。这就是"看到了但没拦住"。
                //
                // 【为什么必须分级】文件启发式（随机名 / 盘根 / PE 形态）的
                // 误报率天然高于行为硬规则 —— 绿软、自解压包、游戏补丁都可能命中。
                // 若一律终止，误报的代价就变成"杀掉用户的正常程序"，
                // 比"只记录不动作"更糟。
                //
                // ---- ★ 全量自动拦截（2026-09-19 第二轮，银泊指示"像正经杀软"）----
                //
                // 【第一轮的分级策略已被否决】原设计：仅 hard==true（确定性硬规则）
                // 才终止，纯评分到档只弹窗 —— 因为怕文件启发式误报。银泊明确指示：
                // 正经杀软就是"有风险活动一律自动处理，再问用户要不要撤销"。
                // 误伤的兜底从"不杀"改成"杀了可撤销/可重开"。
                //
                // 现策略：lv>=2（高危）一律 TerminateProcess；lv==1（旁证）仍只记录。
                // 进程终止本身无法"撤销"（进程不能复活），但该进程的文件改写
                // 由回滚引擎兜底（可撤销），自启动项/落地文件/MBR 各有专属撤销。
                bool terminated = false;
                // ★★ 2026-10-03（C2）处置闭环断言 —— 「判了但没处置」当场暴露。
                //
                //  【为什么需要】今天实测查出三处「判定与处置脱节」：
                //    ① 注入侧判到 level≥1 后**只打一行 LogDbg**，无任何处置；
                //    ② 送检 verdict=error 后**无条件解锁放行**（沙箱失效反成放行理由）；
                //    ③ 送检判成功，但副本**不带依赖** ⇒ 样本被饿死，结论恒为 error。
                //  三处的共同形态：日志里「判定」和「处置」**长得一模一样**，
                //  事后翻日志无法区分「判了并处置了」与「判了什么都没做」。
                //
                //  【这里放什么】在**判定已定档、处置尚未开始**的位置记账：
                //    应处置 = 本次进入自动处置路径（lv≥2 且有 pid 且未被信誉门拦）
                //  处置结束时若「应处置 && 一件都没做成」⇒ 打一条 [half-open]。
                //  刻意**不**把信誉门放行算成半通故障 —— 那是设计决策，不是故障。
                const bool expectDispose = (lv >= 2 && pid > 0 && !sf::ProcReputable(p));
                bool anyAction = false;   // 是否发生过任何一种实际动作
                // ★★ 2026-10-03（真样本轮实测打出的误报）：「目标进程自己已经退出」
                //   **不算** half-open。
                //   背景：本机一轮测试里 10 次 half-open，逐条核对后发现
                //   **10 次全部**对应「终止进程失败 Win32=87（ERROR_INVALID_PARAMETER，
                //   典型成因就是 pid 已不存在）」，而那些是我自己编译的**短命探针**
                //   （跑完就退的 console 程序）。
                //   ⇒ 目标已经自己退了 = 危害已经消失 = **处置其实成功了**
                //     （以最省事的方式达成），把��记成"判定了却一件都没处置"，
                //     是**凭空造出来的假故障**。
                //   ⇒ 真 half-open（本该处置却做不到：权限不足、句柄占用等）
                //     会被这些噪音淹没 —— 而那正是这个断言存在的唯一理由。
                bool targetGone = false;   // 目标进程已自行退出
                // ★ 2026-09-24（银泊要求）：高危落地文件的**自动隔离**撤销 id。
                //   非空 = 已把文件本体移入隔离区（撤销 token = "30" + 此 id）。
                std::string quarantineId;
                // ★ 信誉门 v2（2026-09-19）：知名厂商签名/可信路径的进程，
                //   「评分型高危」不终止、不拉 infected、不弹高危卡（findings 仍记录）
                //   —— wallpaper64.exe 误杀事故的根治。
                //   但**硬规则行为压过信誉**：vssadmin delete shadows 这类确定性
                //   恶意行为，即使借微软签名的 cmd.exe/powershell.exe 跑也照样拦
                //   —— 否则真银狐借系统工具作案会被信誉门整个放行（测试盲点）。
                const bool reputable = (lv >= 2 && pid > 0 && havePath) ? sf::ProcReputable(p) : false;
                const bool reputableBlock = reputable && !hardHit;
                if (lv >= 2 && pid > 0 && !reputableBlock) {
                    // ★ 2026-10-03 修正：分两步记原因，别再把权限问题说成"进程已退出"。
                    //   原来只有 `if (hp)`，OpenProcess 失败时**错误码被丢掉**，
                    //   一路落到 2638 那句「终止进程失败（权限不足或进程已退出）」——
                    //   **两种完全不同的原因写在同一句里**，排障会被带偏去查
                    //   "进程是不是自己退了"（实测 5 次全是权限不足，进程一个没死）。
                    //   正确做法：分别记 OpenProcess 失败与 TerminateProcess 失败，
                    //   各自带上真实错误码，这样「权限断层」才能被看见。
                    DWORD termErr = 0;
                    const char* termWhy = "";
                    HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
                    if (hp) {
                        SetLastError(ERROR_SUCCESS);
                        terminated = (TerminateProcess(hp, 1) != FALSE);
                        if (!terminated) {
                            termErr = GetLastError();
                            termWhy = (termErr == ERROR_ACCESS_DENIED)
                                    ? "OpenProcess 成功但 TerminateProcess 被拒（权限不足）"
                                    : "TerminateProcess 调用失败";
                        }
                        CloseHandle(hp);
                    } else {
                        termErr = GetLastError();
                        // ERROR_INVALID_PARAMETER = 进程已不存在（PID 复用/已退出）
                        // ERROR_ACCESS_DENIED      = 权限不够（**SeDebug 没生效**）
                        termWhy = (termErr == ERROR_INVALID_PARAMETER)
                                ? "进程已退出或 PID 无效"
                                : (termErr == ERROR_ACCESS_DENIED
                                   ? "OpenProcess 被拒：权限不足（★ 检查 SeDebugPrivilege 是否已启用）"
                                   : "OpenProcess 失败");
                    }
                    if (terminated) {
                        LogDbg("[real-time] 已自动终止高危进程 pid=" + std::to_string(pid) +
                               " " + p + "（tag=" + tag + "｜理由：" + reason + "）");
                        detail += "\n已自动终止该进程（正经杀软模式：先处置，误伤可另寻撤销）。";
                        // ★ 衍生物清除联动：进程杀了，它释放的伴生文件不能留
                        //   （否则下一轮它自己被另一个副本拉起来，用户看到"清不干净"）
                        SweepDerivativesFor(p, "proc");

                        // ============================================================
                        //  ★ 2026-09-24（银泊要求）：高危落地文件 → 自动放入隔离区
                        // ============================================================
                        //  【补的是什么】
                        //  此前实时链路判高危只做一件事：TerminateProcess。进程是死了，
                        //  但**文件还完整躺在原地** —— 用户再双击一次、或另一个副本把它
                        //  拉起来，攻击链立刻继续。这就是"拦了但不清干净"的直接来源。
                        //
                        //  【为什么隔离而不是删除】
                        //  删除不可逆：一旦判错，用户文件就没了（本项目最忌讳的后果）。
                        //  隔离可还原：卡片上点「撤销我的处理」或主界面「隔离区」页点
                        //  「还原」，文件原样搬回原位 —— 与"正经杀软：先处置、误伤可撤销"
                        //  的语义完全一致（进程不能复活，文件可以搬回来）。
                        //
                        //  【只隔离"文件类"判定】
                        //  tag=heuristic（随机名落地）/ birthcard（出生卡）/ landed-exec
                        //  （落地即执行）/ **hashdb（病毒库整文件或导入表同一性命中）**
                        //  判定的是**这个文件本身有问题**，隔离它天经地义。
                        //  而行为类判定（ps-encoded / rat / host-url …）指向的是**宿主进程**
                        //  —— powershell.exe / rundll32.exe / 用户自己的正常软件。
                        //  把宿主收进隔离区等于把系统组件锁走，后果比误杀进程严重得多
                        //  → 一律排除，绝不隔离。
                        //
                        //  【护栏】三重复用既有名单，绝不另立一份：
                        //    · sf::IsNeverCleanPath：系统目录 / Program Files / 反作弊 /
                        //      我方自身目录 / 用户信任目录（与衍生物清除同一份白名单）；
                        //    · 必须是"刚落地"的文件（landedHit 或 10 分钟新鲜度），
                        //      否则可能把用户用了半年的老程序搬走；
                        //    · 文件必须真实存在（路径来自 ETW/WMI，可能已消失）。
                        // ============================================================
                        const bool fileVerdict = (tag == "heuristic" ||
                                                  tag == "birthcard" ||
                                                  tag == "landed-exec" ||
                                                  tag == "hashdb");
                        // ★ `tag == "hashdb"` **不受新鲜度限制**（2026-09-25 新增）。
                        //   上面那条"必须是刚落地"的护栏，防的是**启发式的误判**：
                        //   启发式猜错时，把一个用了半年的正常程序搬走，用户会很痛。
                        //   但病毒库命中是**字节同一性**：库里那条记录就是从这个文件
                        //   （或与它逐字节相同的文件）算出来的。一个半年前就躺在盘上的
                        //   已知恶意文件今天被拉起，照样该进隔离区 ——
                        //   这正是"病毒库"相对"启发式"的本质区别，用新鲜度去限制它
                        //   等于把病毒库降级成另一种启发式。
                        const bool freshEnough = landedHit || IsFreshlyCreated(p, 600) ||
                                                 tag == "hashdb";
                        const std::wstring wp = Utf8PathW(p);
                        if (fileVerdict && freshEnough &&
                            !sf::IsNeverCleanPath(p) && !wp.empty() &&
                            GetFileAttributesW(wp.c_str()) != INVALID_FILE_ATTRIBUTES) {
                            std::string why = "实时防护：" +
                                (title.empty() ? std::string("高危文件") : title);
                            if (!reason.empty()) why += "（" + reason + "）";
                            quarantineId = QuarantineLanded(p, why);
                            if (!quarantineId.empty()) {
                                LogDbg("[real-time] 已自动隔离高危落地文件: " + p +
                                       " → 隔离 id=" + quarantineId +
                                       "（卡片撤销 / 主界面隔离区页均可还原）");
                                detail += "\n已把该文件移入隔离区（可在卡片上点「撤销我的处理」"
                                          "还原回原位，或在主界面「隔离区」里管理）。";
                                anyAction = true;   // C2：文件隔离也是「做成了」
                            } else {
                                LogDbg("[real-time] ⚠ 高危文件隔离失败（被占用或权限不足）: " + p);
                                detail += "\n尝试把该文件移入隔离区失败（被占用或权限不足），"
                                          "请手动处理。";
                            }
                        } else if (lv >= 2 && fileVerdict && !freshEnough) {
                            // 诊断可查性：判了高危但没隔离，必须留下"为什么没隔离"
                            LogDbg("[real-time] 高危文件未隔离（非新落地文件）: " + p);
                        }
                    } else {
                        // ★ 2026-10-03：日志必须能区分「权限不够」与「进程已退出」。
                        //   旧文案「（权限不足或进程已退出）」把两种原因混在一句里，
                        //   实测 5 次全是权限不足，却让人以为是进程自己退了 —— 排障方向直接被带偏。
                        // ★★ 同日再补：`ERROR_INVALID_PARAMETER` 时**标记目标已消失** ——
                        //   它与「处置失败」在后果上是两件事：
                        //     · 权限不足   = 危害还在，处置没做到 ⇒ **真 half-open，必须报**
                        //     · 进程已退出 = 危害自己没了 = 处置其实成功了 ⇒ 不该报
                        //   混报会凭空造出假故障，把真 half-open 淹没。
                        if (termErr == ERROR_INVALID_PARAMETER) targetGone = true;
                        LogDbg("[real-time] 终止进程失败 pid=" + std::to_string(pid) +
                               " " + p + "（tag=" + tag + "）—— 原因：" + termWhy +
                               "（Win32=" + std::to_string((unsigned long)termErr) + "）");
                        detail += std::string("\n尝试自动终止该进程失败：") + termWhy + "。";
                    }
                    // ---- C2 处置闭环断言：到此为止，进程层面「做成了什么」 ----
                    //  成功终止 = 一件实事做成；失败（权限/已退出）= 一件都没做成。
                    //  注意：这里只统计**进程层面**的动作，文件隔离由上面那段独立记账。
                    if (terminated) anyAction = true;
                } else if (reputableBlock) {
                    LogDbg("[real-time] 高危行为命中但进程签名可信 → 信誉门拦截，跳过终止: " + p +
                           "（tag=" + tag + "）");
                    detail += "\n进程有可信厂商签名，已跳过终止（仅记录行为）。";
                }
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    // 已在 findings 里（如刚被全盘扫到）则不重复入列
                    bool dup = false;
                    for (const auto& f : g_result.findings) if (f.path == p) { dup = true; break; }
                    if (!dup) g_result.findings.push_back({"实时防护", sev, title, detail,
                                                           sf::BaseName(p), p});
                    // 信誉门：可信进程不拉 infected（GUI 不显示"已感染"）
                    if (lv >= 2 && !reputableBlock) { g_result.status = "infected"; g_result.score = 200; }
                    g_result.timestamp = NowStr();
                }
                LogDbg("[real-time] " + sev + " [" + tag + "] " + p +
                       (terminated ? " [已终止]" : "") +
                       (reason.empty() ? "" : ("  ｜理由：" + reason)));

                // ---- C2 处置闭环断言：判定与处置的「对账」 ----
                //  走到这里，判定已定档、处置已尝试完。两种结果都算正常：
                //    · 做了（终止或隔离）⇒ 一致
                //    · 被信誉门拦下 ⇒ 设计决策，不算故障（已单独落日志）
                //  真正的故障只有一种：**应该处置，却一件都没做成**
                //    —— 这正是今天查出的三处「判了不处置」的形态。
                //  断言打在**出口**上，所以任何一条新增的处置分支漏接都不会漏检。
                if (expectDispose && !anyAction && !targetGone) {
                    g_halfOpen.fetch_add(1);
                    LogDbg("[real-time] ★★ [half-open] 判定了却**一件都没处置**：lv=" +
                           std::to_string(lv) + " tag=" + tag + " pid=" + std::to_string(pid) +
                           " " + p + "（理由：" + reason + "）—— 处置链与判定链脱节，请查该分支");
                }
                if (lv >= 2 && !reputableBlock) {
                    // MBR 归因登记 + 弹卡归因数据：可疑活动窗口期内的
                    // MBR 变更要能追到这个进程头上（bootguard 10 分钟窗）
                    boot::NoteSuspicion(pid, p);
                    // ★ 2026-09-24：标题与正文按"是否真的隔离了文件"分流 ——
                    //   隔离成功时给的是**可撤销**的卡片（撤销 = 文件搬回原位），
                    //   没隔离成时才退回"进程已终止、不可撤销"的老文案。
                    //   绝不假装可撤销：token 为空时若仍走五参版本，卡片按钮会
                    //   postMessage 出 'undo:'（服务端解析失败）—— 那是假按钮。
                    // ★ 按「是不是库中命中」分开文案（2026-09-25）：
                    //   库中命中 = 字节同一性（确凿）；其余 = 行为/启发式（疑似）。
                    //   与落地路径（LandedAlertWatch）保持同一口径 ——
                    //   「同一类命中在两条链路上有不同文案」正是本项目反复吃亏的模型。
                    const bool hashTag = (tag == "hashdb");
                    const std::string alertTitle = quarantineId.empty()
                        ? (hashTag ? std::string("已知恶意程序已自动拦截")
                                   : std::string("可疑行为已自动拦截"))
                        : (hashTag ? std::string("已知恶意程序已拦截并隔离")
                                   : std::string("可疑程序已拦截并隔离"));
                    SetLastAlertInfo(alertTitle,
                                     "「" + sf::BaseName(p) + "」命中判定（" + tag +
                                     "），已自动终止该进程。" +
                                     (quarantineId.empty()
                                        ? std::string()
                                        : "\n该文件已移入隔离区，点下方「撤销我的处理」可还原回原位。") +
                                     (reason.empty() ? "" : ("\n判定依据：" + reason)),
                                     sf::BaseName(p));
                    // 进程终止本身不可撤销（进程不能复活）；但**文件隔离可以**。
                    // 所以：有 quarantineId → 传 "30"+id 让卡片出现可用的撤销按钮；
                    //       没有 → 只弹四参版本（无撤销按钮）。
                    //
                    // ---- 行为链记录：进程行为是链条的"执行"环节 ----
                    //  detail 里带上机器可读的规则 tag 与命中原因（放 extra），
                    //  这样行为图即使不展开也能看出"是被哪条规则拦的"。
                    const std::string undoToken = quarantineId.empty()
                        ? std::string() : ("30" + quarantineId);
                    trace::Record(trace::Kind::Process, sf::BaseName(p),
                                  "命中判定（" + tag + "），已自动终止该进程" +
                                  (quarantineId.empty() ? std::string()
                                                        : "，并把文件移入隔离区"),
                                  p, undoToken, true, 200);
                    // ★ risk 取值与卡片文案的对应（值在 toast.cpp BuildHtml 与
                    //   index.html deriveFlags **两处**被解释，加值必须同步两处）：
                    //     · 文件确实进了隔离区 → quarantine（疑似）/ hashlanded（确凿）
                    //       → 卡片渲染「…已拦截并隔离」+「撤销我的处理」（token = 30+id）
                    //     · 隔离失败（被占用／权限不足）→ 退回落地的 proc 档：
                    //       卡片渲染「可疑行为已自动拦截」且**不给撤销按钮** ——
                    //       进程杀错了不能复活、文件也没搬走，谎称可撤销就是做假按钮。
                    //       （已知恶意样本落到这一档时标题会被弱化成"可疑行为"，
                    //         这是**刻意**的：宁可低估，也不能说"已隔离"而其实没隔离。
                    //         真实结论由 lastalert 回填的副标题承担。）
                    //   ⚠️ 2026-09-25 修：「quarantine」此前在 toast.cpp 与 index.html
                    //      里**都没有分支**，会一路落到 STATUS==='infected' 兜底分支 ——
                    //      标题错成「高危：疑似环境异常」、按钮错成「清除威胁」，
                    //      撤销入口没渲染 → **隔离了却撤不回来**。已在两处补齐。
                    if (!undoToken.empty())
                        sf::NotifyAnomaly("infected", 200,
                                          hashTag ? "hashlanded" : "quarantine",
                                          undoToken, true);
                    else
                        sf::NotifyAnomaly("infected", 200, "proc");
                }
            }
        }}

// ETW 消费回调：etwproc 消费线程上调用，直接进判定管线
static void OnEtwProcessEvent(const sf::etwproc::ProcEvent& e) {
    // ★ 2026-10-01：跳过**我们自己起的存活探针**进程（见 ProcessWatch 的心跳看门狗）。
    //   探针是 `cmd.exe /c exit`、父进程是服务本身 —— 若放进判定管线，既每 30 秒
    //   白跑一遍全量判定（噪声 + 无谓开销），又可能撞上"服务拉 cmd"这类父子链规则
    //   而产生自产误报。探针的用途只是"证明事件通道还通"，不该进业务链。
    if (sf::etwproc::IsProbePid(e.pid)) return;
    HandleNewProcess(e.pid, e.image);
}


class WmiSink : public IWbemObjectSink {
    LONG m_ref = 1;
public:
    ULONG STDMETHODCALLTYPE AddRef() override { return (ULONG)InterlockedIncrement(&m_ref); }
    ULONG STDMETHODCALLTYPE Release() override {
        LONG r = InterlockedDecrement(&m_ref);
        if (r == 0) delete this;
        return (ULONG)r;
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) { *ppv = this; AddRef(); return S_OK; }
        *ppv = nullptr; return E_NOINTERFACE;
    }
    HRESULT STDMETHODCALLTYPE Indicate(LONG lObjCount, IWbemClassObject** apObjArray) override {
        for (LONG i = 0; i < lObjCount; ++i) {
            VARIANT vt; VariantInit(&vt);
            if (FAILED(apObjArray[i]->Get(L"TargetInstance", 0, &vt, 0, 0)) || vt.vt != VT_UNKNOWN) { VariantClear(&vt); continue; }
            IWbemClassObject* ti = nullptr;
            if (SUCCEEDED(vt.punkVal->QueryInterface(IID_IWbemClassObject, (void**)&ti)) && ti) {
                // ---- 取 ExecutablePath / ProcessId ----
                std::string p;
                unsigned long pid = 0;
                VARIANT ep; VariantInit(&ep);
                if (SUCCEEDED(ti->Get(L"ExecutablePath", 0, &ep, 0, 0)) && ep.vt == VT_BSTR && ep.bstrVal && ep.bstrVal[0]) {
                    int n = WideCharToMultiByte(CP_UTF8, 0, ep.bstrVal, -1, nullptr, 0, nullptr, nullptr);
                    if (n > 1) { p.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, ep.bstrVal, -1, &p[0], n, nullptr, nullptr); }
                }
                VariantClear(&ep);
                VARIANT vpid; VariantInit(&vpid);
                if (SUCCEEDED(ti->Get(L"ProcessId", 0, &vpid, 0, 0)) && vpid.vt == VT_I4) pid = (unsigned long)vpid.lVal;
                VariantClear(&vpid);

                if (!p.empty()) HandleNewProcess(pid, p);
                ti->Release();
            }
            VariantClear(&vt);
        }
        return WBEM_S_NO_ERROR;
    }
    HRESULT STDMETHODCALLTYPE SetStatus(LONG, HRESULT, BSTR, IWbemClassObject*) override { return WBEM_S_NO_ERROR; }
};

// ---------------------------------------------------------------------------
//  落地前置捕获消费线程（2026-09-19 新增）
// ---------------------------------------------------------------------------
//  为什么需要：银狐链条是「下载 → 落盘 → 自启」。回滚引擎（rollback.cpp）
//  已经把"落盘那一刻"的初筛结果放进队列（见 ProbeLandedFile），
//  但那是**纯文件视角**（路径 + 文件名 + 文件头），不知道是谁写入的。
//  本线程负责把它接到**进程视角**：对刚落地的高危文件，
//  用 QuickProbeExecutable + JudgeProcess 做一次完整判定，
//  命中就写 findings + 弹窗（并可终止 —— 见 WmiSink 的分级终止）。
//
//  为什么要独立线程而不是塞进 GuardThread：GuardThread 是秒级的轻量巡检，
//  本线程是 5 秒级轮询队列，生命周期与扫描无关，混在一起会让调度更难懂。
static void LandedAlertWatch() {
    LogDbg("[landed] 落地捕获消费线程已启动");
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;

        std::string json = rb::TakeLandedAlertsJson();   // 取走即清空
        // 极简解析：逐条抠出 path / reason（不引第三方 JSON 库，与项目一贯做法一致）
        size_t pos = 0;
        int handled = 0;
        while (handled < 16) {                            // 单轮上限，避免突发事件刷屏
            size_t p1 = json.find("\"path\":\"", pos);
            if (p1 == std::string::npos) break;
            p1 += 8;
            // ★★★ 2026-10-02 严重误报修复（System32 正版组件被判「无可信签名」并锁死原件）
            //   生产者 rollback.cpp::TakeLandedAlertsJson 走 JsonString() → 标准 JSON 转义，
            //   路径里的每个 '\' 都写成 "\\"。而这里以前直接把两个引号之间的**原文**当路径用
            //   → 服务内部拿到的是 "C:\\WINDOWS\\system32\\cmd.exe"（双反斜杠）。
            //   危害不是"打不开文件"（Win32 自动折叠重复分隔符 → 复制副本、算哈希、加锁全都
            //   照常成功，所以故障完全静默），而是**前缀比较类判定静默失效**：
            //     scanner.cpp HasCatalogSignature 用 ToLowerW(path).compare(0,n,%SystemRoot%)
            //     判"在不在 Windows 目录下" → "c:\\windows" 与 "c:\windows" 第 3 个字符就不等
            //     → 直接 return false = 「无可信签名」→ 右腿送检 → 且被本轮送检封锁锁住原件。
            //   实证（guard.log 2026-10-02 16:39 批次，服务启动后 6 秒内）：refsdedupsvc /
            //   msra / TieringEngineService / dsregcmd / sc / powershell / cmd / Conhost
            //   共 8 个微软正版组件全部被判无签名并锁死，日志里这 8 条的路径都是双反斜杠。
            //   正确做法有两步，缺一不可：
            //     ① 找结束引号时**跳过转义字符**（否则值里含 \" 会提前截断）；
            //     ② 取出的原文必须过 JsonUnescape() 还原（这才是路径本身）。
            size_t p2 = p1;
            while (p2 < json.size()) {
                if (json[p2] == '\\' && p2 + 1 < json.size()) { p2 += 2; continue; }  // 跳过转义字符
                if (json[p2] == '"') break;
                ++p2;
            }
            if (p2 >= json.size()) break;
            std::string path = sf::JsonUnescape(json.substr(p1, p2 - p1));
            pos = p2 + 1;
            if (path.empty()) continue;

            // ⓪ ★★ 病毒库点查 —— 先于一切启发式，**也先于 packscan 分流**。
            //    2026-09-26 修「压缩包命中云库却毫无反应」：库条目可能就是压缩包
            //    本身的 SHA-256（theZoo 类投递形态——官方 .sha256 记的是 zip 自身
            //    哈希）。旧顺序 packscan 分流在前 → zip 一律 continue，哈希判定
            //    被整段跳过 → 命中库也无任何反应。现在先查库：命中则掉出分流
            //    走下方通用「lv>=2 自动隔离」路径；不命中才交 packscan 异步解包。
            //    （放在"落地"这一刻尤其合适：文件刚落盘、内容尚未变化，这里算出
            //    的哈希就是它将来被执行时的哈希，且 pehash 缓存可复用。）
            std::string hashWhy;
            const bool hashHit = (sf::hashverdict::MaliciousVerdict(path, &hashWhy) >= 2);

            // ★ 压缩包落地：归档不适用 QuickProbeExecutable（它只认 PE/脚本，
            //   归档到那行就 return 0），且解包是秒级 + 大量磁盘 I/O 的重活，
            //   **绝不能**在这个 5 秒轮询的实时循环里同步做 —— 攻击者连续丢几个
            //   大压缩包就能把实时防护拖死（可被利用的 DoS 面）。
            //   哈希命中 → 不分流，直接走通用隔离链（四道锁 + 索引 + 可撤销）；
            //   不命中 → 只入队，扫描交给 packscan 的独立消费者线程（异步、串行）。
            //
            // ★ 2026-10-03 澄清（此前我误判此处是断点，核实后不是）：
            //   这个 `continue` 本身**是对的** —— packscan 已在 `service.cpp:1857`
            //   接了 `SetSink(&OnPackHit)`，命中 level>=2 会回调 `OnPackHit`
            //   走隔离+弹卡，处置链是通的（异步是为了防 DoS，不是为了漏处置）。
            //   ★ 真正的漏洞在**分流条件**：`IsArchiveExt` 只认 21 种归档扩展名
            //     （packscan.cpp:62-66），**`.exe` 不在内** ⇒ 而银狐本体恰恰是
            //     **PE 头的安装器**（Inno/NSIS 自解压包，扩展名是 .exe）⇒
            //     它永远进不了 packscan 队列，只能靠 DeepProbeExecutable 单文件判定，
            //     而单文件判定看不见包内的载荷。
            //   ⇒ 判据从「扩展名像不像归档」改成「**外层类型是不是安装器**」。
            //   用 DeepProbeExecutable 已在 2870 行算出的类型，这里复用其结论。
            if (packscan::IsArchiveExt(path) || LooksLikeInstallerExe(path)) {
                if (!hashHit) {
                    packscan::Enqueue(path);
                    continue;
                }
                // 哈希命中：落出本分支，lv = hashHit ? 2 → 走下方 QuarantineLanded。
            }

            // 完整判定（复用与前台扫描完全相同的判定核心，避免规则两套）
            int lv = hashHit ? 2 : QuickProbeExecutable(path);
            // ★ 2026-09-24：实时链路接内容 probe —— 消除与全盘扫描的口径差。
            //   实证（虚拟机）：同一个 YouDaoX64.exe，全盘扫描判 level=2 / 300 分
            //   （probe 引擎命中家族串 + INNO 特征），实时链路只给「1 级旁证」。
            //   根因：QuickProbeExecutable 建模的是"随机名落地"这一种形态，
            //   而真实样本命名正常 → 直接判 0。这里在它判 0 时补一次完整内容判定，
            //   两条链路从此同一套判据（probe.cpp 的 ScanTargetFile）。
            std::string deepNote;
            if (lv == 0) {
                std::string dTitle; int dScore = 0;
                int dl = DeepProbeExecutable(path, &dTitle, &dScore);
                if (dl > lv) {
                    lv = dl;
                    deepNote = "\n内容判定命中：" + dTitle +
                               "（" + std::to_string(dScore) + " 分）";
                }
            }
            if (hashHit) deepNote = "\n" + hashWhy + "（已知恶意样本）。";
            std::string detail;
            std::string quarantineId;   // 非空 = 已自动隔离（撤销 token 的后 8 位）
            // ★ 2026-09-27 修正（银泊指出）：门禁不能只认"随机名"。
            //   正常名 + 内容引擎一时看不出的病毒安装包会落进 lv==0 直接放过 —— 给正常名
            //   恶意样本留后门（病毒常伪装成 setup/installer/update 这类正常名）。
            //   改法：除 lv==1 外，凡是「高发区落地的非可信签名可执行体」也送沙箱动态分析
            //   —— 名字正常与否无所谓，关键看有没有可信签名（正经厂商安装器有签名，
            //   恶意安装包通常没有）。病毒库命中(hashHit)走 lv>=2 直接隔离，不在此重复送。
            //   ⚠️ 代价：会把落进高发区的无签名良性工具也送沙箱（良性但无签名很常见），
            //      由 sandbox 的「按路径去重 + 每小时 12 次限流」兜底，不会把沙箱当耗材烧。
            auto extMatch = [&](const char* e) {
                const size_t n = path.size(), m = strlen(e);
                return n >= m && _strcmpi(path.c_str() + n - m, e) == 0;
            };
            const bool exeLike = extMatch(".exe") || extMatch(".com") || extMatch(".scr") ||
                                 extMatch(".dll") || extMatch(".sys");
            const bool unsignedSusp = exeLike && !SigTrustedCached(path) && !hashHit;
            if (lv >= 1 || unsignedSusp) {
                detail = (hashHit ? std::string("文件在落地高发区被创建时即被捕获。")
                                  : std::string("文件在落地高发区被创建时即被捕获，命中初始筛查。"))
                         + deepNote;
                if (lv >= 2) {
                    // 正经杀软模式（银泊 09-19）：高危落地载荷自动隔离，可撤销移回原位
                    quarantineId = QuarantineLanded(path);
                    boot::NoteSuspicion(0, path);   // MBR 归因登记
                    detail += quarantineId.empty()
                        ? "\n自动隔离失败（文件被占用或权限不足），请手动处理。"
                        : "\n已自动隔离该文件（先处置，误判可点「撤销」移回）。";
                    // ★ 衍生物清除联动：银狐一次落地多份随机名副本，隔离了当前这个，
                    //   同一批写进 Temp/ProgramData/Users\Public 的其它副本必须一并清掉
                    if (!quarantineId.empty()) SweepDerivativesFor(path, "landed");
                } else {
                    // ==========================================================
                    //  ★★ 自动送检沙箱（2026-09-27 新增）—— 补上设计里断掉的那一段
                    // ==========================================================
                    //  lv==1 的确切含义：静态初筛**判拿不准**。
                    //  初筛看到了旁证（随机名 / 可疑位置 / PE 异常 / 家族特征串…），
                    //  但完整内容判定不认账 —— 不够格直接隔离，也**不该直接放行**。
                    //  这正是 sandbox.h 顶部写的那个候选池：
                    //      「静态初筛判『拿不准』的样本 → 送进沙箱跑一遍 → 看它落什么」
                    //  在此之前这条链**只存在于注释里**：送检只能人手点（sandboxscan）。
                    //
                    //  ★ 为什么必须异步：一次沙箱分析要几十秒（建箱 → 送检 → 观察
                    //    窗口 → 采样 → 销毁）。这里是 5 秒轮询的**实时路径**，就地
                    //    同步做会把整条落地防护拖死 —— 攻击者连丢几个样本就能造成
                    //    可被利用的 DoS 面。与 packscan 完全同一条纪律。
                    //  ★ 为什么必须去重：样本自身会反复触发落地事件，指纹级抖动
                    //    就能把队列刷满、把沙箱当一次性耗材烧掉。
                    //  ★ waitSec=0 → 用沙箱模块的默认观察窗口（不在这里写死时长，
                    //    否则调窗口要改两处，且两处一定会走偏）。
                    //
                    //  ⚠️ 这里**只入队**，不做任何处置：结论出来后由
                    //     OnSandboxReport 统一决定（malicious 才隔离）。
                    //     判定与处置分家的原因：送检是"取证"，处置是"裁决"，
                    //     取证期间不能先动手 —— 那等于用静态旁证替动态结论背书。
                    //  ★ 2026-10-01：入队时必须**报出触发腿**，否则无法验证新引擎。
                    //   问题（银泊指出）：两条腿以前在 guard.log 里长得一模一样 ——
                    //   原来那行只打「路径 / 去重 / 队列深度」。用随机名样本做测试时
                    //   永远走左腿、右腿一次没触发，但日志看不出任何区别 →
                    //   **新引擎"跑过没有"不可验证**（典型半通故障：功能在，无从观测）。
                    //   现在拆开：lv>=1 = 左腿；lv==0 且 unsignedSusp = 右腿。
                    std::string whySend =
                        (lv >= 1)
                        ? ("左腿 lv=" + std::to_string(lv) +
                           "（随机名画像/内容判定命中，与文件名形态相关）")
                        : std::string("右腿 unsignedSusp（正常名 + 无可信签名 + 未命中哈希"
                                      "→ 与文件名无关的新送检引擎）");
                    sf::sandbox::EnqueueScan(path, /*dryrun=*/false, /*waitSec=*/0,
                                             /*dedup=*/true, whySend.c_str());
                    detail += "\n已加入沙箱动态分析队列（静态初筛拿不准 → 送进沙箱"
                              "跑一遍看它到底干什么；结论稍后单独出卡）。";
                }
            } else {
                continue;   // 初筛过了但完整判定不认账 → 不报（宁可漏报不误报）
            }

            {
                std::lock_guard<std::mutex> lk(g_resultMutex);
                bool dup = false;
                for (const auto& f : g_result.findings) if (f.path == path) { dup = true; break; }
                if (!dup)
                    g_result.findings.push_back({ "落地捕获", lv >= 2 ? "高" : "中",
                                                  hashHit ? "落地即捕获已知恶意样本"
                                                          : (lv >= 2 ? "落地即捕获可疑载荷"
                                                                     : "落地即发现可疑文件（旁证）"),
                                                  detail + "\n" + path,
                                                  sf::BaseName(path), path });
                if (lv >= 2) { g_result.status = "infected"; if (g_result.score < 200) g_result.score = 200; }
                g_result.timestamp = NowStr();
            }
            LogDbg("[landed] 落地捕获命中（" + std::to_string(lv) + "级）: " + path +
                   (quarantineId.empty() ? "" : " [已隔离]"));
            if (lv >= 2) {
                if (!quarantineId.empty()) {
                    // ★★ 两类命中的口径必须分开（2026-09-25 新增 hashlanded）：
                    //   库中命中 = **字节同一性** —— 「这就是病毒库里记录的那个样本」。
                    //     结论确凿，用户动作只有一个：清掉（「撤销」只是为了兜误判）。
                    //   启发式命中 = **形态可疑** —— 「它长得像恶意样本」。
                    //     结论是概率，用户动作是"看一眼再决定"。
                    //   混成一张卡，用户就分不出「确凿」与「疑似」，也就无从判断
                    //   该不该点「撤销」——而把确凿样本恢复回去等于主动放行已知恶意。
                    //   所以 risk 值、标题、副标题、行为链描述四处全部按命中来源分开。
                    //
                    //   risk 值在三个地方有白名单/映射，新增值必须同步：
                    //     toast.cpp BuildHtml（WebView2 路径）
                    //     toast-app/resources/app/main.js parseArgs（Electron 路径）
                    //     toast-app/resources/app/index.html deriveFlags（Electron 渲染）
                    const std::string riskKey = hashHit ? "hashlanded" : "landed";
                    SetLastAlertInfo(hashHit ? "已知恶意样本已自动隔离"
                                             : "落地载荷已自动隔离",
                                     hashHit
                                       ? ("「" + sf::BaseName(path) +
                                          "」与病毒库中的已知恶意样本一致，已自动隔离。")
                                       : ("「" + sf::BaseName(path) +
                                          "」在落地高发区被创建且形态可疑，已自动隔离。"),
                                     sf::BaseName(path));
                    // ---- 行为链记录：落地是链条的**起点**（"下载 → 落盘"）----
                    //  这是行为图里最有价值的一条 —— 用户能看到"它是怎么进来的"。
                    //  detail 用来源 + lv 区分「库中确凿 / 高危载荷 / 旁证级可疑」（诚实口径）。
                    trace::Record(trace::Kind::Landed, sf::BaseName(path),
                                  (hashHit
                                     ? "病毒库命中的已知恶意样本在落地高发区被创建，已自动隔离："
                                     : (lv >= 3 ? "高危载荷在落地高发区被创建，已自动隔离："
                                                : "可疑文件在落地高发区被创建，已自动隔离：")) + detail,
                                  path, "30" + quarantineId, true, 200);
                    sf::NotifyAnomaly("infected", 200, riskKey, "30" + quarantineId, true);
                } else {
                    sf::NotifyAnomaly("infected", 200);   // 隔离失败 → 普通告警卡（清除威胁）
                }
            }
            handled++;
        }
    }
    LogDbg("[landed] 落地捕获消费线程已退出");
}

// ---------------------------------------------------------------------------
//  网络外联监听（第四个实时防护事件源，2026-09-22）
//
//  定位：银狐 / ValleyRAT / 挖矿 / 银行木马的共同出口 —— **它们最终都要外联**。
//  前三个事件源覆盖「下载 → 落盘 → 自启」，本线程补上「连出去想干什么」。
//
//  能力边界（写卡片文案时必须守住，见 docs/six-class-detection-plan.md §四）：
//    纯用户态，ETW 是**事后通知** —— 我们看到 id=10 时连接已经建好了。
//    所以这里能做的是「发现外联 → 处置该进程」，**不是**「阻断这次连接」。
//    无内核级阻断能力，任何"已阻止连接"的文案都是虚假承诺。
//
//  与 etw.cpp 的关系：复用其采集层的写法（会话/订阅/回调/队列），但独立成模块，
//  原因是判定口径与过滤策略完全不同（进程事件看命令行，网络事件看对端 IP/端口）。
// ---------------------------------------------------------------------------
static void NetWatch() {
    // ⚠️ 已知 IOC 外联判定：命中 C2_IPS / C2_PORTS 是**铁证级**信号。
    //   数据源 iocs.h 的 C2_IPS（13 条）/ C2_PORTS（4 条），与全盘扫描同源 ——
    //   这样"实时拦截"和"事后体检"的结论口径一致，不会出现两者互相矛盾。
    //   队列在 netwatch 的消费线程上被调用，**不得做重活**。
    netwatch::Start([](const netwatch::ConnEvent& e) {
        // 逐条比对已知 C2（条数少，线性扫足够；将来 IOC 变多再上哈希表）
        bool hitIp = false;
        for (const char* ip : iocs::C2_IPS) {
            if (ip && e.remoteIp == ip) { hitIp = true; break; }
        }
        bool hitPort = false;
        for (unsigned short port : iocs::C2_PORTS) {
            if (e.remotePort == port) { hitPort = true; break; }
        }
        // 判定口径：IP 命中即高危；仅端口命中只作旁证（9899/5040 等端口偶有正常软件用）
        // ★ 2026-10-03（P1-1 消灭静默降级）：原实现 `if (!hitIp && !hitPort) return;`
        //   ⇒ 未命中 C2 名单的连接**当场丢弃，连一行日志都不打**。实测代价：
        //   挖矿进程 CPU 100% 烧了一整轮、主防零告警，而日志里对此**毫无痕迹** ——
        //   排障时无法区分「没发生」和「发生了但被丢了」（铁律 24 同族）。
        //   改法：① 矿池端口/协议特征另设**旁证**通道（不进 C2 表，避免污染铁证信号）；
        //        ② 未命中 IOC 的外联改为**按周期统计**落日志，让「静默丢弃」变成可观测。
        if (!hitIp && !hitPort) {
            // ---- 旁证通道一：矿池端口 ----
            bool hitMinerPort = false;
            for (std::size_t k = 0; k < iocs::MINER_PORTS_N && !hitMinerPort; ++k) {
                if (e.remotePort == iocs::MINER_PORTS[k]) { hitMinerPort = true; break; }
            }
            // ---- 旁证通道二：矿池协议串（需要进程命令行，稍后取） ----
            bool hitMinerProto = false;
            std::string minerToken;
            if (!hitMinerPort) {
                ProcEntity me = MakeEntityOfPid((unsigned long)e.pid);
                if (!me.commandLine.empty() && me.commandLine == me.imagePath) {
                    // 命令行读不到（Win10 上是已知问题）⇒ 这条旁证本轮不可用
                    me.commandLine.clear();
                }
                if (!me.commandLine.empty()) {
                    std::string cl = to_lower(me.commandLine);
                    for (std::size_t k = 0; k < iocs::MINER_PROTO_TOKENS_N; ++k) {
                        if (cl.find(iocs::MINER_PROTO_TOKENS[k]) != std::string::npos) {
                            hitMinerProto = true; minerToken = iocs::MINER_PROTO_TOKENS[k]; break;
                        }
                    }
                }
                if (hitMinerProto || hitMinerPort) {
                    // 矿池信号：**必须与进程自身可疑叠加**才处置，绝不单凭端口/协议定罪。
                    ProcEntity ent2 = MakeEntityOfPid((unsigned long)e.pid);
                    if (ent2.imagePath.empty()) return;
                    if (ProcReputable(ent2.imagePath)) return;   // 硬纪律：信誉门优先
                    // ★ `observed` 是 ProcEntity 的字段，**不是 ProcVerdict 的** ——
                    //   打标必须打在实体上、再交给 JudgeProcess，判层才会走 observed 升档。
                    //   （写在 verdict 上是类型错误，编译期就会拦；这里记下来防再犯。）
                    if (sf::ObserveHit(ent2.imagePath)) ent2.observed = true;
                    ProcVerdict mv = JudgeProcess(ent2);
                    if (mv.level < 1) {
                        // 旁证不足以独立升级 ⇒ 落日志留痕，不处置（宁可吵不可瞎）
                        LogDbg("[netwatch] 可疑外联·矿池旁证（未升级）pid=" + std::to_string(e.pid) +
                               " " + e.remoteIp + ":" + std::to_string(e.remotePort) +
                               " 进程=" + ent2.imagePath +
                               " 判据=" + (minerToken.empty() ? std::string("矿池端口") : minerToken) +
                               " 进程判定 lv=" + std::to_string(mv.level) +
                               "（需与进程可疑叠加才处置）");
                        return;
                    }
                    // ★ 显式比较而非 std::max —— <algorithm> 的重载与 windows.h 的
                    //   min/max 宏冲突（MSVC 下模板形式触发 C2589）。
                    if (mv.level < 2)   mv.level = 2;
                    if (mv.score < 120) mv.score = 120;
                    mv.hard = true;
                    mv.tag = "miner";
                    mv.reason = std::string("疑似挖矿行为（") +
                                (minerToken.empty() ? ("连接矿池常用端口 " + std::to_string(e.remotePort))
                                                    : ("命令行含矿池协议特征 " + minerToken)) +
                                "）" + (mv.reason.empty() ? "" : ("；" + mv.reason));
                    mv.level = 2;
                    int mlv = mv.level;
                    if (mlv >= 2) {
                        std::string det = "疑似挖矿：连接 " + e.remoteIp + ":" +
                                         std::to_string(e.remotePort);
                        if (!mv.reason.empty()) det += "。" + mv.reason;
                        LogDbg("[netwatch] ★挖矿外联 pid=" + std::to_string(e.pid) +
                               " " + e.remoteIp + ":" + std::to_string(e.remotePort) + " → 升级 2 级");
                        HANDLE mhp = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                                 FALSE, (DWORD)e.pid);
                        bool mkilled = false;
                        DWORD  merr = ERROR_INVALID_PARAMETER;
                        if (mhp) {
                            mkilled = (TerminateProcess(mhp, 0) != 0);
                            if (!mkilled) merr = GetLastError();
                            CloseHandle(mhp);
                        }
                        if (mkilled) {
                            SweepDerivativesFor(ent2.imagePath, "net");
                            det += "。已自动终止该进程";
                        } else {
                            // ★ 按 GetLastError 分开落日志（铁律：不要把两种原因写在一句里，
                            //   否则排障会被带偏去查"是不是进程自己退了"）
                            LogDbg("[netwatch] 终止挖矿进程失败 pid=" + std::to_string(e.pid) +
                                   " 原因：" + (merr == ERROR_ACCESS_DENIED
                                                ? "权限不足（检查 SeDebugPrivilege 是否已启用）"
                                                : "进程已退出或句柄打开失败"));
                        }

                        // ---- 落账四连（与 C2 路径完全同一套契约，顺序固定）----
                        sf::AddFinding("网络", "高", "疑似挖矿行为", det,
                                       ent2.imagePath, e.remoteIp, 60);
                        sf::EscalateInfected(200);
                        trace::Record(trace::Kind::Process, sf::BaseName(ent2.imagePath),
                                      "挖矿外联：" + det, ent2.imagePath, "", true, 200);
                        SetLastAlertInfo("挖矿行为已自动拦截",
                                         "「" + sf::BaseName(ent2.imagePath) + "」" + det,
                                         ent2.imagePath);
                        sf::NotifyAnomaly("infected", 200, "proc");
                    }
                    return;
                }
            }
            // ---- 都不是：按周期统计落日志，让「静默丢弃」可观测（不逐条打，量太大）----
            {
                static std::atomic<uint64_t> s_passCount{ 0 };
                const uint64_t n = s_passCount.fetch_add(1, std::memory_order_relaxed) + 1;
                if (n % 500 == 1) {
                    LogDbg("[netwatch] 周期统计：未命中 IOC 的外联事件累计 " + std::to_string(n) +
                           " 条（矿池端口命中 0；这些连接不告警、不处置，仅留痕以便排障）");
                }
            }
            return;
        }

        // ---- 归因：拿到发起外联的进程实体 ----
        ProcEntity ent = MakeEntityOfPid((unsigned long)e.pid);
        if (ent.imagePath.empty()) return;   // 进程已退出，无从处置（且不该凭 PID 猜）

        // ★ 硬纪律二：任何终止动作前必须先过信誉门（防止误杀浏览器/系统组件）
        if (ProcReputable(ent.imagePath)) return;

        // ---- 判定：交给统一判定核心，不自己造阈值 ----
        if (sf::ObserveHit(ent.imagePath)) ent.observed = true;   // 放行后监控打标
        ProcVerdict v = JudgeProcess(ent);
        // 已知 C2 命中 → 至少抬到 level 2（否则 IOC 的意义就没了）
        if (hitIp && v.level < 2) { v.level = 2; v.score = 200; v.hard = true; }

        int lv = v.level;
        if (lv >= 2) {
            // ---- 处置：终止 + 清除衍生物（与 WMI 路径同一条处置链）----
            std::string detail = hitIp
                ? ("与已知恶意服务器 " + e.remoteIp + ":" + std::to_string(e.remotePort) + " 建立了连接")
                : ("连接了可疑端口 " + std::to_string(e.remotePort) + "（" + e.remoteIp + "），且进程本身可疑");
            if (!v.reason.empty()) detail += "。" + v.reason;

            HANDLE hp = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                    FALSE, (DWORD)e.pid);
            bool killed = false;
            if (hp) {
                killed = (TerminateProcess(hp, 0) != 0);
                CloseHandle(hp);
            }
            if (killed) {
                SweepDerivativesFor(ent.imagePath, "net");
                detail += "。已自动终止该进程";
            }

            // ---- 落账四连（顺序固定：结果 → 行为链 → 归因 → 弹卡）----
            sf::AddFinding("网络", lv >= 3 ? "高" : "中",
                           "可疑程序外联", detail, ent.imagePath,
                           hitIp ? e.remoteIp : std::string(), 60);
            sf::EscalateInfected(200);

            trace::Record(trace::Kind::Process, sf::BaseName(ent.imagePath),
                          (hitIp ? "外联已知恶意服务器：" : "可疑外联：") + detail,
                          ent.imagePath, "", true, 200);

            SetLastAlertInfo("可疑程序已自动拦截",
                             "「" + sf::BaseName(ent.imagePath) + "」" + detail,
                             ent.imagePath);

            sf::NotifyAnomaly("infected", 200, "proc");
        } else if (lv == 1) {
            // 旁证级：只记录不处置，避免误伤正常软件的非常规端口
            sf::AddFinding("网络", "中", "可疑外联",
                           "「" + sf::BaseName(ent.imagePath) + "」连接 " + e.remoteIp +
                           ":" + std::to_string(e.remotePort), ent.imagePath,
                           e.remoteIp, 30);
        }
    });

    // 监视线程：定期汇报运行状况 + 响应停止。
    // ⚠️ netwatch::Start 内部已起两个线程（ProcessTrace + 消费），
    //    本函数只负责守着停止信号并做健康检查，不做采集。
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        if (!netwatch::IsRunning()) break;   // 采集层自己退了（权限/会话问题）→ 收工
        if (!netwatch::IsHealthy(120000)) {
            netwatch::Stats s = netwatch::GetStats();
            LogDbg("[netwatch] 采集层静默超 2 分钟（recv=" + std::to_string(s.received) +
                   " drop=" + std::to_string(s.dropped) +
                   " parseFail=" + std::to_string(s.parseFail) + "）");
        }
    }
    netwatch::Stop();
    LogDbg("[netwatch] 网络外联监听线程已退出");
}

// ---------------------------------------------------------------------------
//  进程资源监控线程（第八个实时防护事件源，2026-10-03）
// ---------------------------------------------------------------------------
//  定位：挖矿检测的**最后一道兜底**，也是本轮唯一「此前完全不存在」的检测面。
//
//  ★ 为什么必须有（虚拟机真样本实测：挖矿 CPU 100% 烧了一整轮、主防零告警）：
//    那次断链有四环，本线程补的是第四环：
//      ① 命令行在 Win10 上读不到（PEB 时序）⇒ `stratum+tcp`/`xmrig` 规则全落空
//      ② `NetWatch` 里 `if (!hitIp && !hitPort) return;`
//         ⇒ 矿池地址不在 13 条 C2 IP 里 ⇒ 连接事件当场丢弃、连日志都不打
//      ③ `netwatch::IsHealthy` 的 `if (last == 0) return true;`
//         ⇒ 从未收到事件 = 「健康」，故障被完全掩盖（铁律 24 同族，本轮已修）
//      ④ ★ 全工程无进程 CPU 监控 —— 而挖矿的 CPU 高占用是**换不掉**的特征
//
//  ★ 为什么 CPU 比外联更稳：攻击者可以换矿池、改端口、走 HTTPS 隧道（让 ①②③
//    全部失效），但挖矿的本质是**持续做哈希运算** ⇒ CPU 必然长期占用。
//    正规沙软（西瓜 / PYAS）都有资源阈值规则，这是行业标准做法。
//
//  判据与纪律（详见 resmon.cpp）：
//    · 用「持续占用」而非「瞬时峰值」区分（正常高负载是突发，挖矿是持续）
//    · **高 CPU 只是旁证**，必须与进程自身可疑判定叠加才处置 —— 单靠 CPU 就终止
//      会误杀编译器/压缩软件/Defender 全盘扫（这些在 resmon.cpp 的白名单里）
//    · 单核机器直接跳过判定（一个进程吃满 100% 在单核上是常态）
static void ResMonWatch() {
    resmon::Start();
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        if (!resmon::IsRunning()) break;   // 监控层自己退了 → 收工
    }
      resmon::Stop();
      LogDbg("[resmon] 进程资源监控线程已退出");
  }

  // -----------------------------------------------------------------------
  //  能力看门狗线程（2026-10-03，C1）
  // -----------------------------------------------------------------------
  //  为什么必须有：今天在 Win10 单核虚拟机上实测到 `resmon` 因单核门槛
  //  **整条跳过**（日志明写「跳过 CPU 占用判定」），而同期日志一切正常
  //  —— 线程在跑、周期统计每分钟都在打、零报错。**从日志完全看不出它没在工作。**
  //  同族还有 netwatch「从未收到 = 健康」、命令行读空被映像路径顶替。
  //
  //  它本身不检测任何东西，只回答一个问题：**八路事件源现在各是什么状态、
  //  有哪几路在降级或停摆。** 把「拿不到」从隐含变成显式（铁律 24/46）。
  static void GuardCheckWatch() {
      guardcheck::Start();
      while (!g_stop.load()) {
          if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
      }
      guardcheck::Stop();
  }

// ---------------------------------------------------------------------------
//  文件 / 注册表写操作采集线程（第六个实时防护事件源，2026-09-25）
// ---------------------------------------------------------------------------
//  定位：补齐「落地 → 改写 → 自启」链条中间那一段。
//  前五个事件源只能看到「目录里出现了一个新文件」（落地捕获，靠回滚引擎的
//  写前钩子）与「进程起来了」（etwproc）。而在这两者之间，恶意程序真正做的
//  事是：把载荷改名、删掉原始下载文件、把配置/持久化写进 %APPDATA% 或注册表
//  —— 这一段此前完全没有遥测。
//
//  ★ 本线程**只采集，不处置**（V1 定稿）：
//    新增一路高频事件源的同时新增自动终止逻辑，误报风险会成倍放大，而误报
//    是本产品最大的质量红线。采集到的数据先落环形缓冲 + 外发 sink，处置判断
//    留给后续的行为模型评分（docs/behavior-ml-plan.md 阶段 4）与上层决策。
//    这也是把"订阅补全"和"新增拦截"两件事分开做、分开验证的原因。
//
//  能力边界（写卡片文案时必须守住）：ETW 是**事后通知**，我们看到 id=30 时
//  文件已经建好了。本线程不提供任何"已阻止写入"的能力。
static void IoWatch() {
    // sink 只做一件事：把事件写进调试日志（**限量**，否则高频事件会把
    // guard.log 冲垮）。常态查询走 iowatchq 命令读环形缓冲，不读日志。
    //
    // ⚠️ 这个 sink 运行在 iowatch 的消费线程上，**不得做重活**。
    //    遥测日志用**滚动限流**（每秒最多 1 条）而非「只打前 40 条」：
    //    全局限额在服务跑一会儿后就永久耗尽，之后事件流完全不可观测——
    //    2026-09-26 排查「浏览器下载零事件」时想看 ETW 事件流已无从看起。
    static std::atomic<ULONGLONG> lastTelemMs{ 0 };
    iowatch::Start([](const iowatch::IoEvent& e) {
        // ★ ETW 全盘落地哨兵（2026-09-26，银泊提议）：文件新建/改名 → 落地捕获链。
        //   此前落地捕获只挂 ReadDirectoryChangesW 的目录清单，C:\ 自建目录等
        //   位置是盲区（落到那里的云库样本永远进不了隔离链）。ETW 天然全盘，
        //   直接把这一面补掉。NotifyExternalLanded 是纯内存过滤 + 入队（真正的
        //   磁盘判定由 rollback 的重探队列在自己的监视线程里做），符合本 sink
        //   「不得做重活」的约束。必须先于下面的遥测日志限流分支执行。
        //
        // ★★★ 2026-10-02 严重误报事故修复 —— 这条判据曾经是整场事故的闸门失守点
        //   旧代码只判 `kind == Created`，而 iowatch 当年把 **EID 12（打开/创建）**
        //   也归成了 Created → 于是**全系统每一次文件打开**都在这里被当成「刚落地」，
        //   送进重探队列，1.5 秒后被判成落地载荷 → 右腿送检 → 锁住原件。
        //   2026-10-02 16:39 / 16:45 两批共 12 条封锁全部由此而来，被锁的是
        //   cmd.exe / conhost.exe / sc.exe / powershell.exe / dsregcmd.exe / msra.exe
        //   / TieringEngineService.exe / refsdedupsvc.exe（微软正版组件，只是被打开），
        //   以及银泊桌面上数月前就存在的 OneMail.exe / OneMail_Manager.exe 与
        //   PortableGit 的 grep.exe。顺带把沙箱每小时 12 次的送检额度全数烧光。
        //   修法分三层，缺一不可：
        //     ① iowatch.cpp：EID 12 改归 Kind::Opened（语义层根治）；
        //     ② iowatch.cpp：EID 10（NameCreate）**同样改归 Opened** —— 这是事故的
        //        第二入口，2026-10-02 17:42 那批「落地初筛命中（1级）」就是它造成的。
        //        旧注释把 EID 10 误读成"新建文件"，真实语义是"把名字关联到
        //        FILE_OBJECT"，**系统只要读一下存量文件就会发**（与 EID 12 是同一次
        //        打开操作的前后两拍）。更正后，store.exe / mspaint.exe / GetHelp.exe /
        //        olk.exe / regsvr32.exe 这批被系统索引/扫描**读**到的老文件才不再进落地链。
        //     ③ 本行：再加一道 EID 显式硬拦 —— 即使将来有人把分类改回去，
        //        「EID 12 / EID 10 永不进落地链」这条不变量依然成立。
        //       （belt-and-braces：这类事故的代价是封锁用户自己的文件，不能只靠一处。）
        if (!e.registry && e.eid != 12 && e.eid != 10 && e.kind != iowatch::Kind::Opened &&
            (e.kind == iowatch::Kind::Created || e.kind == iowatch::Kind::Renamed)) {
            rb::NotifyExternalLanded(e.path);
        }
        // 遥测滚动限流：每秒最多 1 条（ CAS 定速），事件流长期可观测且不刷爆日志
        const ULONGLONG nowT = GetTickCount64();
        ULONGLONG prevT = lastTelemMs.load();
        if (nowT - prevT < 1000 || !lastTelemMs.compare_exchange_strong(prevT, nowT)) return;
        const char* what = "?";
        switch (e.kind) {
            case iowatch::Kind::Created: what = "创建"; break;
            case iowatch::Kind::Renamed: what = "改名"; break;
            case iowatch::Kind::Deleted: what = "删除"; break;
            case iowatch::Kind::Opened:  what = "打开"; break;   // EID 12：纯遥测，非落地
            default:                     what = "其它"; break;
        }
        LogDbg(std::string("[iowatch] 事件流 ") + (e.registry ? "注册表" : "文件") +
               " " + what +
               " pid=" + std::to_string(e.pid) +
               (e.procName.empty() ? "" : (" 进程=" + sf::BaseName(e.procName))) +
               " EID=" + std::to_string((unsigned)e.eid) +
               " 路径=" + e.path +
               (e.valueName.empty() ? "" : (" 值=" + e.valueName)));
    });

    // 监视线程：守着停止信号 + 健康检查（与 NetWatch 同构）。
    // ⚠️ 本模块**没有 WMI 兜底**（文件写操作没有等价的 WMI 事件源），
    //    ETW 订阅失败就只能是"这一路不可用"，靠日志显式暴露，不静默。
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        if (!iowatch::IsRunning()) break;      // 采集层自己退了（权限/会话问题）→ 收工

        // ★ 2026-10-02（#618）：每 60 秒一行统计 —— 修好 FindProp 后**效果可验证**：
        //   修复前 delivered 几乎全是 EID=12 兜底、注册表 recvReg 恒 0；
        //   修复后 recvReg 应显著上升、parseFail 应骤降。没有这行，修复无从证实。
        {
            static std::atomic<ULONGLONG> s_lastStatsMs{ 0 };
            const ULONGLONG nowS = GetTickCount64();
            ULONGLONG prevS = s_lastStatsMs.load();
            if (nowS - prevS >= 60000 && s_lastStatsMs.compare_exchange_strong(prevS, nowS)) {
                iowatch::Stats s = iowatch::GetStats();
                LogDbg("[iowatch] 60s 统计 收文件=" + std::to_string(s.receivedFile) +
                       " 收注册表=" + std::to_string(s.receivedReg) +
                       " 外发=" + std::to_string(s.delivered) +
                       " 解析失败=" + std::to_string(s.parseFail) +
                       " 丢队列=" + std::to_string(s.dropped) +
                       " 自滤=" + std::to_string(s.filteredSelf) +
                       " 噪滤=" + std::to_string(s.filteredNoise) +
                       " 去重=" + std::to_string(s.deduped));
            }
        }

        if (!iowatch::IsHealthy(120000)) {
            iowatch::Stats s = iowatch::GetStats();
            LogDbg("[iowatch] 采集层静默超 2 分钟（文件=" + std::to_string(s.receivedFile) +
                   " 注册表=" + std::to_string(s.receivedReg) +
                   " 外发=" + std::to_string(s.delivered) +
                   " 丢队列=" + std::to_string(s.dropped) +
                   " 解析失败=" + std::to_string(s.parseFail) + "）");
        }
    }
    iowatch::Stop();
    LogDbg("[iowatch] 文件/注册表事件采集线程已退出");
}

// 跨进程注入 / 内存加载采集线程（第七个事件源，2026-09-30）
//
// 与 IoWatch 同构：sink 在 auditapi 的消费线程上调用（不得做重活）。
// 关键取舍：只对**真正有注入含义**的事件做进程台账 join + 评分层加权
//   · id=4  NtSetContextThread          —— 铁证注入
//   · id=5 NtOpenProcess 且 access mask 含
//           PROCESS_CREATE_THREAD(0x2) && (PROCESS_VM_OPERATION(0x8)|PROCESS_VM_WRITE(0x20))
//   · id=6 NtOpenThread  且 access mask 含
//           THREAD_SUSPEND_RESUME(0x2) && (THREAD_SET_CONTEXT(0x10)|THREAD_GET_CONTEXT(0x8))
//           —— 两者均为经典注入 / 线程执行劫持的前兆组合
//          ★ 注意：PROCESS_ 与 THREAD_ 是**两套不同的位定义**，必须按 op 区分（见下）。
// 其余事件（跨进程终止 / 驱动回调注册 / 符号链接）只记录、不判定，避免把一切
// 合法 OpenProcess 误判，也避免对高频 OpenProcess 做 MakeEntityOfPid（读远程命令行）的昂贵操作。
// ── 告警取证用的小工具（2026-10-02 补）──────────────────────────────────────
//  ★ 为什么告警行必须打 op / eid / mask / ret：
//    2026-10-02 日志里反复出现这样一条：
//      [auditapi] 注入类操作 → 可疑(level=1 score=45
//                 src=26560(SilverFoxGuardSvc.exe) tgt=28616(svchost.exe))
//    但**全树清单证明我方不具备产生它的能力**：
//      · 所有 OpenProcess 调用点的掩码都不含 CREATE_THREAD(0x2)，
//        也不含 VM_OPERATION(0x8) / VM_WRITE(0x20)；
//      · OpenThread / SuspendThread / GetThreadContext / MiniDumpWriteDump 全树 0 命中。
//    于是只剩两种可能：① 归属解析错（src 并不是真实调用方）；② 掩码解析错。
//    而原告警行**这两样都没打** —— 连"是 4/5/6 里的哪一个事件"都看不出 →
//    无法定性，只能停在猜测上。补上这几个字段后，一次复现即可结案。
//  ★ op/eid 是原始事实；掩码用 hasAccess 区分「真的是 0」与「压根没解析到」，
//    两者混为一谈会让"误判来源"永远查不出来。
static const char* ApiOpName(sf::auditapi::ApiOp op) {
    switch (op) {
        case sf::auditapi::ApiOp::SetContextThread:  return "SetContextThread";
        case sf::auditapi::ApiOp::OpenProcess:       return "OpenProcess";
        case sf::auditapi::ApiOp::OpenThread:        return "OpenThread";
        case sf::auditapi::ApiOp::TerminateProcess:  return "TerminateProcess";
        case sf::auditapi::ApiOp::LoadImageCallback: return "LoadImageCb";
        case sf::auditapi::ApiOp::CreateSymlink:     return "CreateSymlink";
        default:                                     return "unknown";
    }
}

// 32 位十六进制；valid=false 时显式写「未解析」而不是 0x00000000
static std::string Hex32(uint32_t v, bool valid) {
    if (!valid) return "未解析";
    char b[16];
    snprintf(b, sizeof(b), "0x%08X", (unsigned)v);
    return std::string(b);
}

// ★ 注入前兆的**分级计数**（EDR 闭环，2026-10-03）。
//   为什么要分级而不是「一律终止」：
//     · SetContextThread（线程执行劫持）是**铁证**——正常软件几乎不会去改别的线程上下文，
//       一次即可处置；
//     · OpenProcess/OpenThread 带注入前兆组合只是**能力申请**，单次可能是合法软件
//       （调试器、杀软、备份工具都干这事）⇒ 必须同一源进程在窗口内**反复尝试**才处置。
//   窗口取 10 分钟：既能覆盖「注入器连续试探多步」的典型模式，
//   又不会让偶发一次的合法进程在很久之后被误杀。
static unsigned& InjCountOf(unsigned long pid) {
    static std::mutex m;
    static std::map<unsigned long, std::pair<unsigned long long, unsigned>> tbl;  // pid -> (首个计数的时间戳, 次数)
    std::lock_guard<std::mutex> lk(m);
    const unsigned long long now = GetTickCount64();
    auto it = tbl.find(pid);
    if (it == tbl.end()) {
        tbl[pid] = { now, 1 };
        return tbl[pid].second;
    }
    if (now - it->second.first > 10ull * 60 * 1000) {   // 窗口过期，重置
        it->second.first = now;
        it->second.second = 0;
    }
    it->second.second++;
    // ★ 顺带做容量上限：进程表不能无限增长（铁律 28：随机会话不回收 ⇒ 累积泄漏）
    if (tbl.size() > 4096) {
        for (auto i = tbl.begin(); i != tbl.end(); ) {
            if (now - i->second.first > 30ull * 60 * 1000) i = tbl.erase(i); else ++i;
        }
    }
    return it->second.second;
}

// ★★ 2026-10-03 更新（EDR 闭环第一期）：本线程**已接上自动终止链路**，
//   但走的是**分级处置**而非一律终止 —— 详见 sink 里 InjCountOf 上方的说明。
//   原注释「自动终止链路暂未接（误报比漏报更致命）」保留为决策依据：
//   顾虑是真实的（2026-10-02 我方曾被自己的产品报「注入」且至今未归因闭环），
//   所以处置门槛按证据强度分级：铁证一次即处置，前兆需窗口内累计 3 次。
static void ApiWatch() {
    // ── 遥测：**分类汇总**取代旧版「每秒 1 条事件流原始行」──
    //   旧实现无条件每秒刷一条（本机实测 ~8.6 万行/天，把日志淹掉）。这里改为：
    //     · 常规事件**逐条不记**（只计数）；
    //     · 命中注入前兆 → 计入 cInjCap，判到 level>=1 才单条告警（本就稀有）；
    //     · 每 5 分钟输出一行分类汇总（且期间确有事件），既保可观测又不刷屏。
    //   ⚠️ 消费线程**单线程**调用本 sink（auditapi ConsumerLoop）→ 计数无需原子。
    static ULONGLONG lastTelemMs = 0;
    static uint64_t cSetCtx = 0, cOpenProc = 0, cOpenThread = 0;
    static uint64_t cTerm = 0, cLoadCb = 0, cSymlink = 0, cOther = 0;
    static uint64_t cInjCap = 0;   // 命中注入/劫持前兆组合、已进判定的条数
    static uint64_t cAlerts = 0;   // 其中判到 level>=1 的条数
    // ★ 采集层丢队列的**窗口增量**（2026-10-02 补）：
    //   auditapistat 实测 received=2365万 / delivered=1161万 / dropped=1204万
    //   —— **51% 的事件因队列满被静默丢弃**，而 `healthy` 仍报 true。
    //   根因是 IsHealthy 只看"最近有没有事件"，看不出"丢了一半"。
    //   本处只做**可观测**（打印窗口增量与丢弃率），**不改** IsHealthy 的判据 ——
    //   贸然把它接进看门狗会引发重建风暴，而重建期间只会丢得更狠。
    //   ★ 丢弃率 >0 意味着判定是**概率性**的：攻击者的一次注入事件有相当概率
    //     根本没被判定。这是与「日志静默丢行」同族的毛病，必须长期可见。
    static uint64_t lastRecv = 0, lastDrop = 0;
    static constexpr ULONGLONG kTelemEveryMs = 300000;   // 5 分钟

    sf::auditapi::Start([](const sf::auditapi::ApiEvent& e) {
        // ① 分类计数（供 5 分钟汇总）
        switch (e.op) {
            case sf::auditapi::ApiOp::SetContextThread:  ++cSetCtx;     break;
            case sf::auditapi::ApiOp::OpenProcess:       ++cOpenProc;   break;
            case sf::auditapi::ApiOp::OpenThread:        ++cOpenThread; break;
            case sf::auditapi::ApiOp::TerminateProcess:  ++cTerm;       break;
            case sf::auditapi::ApiOp::LoadImageCallback: ++cLoadCb;     break;
            case sf::auditapi::ApiOp::CreateSymlink:     ++cSymlink;    break;
            default:                                     ++cOther;      break;
        }

        // ② 注入前兆判定：★ OpenProcess 用 PROCESS_ 位，OpenThread 用 THREAD_ 位
        //    （两套位定义不同；旧版把 PROCESS_ 位套到 OpenThread 上属语义错位）
        bool setCtx   = (e.op == sf::auditapi::ApiOp::SetContextThread);
        bool openProc = (e.op == sf::auditapi::ApiOp::OpenProcess);
        bool openThr  = (e.op == sf::auditapi::ApiOp::OpenThread);
        bool injCapProc = openProc && (e.desiredAccess & 0x2) && (e.desiredAccess & (0x8 | 0x20));
        bool injCapThr  = openThr  && (e.desiredAccess & 0x2) && (e.desiredAccess & (0x8 | 0x10));

        // ★ 自身开自身（src==tgt）不是"跨进程"注入 —— 排除。实测每个进程（含
        //   PowerShell 自己）都会对自己 OpenProcess(ALL_ACCESS=0x1FFFFF)，而
        //   ALL_ACCESS 恰好含 0x2|0x8|0x20 → 不排除会把自开自误报成注入。
        bool selfOp = (e.tgtPid != 0 && e.tgtPid == e.srcPid);

        // ★ 仅对有注入含义的事件做台账 join + 评分层加权（MakeEntityOfPid 读远程命令行较重，必须门控）
        if (!selfOp && (setCtx || injCapProc || injCapThr)) {
            ++cInjCap;
            sf::InjHandleKind kind = openThr ? sf::InjHandleKind::Thread
                                             : sf::InjHandleKind::Process;
            sf::ProcVerdict v = sf::JudgeInjectionActivity(e.srcPid, e.tgtImage,
                                                          e.desiredAccess, setCtx, kind);
            if (v.level >= 1) {
                ++cAlerts;
                // ★ 取证字段前置：op/eid 是原始事实，mask/ret 是判定依据（理由见 ApiOpName 上方）
                std::string msg = "[auditapi] 注入类操作 → 可疑(op=" +
                    std::string(ApiOpName(e.op)) +
                    " eid=" + std::to_string(e.eid) +
                    " level=" + std::to_string(v.level) +
                    " score=" + std::to_string(v.score) +
                    " src=" + std::to_string(e.srcPid) +
                    (e.srcImage.empty() ? "" : ("(" + sf::BaseName(e.srcImage) + ")")) +
                    " tgt=" + std::to_string(e.tgtPid) +
                    (e.tgtImage.empty() ? "" : ("(" + sf::BaseName(e.tgtImage) + ")")) +
                    " tid=" + std::to_string(e.tgtTid) +
                    " mask=" + Hex32(e.desiredAccess, e.hasAccess) +
                    " ret=" + Hex32(e.returnCode, e.hasRet) +
                    ") " + v.reason;
                LogDbg(msg);

                // ★★★ 2026-10-03 EDR 闭环：把注入信号接到**处置链**（此前只打日志）。
                //   架构对比结论（三家正规沙软都是「判出即拦」，我们是「判出、不拦」）：
                //     西瓜/PYAS 靠内核回调在**操作发生前**同步阻断；
                //     我们是用户态 ETW 事后通知 ⇒ **不能阻断这次注入**（那是内核的活），
                //     但**可以立即处置源进程** —— 注入源是攻击者的工具，
                //     留着它下一次还会注入。这是用户态能拿到的最大价值。
                //
                //   ★ 为什么此前不做（不是忘了，是有真实顾虑）：
                //     ① `auditapi` 的事件**概率性丢失**（队列满就丢，日志里能看到 drop 率）
                //        ⇒ 判据必须能扛住误报；
                //     ② 我方曾被自己的产品报「注入」（2026-10-02，见上方 ApiOpName 注释），
                //        至今没结案 ⇒ 在归因没闭环前对注入一律自动终止，
                //        等于**用误杀换拦截**。
                //   ⇒ 本次采取**分级处置**，而不是「一律终止」：
                //     · SetContextThread（线程执行劫持，铁证）→ 源进程直接终止
                //     · OpenProcess/OpenThread 的注入前兆组合 → 累加计数，
                //       同一源进程在窗口内反复尝试才终止（单次可能是正常软件）
                //   这样既拿到拦截，又把误杀面压到最低。
                //
                //   ⚠️ 硬纪律：终止前必须过信誉门（浏览器/系统组件/自家进程一律放过），
                //      且**绝不终止自己**（src == 本进程）。
                //   ⚠️ 这里的控制流**不能用 continue** —— 外层是 lambda 里的 if 块而非循环，
                //      写成 continue 会 C2044。改用 if/else 显式收口。
                const bool srcAlive   = (e.srcPid != 0) && (e.srcPid != GetCurrentProcessId());
                if (!srcAlive) {
                    if (e.srcPid == GetCurrentProcessId()) {
                        LogDbg(msg + "  → 源进程是自己（本服务），不处置");
                    }
                } else {
                    sf::ProcEntity src = sf::MakeEntityOfPid(e.srcPid);
                    if (src.imagePath.empty()) {
                        // 进程已退出，无从处置（且不该凭 PID 猜）
                    } else if (sf::ProcReputable(src.imagePath)) {
                        LogDbg(msg + "  → 源进程信誉可信，仅记录不处置");
                    } else {
                    // 分级：铁证（SetContextThread）立即处置；前兆需累加
                    const bool isIronclad = setCtx;
                    unsigned& cnt = InjCountOf(e.srcPid);
                    if (isIronclad || ++cnt >= 3) {
                        if (isIronclad) cnt = 100;   // 铁证一次即达标
                        const char* why = isIronclad
                            ? "跨进程线程执行劫持（SetContextThread，铁证）"
                            : "反复尝试跨进程注入（窗口内累计多次注入前兆操作）";
                        std::string det = std::string("检测到") + why + "：进程 " +
                                         sf::BaseName(src.imagePath) + "（pid=" +
                                         std::to_string(e.srcPid) + "）试图对 " +
                                         sf::BaseName(e.tgtImage) + "（pid=" +
                                         std::to_string(e.tgtPid) + "）" +
                                         std::string(isIronclad ? "实施线程执行劫持"
                                                                  : "申请注入能力句柄") +
                                         "。已终止该源进程。";
                        LogDbg("[auditapi] ★注入处置 pid=" + std::to_string(e.srcPid) +
                               " " + src.imagePath + " → " + why);

                        HANDLE hp = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
                                                FALSE, (DWORD)e.srcPid);
                        bool killed = false;
                        DWORD err = ERROR_INVALID_PARAMETER;
                        if (hp) {
                            killed = (TerminateProcess(hp, 0) != 0);
                            if (!killed) err = GetLastError();
                            CloseHandle(hp);
                        }
                        if (killed) {
                            SweepDerivativesFor(src.imagePath, "inj");
                            det += "已自动终止";
                        } else {
                            // ★ 分开落日志：权限不足 vs 进程已退出，必须能区分
                            LogDbg("[auditapi] 终止注入源进程失败 pid=" + std::to_string(e.srcPid) +
                                   " 原因：" + (err == ERROR_ACCESS_DENIED
                                                ? "权限不足（检查 SeDebugPrivilege 是否已启用）"
                                                : "进程已退出或句柄打开失败"));
                        }

                        // ---- 落账四连（与其余事件源同一套契约，顺序固定）----
                        sf::AddFinding("注入", "高", "跨进程注入攻击", det,
                                       src.imagePath, std::string(), 60);
                        sf::EscalateInfected(200);
                        trace::Record(trace::Kind::Process, sf::BaseName(src.imagePath),
                                      "注入攻击：" + det, src.imagePath, e.tgtImage, true, 200);
                        SetLastAlertInfo("跨进程注入已自动拦截",
                                         "「" + sf::BaseName(src.imagePath) + "」" + det,
                                         src.imagePath);
                        sf::NotifyAnomaly("infected", 200, "high");
                    } else {
                        LogDbg(msg + "  → 注入前兆累计 " + std::to_string(cnt) + "/3（未达阈值，仅记录）");
                    }
                    }   // ← 收口：else（源进程不可信分支）
                }
            }
        }

        // ③ 5 分钟分类汇总（空转不写；静默由 IsHealthy 兜底，不靠这里报活）
        const ULONGLONG nowT = GetTickCount64();
        if (nowT - lastTelemMs >= kTelemEveryMs) {
            lastTelemMs = nowT;
            uint64_t tot = cSetCtx + cOpenProc + cOpenThread + cTerm + cLoadCb + cSymlink + cOther;
            if (tot > 0) {
                // ★ 采集层丢队列（窗口增量）—— 让"丢了一半"这件事在日志里长期可见，
                //   而不是只在 auditapistat 里躺着等人去看。
                sf::auditapi::Stats st = sf::auditapi::GetStats();
                uint64_t dRecv = (st.received >= lastRecv) ? (st.received - lastRecv) : 0;
                uint64_t dDrop = (st.dropped  >= lastDrop) ? (st.dropped  - lastDrop) : 0;
                lastRecv = st.received; lastDrop = st.dropped;
                std::string dropTxt;
                if (dRecv > 0) {
                    dropTxt = " 采到=" + std::to_string(dRecv) +
                              " 丢队列=" + std::to_string(dDrop) +
                              "（" + std::to_string(dDrop * 100 / dRecv) + "%）";
                }
                LogDbg("[auditapi] 5min汇总 事件=" + std::to_string(tot) +
                       "（OpenProcess=" + std::to_string(cOpenProc) +
                       " OpenThread=" + std::to_string(cOpenThread) +
                       " SetContext=" + std::to_string(cSetCtx) +
                       " Terminate=" + std::to_string(cTerm) +
                       " LoadCb=" + std::to_string(cLoadCb) +
                       " Symlink=" + std::to_string(cSymlink) +
                       " 其它=" + std::to_string(cOther) +
                       "）注入前兆=" + std::to_string(cInjCap) +
                       " 可疑告警=" + std::to_string(cAlerts) + dropTxt);
                cSetCtx = cOpenProc = cOpenThread = cTerm = cLoadCb = cSymlink = cOther = 0;
                cInjCap = 0; cAlerts = 0;
            }
        }

        sf::auditapi::PushRecent(e);
    });

    // 监视线程：守着停止信号 + 健康检查（与 IoWatch 同构）。
    // ⚠️ 本模块**没有 WMI 兜底**（Audit-API-Calls 无等价 WMI 事件源），
    //   ETW 订阅失败就只能是"这一路不可用"，靠日志显式暴露，不静默。
    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        if (!sf::auditapi::IsRunning()) break;      // 采集层自己退了（权限/会话问题）→ 收工
        if (!sf::auditapi::IsHealthy(120000)) {
            sf::auditapi::Stats s = sf::auditapi::GetStats();
            LogDbg("[auditapi] 采集层静默超 2 分钟（收到=" + std::to_string(s.received) +
                   " 外发=" + std::to_string(s.delivered) +
                   " 丢队列=" + std::to_string(s.dropped) +
                   " 解析失败=" + std::to_string(s.parseFail) + "）");
        }
    }
    sf::auditapi::Stop();
    LogDbg("[auditapi] 注入/跨进程事件采集线程已退出");
}

// WMI 订阅线程：异步回调（ExecNotificationQueryAsync），每 60 秒重建订阅以防断线；
// g_stop 置位时退出。
static void WmiProcessWatch() {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return;
    IWbemLocator* loc = nullptr;
    if (FAILED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**)&loc))) { CoUninitialize(); return; }
    IWbemServices* svc = nullptr;
    BSTR ns = SysAllocString(L"root\\cimv2");
    HRESULT ch = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &svc);
    SysFreeString(ns);
    if (FAILED(ch) || !svc) { loc->Release(); CoUninitialize(); return; }
    // 进程级 RPC 安全设置（可与本地服务通信）
    CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    while (!g_stop.load()) {
        WmiSink* sink = new WmiSink();
        BSTR wql = SysAllocString(L"SELECT * FROM __InstanceCreationEvent WITHIN 3 WHERE TargetInstance ISA 'Win32_Process'");
        BSTR path = SysAllocString(L"root\\cimv2");
        if (SUCCEEDED(svc->ExecNotificationQueryAsync(path, wql, WBEM_FLAG_SEND_STATUS, nullptr, sink))) {
            // 订阅成功：等 60 秒或服务停止，然后取消并重建
            WaitForSingleObject(g_stopEvent, 60000);
            svc->CancelAsyncCall(sink);
        }
        SysFreeString(path);
        SysFreeString(wql);
        sink->Release();   // 服务端已持引用；释放本地引用（Cancel 后 sink 自我回收）
        if (g_stop.load()) break;
        Sleep(3000);       // 重建间隔，避免 WMI 风暴
    }
    svc->Release(); loc->Release(); CoUninitialize();
}

// ---------------------------------------------------------------------------
//  实时事件订阅线程（2026-09-23 起：ETW 优先，WMI 兜底）
// ---------------------------------------------------------------------------
//  ETW（Microsoft-Windows-Kernel-Process id=1）毫秒级推送进程创建；
//  WMI（WITHIN 3）最多 3 秒延迟 + 60 秒重建盲窗。银泊指定：整体换 ETW，
//  只有 ETW 订阅失败（权限/会话上限/enable 失败）才回退旧 WMI 订阅。
//
// ★★ 2026-10-01 修复（P0）：**ETW 会话静默失效，烧掉 4 天实时防护。**
//   现象：`[etwproc] 采集统计 recv=0` 自 2026-09-27 18:03 起恒为 0（此前 18:02
//         还是 recv=6894），而每次重启都打印「进程创建事件采集已启动（ETW）」
//         —— `StartTraceW` / `EnableTraceEx2` / `OpenTraceW` **全部返回成功**。
//         即：会话句柄活着、provider 也 enable 成功，事件却一条都不来。
//   根因（架构缺陷，不是参数问题）：旧循环只判 `IsRunning()` —— 那是一个 bool
//         标志位，代表"我们**启动过**"，不代表"事件在**流动**"。模块里其实
//         早写好了 `IsHealthy()`，**却从来没有人调用它** → 代码层面
//         「会话已死」与「系统真安静」不可分 → 静默 4 天无人知。
//   ★ 这与本项目「日志会静默丢行」是**同一族毛病**：能观察到"没有输出"，
//     但代码自己不观察、不告警。
//   修法（三层）：
//     ① 每 30 秒一次**存活探针**（`etwproc::LivenessProbe`）—— 起一个无害子进程，
//        看 ETW 是否把它报到解析层。这是**唯一**能区分"死"与"安静"的判据：
//        静态桌面也可能十几秒没有新进程，但**我们起的探针必然产生一条事件**。
//     ② 连续 2 次探针失败 → 判定会话已死 → `Stop()` + `Start()` **重建**（普通实时模式；
//        会话名固定 + 启动清同名残留 + 撞 183 有限重试，见 2026-10-02 残留治理说明）。
//     ③ 重建累计 3 次仍失败 → **回退 WMI 订阅**（防护不出现空窗）。
//   ★★ 2026-10-02（铁律 35）：会话名改回**固定名**（原为随机后缀），并移除
//      `SYSTEM_LOGGER_MODE`（实测 18/18 无效 + 制造跨重启持久残留）。这两条都在
//      etwproc.cpp 内部实现，本函数不再需要任何模式开关调用。
//   ⚠️ 别把探针换成"看 recv 有没有涨"：那正是**旧代码失败的方式**。
static void ProcessWatch() {
    const int kMaxAttempt = 3;      // 1 次初始 + 最多 2 次重建
    const int kProbeEveryMs = 30000;
    // ★★ 2026-10-02：区分两种"采集层自己退了"。见下方 IsRunning() 分支与循环末尾。
    bool ptFailExhausted = false;

    for (int attempt = 1; attempt <= kMaxAttempt; ++attempt) {
        // ★★ 2026-10-02：**移除 SYSTEM_LOGGER_MODE 实验开关**。它实测启用 18 次全部无效，
        //   且 System Logger 是**跨重启存活的持久会话** = 会话残留的直接来源（铁律 35）。
        //   重建直接用普通实时模式；会话名固定 + 启动清同名残留 + 撞 183 有限重试
        //   已在 etwproc 内部处理（PurgeStaleSession + 3 次重试）。
        bool started = sf::etwproc::Start(OnEtwProcessEvent);
        if (!started) {
            LogDbg("[real-time] ETW 订阅不可用（第 " + std::to_string(attempt) + " 次尝试）");
            break;
        }

        LogDbg("[real-time] 事件订阅已切换到 ETW（WMI 转兜底待命）" +
               (attempt > 1 ? ("，本次为第 " + std::to_string(attempt) + " 次尝试") : std::string()));
        // ★ 每分钟打一次采集统计（2026-09-23 加）：
        //   「样本跑了但毫无反应」这类问题必须先分清是
        //     (a) 事件压根没进来（recv=0 → ETW 会话/provider 问题）
        //     (b) 进来了但判定/处置没生效（recv>0 delivered>0 却无命中日志）
        //   没有这行统计就只能靠猜。periodic 打印成本可忽略。
        ULONGLONG lastStatMs  = GetTickCount64();
        ULONGLONG lastProbeMs = GetTickCount64();
        int       probeFails  = 0;
        bool      sessionDead = false;

        while (!g_stop.load()) {
            if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
            if (!sf::etwproc::IsRunning()) {
                // ★★ 2026-10-02：采集层自己退出了 —— 分两种，必须区分：
                //   ① ProcessTrace 连续异常（它内部已经"强制重启一次"仍失败）
                //      → **必须回退 WMI**，防护不能留空窗；
                //   ② 其它（服务在停 / 上层主动 Stop）→ 正常收工，不回退。
                //   标志是"取走即清零"的一次性语义，不会重复消费。
                if (sf::etwproc::TakeWmiFallbackRequest()) {
                    ptFailExhausted = true;
                    LogDbg("[etwproc] 采集层因 ProcessTrace 连续异常而退出（已自动重启过一次）"
                           " → 不再重建，直接回退 WMI 订阅");
                }
                break;
            }
            const ULONGLONG nowTick = GetTickCount64();

            if (nowTick - lastStatMs >= 60000) {
                lastStatMs = nowTick;
                sf::etwproc::Stats st = sf::etwproc::GetStats();
                LogDbg("[etwproc] 采集统计 recv=" + std::to_string(st.received) +
                       " delivered=" + std::to_string(st.delivered) +
                       " parseFail=" + std::to_string(st.parseFail) +
                       " dropped=" + std::to_string(st.dropped) +
                       " ptErr=" + std::to_string(st.ptErrors) +
                       " ptRestart=" + std::to_string(st.ptRestarts));
            }

            // ★ 心跳看门狗：主动探针（不是被动看计数器 —— 见上方根因说明）
            if (nowTick - lastProbeMs >= (ULONGLONG)kProbeEveryMs) {
                lastProbeMs = nowTick;
                unsigned long probePid = 0;
                const bool alive = sf::etwproc::LivenessProbe(6000, &probePid);
                if (alive) {
                    if (probeFails > 0)
                        LogDbg("[etwproc] 存活探针恢复正常（探针进程 pid=" +
                               std::to_string(probePid) + " 已被 ETW 报到）");
                    probeFails = 0;
                } else {
                    ++probeFails;
                    LogDbg("[etwproc] ⚠ 存活探针失败（连续 " + std::to_string(probeFails) +
                           " 次）：已创建探针进程（pid=" + std::to_string(probePid) +
                           "），但 6 秒内 ETW 未报到它 → 会话疑似静默失效");
                    if (probeFails >= 2) { sessionDead = true; break; }
                }
            }
        }
        sf::etwproc::Stop();

        // ★ ProcessTrace 连续异常：采集层内部已经"强制重启会话一次"仍救不回来，
        //   再走下面的"重建"循环只是重复同一个动作 → 直接跳到 WMI 兜底。
        if (ptFailExhausted) break;
        if (!sessionDead) {
            LogDbg("[etwproc] ETW 事件订阅线程已退出");
            return;
        }
        LogDbg("[etwproc] 判定 ETW 会话已静默失效 → 重建订阅（第 " +
               std::to_string(attempt) + "/" + std::to_string(kMaxAttempt) + " 次）");
        Sleep(1500);   // 给 ControlTrace 的会话真正消失留时间（否则 StartTraceW 报 183 名字冲突）
    }

    // ETW 不可用 / 已耗尽重建次数 → 旧 WMI 订阅兜底（防护不出现空窗）
    if (g_stop.load()) { LogDbg("[etwproc] 服务正在停止，不再回退 WMI 订阅"); return; }
    LogDbg("[real-time] ETW 订阅不可用，回退旧 WMI 订阅");
    WmiProcessWatch();
}

// ---------------------------------------------------------------------------
//  注册表自启动项实时监控（第二个实时防护事件源）
// ---------------------------------------------------------------------------
//  为什么需要：WMI 进程创建监听只能看见「已经跑起来的进程」，而银狐的持久化
//  是在**写入自启动项**那一刻完成的 —— 此时进程可能早已退出，下次开机才复活。
//  实测（2026-09-19 日志）`[real-time]` 命中 0 次，正是只有单一事件源的后果。
//
//  覆盖范围（银狐最常用的持久化点）：
//    HKLM\...\Run / RunOnce / RunServices / RunServicesOnce / Policies\Explorer\Run
//    HKCU\...\Run / RunOnce / Policies\Explorer\Run
//    HKU\<SID>\...\Run（服务在 Session 0，HKCU 是 SYSTEM 的 hive，必须显式枚举用户 SID）
//
//  实现：**轮询快照比对**（每 5 秒读一次全部值的「名称→命令行」映射）而不是
//  RegNotifyChangeKeyValue —— 后者只能告警「有变化」、拿不到具体是哪个值变了，
//  还得重新枚举一遍才知道，实际开销反而更高；而这些键的值总数通常 < 100，
//  一次全量枚举在微秒级，5 秒轮询 CPU 占用可忽略。
//
//  判定：新增值交给 sf::JudgeCommandLine()（复用与前台扫描/注册表扫描完全相同的
//  行为判定核心，避免规则两套），命中即写 findings + 弹窗。
// ---------------------------------------------------------------------------
static void RegRunWatch() {
    // 目标键（相对根键的路径）
    static const char* kKeys[] = {
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };
    const size_t kKeysN = sizeof(kKeys) / sizeof(kKeys[0]);

    // 枚举一个键下的全部「值名 → 值内容」
    auto enumKey = [](HKEY root, const std::string& sub,
                      std::map<std::string, std::string>* out) {
        HKEY hk;
        if (RegOpenKeyExA(root, sub.c_str(), 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
        DWORD nVal = 0, nMax = 0;
        if (RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
                             &nVal, &nMax, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            std::vector<char> name(nMax + 2), data(8192);
            for (DWORD i = 0; i < nVal; ++i) {
                DWORD ns = (DWORD)name.size(), ds = (DWORD)data.size(), type = 0;
                if (RegEnumValueA(hk, i, name.data(), &ns, nullptr, &type,
                                  (LPBYTE)data.data(), &ds) != ERROR_SUCCESS) continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                std::string v(data.data(), ds ? ds - 1 : 0);   // 去掉结尾 NUL
                (*out)[std::string(name.data(), ns)] = v;
            }
        }
        RegCloseKey(hk);
    };

    // 收集全部受监控键（含 HKU\<SID>）
    // ⚠️ 必须显式捕获 [&]：lambda 内要用到 kKeys / kKeysN / enumKey，裸 [] 会报 C3493。
    auto collect = [&]() {
        std::map<std::string, std::string> all;   // "hive|path|valuename" -> 命令行
        for (size_t i = 0; i < kKeysN; ++i) {
            std::map<std::string, std::string> m;
            enumKey(HKEY_LOCAL_MACHINE, kKeys[i], &m);
            for (auto& kv : m) all["HKLM|" + std::string(kKeys[i]) + "|" + kv.first] = kv.second;
            m.clear();
            enumKey(HKEY_CURRENT_USER, kKeys[i], &m);
            for (auto& kv : m) all["HKCU|" + std::string(kKeys[i]) + "|" + kv.first] = kv.second;
        }
        // HKU\<SID>：服务在 Session 0，HKCU 是 SYSTEM hive，用户级自启必须显式枚举
        HKEY hkUsers;
        if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hkUsers) == ERROR_SUCCESS) {
            DWORD nSub = 0;
            RegQueryInfoKeyA(hkUsers, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                             nullptr, nullptr, nullptr, nullptr, nullptr);
            std::vector<char> nm(256);
            for (DWORD i = 0; i < nSub; ++i) {
                DWORD ns = (DWORD)nm.size();
                if (RegEnumKeyA(hkUsers, i, nm.data(), ns) != ERROR_SUCCESS) continue;
                std::string sid(nm.data());
                if (sid.find("S-1-5-21-") == std::string::npos) continue;   // 只看用户 SID
                for (size_t k = 0; k < kKeysN; ++k) {
                    std::map<std::string, std::string> m;
                    enumKey(HKEY_USERS, sid + "\\" + kKeys[k], &m);
                    for (auto& kv : m) all["HKU|" + sid + "\\" + kKeys[k] + "|" + kv.first] = kv.second;
                }
            }
            RegCloseKey(hkUsers);
        }
        return all;
    };

    // 首轮：建立基线，**不报警**（否则每次服务启动都会把全部既有自启动项报一遍）
    std::map<std::string, std::string> base = collect();
    LogDbg("[real-time] 注册表自启动基线已建立，共 " + std::to_string(base.size()) + " 项");

    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;
        std::map<std::string, std::string> cur = collect();
        for (const auto& kv : cur) {
            if (base.count(kv.first)) continue;   // 已有项 → 不是新增
            // ---- 新增自启动项：交给行为判定核心 ----
            const std::string& cmdline = kv.second;
            if (cmdline.empty()) continue;
            // 自排除：我方程序自身写入的项不报
            if (ci_contains(to_lower(cmdline), "silverfox")) continue;
            sf::ProcVerdict v;
            std::string imagePath;
            // 从命令行里抠出可执行路径（首个引号块或首个空格前的 token）
            if (!cmdline.empty() && cmdline[0] == '"') {
                size_t e = cmdline.find('"', 1);
                if (e != std::string::npos) imagePath = cmdline.substr(1, e - 1);
            }
            if (imagePath.empty()) {
                size_t sp = cmdline.find(' ');
                imagePath = (sp == std::string::npos) ? cmdline : cmdline.substr(0, sp);
            }
            try { v = sf::JudgeCommandLine(cmdline, imagePath); } catch (...) { continue; }
            if (v.level <= 0) continue;
            std::string sev = (v.level >= 2) ? "高" : "中";
            std::string removedId;   // 非空 = 已自动移除该启动项（撤销 token 后 8 位）
            if (v.level >= 2) {
                // 正经杀软模式（银泊 09-19）：可疑自启动项自动移除，原值在案可撤销写回
                removedId = RemoveAutorunValue(kv.first);
                boot::NoteSuspicion(0, imagePath);   // MBR 归因登记
                // ★ 衍生物清除联动：自启动项指向的载荷本体还在磁盘上，
                //   留着它下次手动执行照样中招（自启只是它的一种复活方式）
                if (!removedId.empty() && !imagePath.empty())
                    SweepDerivativesFor(imagePath, "regrun");
            }
            {
                std::lock_guard<std::mutex> lk(g_resultMutex);
                bool dup = false;
                for (const auto& f : g_result.findings) if (f.path == cmdline) { dup = true; break; }
                if (!dup) g_result.findings.push_back({"自启动", sev,
                    (v.level >= 2) ? "实时拦截可疑自启动项" : "实时发现新增自启动项（旁证）",
                    "注册表位置：" + kv.first + "\n命令行：" + cmdline + "\n判定依据：" + v.reason +
                    (removedId.empty() ? "" : "\n已自动移除该启动项（误判可点「撤销」写回）。"),
                    "", imagePath});
                if (v.level >= 2) { g_result.status = "infected"; g_result.score = 200; }
                g_result.timestamp = NowStr();
            }
            LogDbg("[real-time] " + sev + " [regrun] " + kv.first + " => " + cmdline +
                   (removedId.empty() ? "" : " [已移除]"));
            if (v.level >= 2) {
                if (!removedId.empty()) {
                    SetLastAlertInfo("可疑自启动项已自动拦截",
                                     "「" + (imagePath.empty() ? cmdline : sf::BaseName(imagePath)) +
                                     "」试图通过注册表自启动建立持久化，已自动移除该启动项。",
                                     imagePath.empty() ? "" : sf::BaseName(imagePath));
                    // ---- 行为链记录：自启是链条的"持久化"环节 ----
                    //  ★ extra 放注册表位置 —— 行为图展开这条时能直接告诉用户
                    //    "它把自己挂到了哪个键上"，这是取证的第一个落点。
                    {
                        trace::Event ev;
                        ev.kind    = trace::Kind::RegRun;
                        ev.subject = imagePath.empty() ? sf::BaseName(cmdline)
                                                       : sf::BaseName(imagePath);
                        ev.detail  = "试图通过注册表自启动建立持久化，已自动移除该启动项"
                                     + std::string("（判定依据：") + v.reason + "）";
                        ev.path    = imagePath;
                        ev.token   = "20" + removedId;
                        ev.extra   = kv.first;      // 注册表位置
                        ev.handled = true;
                        ev.score   = 200;
                        trace::Record(ev);
                    }
                    sf::NotifyAnomaly("infected", 200, "regrun", "20" + removedId, true);
                } else {
                    sf::NotifyAnomaly("infected", 200);   // 移除失败 → 普通告警卡
                }
            }
        }
        base.swap(cur);   // 更新基线（含被删除项，避免删后重建反复报）
    }
}

// ===========================================================================
//  持久化面全覆盖（2026-09-24）—— 第五个实时防护事件源
// ===========================================================================
//
// 【为什么必须加 · 虚拟机实战实证】
//   银狐从落地到载荷运行，主防全场只拦下"改 Defender 排除项"这一条。
//   根因之一是**持久化监视只覆盖注册表 Run 键**（见 RegRunWatch）。而银狐现在
//   更常用的四条持久化路径，一条都不碰 Run 键，于是完全静默：
//     ① 计划任务        —— schtasks / ITaskService COM / 直接写 System32\Tasks
//     ② 创建系统服务    —— sc create / CreateService
//     ③ WMI 永久事件订阅 —— __EventFilter + CommandLineEventConsumer
//     ④ IFEO 劫持       —— Image File Execution Options\<exe>\Debugger
//
// 【为什么用快照 diff，而不是 API 钩子】
//   纯用户态、无内核驱动/无 minifilter 的前提下，没有可靠的"注册表/计划任务写入"
//   回调：RegNotifyChangeKeyValue 只能盯**已打开**的键，而银狐恰恰是"新建子键"。
//   快照 diff 的代价是"最多 5 秒延迟"，收益是零依赖、零驱动、可独立回退 ——
//   与 RegRunWatch 同一套思路，保持全项目一致。
//
// 【★ 处置分级：这里必须克制，不能一律自动删】
//   新增计划任务/系统服务在**正常软件安装**里极其常见 —— Chrome / Steam /
//   显卡驱动 / 各种更新器都会做。若一律自动删除，用户会说"装个软件就被你删了"，
//   误删代价远高于漏报。所以四个面的处置强度刻意不同：
//     · 计划任务：lv>=2 → 备份 XML 后删除任务文件（可撤销，undo kind=40）
//     · 系统服务：只告警、**不自动处置**（删服务的恢复路径复杂，
//                 误删会让用户刚装的软件失效）——卡片如实说明"需你确认"
//     · WMI 订阅：只告警（正常软件几乎不建 WMI 订阅，所以哪怕只告警信噪比也高；
//                 不自动删是因为撤销要重建三个对象，风险大于收益）
//     · IFEO：命中即高危告警（正常软件不会给**别的**进程设 Debugger）
//
// 【自排除】命令行里含 silverfox 的项一律跳过 —— 我方程序自己写的计划任务不报。

// ---- 小工具：宽字符 → UTF-8 ----
static std::string PersistW2U(const wchar_t* w) {
    if (!w || !*w) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return std::string();
    std::string s((size_t)n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], n, nullptr, nullptr);
    return s;
}

// ---- 计划任务目录（%SystemRoot%\System32\Tasks）----
static std::string TasksRootDir() {
    char win[MAX_PATH] = { 0 };
    if (!GetWindowsDirectoryA(win, MAX_PATH)) return std::string();
    return std::string(win) + "\\System32\\Tasks";
}

// 计划任务备份目录
static std::string PersistBackupDir() {
    const std::string base = "C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryA(base.c_str(), nullptr);
    const std::string d = base + "\\persist_backup";
    CreateDirectoryA(d.c_str(), nullptr);
    return d;
}

// 递归枚举计划任务：map<相对名, 最后写入时间(Unix ms)>
// 用"相对名"作 key 而不是文件名 —— Tasks 目录有子目录（Microsoft\Windows\...），
// 只取文件名会让两个不同路径的同名任务互相覆盖，产生**静默漏报**。
static void CollectTasksRec(const std::string& root, const std::string& rel,
                            std::map<std::string, uint64_t>& out, int depth) {
    if (depth > 8) return;
    const std::string base = root + (rel.empty() ? "" : ("\\" + rel));
    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA((base + "\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        const std::string nm = fd.cFileName;
        if (nm == "." || nm == "..") continue;
        const std::string nrel = rel.empty() ? nm : (rel + "\\" + nm);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            CollectTasksRec(root, nrel, out, depth + 1);
        } else {
            ULARGE_INTEGER u{};
            u.LowPart  = fd.ftLastWriteTime.dwLowDateTime;
            u.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            out[nrel] = u.QuadPart / 10000ull;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

// 读文本文件并统一转 UTF-8（计划任务 XML 通常是 UTF-16LE + BOM）
static std::string ReadTextUtf8(const std::string& path, size_t maxBytes = 512 * 1024) {
    HANDLE h = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    DWORD sz = GetFileSize(h, nullptr);
    if (sz == INVALID_FILE_SIZE || sz == 0 || sz > maxBytes) { CloseHandle(h); return std::string(); }
    std::vector<char> buf((size_t)sz + 2, 0);
    DWORD got = 0;
    BOOL ok = ReadFile(h, buf.data(), sz, &got, nullptr);
    CloseHandle(h);
    if (!ok || got == 0) return std::string();
    const unsigned char* p = (const unsigned char*)buf.data();
    auto utf16 = [&](size_t offBytes) -> std::string {
        int wchars = (int)((got - offBytes) / 2);
        if (wchars <= 0) return std::string();
        int n = WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(buf.data() + offBytes),
                                    wchars, nullptr, 0, nullptr, nullptr);
        if (n <= 0) return std::string();
        std::string s((size_t)n, '\0');
        WideCharToMultiByte(CP_UTF8, 0, (const wchar_t*)(buf.data() + offBytes),
                            wchars, &s[0], n, nullptr, nullptr);
        return s;
    };
    if (got >= 2 && p[0] == 0xFF && p[1] == 0xFE) return utf16(2);          // UTF-16LE BOM
    if (got >= 3 && p[0] == 0xEF && p[1] == 0xBB && p[2] == 0xBF)           // UTF-8 BOM
        return std::string(buf.data() + 3, got - 3);
    // 无 BOM：奇数位大量 0x00 → 判为 UTF-16LE
    size_t zeros = 0, odd = 0;
    for (DWORD i = 1; i < got; i += 2) { ++odd; if (buf[i] == 0) ++zeros; }
    if (odd && zeros * 2 > odd) return utf16(0);
    return std::string(buf.data(), got);
}

// 从 UTF-8 文本里抠 XML 标签内容
static bool XmlTagText(const std::string& xml, const char* tag, std::string* out) {
    const std::string open  = std::string("<") + tag + ">";
    const std::string close = std::string("</") + tag + ">";
    size_t a = xml.find(open);
    if (a == std::string::npos) return false;
    a += open.size();
    size_t b = xml.find(close, a);
    if (b == std::string::npos) return false;
    if (out) *out = xml.substr(a, b - a);
    return true;
}

// ---- 系统服务：map<服务名, ImagePath> ----
static void CollectServices(std::map<std::string, std::string>& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services",
                      0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    DWORD nSub = 0;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                     nullptr, nullptr, nullptr, nullptr, nullptr);
    std::vector<char> nm(512);
    for (DWORD i = 0; i < nSub; ++i) {
        DWORD ns = (DWORD)nm.size();
        if (RegEnumKeyExA(hk, i, nm.data(), &ns, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
        const std::string sub(nm.data(), ns);
        std::string ip;
        HKEY hs = nullptr;
        if (RegOpenKeyExA(hk, sub.c_str(), 0, KEY_READ, &hs) == ERROR_SUCCESS) {
            char buf[4096] = { 0 };
            DWORD bs = sizeof(buf) - 1, type = 0;
            if (RegQueryValueExA(hs, "ImagePath", nullptr, &type, (LPBYTE)buf, &bs) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ) && bs > 0)
                ip.assign(buf, bs - 1);
            RegCloseKey(hs);
        }
        out[sub] = ip;
    }
    RegCloseKey(hk);
}

// ---- IFEO 劫持：只收**设了 Debugger** 的项（空键位是正常现象，不必看）----
static void CollectIfeo(std::map<std::string, std::string>& out) {
    static const char* kRoots[] = {
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    };
    for (const char* root : kRoots) {
        HKEY hk = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, root, 0, KEY_READ, &hk) != ERROR_SUCCESS) continue;
        DWORD nSub = 0;
        RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                         nullptr, nullptr, nullptr, nullptr, nullptr);
        std::vector<char> nm(512);
        for (DWORD i = 0; i < nSub; ++i) {
            DWORD ns = (DWORD)nm.size();
            if (RegEnumKeyExA(hk, i, nm.data(), &ns, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) continue;
            const std::string sub(nm.data(), ns);
            std::string dbg;
            HKEY hs = nullptr;
            if (RegOpenKeyExA(hk, sub.c_str(), 0, KEY_READ, &hs) == ERROR_SUCCESS) {
                char buf[4096] = { 0 };
                DWORD bs = sizeof(buf) - 1, type = 0;
                if (RegQueryValueExA(hs, "Debugger", nullptr, &type, (LPBYTE)buf, &bs) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ) && bs > 0)
                    dbg.assign(buf, bs - 1);
                RegCloseKey(hs);
            }
            if (!dbg.empty()) out[sub] = dbg;
        }
        RegCloseKey(hk);
    }
}

// ---- WMI 订阅：把 __EventFilter / *EventConsumer 的名字收成一张表 ----
static bool WmiQueryAll(IWbemServices* svc, const wchar_t* cls,
                        std::map<std::string, std::string>& out) {
    if (!svc) return false;
    BSTR lang = SysAllocString(L"WQL");
    const std::wstring w = std::wstring(L"SELECT * FROM ") + cls;
    BSTR q = SysAllocString(w.c_str());
    IEnumWbemClassObject* en = nullptr;
    HRESULT hr = svc->ExecQuery(lang, q,
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &en);
    SysFreeString(q);
    SysFreeString(lang);
    if (FAILED(hr) || !en) return false;
    IWbemClassObject* o = nullptr;
    ULONG ret = 0;
    while (en->Next(WBEM_INFINITE, 1, &o, &ret) == S_OK && ret == 1 && o) {
        auto get = [&](const wchar_t* prop) -> std::string {
            VARIANT v; VariantInit(&v);
            std::string r;
            if (SUCCEEDED(o->Get(prop, 0, &v, nullptr, nullptr)) &&
                v.vt == VT_BSTR && v.bstrVal) r = PersistW2U(v.bstrVal);
            VariantClear(&v);
            return r;
        };
        std::string name = get(L"Name");
        std::string extra = get(L"Query");
        const std::string cl = get(L"CommandLineTemplate");
        if (!cl.empty()) extra += std::string(extra.empty() ? "" : " | ") + cl;
        const std::string st = get(L"ScriptText");
        if (!st.empty()) extra += std::string(extra.empty() ? "" : " | ") + st.substr(0, 200);
        if (!name.empty()) out[name] = extra;
        o->Release();
        o = nullptr;
    }
    en->Release();
    return true;
}

// ---- 备份计划任务原文并删除任务文件。返回撤销 id（失败返回空串）----
static std::string RemoveScheduledTask(const std::string& relName) {
    const std::string root = TasksRootDir();
    if (root.empty()) return std::string();
    const std::string src = root + "\\" + relName;

    // ① 先备份**原始字节**（不解码 —— 还原必须一字不差）
    std::string safe = relName;
    for (auto& c : safe) if (c == '\\' || c == '/' || c == ':') c = '_';
    const std::string bak = PersistBackupDir() + "\\task_" + safe;
    if (!CopyFileA(src.c_str(), bak.c_str(), FALSE)) {
        LogDbg("[persist] 计划任务备份失败，为安全起见不删除：" + relName);
        return std::string();
    }
    // ② 删除任务文件（Task Scheduler 监视该目录，删除即生效）
    SetFileAttributesA(src.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (!DeleteFileA(src.c_str())) {
        LogDbg("[persist] 计划任务文件删除失败：" + relName);
        return std::string();
    }
    // ③ 登记撤销（kind=4：写回计划任务）
    const std::string id = NewUndoId();
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        UndoRec r;
        r.kind = 4;
        r.a = "task";
        r.b = relName;
        r.c = bak;
        g_undoMap[id] = r;
    }
    return id;
}

static void PersistWatch() {
    const std::string tasksRoot = TasksRootDir();
    // ---- 建立基线（**不报警**，否则每次服务启动都会把全部既有项报一遍）----
    std::map<std::string, uint64_t> baseTasks;
    if (!tasksRoot.empty()) CollectTasksRec(tasksRoot, "", baseTasks, 0);
    std::map<std::string, std::string> baseSvc, baseIfeo, baseWmi;
    CollectServices(baseSvc);
    CollectIfeo(baseIfeo);

    // WMI 会话（本线程独占；不可用不影响其它三个面）
    HRESULT ci = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    IWbemLocator* loc = nullptr;
    IWbemServices* wmi = nullptr;
    const bool comOk = SUCCEEDED(ci) || ci == RPC_E_CHANGED_MODE;
    if (comOk) {
        if (SUCCEEDED(CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                                       IID_IWbemLocator, (void**)&loc)) && loc) {
            BSTR ns = SysAllocString(L"root\\subscription");
            HRESULT ch = loc->ConnectServer(ns, nullptr, nullptr, nullptr, 0, nullptr, nullptr, &wmi);
            SysFreeString(ns);
            if (FAILED(ch) || !wmi) wmi = nullptr;
            if (wmi)
                CoSetProxyBlanket(wmi, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                                  RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE,
                                  nullptr, EOAC_NONE);
        }
    }
    if (wmi) {
        WmiQueryAll(wmi, L"__EventFilter", baseWmi);
        WmiQueryAll(wmi, L"CommandLineEventConsumer", baseWmi);
        WmiQueryAll(wmi, L"ActiveScriptEventConsumer", baseWmi);
    }
    LogDbg("[persist] 持久化基线已建立：计划任务 " + std::to_string(baseTasks.size()) +
           " / 服务 " + std::to_string(baseSvc.size()) +
           " / IFEO " + std::to_string(baseIfeo.size()) +
           " / WMI 订阅 " + std::to_string(baseWmi.size()) +
           (wmi ? "" : "（WMI 不可用 → 该面本次跳过）"));

    while (!g_stop.load()) {
        if (WaitForSingleObject(g_stopEvent, 5000) != WAIT_TIMEOUT) break;

        // =====================================================================
        // ① 计划任务：新增 → 取 XML 里的 Command/Arguments 判命令行
        //    附带：任务指向的可执行文件本身也过一次 QuickProbeExecutable ——
        //    银狐会写一个"指向刚落地载荷"的任务，这样两条判据互相印证。
        // =====================================================================
        if (!tasksRoot.empty()) {
            std::map<std::string, uint64_t> cur;
            CollectTasksRec(tasksRoot, "", cur, 0);
            for (const auto& kv : cur) {
                if (baseTasks.count(kv.first)) continue;         // 已有 → 不是新增
                const std::string full = tasksRoot + "\\" + kv.first;
                const std::string xml = ReadTextUtf8(full);
                std::string cmd, args;
                XmlTagText(xml, "Command", &cmd);
                XmlTagText(xml, "Arguments", &args);
                std::string line = cmd + (args.empty() ? "" : (" " + args));
                if (line.empty()) line = xml.substr(0, 300);
                if (ci_contains(line, "silverfox")) continue;    // 自排除
                sf::ProcVerdict v;
                try { v = sf::JudgeCommandLine(line, cmd); } catch (...) { continue; }
                int lv = v.level;
                if (lv == 0 && !cmd.empty()) {
                    int q = 0;
                    try { q = QuickProbeExecutable(cmd); } catch (...) { q = 0; }
                    // 指向"刚落地"的文件 → 再补一次内容判定（银狐的典型形态：
                    // 先释放载荷，再写一个指向它的计划任务）
                    if (q == 0 && IsFreshlyCreated(cmd, 1800)) {
                        try { q = DeepProbeExecutable(cmd, nullptr, nullptr); } catch (...) { q = 0; }
                    }
                    if (q > 0) lv = q;
                }
                if (lv <= 0) continue;

                const std::string sev = (lv >= 2) ? "高" : "中";
                std::string undoId;
                if (lv >= 2) undoId = RemoveScheduledTask(kv.first);
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    bool dup = false;
                    for (const auto& f : g_result.findings)
                        if (f.path == line) { dup = true; break; }
                    if (!dup) g_result.findings.push_back({ "计划任务", sev,
                        (lv >= 2) ? "实时拦截可疑计划任务" : "实时发现新增计划任务（旁证）",
                        "计划任务：" + kv.first + "\n命令行：" + line +
                        "\n判定依据：" + (v.reason.empty() ? "计划任务指向可疑可执行文件" : v.reason) +
                        (undoId.empty() ? "" : "\n已自动删除该任务（误判可点「撤销」写回）。"),
                        "", cmd });
                    if (lv >= 2) { g_result.status = "infected"; g_result.score = 200; }
                    g_result.timestamp = NowStr();
                }
                LogDbg("[persist] " + sev + " [task] " + kv.first + " => " + line +
                       (undoId.empty() ? "" : " [已删除]"));
                if (lv >= 2) {
                    if (!undoId.empty()) {
                        SetLastAlertInfo("可疑计划任务已自动拦截",
                            "「" + kv.first + "」被创建为计划任务并指向可疑程序，已自动删除该任务。",
                            BaseName(cmd));
                        trace::Event ev;
                        ev.kind    = trace::Kind::RegRun;   // 语义同属"持久化被建立"
                        ev.subject = kv.first;
                        ev.detail  = "试图通过计划任务建立持久化，已自动删除该任务（判定依据：" +
                                     (v.reason.empty() ? std::string("任务指向可疑可执行文件") : v.reason) + "）";
                        ev.path    = cmd;
                        ev.token   = "40" + undoId;
                        ev.extra   = "计划任务\\" + kv.first;
                        ev.handled = true;
                        ev.score   = 200;
                        trace::Record(ev);
                        sf::NotifyAnomaly("infected", 200, "regrun", "40" + undoId, true);
                    } else {
                        sf::NotifyAnomaly("infected", 200);
                    }
                } else {
                    sf::NotifyAnomaly("warning", 120);
                }
            }
            baseTasks.swap(cur);
        }

        // =====================================================================
        // ② 系统服务：新增 / ImagePath 被改写 → 判定。**只告警不处置**
        //    （正常软件安装就会建服务；自动删服务会让用户刚装的软件失效）
        // =====================================================================
        {
            std::map<std::string, std::string> cur;
            CollectServices(cur);
            for (const auto& kv : cur) {
                auto it = baseSvc.find(kv.first);
                const bool isNew = (it == baseSvc.end());
                const bool changed = (!isNew && it->second != kv.second);
                if (!isNew && !changed) continue;
                if (kv.second.empty()) continue;                 // 无 ImagePath（内核驱动等）→ 不做文本判定
                if (ci_contains(kv.second, "silverfox")) continue;
                // 服务名命中已知恶意项 → 直接高危
                sf::ProcVerdict v;
                try { v = sf::JudgeCommandLine(kv.second, kv.second); } catch (...) { continue; }
                int lv = v.level;
                // ★ 新增服务 + ImagePath 指向"刚落地"的文件 → 补两次文件判定。
                //   正常软件安装的服务指向的是自己安装目录里**已签名**的程序；
                //   而银狐的形态是"先释放服务二进制（无签名、刚落盘）再注册服务"。
                //   所以把重判定**只**挂在这道新鲜度门上，不对每个服务都跑。
                if (lv < 2 && !kv.second.empty() && IsFreshlyCreated(kv.second, 1800)) {
                    int q = 0;
                    try { q = QuickProbeExecutable(kv.second); } catch (...) { q = 0; }
                    if (q > lv) lv = q;
                    if (lv < 2) {
                        int dl = 0;
                        try { dl = DeepProbeExecutable(kv.second, nullptr, nullptr); } catch (...) { dl = 0; }
                        if (dl > lv) lv = dl;
                    }
                }
                if (lv <= 0) continue;
                const std::string sev = (lv >= 2) ? "高" : "中";
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    bool dup = false;
                    for (const auto& f : g_result.findings)
                        if (f.path == kv.second) { dup = true; break; }
                    if (!dup) g_result.findings.push_back({ "系统服务", sev,
                        (lv >= 2) ? "实时发现可疑系统服务" : "实时发现新增系统服务（旁证）",
                        std::string(isNew ? "新增服务：" : "服务指向被改写：") + kv.first +
                        "\nImagePath：" + kv.second +
                        "\n判定依据：" + (v.reason.empty() ? "服务指向可疑可执行文件" : v.reason) +
                        "\n（本类改动不自动处理 —— 正常软件安装也会注册服务，请你确认是否为自己操作）",
                        "", kv.second });
                    if (lv >= 2) { g_result.status = "infected"; g_result.score = 200; }
                    g_result.timestamp = NowStr();
                }
                LogDbg("[persist] " + sev + " [svc] " + kv.first + " => " + kv.second +
                       (isNew ? " [新增]" : " [指向被改]"));
                if (lv >= 2) sf::NotifyAnomaly("infected", 200);
                else         sf::NotifyAnomaly("warning", 120);
            }
            baseSvc.swap(cur);
        }

        // =====================================================================
        // ③ IFEO 劫持：新增了 Debugger 项 = 有程序被指定用别的程序启动
        //    正常软件**不会**给别的进程设 Debugger，所以命中即高危
        // =====================================================================
        {
            std::map<std::string, std::string> cur;
            CollectIfeo(cur);
            for (const auto& kv : cur) {
                if (baseIfeo.count(kv.first)) continue;
                if (ci_contains(kv.second, "silverfox")) continue;
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    bool dup = false;
                    for (const auto& f : g_result.findings)
                        if (f.path == kv.second) { dup = true; break; }
                    if (!dup) g_result.findings.push_back({ "IFEO劫持", "高",
                        "实时发现 IFEO 调试器劫持",
                        "被劫持目标：" + kv.first + "\nDebugger：" + kv.second +
                        "\n（Debugger 会在目标程序启动时被优先执行 —— 经典的持久化/提权手法）",
                        "", kv.second });
                    g_result.status = "infected";
                    g_result.score = 200;
                    g_result.timestamp = NowStr();
                }
                LogDbg("[persist] 高 [ifeo] " + kv.first + " => " + kv.second);
                sf::NotifyAnomaly("infected", 200);
            }
            baseIfeo.swap(cur);
        }

        // =====================================================================
        // ④ WMI 永久事件订阅：正常软件几乎不建，所以"新增"本身就值得报
        //    （只告警：撤销要重建 Filter/Consumer/Binding 三个对象，风险大于收益）
        // =====================================================================
        if (wmi) {
            std::map<std::string, std::string> cur;
            WmiQueryAll(wmi, L"__EventFilter", cur);
            WmiQueryAll(wmi, L"CommandLineEventConsumer", cur);
            WmiQueryAll(wmi, L"ActiveScriptEventConsumer", cur);
            for (const auto& kv : cur) {
                if (baseWmi.count(kv.first)) continue;
                if (ci_contains(kv.second, "silverfox")) continue;
                // 含脚本宿主 / 落地高发区路径 → 高危；否则旁证
                const bool evil =
                    ci_contains(kv.second, "powershell") || ci_contains(kv.second, "cmd.exe") ||
                    ci_contains(kv.second, "wscript")    || ci_contains(kv.second, "cscript") ||
                    ci_contains(kv.second, "mshta")      || ci_contains(kv.second, "rundll32") ||
                    ci_contains(kv.second, "\\temp\\")   || ci_contains(kv.second, "\\appdata\\") ||
                    ci_contains(kv.second, "\\programdata\\") || ci_contains(kv.second, "\\users\\public\\");
                const int lv = evil ? 2 : 1;
                const std::string sev = evil ? "高" : "中";
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    bool dup = false;
                    for (const auto& f : g_result.findings)
                        if (f.path == kv.first) { dup = true; break; }
                    if (!dup) g_result.findings.push_back({ "WMI订阅", sev,
                        evil ? "实时发现恶意 WMI 事件订阅" : "实时发现新增 WMI 事件订阅（旁证）",
                        "订阅名：" + kv.first + "\n定义：" + kv.second +
                        "\n（WMI 永久事件订阅在正常软件里极少出现，是 APT/银行木马的常用驻留手法）",
                        "", kv.first });
                    if (lv >= 2) { g_result.status = "infected"; g_result.score = 200; }
                    g_result.timestamp = NowStr();
                }
                LogDbg("[persist] " + sev + " [wmi] " + kv.first + " => " + kv.second);
                if (lv >= 2) sf::NotifyAnomaly("infected", 200);
                else         sf::NotifyAnomaly("warning", 120);
            }
            baseWmi.swap(cur);
        }
    }

    if (wmi) wmi->Release();
    if (loc) loc->Release();
    if (comOk) CoUninitialize();
    LogDbg("[persist] 持久化监视线程已退出");
}

// ---------------------------------------------------------------------------
//  SCM 失败自启联动（维护模式用）
// ---------------------------------------------------------------------------
// 维护模式的三层守护里，"服务崩溃后被 SCM 拉起"这一层由 SCM 的
// SERVICE_CONFIG_FAILURE_ACTIONS 决定。仅靠跳过 EnsureServiceRegistered 不够：
// 用户 taskkill 掉服务进程（非正常退出）时，SCM 仍会按策略把它拉回来。
// 故进入维护模式时把失败动作清零，退出/下次启动时恢复 3×60s 重启。
//
// 幂等设计：服务每次启动都按"当前维护状态"重新同步一次 → 即使上次维护模式
// 期间机器断电（来不及恢复配置），下次启动也会自动纠回，不会永久失去自保。
// ★★ 2026-09-27 修复：原实现**从不检查 ChangeServiceConfig2A 的返回值**，
//    日志无条件打「已关闭」→ 实测注册表里 FailureActions 仍是 cActions=3，
//    即"日志说关了、实际没关"，而这正是维护模式最容易失效的一层
//    （net stop 能停，但一 taskkill 就被 SCM 在 60s 内拉回）。
//    本次改造三点：
//      ① 统一用 **W 版** API（OpenServiceW / ChangeServiceConfig2W +
//         SERVICE_FAILURE_ACTIONSW），彻底消除 A/W 结构体混用隐患；
//      ② 检查返回值 + 记录 GetLastError()，失败时用合法 reset period 重试一次；
//      ③ **回读验证**（QueryServiceConfig2 读回 cActions）—— 本项目铁律：
//         别信返回值，要看副作用。只有回读到的 cActions 与预期一致才算生效。
// 返回：true = 回读确认已生效。
static bool SetSvcFailureActions(bool enable, DWORD* outChgErr, DWORD* outReadBack) {
    if (outChgErr)  *outChgErr  = 0;
    if (outReadBack) *outReadBack = 0xFFFFFFFFu;   // 哨兵：未能回读

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { if (outChgErr) *outChgErr = GetLastError(); return false; }
    SC_HANDLE svc = OpenServiceW(scm, SVC_NAME,
                                 SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG);
    if (!svc) { if (outChgErr) *outChgErr = GetLastError(); CloseServiceHandle(scm); return false; }

    SC_ACTION actions[3];
    for (auto& a : actions) { a.Delay = 60000; a.Type = SC_ACTION_RESTART; }
    SERVICE_FAILURE_ACTIONSW fa{};
    if (enable) {
        fa.cActions = 3; fa.lpsaActions = actions; fa.dwResetPeriod = 86400;
    } else {
        fa.cActions = 0; fa.lpsaActions = nullptr; fa.dwResetPeriod = 0;
    }

    BOOL ok  = ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    DWORD err = ok ? 0 : GetLastError();
    if (!ok) {
        // 备用：个别系统上 dwResetPeriod=0 被拒 → 换成合法周期再试一次
        fa.dwResetPeriod = 86400;
        ok  = ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
        err = ok ? 0 : GetLastError();
    }

    // ---- 回读验证：真正改动生效与否以此为准 ----
    DWORD need = 0;
    QueryServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, nullptr, 0, &need);
    if (need > 0) {
        std::vector<BYTE> buf(need);
        DWORD got = 0;
        if (QueryServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, buf.data(), need, &got)) {
            auto* q = reinterpret_cast<SERVICE_FAILURE_ACTIONSW*>(buf.data());
            if (outReadBack) *outReadBack = q->cActions;
        }
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    if (outChgErr) *outChgErr = err;

    DWORD want = enable ? 3u : 0u;
    bool live = (outReadBack && *outReadBack == want);
    return live;
}

static void ApplySvcFailureActions(bool enable) {
    DWORD err = 0, back = 0xFFFFFFFFu;
    bool live = SetSvcFailureActions(enable, &err, &back);
    // 日志必须带上"请求是否被 API 接受"与"回读到的真实值"，否则又是一条
    // "说自己成功、其实没生效"的假日志（这正是本次修复的起因）。
    LogDbg(std::string("[maint] SCM 失败自启 → ") + (enable ? "恢复（3×60s）" : "关闭") +
           "｜API=" + (err == 0 ? std::string("OK") : ("失败 err=" + std::to_string(err))) +
           "｜回读 cActions=" + (back == 0xFFFFFFFFu ? std::string("(读不到)") : std::to_string(back)) +
           "｜" + (live ? "已生效" : "★未生效"));
}

void GuardThread() {
    // ---- 恢复跨进程基线 ----
    // 关键：把上次进程记下的「已通知状态」读回来，避免服务重启后第一轮扫描
    // 把同一个状态又当成新变化弹一次窗（旧架构没做这件事，是"老是弹窗"的元凶之一）。
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        g_lastToastStatus = LoadToastBaseline();
        if (!g_lastToastStatus.empty())
            LogDbg("[check] 恢复已通知基线: " + g_lastToastStatus);
    }

    // ---- 启动自检 ----
    // 只跑【秒级轻量巡检】：进程 + 注入 + 注册表 + 服务 + 计划任务，纯内存/注册表读取，
    // 立即出初步结果并通知，用户开机后几秒内即可在扩展看到检测状态。
    // 全盘精扫**不在这里跑**——它要 40~90 秒，且是 GPU 崩溃的触发点；放在启动路径上
    // 会让"服务启动"与"重扫描"强耦合，一旦崩就进入重启循环。
    // ⚠️ 2026-09-19：此处原为 RunQuickScan()（含磁盘遍历），改为 RunGuardTick()（零遍历）。
    RunGuardTick();
    CheckAndNotify();
    // 维护模式（临时停止守护）下跳过自保重建：否则用户"删掉服务项"后，
    // 服务自己每轮又把它装回去，无法排障。见 common.h 的安全模型说明。
    if (!MaintenanceActive()) EnsureServiceRegistered();
    else LogDbg("[maint] 维护模式生效：启动时跳过 EnsureServiceRegistered");
    // 按当前维护状态同步 SCM 失败自启（幂等，见 ApplySvcFailureActions 注释）
    ApplySvcFailureActions(!MaintenanceActive());
    // 哈希基线只在安装时（DoInstall）写入一次，此处不重复写，
    // 避免被篡改的二进制在启动时自我重新基线化、绕过完整性校验。

    // ---- 分层调度 ----
    // 两个独立计时器：快扫高频（实时性）、全盘扫低频（完整性）。
    // 用 WaitForSingleObject 的毫秒超时做粗粒度调度，单轮扫描耗时不影响相位
    // （扫描结束时重置对应计时器，不做"补跑"，避免多轮积压）。
    const ULONGLONG startedAt = GetTickCount64();
    ULONGLONG lastQuick = startedAt;
    ULONGLONG lastFull  = startedAt;
    ULONGLONG lastGuard = startedAt;   // 自保复核（注册服务项 + ACL 加固）
    bool firstFullDone  = false;

    // 距上次全盘扫描已过多久？若已超过一个完整周期，说明本进程"欠"了一轮全盘扫
    // （服务停过、崩溃过、或机器关机），此时**不等**启动延迟，尽快补上。
    {
        long long last = LoadLastScanTime();
        if (last > 0) {
            auto nowT = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            long long elapsed = (long long)nowT - last;
            if (elapsed * 1000LL >= (long long)FULL_SCAN_INTERVAL_MS) {
                // 让 lastFull 往前推到"已经超期"，从而在首次循环立刻触发全盘扫
                ULONGLONG overdue = (ULONGLONG)(elapsed * 1000LL);
                lastFull = startedAt - (overdue > startedAt ? startedAt : overdue);
                LogDbg("[sched] 距上次全盘扫描 " + std::to_string(elapsed / 3600) +
                       " 小时（已超期），启动后立即补扫");
            }
        }
    }

    while (!g_stop.load()) {
        // 100ms 粒度的轻量等待，便于及时响应停止事件
        if (WaitForSingleObject(g_stopEvent, 100) != WAIT_TIMEOUT) break;
        const ULONGLONG now = GetTickCount64();

        // ---- 全盘精扫（低频；首轮延后到 FULL_SCAN_STARTUP_DELAY_MS）----
        const ULONGLONG fullDue = firstFullDone ? FULL_SCAN_INTERVAL_MS
                                                : FULL_SCAN_STARTUP_DELAY_MS;
        if (now - lastFull >= fullDue) {
            firstFullDone = true;
            lastFull = now;
            RunFullScan();
            CheckAndNotify();
            SaveLastScanTime();
            lastQuick = GetTickCount64();   // 全盘扫已覆盖快扫范围，重置快扫相位
            continue;
        }

        // ---- 轻量巡检（高频，零磁盘遍历）----
        // 2026-09-19 重构：原为 RunQuickScan()，它内部会调 ScanFiles 递归
        // Desktop/Downloads/Temp（预算最多 6 万文件）→ 每 3 分钟一轮缩水全盘，
        // 实测 fullscan 间隔退化为 4~6 分钟（上轮没跑完相位已到期）。
        // 改 RunGuardTick()：只读进程/注册表/服务/计划任务，秒级、CPU 与磁盘近零占用。
        if (now - lastQuick >= QUICK_SCAN_INTERVAL_MS) {
            lastQuick = now;
            RunGuardTick();
            CheckAndNotify();
            BootScanTick();   // MBR 兜底校验：监视线程意外退出时仍 ≤3 分钟必有人盯引导扇区
        }

        // ---- 自保复核（每 ~30 分钟）----
        if (now - lastGuard >= 30 * 60 * 1000) {
            lastGuard = now;
            // 维护模式下连 ACL 加固一起跳过：用户此时可能需要替换/调试程序文件，
            // 每 30 分钟把 ACL 收紧回去会让替换随机失败（"有时能换有时不能"最难查）。
            if (!MaintenanceActive()) {
                EnsureServiceRegistered();
                HardenFileAcl(GetExePath());
            }
            // ★ 每轮无条件重同步 SCM 失败自启（幂等）——这是**自动到期**的唯一恢复点：
            //   维护模式开了又到期时，服务进程一直没重启，仅在 GuardThread 启动时同步过
            //   一次（当时是"关闭"状态）。若此处不补，SCM 那 3×60s 崩溃自启会一直停用，
            //   直到下次服务重启才恢复 —— 即"守护悄悄少了一层却毫无提示"。
            ApplySvcFailureActions(!MaintenanceActive());
        }
    }
}

// ---------------------------------------------------------------------------
//  命名管道服务（与 NM 宿主通信，无 TCP 端口，银狐无法劫持）
//  支持：① 单连接多帧（宿主长连接，避免每次轮询都重连 → 不再反复拉起新程序）
//        ② 多客户端并发（nMaxInstances>1，避免 ERROR_PIPE_BUSY 导致扩展侧掉线）
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  维护模式调用方鉴权（cmd=maint 专用）
// ---------------------------------------------------------------------------
// 只允许【本程序安装目录树下的 SilverFoxGUI.exe】开启维护模式。
// ⚠️ 实际布局：服务 = <安装目录>\SilverFoxGuardSvc.exe，GUI = <安装目录>\gui\SilverFoxGUI.exe
//    —— GUI 在**子目录**里，所以目录不能用「相等」判定，必须用「同树」判定。
//    同树 = 目录等于安装目录，或 以「安装目录 + 路径分隔符」开头。
//    绝不能只写 _wcsnicmp(dir, instDir, len(instDir))：那会把
//    `...\SilverFoxGuardEvil\` 一并放进来（前缀相同但不同树）。
// 依据：安装目录 ACL 已由 HardenFileAcl 收紧为仅 SYSTEM/Administrators 可写，
// 恶意程序无法在该目录树里放一个同名 exe 冒充 GUI 来关掉自保。
// ⚠️ 关闭（action=off）刻意不加闸门 —— 关掉维护模式 = 恢复防护，是安全方向
//    的动作，被谁触发都无害；加闸门反而会在"GUI 打不开、用户急着恢复防护"时卡住。
//
// 注：不能用 AToW（它定义在本文件靠后的位置），此处用 GetModuleFileNameW 自取宽路径。
static bool CallerIsTrustedGui(HANDLE pipe) {
    ULONG pid = 0;
    if (!GetNamedPipeClientProcessId(pipe, &pid)) return false;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hp) return false;
    bool ok = false;
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD n = MAX_PATH;
    if (QueryFullProcessImageNameW(hp, 0, buf, &n) && n > 0) {
        std::wstring img(buf, n);
        size_t sl = img.find_last_of(L"\\/");
        std::wstring name = (sl == std::wstring::npos) ? img : img.substr(sl + 1);
        std::wstring dir  = (sl == std::wstring::npos) ? std::wstring() : img.substr(0, sl);
        // 安装目录 = 本服务 exe 所在目录
        wchar_t selfW[MAX_PATH] = { 0 };
        DWORD sn = GetModuleFileNameW(nullptr, selfW, MAX_PATH);
        std::wstring selfPath(selfW, sn > 0 ? sn : 0);
        size_t es = selfPath.find_last_of(L"\\/");
        std::wstring instDir = (es == std::wstring::npos) ? selfPath : selfPath.substr(0, es);
        // 同树判定（见上方注释）：相等，或以「安装目录\\」开头
        bool sameTree = false;
        if (!instDir.empty() && dir.size() >= instDir.size()) {
            if (dir.size() == instDir.size()) {
                sameTree = (_wcsicmp(dir.c_str(), instDir.c_str()) == 0);
            } else {
                sameTree = (_wcsnicmp(dir.c_str(), instDir.c_str(), instDir.size()) == 0 &&
                            (dir[instDir.size()] == L'\\' || dir[instDir.size()] == L'/'));
            }
        }
        if (_wcsicmp(name.c_str(), L"SilverFoxGUI.exe") == 0 && sameTree) {
            ok = true;
        } else {
            LogDbg("[maint] 拒绝不可信调用方: " + PersistW2U(img.c_str()));
        }
    }
    CloseHandle(hp);
    return ok;
}

void PipeServerThread() {
    SECURITY_ATTRIBUTES sa{ sizeof(sa) };
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFW;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr)) {
        return;
    }
    const int MAX_INSTANCES = 8;
    while (!g_stop.load()) {
        HANDLE h = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, MAX_INSTANCES, 8192, 8192, 0, &sa);
        if (h == INVALID_HANDLE_VALUE) { Sleep(500); continue; }
        OVERLAPPED ov{}; ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        ResetEvent(ov.hEvent);
        BOOL ok = ConnectNamedPipe(h, &ov);
        DWORD err = GetLastError();
        if (!ok && err == ERROR_IO_PENDING) {
            HANDLE ws[2] = { ov.hEvent, g_stopEvent };
            // ★ 2026-09-19 修复持续 err=233：等待超时（1s）时客户端可能恰在此刻连上
            //   （事件已触发但等待刚超时返回 WAIT_TIMEOUT），旧代码直接 CloseHandle 把
            //   带着连接的实例扔掉 → 客户端 WriteFile/ReadFile 立刻 233（管道关闭）。
            //   正解：超时后先 GetOverlappedResult(FALSE) 探测，已连接则照常派发。
            DWORD r = WaitForMultipleObjects(2, ws, FALSE, 1000);
            if (r == WAIT_OBJECT_0 + 1 || g_stop.load()) { CloseHandle(h); CloseHandle(ov.hEvent); break; }
            if (r != WAIT_OBJECT_0) {
                DWORD trp = 0;
                if (!GetOverlappedResult(h, &ov, &trp, FALSE)) {
                    CloseHandle(h); CloseHandle(ov.hEvent); continue;   // 真没人连，重开实例
                }
                // 已连接（探测成功）→ 落到下面派发线程
            } else {
                DWORD tr = 0; GetOverlappedResult(h, &ov, &tr, TRUE);
            }
        } else if (!(ok || err == ERROR_PIPE_CONNECTED)) {
            CloseHandle(h); CloseHandle(ov.hEvent); continue;
        }
        CloseHandle(ov.hEvent);
        // 每连接交给独立工作线程：在同一个长连接上循环处理多帧（status/rescan），
        // 主循环立刻回到 accept，从而支持并发与持久连接。
        std::thread([h]() {
            while (!g_stop.load()) {
                std::string req;
                if (!ReadFramed(h, req)) break;            // 客户端断开 → 退出本线程
                std::string cmd = JsonGetString(req, "cmd");

                // ---- ★ 主干分发：先查分体命令表（2026-09-22 主干式架构）----
                //  分体（mod_*.cpp）自带命令表，主干在这里统一找到它们。
                //  因此新增一条命令 = 写一个分体 + 在 modules_list.cpp 加一行清单，
                //  **不必**再改这条 if-else 链，也不必改 gui.cpp 的转发白名单。
                //  返回 false = 分体声明"这不是我的活" → 继续往下走既有分支。
                if (const sf::mod::CmdEntry* ce = sf::mod::FindCommand(cmd)) {
                    if (ce->run(h, req)) continue;
                }

                if (cmd == "probe") {
                    // 右键自定义查杀：单文件启发式判定（服务以 SYSTEM 执行，可读受保护文件）
                    std::string p = JsonGetString(req, "path");
                    if (p.empty()) { WriteFramed(h, "{\"cmd\":\"probe\",\"ok\":false,\"msg\":\"no path\"}"); continue; }
                    std::string verdict;
                    try { verdict = ScanTargetFile(p); }
                    catch (...) {
                        verdict = "{\"level\":0,\"score\":0,\"type\":\"ERR\",\"title\":\"查杀过程异常\",\"hits\":[]}";
                    }
                    // 平铺字段到顶层 + 原样抠出 hits 数组（极简 JSON 解析器取不了嵌套引号中的值）
                    {
                        std::string flat = "{\"cmd\":\"probe\",\"ok\":true,\"path\":" + JsonString(p);
                        flat += ",\"level\":" + std::to_string(JsonGetInt(verdict, "level"));
                        flat += ",\"score\":" + std::to_string(JsonGetInt(verdict, "score"));
                        flat += ",\"type\":\"" + JsonEscape(JsonGetString(verdict, "type")) + "\"";
                        flat += ",\"title\":\"" + JsonEscape(JsonGetString(verdict, "title")) + "\"";
                        size_t hb = verdict.find("\"hits\":[");
                        if (hb != std::string::npos) {
                            size_t ob = hb + 7; int depth = 0; size_t i = ob;
                            for (; i < verdict.size(); ++i) {
                                if (verdict[i] == '{' || verdict[i] == '[') ++depth;
                                else if (verdict[i] == '}' || verdict[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
                            }
                            flat += ",\"hits\":" + verdict.substr(ob, i - ob);
                        } else flat += ",\"hits\":[]";
                        flat += "}";
                        WriteFramed(h, flat);
                    }
                    continue;
                }
                if (cmd == "probeclean") {
                    std::string p = JsonGetString(req, "path");
                    if (p.empty()) { WriteFramed(h, "{\"cmd\":\"probeclean\",\"ok\":false,\"msg\":\"no path\"}"); continue; }
                    CleanReport cr = CleanFiles({ p });
                    WriteFramed(h, "{\"cmd\":\"probeclean\",\"ok\":true,\"path\":" + JsonString(p) + ",\"clean\":" + BuildCleanJson(cr) + "}");
                    continue;
                }
                // ---- 维护模式（临时停止守护）----
                // 用途：调试 / 排障时临时停掉三层自保（服务重建 / SCM 拉起 / NM 宿主自愈），
                //       否则"停不掉、删了又回来"，只能删整个安装目录 —— 那会把同目录下的
                //       沙箱等组件一起带走。安全模型见 common.h。
                // 响应必须带 cmd 字段（回包契约，避免"静默丢弃"被误判成半通故障）。
                if (cmd == "maint") {
                    std::string act = JsonGetString(req, "action");
                    if (act == "on") {
                        if (!CallerIsTrustedGui(h)) {
                            LogDbg("[maint] 拒绝开启：调用方非安装目录下的 SilverFoxGUI.exe");
                            WriteFramed(h, "{\"cmd\":\"maint\",\"ok\":false,\"msg\":\"not authorized\"}");
                            continue;
                        }
                        int ttl = JsonGetInt(req, "ttl");
                        bool okM = EnterMaintenance(ttl);
                        if (okM) ApplySvcFailureActions(false);
                        LogDbg(std::string("[maint] 经 GUI 开启维护模式 ttl=") + std::to_string(ttl) +
                               "min → " + (okM ? "成功" : "失败"));
                        WriteFramed(h, std::string("{\"cmd\":\"maint\",\"ok\":") + (okM ? "true" : "false") +
                                       ",\"data\":" + MaintenanceInfoJson() + "}");
                    } else if (act == "off") {
                        bool okM = ExitMaintenance();
                        if (okM) {
                            // ★ 立即恢复三层自保，不留空窗：
                            //   维护期间用户可能删过服务项，若不在此刻补装，就要等最多
                            //   30 分钟的 GuardThread 自保复核才会回来 —— 用户已经点了
                            //   "关闭"，却还在无自保状态跑半小时，这是最不该出现的状态。
                            EnsureServiceRegistered();
                            HardenFileAcl(GetExePath());
                            ApplySvcFailureActions(true);
                        }
                        LogDbg(std::string("[maint] 退出维护模式 → ") + (okM ? "成功（自保已即时恢复）" : "失败"));
                        WriteFramed(h, std::string("{\"cmd\":\"maint\",\"ok\":") + (okM ? "true" : "false") +
                                       ",\"data\":" + MaintenanceInfoJson() + "}");
                    } else {
                        // 无 action（或 action=status）：只查状态，前端用于刷新开关与倒计时
                        WriteFramed(h, std::string("{\"cmd\":\"maint\",\"ok\":true,\"data\":") +
                                       MaintenanceInfoJson() + "}");
                    }
                    continue;
                }
                // ---- ★ 衍生物清除干跑 / 白名单自检（2026-09-20 新增）----
                // derivdry：只枚举「若现在触发衍生物清除，会删哪些文件」，一个都不删。
                //   用于验收误删面（尤其确认反作弊目录零命中），也可在出事后取证。
                // whitest：路径白名单自检，输入 path 返回是否受保护（含命中的保护原因）。
                if (cmd == "derivdry") {
                    std::string p = JsonGetString(req, "path");
                    bool dry = JsonGetInt(req, "dry") == 1;
                    std::vector<std::string> seeds;
                    if (!p.empty()) seeds.push_back(p);
                    else {
                        // 未指定种子 → 用当前扫描结果里的可疑样本
                        std::lock_guard<std::mutex> lk(g_resultMutex);
                        for (const auto& f : g_result.findings)
                            if (QuickProbeExecutable(f.path) >= 1) seeds.push_back(f.path);
                    }
                    CleanReport rep;
                    int n = sf::SweepDerivatives(seeds, &rep, dry ? true : true);   // 本命令恒为干跑
                    std::string s = "{\"cmd\":\"derivdry\",\"ok\":true,\"mode\":\"dry\",\"seeds\":" +
                                    std::to_string((int)seeds.size()) + ",\"candidates\":" +
                                    std::to_string((int)rep.requested) + ",\"clean\":" + BuildCleanJson(rep) + "}";
                    WriteFramed(h, s);
                    continue;
                }
                if (cmd == "whitest") {
                    std::string p = JsonGetString(req, "path");
                    bool prot = sf::IsNeverCleanPath(p);
                    WriteFramed(h, "{\"cmd\":\"whitest\",\"ok\":true,\"path\":" + JsonString(p) +
                                   ",\"protected\":" + (prot ? "true" : "false") + "}");
                    continue;
                }
                if (cmd == "trustadd") {
                    // 登记用户信任目录（永不进入任何清除流程）
                    std::string p = JsonGetString(req, "path");
                    if (p.empty()) { WriteFramed(h, "{\"cmd\":\"trustadd\",\"ok\":false,\"msg\":\"no path\"}"); continue; }
                    sf::AddNeverCleanDir(p);
                    WriteFramed(h, "{\"cmd\":\"trustadd\",\"ok\":true,\"path\":" + JsonString(p) + "}");
                    continue;
                }
                std::string extra;                         // 附加字段（清除报告）
                if (cmd == "rollbackstatus") {
                    // 勒索回滚引擎运行态：快照数量/占用/累计回滚次数/最近触发原因。
                    // 扩展设置页用它在「勒索防护」卡片里展示真实数字（不吹牛、不隐藏）。
                    WriteFramed(h, "{\"cmd\":\"rollbackstatus\",\"ok\":true,\"data\":" + rb::StatusJson() + "}");
                    continue;
                }
                if (cmd == "rollbacklist") {
                    // 当前受保护（已持有快照）的文件清单，供 UI 展示"哪些文件有后悔药"
                    WriteFramed(h, "{\"cmd\":\"rollbacklist\",\"ok\":true,\"data\":" + rb::ListSnapshotsJson() + "}");
                    continue;
                }
                if (cmd == "rollbackdo") {
                    // 用户主动发起的回滚：把全部持有快照的文件恢复到快照状态。
                    // 这是一把双刃剑（会把用户正常保存的改动也退回去），
                    // 故扩展端必须二次确认后才允许调用。
                    std::string why = JsonGetString(req, "reason");
                    std::string rep = rb::ManualRollback(why);
                    WriteFramed(h, "{\"cmd\":\"rollbackdo\",\"ok\":true,\"report\":" + rep + "}");
                    continue;
                }
                if (cmd == "rollbackclean") {
                    rb::ClearCache();
                    WriteFramed(h, "{\"cmd\":\"rollbackclean\",\"ok\":true}");
                    continue;
                }
                // ---- 回滚前备份（2026-09-21 新增）----
                // 背景：回滚是 CREATE_ALWAYS 覆盖写，文件系统无删除记录，
                // 回收站/卷影都救不回来。这套接口让用户能把"被覆盖掉的那一版"捞回。
                if (cmd == "prebackuplist") {
                    WriteFramed(h, "{\"cmd\":\"prebackuplist\",\"ok\":true,\"data\":" +
                                   rb::ListPreBackupsJson() + "}");
                    continue;
                }
                if (cmd == "prebackuprestore") {
                    // 还原某一份备份。注意：还原本身也会先备份当前内容
                    // （否则"还原"就变成另一个不可反悔的动作）。
                    std::string id = JsonGetString(req, "id");
                    WriteFramed(h, "{\"cmd\":\"prebackuprestore\",\"ok\":true,\"data\":" +
                                   rb::RestorePreBackup(id) + "}");
                    continue;
                }
                if (cmd == "prebackupclear") {
                    // 默认只清过期的；force=1 才全清（与 keyclear 同一套语义，
                    // 避免用户误点一次就把唯一的副本销毁）
                    bool force = (JsonGetInt(req, "force") == 1);
                    WriteFramed(h, "{\"cmd\":\"prebackupclear\",\"ok\":true,\"data\":" +
                                   rb::ClearPreBackups(force) + "}");
                    continue;
                }
                if (cmd == "prebackupdir") {
                    WriteFramed(h, "{\"cmd\":\"prebackupdir\",\"ok\":true,\"dir\":" +
                                   JsonString(rb::PreBackupDir()) + "}");
                    continue;
                }
                // ---- 隔离区管理（2026-09-20 新增，供主界面「隔离区」页）----
                // 原本隔离只有"进去"没有"出来"：GUI 一行隔离区代码都没有，
                // 隔离记录也只活在内存 g_undoMap 里（服务重启即失联）。
                // 这四条命令 + index.tsv 索引，才让隔离区真正成为一个可管理的功能。
                if (cmd == "quarlist") {
                    WriteFramed(h, std::string("{\"cmd\":\"quarlist\",\"data\":") +
                                BuildQuarantineListJson() + "}");
                    continue;
                }
                if (cmd == "quarrestore") {
                    std::string id = JsonGetString(req, "id");
                    WriteFramed(h, "{\"cmd\":\"quarrestore\",\"ok\":true,\"report\":" +
                                QuarantineRestore(id) + "}");
                    continue;
                }
                if (cmd == "quardelete") {
                    std::string id = JsonGetString(req, "id");
                    WriteFramed(h, "{\"cmd\":\"quardelete\",\"ok\":true,\"report\":" +
                                QuarantineDelete(id) + "}");
                    continue;
                }
                if (cmd == "quarclear") {
                    WriteFramed(h, "{\"cmd\":\"quarclear\",\"ok\":true,\"report\":" +
                                QuarantineClear() + "}");
                    continue;
                }
                if (cmd == "quardir") {
                    std::wstring d = QuarantineDirW();
                    WriteFramed(h, "{\"cmd\":\"quardir\",\"ok\":true,\"dir\":" +
                                sf::JsonString(std::string(d.begin(), d.end())) + "}");
                    continue;
                }
                // ---- 落地前置捕获（2026-09-19 新增）----
                // 取走当前待处理的落地初筛命中（取走即清空，避免反复上报）。
                if (cmd == "landlist") {
                    WriteFramed(h, "{\"cmd\":\"landlist\",\"ok\":true,\"data\":" + rb::TakeLandedAlertsJson() + "}");
                    continue;
                }
                // 弹窗卡归因回填：最近一次自动拦截事件的标题/详情/进程名（正经杀软文案）
                if (cmd == "lastalert") {
                    WriteFramed(h, "{\"cmd\":\"lastalert\",\"ok\":true,\"data\":" + LastAlertJson() + "}");
                    continue;
                }
                // ★ 资源监控状态查询（2026-10-03 新增）。
                //   可观测性纪律：新增的检测面**必须能查状态**。
                //   否则「它到底跑没跑、扫了几轮、一轮挑出几个」在排障时是黑洞 ——
                //   这正是本轮挖矿零告警踩到的坑（④ 环连日志都没有）。
                //   once=1 时立即跑一轮扫描并返回本轮结果（供验收时手动触发）。
                  if (cmd == "resmonq") {
                      bool once = JsonGetString(req, "once") == "1";
                      unsigned n = 0;
                      if (once) n = resmon::ScanOnce();
                      WriteFramed(h, std::string("{\"cmd\":\"resmonq\",\"ok\":true,\"scanNow\":") +
                                   (once ? "true" : "false") + ",\"hitsNow\":" + std::to_string(n) +
                                   ",\"data\":" + resmon::FormatHits() + "}");
                      continue;
                  }
                  // ---- 能力看门狗查询（C1，2026-10-03）----
                  //  一句话回答「八路事件源现在各是什么状态、有哪几路在降级/停摆」。
                  //  存在的理由：今天出现过「日志一切正常、实际整条检测没在工作」
                  //  （resmon 单核门槛），而**光看日志看不出来** —— 必须能主动查。
                  if (cmd == "guardcheck") {
                      WriteFramed(h, std::string("{\"cmd\":\"guardcheck\",\"ok\":true,\"data\":") +
                                       guardcheck::SummaryJson() + "}");
                      continue;
                  }
                  // ---- 处置闭环断言查询（C2）----
                  //  halfOpen 累计数应恒为 0；非 0 表示存在「判定了却没处置」的分支。
                  if (cmd == "halfopen") {
                      WriteFramed(h, std::string("{\"cmd\":\"halfopen\",\"ok\":true,\"halfOpen\":") +
                                       std::to_string(g_halfOpen.load()) +
                                       ",\"ok_expect_zero\":true}");
                      continue;
                  }
                  // ---- 无结论文件的用户决策（2026-10-03）----
                  //  沙箱没测出结论（verdict=error）时，处置权交回用户：
                  //  删掉 / 不删除 / 知道了，超时 30 秒自动删除。
                  //
                  //  ★★ **只认令牌，绝不认路径**。路径是外部可写边界（渲染进程、
                  //    扩展、任何本地程序都能伪造任意路径字符串）；令牌由服务端生成、
                  //    只认自己发出去的那一批。删文件这种不可逆操作必须以不可伪造的
                  //    凭据为依据，否则任何本地程序都能让服务替它删任意文件。
                  //  ★★ 取用即出表（errhold::Take）⇒ 三条路径互斥且幂等：
                  //    重复点击、点击与超时竞态，都只会有一个结果生效。
                  if (cmd == "errdecide") {
                      const std::string tok  = JsonGetString(req, "token");
                      const std::string act  = JsonGetString(req, "act");   // del | keep | release
                      sf::errhold::Pending pd;
                      if (!sf::errhold::Take(tok, pd)) {
                          // 已出表 = 已被处理过（用户点过、或已超时自动处置）。
                          // 回 ok=false 而不是静默成功：前端要据此把按钮置灰，
                          // 否则用户会以为"点了没反应"而反复点。
                          WriteFramed(h, std::string("{\"cmd\":\"errdecide\",\"ok\":false,"
                                       "\"reason\":\"该决策已失效（可能已超时自动处置，或已处理）。\"}"));
                          continue;
                      }
                      LogDbg("[errhold] 收到用户决策 act=" + act + "：" + pd.origPath +
                             "（令牌 " + tok.substr(0, 6) + "…）");
                      if (act == "del") {
                          ErrHoldDeleteNow(pd.origPath, "用户选择删除");
                          WriteFramed(h, std::string("{\"cmd\":\"errdecide\",\"ok\":true,"
                                       "\"act\":\"del\",\"reason\":\"已删除（删除前已留底到隔离区，可在隔离区还原）。\"}"));
                      } else if (act == "release") {
                          ErrHoldReleaseNow(pd.origPath);
                          WriteFramed(h, std::string("{\"cmd\":\"errdecide\",\"ok\":true,"
                                       "\"act\":\"release\",\"reason\":\"已放行，并将在 1 小时内持续监控其行为。\"}"));
                      } else {
                          // act 缺失/非法：**不动作**（继续锁着），但记日志。
                          // ★ 刻意不把它当"删除"：用户没表达删除意图，
                          //   程序替他删是不可撤销的误处置。
                          // ★ 也不再放行：用户没选，就不该替他选。
                          //   结果是文件继续被锁 —— 属"知道了"分支的语义。
                          LogDbg("[errhold] ★决策动作非法或缺失（act=" + act +
                                 "）⇒ 不动作，该文件**继续保持封锁**等用户手动处置：" + pd.origPath);
                          WriteFramed(h, std::string("{\"cmd\":\"errdecide\",\"ok\":false,"
                                       "\"reason\":\"未识别的操作，已保持封锁。\"}"));
                      }
                      continue;
                  }
                  // ---- 待决状态查询（给卡片判断按钮是否还有效）----
                  if (cmd == "errlist") {
                      WriteFramed(h, std::string("{\"cmd\":\"errlist\",\"ok\":true,\"data\":") +
                                   sf::errhold::SummaryJson() + "}");
                      continue;
                  }
                // 撤销最近一次自动回滚（"反向回滚"）：把文件还原回"回滚前"的版本。
                // 高风险自动处置后，用户在弹窗里点「撤销我的处理」时走这条命令。
                if (cmd == "rollbackundo") {
                    std::string tok = JsonGetString(req, "token");
                    // 统一撤销入口（银泊 09-19 正经杀软模式）：按 token 前缀分发 ——
                    // 10=引导扇区（bootguard）/ 20=自启动项 / 30=落地隔离 / 其余=勒索回滚
                    std::string rep = UniversalUndo(tok);
                    WriteFramed(h, "{\"cmd\":\"rollbackundo\",\"ok\":true,\"report\":" + rep + "}");
                    continue;
                }
                if (cmd == "history") {
                    // 清除历史：独立轻量响应（不触发扫描），供扩展端「清除记录」卡片
                    WriteFramed(h, BuildHistoryJson());
                    continue;
                } else if (cmd == "rescan") {
                    // 仅 rescan 触发全量扫描；扫描中收到的重复 rescan 直接走通用回包（返回缓存），
                    // 不排队重扫——否则连点 N 次就串行跑 N 轮全盘、N 个弹窗。
                    if (!g_rescanBusy.exchange(true)) {
                        RunFullScan();
                        g_rescanBusy = false;
                        CheckAndNotify();
                    }
                } else if (cmd == "clean_adv") {
                    // 「高级清除」：普通清除（cmd=clean）仍失败的目标清单在此清理。
                    // 遏制（按基名杀全部实例+子进程树）+ 硬删（清属性/解ACL/POSIX删除/重启登记）。
                    std::vector<std::string> adv;
                    {
                        std::lock_guard<std::mutex> lk(g_failedMtx);
                        adv = g_failedTargets;
                    }
                    CleanReport ar = AdvancedCleanFiles(adv);
                    LogDbg("[clean_adv] requested=" + std::to_string(ar.requested) +
                           " deleted=" + std::to_string(ar.deleted) +
                           " deferred=" + std::to_string(ar.deferred) +
                           " failed=" + std::to_string(ar.failed) +
                           " killed=" + std::to_string(ar.killed));
                    g_failedTargets.clear();
                    // 先回包（含高级清除报告）再复查：全盘复查要几十秒，若放在回包前，
                    // 弹窗进度条到 100% 后还要干等复查完成才显示结果。
                    std::string resp;
                    {
                        std::lock_guard<std::mutex> lk(g_resultMutex);
                        resp = BuildResultJson(g_result);
                    }
                    if (!resp.empty() && resp.back() == '}') {
                        resp.pop_back();
                        resp += "," + BuildCleanJson(ar);
                        resp += "}";
                    }
                    WriteFramed(h, resp);
                    AppendCleanHistory("advanced", ar);   // 落历史（回包后写，不阻塞响应）
                    RunFullScan(); SyncLastToastStatus();   // 高级清除后刷新状态（不阻塞回包）
                    continue;
                } else if (cmd == "clean") {
                    // 「一键清除」：清除预扫不重做全盘——直接盯住【上一轮全盘扫描已发现的可疑样本
                    // 所在目录】做定点扫描（RunQuickScan 内部实现：快照 g_result 中样本的父目录，
                    // 只扫这些目录 + 常规落点）。既与展示同源（深层文件夹样本也清得到），又秒级完成。
                    RunQuickScan();
                    std::vector<std::string> targets = CollectCleanTargets();
                    CleanReport cr = CleanFiles(targets);
                    // 记录「未清除干净」的路径清单：failed（当场失败）与 deferred（登记重启删除）都收——
                    // deferred 文件同样有复活/ACL 自保，若留给重启删除可能把样本带到下次开机；
                    // 高级删除（clean_adv）对它们一并夺权+硬删+连坐，当场根除。
                    {
                        std::lock_guard<std::mutex> lk(g_failedMtx);
                        g_failedTargets.clear();
                        for (const auto& it : cr.items)
                            if (it.action == "failed" || it.action == "deferred")
                                g_failedTargets.push_back(it.path);
                    }
                    LogDbg("[clean] requested=" + std::to_string(cr.requested) +
                           " deleted=" + std::to_string(cr.deleted) +
                           " deferred=" + std::to_string(cr.deferred) +
                           " failed=" + std::to_string(cr.failed) +
                           " extraDlls=" + std::to_string(cr.extraDlls) +
                           " killed=" + std::to_string(cr.killed));
                    // 先用「当前结果 + 清除报告」立即回包。全量重扫要 ~20 秒，若放在回包之前，
                    // 调用方（弹窗进度卡片 / 扩展面板）会在进度条走满后干等 20 秒才看到结果。
                    std::string resp;
                    {
                        std::lock_guard<std::mutex> lk(g_resultMutex);
                        resp = BuildResultJson(g_result);
                    }
                    if (!resp.empty() && resp.back() == '}') {
                        resp.pop_back();
                        resp += "," + BuildCleanJson(cr);
                        resp += "}";
                    }
                    WriteFramed(h, resp);
                    AppendCleanHistory("normal", cr);   // 落历史（回包后写，不阻塞响应）
                    // 回包之后再重扫刷新状态；同步通知基线，避免下一轮扫描把「异常→正常」当成新变化又弹一次
                    RunFullScan();
                    SyncLastToastStatus();
                    continue;   // 响应已写出，跳过通用回包流程
                }
                std::string resp;
                {
                    std::lock_guard<std::mutex> lk(g_resultMutex);
                    resp = BuildResultJson(g_result);      // status 直接返回缓存结果（瞬时）
                }
                // 把清除报告并入同一帧响应（status/score 仍在顶层，兼容既有解析）
                if (!extra.empty() && !resp.empty() && resp.back() == '}') {
                    resp.pop_back(); resp += extra; resp += "}";
                }
                if (!WriteFramed(h, resp)) break;
            }
            DisconnectNamedPipe(h);
            CloseHandle(h);
        }).detach();
    }
    if (sa.lpSecurityDescriptor) LocalFree(sa.lpSecurityDescriptor);
}

// ---------------------------------------------------------------------------
//  服务安装 / 自保重建
// ---------------------------------------------------------------------------
// 窄串→宽串（按系统 ANSI 代码页，匹配 GetModuleFileNameA 的返回）。
// 用于以 Unicode（CreateServiceW）注册服务，避免中文显示名 / 中文安装路径在服务管理器里乱码。
static std::wstring AToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 清除历史版本的遗留服务。SilverFoxEnvScan 更名为 SilverFoxGuard 后，
// 若旧服务未卸载，新旧两个服务会【同时开机自启】→ 各自跑一份「快速扫 + 每 3 分钟全盘扫」，
// 用户感知就是「每 3 分钟扫一次全盘并弹窗」（2026-09-18 用户实测踩坑）。
// 这里在注册新服务前无条件终结并删除全部历史服务名，保证系统内只有一个扫描引擎。
static void RemoveLegacyServices() {
    static const wchar_t* kLegacy[] = { L"SilverFoxEnvScanSvc" };
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return;
    for (const wchar_t* name : kLegacy) {
        SC_HANDLE svc = OpenServiceW(scm, name, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
        if (!svc) continue;   // 不存在：正常情况
        // ① 优雅停止
        SERVICE_STATUS ss{};
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 20 && ss.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(300);
            if (!QueryServiceStatus(svc, &ss)) break;
        }
        // ② 停止超时（服务卡在命名管道阻塞）→ 按 PID 强杀，否则 SCM 不置为 STOPPED，DeleteService 会静默失败
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD cb = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                     (LPBYTE)&ssp, sizeof(ssp), &cb) && ssp.dwProcessId) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, ssp.dwProcessId);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            for (int i = 0; i < 10; ++i) {
                Sleep(300);
                if (!QueryServiceStatus(svc, &ss) || ss.dwCurrentState == SERVICE_STOPPED) break;
            }
        }
        // ③ 删除服务项（失败也无妨：SCM 下次启动会因 ImagePath 缺失而失败，至少不再扫描）
        BOOL del = DeleteService(svc);
        CloseServiceHandle(svc);
        LogDbg(std::string("[install] 清理历史服务 ") +
               std::string(name, name + wcslen(name)) + (del ? " 成功" : " 失败（可能已在删除标记）"));
    }
    CloseServiceHandle(scm);
}

bool SvcInstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return false;
    // 先摘除历史服务（SilverFoxEnvScanSvc），避免新旧服务并存导致的「双份全盘扫描 + 重复弹窗」
    RemoveLegacyServices();
    std::string exe = GetExePath();
    std::wstring exeW = AToW(exe);
    std::wstring binW = L"\"" + exeW + L"\" --run-service";
    SC_HANDLE svc = CreateServiceW(scm, L"SilverFoxGuardSvc", L"银狐主防服务",
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL);
    bool ok = !!svc;
    if (svc) { CloseServiceHandle(svc); svc = NULL; }
    else {
        // 服务已存在：必须把 ImagePath 更新成本次安装所在路径。
        // 否则服务仍从旧文件夹启动，与 DoInstall 写入的哈希基线对不上 → 自身完整性校验永久误报
        // （用户装到别的文件夹就会触发）。这也是“路径被写死”错觉的根因。
        svc = OpenServiceW(scm, L"SilverFoxGuardSvc", SERVICE_CHANGE_CONFIG);
        if (svc) {
            ok = ChangeServiceConfigW(svc, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE, SERVICE_NO_CHANGE,
                                      binW.c_str(), NULL, NULL, NULL, L"LocalSystem", NULL, NULL) != 0;
            CloseServiceHandle(svc); svc = NULL;
        }
    }
    if (ok) {
        // 失败自动重启（自保：被杀后 SCM 拉起）
        // ★ 统一走 W 版并检查返回值（2026-09-27）：与 ApplySvcFailureActions 同源，
        //   避免"安装时没配上、却以为配上了"。此处不写回读日志以免刷屏，
        //   但失败必须留痕 —— 静默失败正是本项目反复踩的坑。
        svc = OpenServiceW(scm, SVC_NAME, SERVICE_ALL_ACCESS);
        if (svc) {
            SC_ACTION actions[3];
            for (auto& a : actions) { a.Delay = 60000; a.Type = SC_ACTION_RESTART; }
            SERVICE_FAILURE_ACTIONSW fa{};
            fa.cActions = 3; fa.lpsaActions = actions; fa.dwResetPeriod = 86400;
            if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa))
                LogDbg("[svcinstall] 失败自启配置失败 err=" + std::to_string(GetLastError()));
            CloseServiceHandle(svc);
        } else {
            LogDbg("[svcinstall] OpenService(ALL_ACCESS) 失败 err=" + std::to_string(GetLastError()));
        }
    }
    CloseServiceHandle(scm);
    return ok;
}

bool EnsureServiceRegistered() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxGuardSvc", SERVICE_QUERY_STATUS);
    if (svc) { CloseServiceHandle(svc); CloseServiceHandle(scm); return true; }
    CloseServiceHandle(scm);
    return SvcInstall();   // 被删则重建（服务以 SYSTEM 运行，有权限）
}

bool SvcUninstall() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxGuardSvc",
                                 SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (svc) {
        SERVICE_STATUS ss{};
        // ① 优先优雅停止
        ControlService(svc, SERVICE_CONTROL_STOP, &ss);
        for (int i = 0; i < 20 && ss.dwCurrentState != SERVICE_STOPPED; ++i) {
            Sleep(500); QueryServiceStatus(svc, &ss);
        }
        // ② 优雅停止超时（服务卡在命名管道 Accept/Connect 阻塞等死锁场景）：强制结束进程
        if (ss.dwCurrentState != SERVICE_STOPPED) {
            SERVICE_STATUS_PROCESS ssp{};
            DWORD cb = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO,
                                    (LPBYTE)&ssp, sizeof(ssp), &cb) && ssp.dwProcessId) {
                HANDLE hp = OpenProcess(PROCESS_TERMINATE, FALSE, ssp.dwProcessId);
                if (hp) { TerminateProcess(hp, 0); CloseHandle(hp); }
            }
            for (int i = 0; i < 10; ++i) {
                Sleep(300); QueryServiceStatus(svc, &ss);
                if (ss.dwCurrentState == SERVICE_STOPPED) break;
            }
        }
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return true;
}

bool IsServiceRunning() {
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return false;
    SC_HANDLE svc = OpenServiceA(scm, "SilverFoxGuardSvc", SERVICE_QUERY_STATUS);
    bool running = false;
    if (svc) {
        SERVICE_STATUS ss{};
        if (QueryServiceStatus(svc, &ss))
            running = (ss.dwCurrentState == SERVICE_RUNNING ||
                       ss.dwCurrentState == SERVICE_START_PENDING ||
                       ss.dwCurrentState == SERVICE_CONTINUE_PENDING);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
    return running;
}

// ---------------------------------------------------------------------------
//  安装器 / 卸载器
// ---------------------------------------------------------------------------
bool DoInstall(const std::string& extIdChrome, const std::string& extIdEdge) {
    std::string svcExe = GetExePath();
    std::string dir = DirName(svcExe);
    // 单程序：服务本体同时作为 Native Messaging 宿主被浏览器拉起
    std::string hostExe = svcExe;

    // 【升级修复】旧服务若正在运行，必须先停止并删除、再重建。原因：ChangeServiceConfig 虽能更新
    // ImagePath，但运行中的服务进程仍执行旧 EXE 的代码（内存映像不会因文件替换而更新）；而紧随其后的
    // StartService 对「已在运行」的服务只会返回 ERROR_SERVICE_ALREADY_RUNNING。结果是
    // 「覆盖安装了新 EXE，服务却仍按旧逻辑跑」——表现为新修复的检测规则不生效。
    SvcUninstall();
    for (int i = 0; i < 30; ++i) {   // 等 SCM 真正移除服务，避免 CreateService 撞上 marked-for-delete
        SC_HANDLE m = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (!m) break;
        SC_HANDLE s = OpenServiceA(m, "SilverFoxGuardSvc", SERVICE_QUERY_STATUS);
        if (!s) { CloseServiceHandle(m); break; }
        CloseServiceHandle(s); CloseServiceHandle(m);
        Sleep(400);
    }

    std::string manifestPath;
    if (!WriteNmManifest(hostExe, extIdChrome, extIdEdge, manifestPath)) {
        printf("[错误] 写入 Native Messaging 清单失败。\n"); return false;
    }
    printf("[信息] 清单已写入：%s\n", manifestPath.c_str());

    SaveExtIds(extIdChrome, extIdEdge);   // 记录扩展 ID，供双击重装复用

    if (!RegisterNmHost(manifestPath, extIdChrome, extIdEdge))
        printf("[警告] 注册 Native Messaging 失败（需管理员权限）。\n");

    if (!SvcInstall()) { printf("[错误] 安装服务失败（需管理员权限）。\n"); return false; }
    printf("[信息] Windows 服务 SilverFoxGuardSvc 已安装（自动启动 / SYSTEM / 失败自启）。\n");

    HardenFileAcl(svcExe);
    if (FileExists(hostExe)) HardenFileAcl(hostExe);
    // ★ 开源版：不再写 ExeHash 基线（2026-10-04）。
    //   那个基线是**给我们的发行版**用的：安装时记录 EXE 哈希，之后每次扫描比对，
    //   不符即判"程序被篡改"。用户自行编译后哈希必然不同 ⇒ 每次扫描都报
    //   「程序自身完整性校验失败 / 疑似被篡改或遭病毒注入」——
    //   一个刚编译的程序被指控中毒，**这功能在开源形态下是纯误报**。
    //   官方发行版需要它时，把下面这行放回即可（VerifySelfIntegrity 里也要一并放回基线比对）：
    //   StoreHash(Sha256File(svcExe));

    // 立即启动
    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (scm) {
        SC_HANDLE s = OpenServiceA(scm, "SilverFoxGuardSvc", SERVICE_START);
        if (s) { StartServiceA(s, 0, NULL); CloseServiceHandle(s); }
        CloseServiceHandle(scm);
    }
    printf("[完成] 银狐主防已安装并启动。扩展内「主防」将显示盾牌状态。\n");
    return true;
}

bool DoUninstall() {
    SvcUninstall();
    UnregisterNmHost();
    RegDeleteKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, KEY_WOW64_64KEY, 0);
    printf("[信息] 已卸载服务、注销原生消息宿主、清除配置。\n");
    return true;
}

// ---------------------------------------------------------------------------
//  调试：前台运行
// ---------------------------------------------------------------------------
static void PrintResult() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    printf("[%s] status=%s score=%d selfCheck=%d findings=%zu\n",
        g_result.timestamp.c_str(), g_result.status.c_str(), g_result.score,
        (int)g_result.selfCheck, g_result.findings.size());
    for (auto& f : g_result.findings)
        printf("   - [%s/%s] %s | %s | ioc=%s\n", f.category.c_str(), f.severity.c_str(),
               f.title.c_str(), f.detail.c_str(), f.ioc.c_str());
}
void RunConsole() {
    setvbuf(stdout, nullptr, _IONBF, 0);   // 管道下也实时输出，避免被 timeout 杀掉前丢缓冲
    printf("[银狐主防] 前台调试模式（Ctrl+C 退出）\n");
    g_stopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    RunFullScan();
    PrintResult();
    while (!g_stop.load()) {
        DWORD r = WaitForSingleObject(g_stopEvent, 15000);
        if (g_stop.load()) break;
        if (r == WAIT_TIMEOUT) { RunFullScan(); PrintResult(); }
    }
}

}  // namespace sf
