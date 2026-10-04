// sfclock.cpp — 银狐主防程序 · 自有时间基准（时钟静态站客户端）
//
// 设计要点见 sfclock.h 的文件头说明。本文件实现三件事：
//   ① 固有时间轴 T1 —— 跨重启单调不减，运行期**完全不读系统时钟**
//   ② 双冗余持久化 —— 文件（ProgramData）＋ 注册表（HKLM），取两者保守值
//   ③ 两阶段篡改检测 —— 日常零成本本地采样；仅在偏差超阈值时才联网查时钟站
//
// ★★ 一条贯穿全文件的铁律：**T1 只许向前，绝不倒退**。
//    任何"取小值"的写法都是 bug；所有路径一律取「更大者/保守者」。
//    理由：T1 是时间窗判据的度量单位。假若它倒退，窗口会无限拉长或归零，
//    判据方向可能从"收紧"翻成"放宽" —— 那等于给攻击者开后门。

#include "sfclock.h"

#ifdef _WIN32
#  include <windows.h>
#  include <shlobj.h>      // SHGetFolderPathW
#  include <winhttp.h>
#  pragma comment(lib, "winhttp.lib")
#endif

#include <atomic>
#include <chrono>
#include <cstddef>        // offsetof
#include <cstdio>
#include <cstring>
#include <string>
#include <mutex>

namespace sf {
// 来自 common.h —— 此处前向声明，避免把 scanner.h 的整条依赖链拖进本底层模块。
// ⚠️ 签名必须与 common.h 完全一致，否则链接期报未解析外部符号。
void LogDbgC(const char* msg);
void LogDbg(const std::string& msg);
}

namespace sf {
namespace ck {

// ===========================================================================
//  常量
// ===========================================================================

// 状态文件（与隔离区索引、快照同在 ProgramData，但**独立文件名**，
// 避免被"清理临时文件"类工具连带删除）
static const char* kStateFileName = "\\clock_state.bin";

// 注册表位置。★ 必须 HKLM —— HKCU 普通用户可写，护栏自破。
//   我们是 LocalSystem 服务，有写权限；恶意软件通常没有管理员权限。
static const wchar_t* kRegRoot = L"SOFTWARE\\SilverFoxGuard\\Clock";

// 状态文件魔数与版本
static const uint32_t kMagic   = 0x4B434653u;   // 'SFCK'
static const uint32_t kVersion = 1u;

// 「同一开机周期」判定容差。bootTime 是「系统启动时刻」的反推值，
// 同一开机内因采样精度会有几十毫秒抖动，5 分钟足够宽松又足够区分两次开机。
static const uint64_t kBootTimeToleranceMs = 5ull * 60 * 1000;

// ★ 触发云端查询的偏差阈值：1 年（银泊定）。
//   为什么是 1 年：正常 NTP 校正 < 1 秒；用户改时区不影响 Unix 时间戳；
//   手动误调很少超过 1 天。而改时钟规避检测的动机是"让证书过期/让授权失效"，
//   量级必然是年。1 年这条线区分度足够且不会误报。
static const uint64_t kDefaultBigJumpMs = 365ull * 24 * 60 * 60 * 1000;

// 分档（银泊提到"一年、五年、十年"三档）
static const uint64_t kJumpWarn1Ms = 1ull * 365 * 24 * 60 * 60 * 1000;    // 1 年
static const uint64_t kJumpWarn2Ms = 5ull * 365 * 24 * 60 * 60 * 1000;    // 5 年
static const uint64_t kJumpWarn3Ms = 10ull * 365 * 24 * 60 * 60 * 1000;   // 10 年

// 记日志的门槛（低于此值视为正常抖动，静默丢弃）
static const uint64_t kLogThresholdMs = 60ull * 1000;    // 60 秒

// 开机时长上限。「重启后用系统时钟补时」的合理性校验：
// 关机超过这个时长 → 认为系统时钟不可信，拒绝采纳（T1 冻结 + 告警）。
static const uint64_t kMaxPlausibleGapMs = 90ull * 24 * 60 * 60 * 1000;  // 90 天

// 云端查询最小间隔（防抖动、防被诱导频繁联网）
static const uint64_t kCloudMinIntervalMs = 10ull * 60 * 1000;           // 10 分钟

// 单次云端查询超时（3 秒；巡逻节拍 30 秒，最坏阻塞可接受）
static const DWORD kCloudTimeoutMs = 3000;

// 采样间隔（与 rollback.cpp 的 30 秒巡逻同节拍）
static const uint64_t kSampleIntervalMs = 30ull * 1000;

// 时钟站地址（独立域名，与官网分离）
static const wchar_t* kClockHost = L"silverfox-clock.pages.dev";
static const wchar_t* kClockPath = L"/api/time.txt";

// ===========================================================================
//  内部状态
// ===========================================================================

// 锚点：T1 = g_anchorT1 + (MonoMs() - g_anchorMono)
// 用 atomic 因为 T1Ms() 在判定链热路径被多线程读取。
static std::atomic<uint64_t> g_anchorT1{ 0 };
static std::atomic<uint64_t> g_anchorMono{ 0 };
static std::atomic<bool>     g_inited{ false };

// 采样基线（仅 Tick 线程访问，但用 atomic 保证可见性）
static std::atomic<uint64_t> g_lastMono{ 0 };
static std::atomic<uint64_t> g_lastWall{ 0 };
static std::atomic<bool>     g_tickSeeded{ false };

// 状态
static std::atomic<uint32_t> g_anomalyCount{ 0 };
static std::mutex            g_noteMtx;
static std::string           g_lastAnomaly;
static std::string           g_lastCloudNote = "未查询";
static std::atomic<uint64_t> g_lastCloudTryMono{ 0 };
static std::atomic<int64_t>  g_driftMs{ 0 };

// 配置
static std::atomic<bool>     g_cloudEnabled{ true };
static std::atomic<uint64_t> g_bigJumpMs{ kDefaultBigJumpMs };

// ★ 回归测试钩子状态（默认全关 → 与不调用时行为完全一致）。
//   为什么必须有隔离能力：Init()/SubmitExternalAnchor() 会写
//   ProgramData\clock_state.bin 与 HKLM\...\Clock。回归测试若写到真实位置，
//   会把**生产基线**污染成测试值（例如用例里伪造的"一年后"）——
//   此后真实服务的全部时间窗判据都会错位，且症状是"判据莫名其妙不触发"，
//   极难回溯到"是那次跑测试搞的"。所以测试必须换仓、且默认不碰注册表。
static std::atomic<bool>     g_regDisabled{ false };   // true = 跳过 HKLM 读写
static std::mutex            g_dirMtx;
static std::wstring          g_stateDirOverride;       // 非空 = 状态目录重定向

// ===========================================================================
//  基础取时
// ===========================================================================

uint64_t MonoMs() {
    // steady_clock：单调、不受 SetSystemTime 影响。
    // ★ 但其基准是「进程启动」—— 故其绝对值只在进程内有意义，严禁持久化。
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

uint64_t RawWallMs() {
    // system_clock：可被 SetSystemTime 篡改，NTP 对时也会跳。仅展示用。
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

uint64_t T1Ms() {
    if (!g_inited.load(std::memory_order_acquire)) {
        // 未初始化（服务刚起、或 Init 失败）→ 降级用系统时钟，
        // 但这是**有标记的降级**：ClockSane() 会返回 false，日志会体现。
        return RawWallMs();
    }
    // ★ 纯单调推进：运行期完全不读系统时钟 —— 这是「不跟系统时钟走」的实现。
    return g_anchorT1.load(std::memory_order_relaxed)
         + (MonoMs() - g_anchorMono.load(std::memory_order_relaxed));
}

// 反推「系统启动时刻」（Unix 毫秒）。
//   原理：启动时刻 = 当前系统时间 − 开机以来经过的毫秒。
//   ⚠️ 系统时钟被改时此值会变 —— 但那个变化本身正是我们要检测的信号，
//   而且失败方向是「保守」（误判为重启 → 走更谨慎的路径）。
static uint64_t BootTimeMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // FILETIME(100ns @1601) → Unix ms
    uint64_t nowUnixMs = u.QuadPart / 10000ull - 11644473600000ull;
    uint64_t tick = GetTickCount64();
    return (nowUnixMs > tick) ? (nowUnixMs - tick) : 0;
}

// ===========================================================================
//  持久化：状态结构 + 校验
// ===========================================================================

#pragma pack(push, 1)
struct ClockState {
    uint32_t magic;
    uint32_t version;
    uint64_t t1;            // 保存时刻的 T1
    uint64_t monoAtSave;    // 保存时刻的 MonoMs()
    uint64_t bootTimeMs;    // 保存时刻反推的系统启动时刻
    uint64_t flags;         // 保留（位0=上次启动曾检出异常）
    uint64_t check;         // 校验和（防误改；防恶意靠 HKLM 的 ACL）
};
#pragma pack(pop)

// FNV-1a over the struct except the check field.
// ⚠️ 诚实标注：这是**防误改**，不是防恶意篡改。
//    真正的护栏是注册表位于 HKLM（需管理员权限）+ ProgramData 目录 ACL。
//    恶意软件若已拿到管理员，本校验挡不住 —— 但那已超出本模块职责，
//    且此时 T1 的"单调不减"性质仍能防止判据被**放宽**（只会被收紧）。
static uint64_t Checksum(const ClockState& s) {
    uint64_t h = 1469598103934665603ull;
    const unsigned char* p = (const unsigned char*)&s;
    size_t n = offsetof(ClockState, check);
    for (size_t i = 0; i < n; ++i) {
        h ^= (uint64_t)p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static std::wstring StateDirW() {
    // 回归测试可重定向；默认（override 为空）走 ProgramData
    {
        std::lock_guard<std::mutex> lk(g_dirMtx);
        if (!g_stateDirOverride.empty()) return g_stateDirOverride;
    }
    wchar_t p[MAX_PATH] = { 0 };
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        return std::wstring(p) + L"\\SilverFoxGuard";
    return L"C:\\ProgramData\\SilverFoxGuard";
}

// 宽 → UTF-8。
// ★ 为什么不用 `std::string(d.begin(), d.end())`：那是**逐字符取低字节**，
//   一旦路径含非 ASCII（域环境重定向后的中文目录、带重音的用户名盘符等）
//   就会静默产生乱码 —— 正是铁律 §4「UTF-8 路径」要防的那类事故。
//   这里只服务于**诊断显示**（StatePathUtf8），功能路径一律走宽字符 API；
//   但显示错了同样会让人误判故障，所以照铁律走转换。
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::string StatePathA() {
    return WideToUtf8(StateDirW()) + kStateFileName;
}

static bool LoadFromFile(ClockState* out) {
    std::wstring p = StateDirW() + L"\\clock_state.bin";
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    ClockState s;
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &s, sizeof(s), &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd != sizeof(s)) return false;
    if (s.magic != kMagic || s.version != kVersion) return false;
    if (Checksum(s) != s.check) return false;
    *out = s;
    return true;
}

static bool LoadFromReg(ClockState* out) {
    if (g_regDisabled.load(std::memory_order_relaxed)) return false;   // 回归测试隔离
    HKEY hk = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRegRoot, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;
    ClockState s;
    memset(&s, 0, sizeof(s));
    DWORD sz = sizeof(uint64_t), type = 0;
    bool ok = true;
    ok = ok && RegQueryValueExW(hk, L"T1", nullptr, &type, (LPBYTE)&s.t1, &sz) == ERROR_SUCCESS;
    sz = sizeof(uint64_t);
    ok = ok && RegQueryValueExW(hk, L"MonoAtSave", nullptr, &type, (LPBYTE)&s.monoAtSave, &sz) == ERROR_SUCCESS;
    sz = sizeof(uint64_t);
    ok = ok && RegQueryValueExW(hk, L"BootTime", nullptr, &type, (LPBYTE)&s.bootTimeMs, &sz) == ERROR_SUCCESS;
    sz = sizeof(uint64_t);
    ok = ok && RegQueryValueExW(hk, L"Check", nullptr, &type, (LPBYTE)&s.check, &sz) == ERROR_SUCCESS;
    RegCloseKey(hk);
    if (!ok) return false;
    s.magic = kMagic;
    s.version = kVersion;
    s.flags = 0;
    if (Checksum(s) != s.check) return false;    // 注册表侧校验失败
    *out = s;
    return true;
}

static void SaveToFile(const ClockState& s) {
    std::wstring d = StateDirW();
    CreateDirectoryW(d.c_str(), nullptr);

    // 显式收紧 ACL：隔离区教训 —— ProgramData 新建目录默认可能让标准用户可读，
    // 而时钟基线若可被标准用户改，整个护栏就自破了。
    // （用 SetFileSecurityW 而非 icacls：见隔离区实现里的同类处理。）
    std::wstring p = d + L"\\clock_state.bin";
    std::wstring tmp = p + L".tmp";

    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD wr = 0;
    WriteFile(h, &s, sizeof(s), &wr, nullptr);
    CloseHandle(h);
    // 原子替换（沿用隔离区索引的成熟写法）
    if (!MoveFileExW(tmp.c_str(), p.c_str(), MOVEFILE_REPLACE_EXISTING))
        DeleteFileW(tmp.c_str());
}

static void SaveToReg(const ClockState& s) {
    if (g_regDisabled.load(std::memory_order_relaxed)) return;   // 回归测试隔离
    HKEY hk = nullptr;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kRegRoot, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hk, nullptr) != ERROR_SUCCESS)
        return;                                   // 非管理员环境：静默降级到仅文件
    RegSetValueExW(hk, L"T1", 0, REG_QWORD, (const BYTE*)&s.t1, sizeof(s.t1));
    RegSetValueExW(hk, L"MonoAtSave", 0, REG_QWORD, (const BYTE*)&s.monoAtSave, sizeof(s.monoAtSave));
    RegSetValueExW(hk, L"BootTime", 0, REG_QWORD, (const BYTE*)&s.bootTimeMs, sizeof(s.bootTimeMs));
    RegSetValueExW(hk, L"Check", 0, REG_QWORD, (const BYTE*)&s.check, sizeof(s.check));
    RegCloseKey(hk);
}

// ★ 双冗余保存：两处都写。任一处可读即可恢复锚点 ——
//   这样单点被删（清理工具误删文件 / 注册表被"优化"软件清）都不会丢失基线。
static void SaveState(uint64_t t1) {
    ClockState s;
    memset(&s, 0, sizeof(s));
    s.magic = kMagic;
    s.version = kVersion;
    s.t1 = t1;
    s.monoAtSave = MonoMs();
    s.bootTimeMs = BootTimeMs();
    s.flags = 0;
    s.check = Checksum(s);
    SaveToFile(s);
    SaveToReg(s);
}

// ===========================================================================
//  异常记录
// ===========================================================================

static void NoteAnomaly(const std::string& msg) {
    std::lock_guard<std::mutex> lk(g_noteMtx);
    g_lastAnomaly = msg;
    g_anomalyCount.fetch_add(1, std::memory_order_relaxed);
    // 直接落日志 —— 时钟异常本身就是高价值信号，不能只留在内存里
    std::string line = "[clock] 时钟异常：" + msg;
    LogDbgC(line.c_str());
}

// ===========================================================================
//  云端旁站查询（WinHTTP）
// ===========================================================================

// 单次 GET /api/time.txt，返回服务器生成响应的 Unix 毫秒。
// body 是一行十进制数字，解析成本最低（不需要 JSON 解析器）。
static bool HttpFetchTimeOnce(uint64_t* outServerMs, std::string* outNote) {
    bool ok = false;
    *outServerMs = 0;

    HINTERNET hSess = WinHttpOpen(L"SilverFoxGuard/1.0 (clock)",
                                  WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) { *outNote = "WinHttpOpen 失败"; return false; }

    WinHttpSetTimeouts(hSess, kCloudTimeoutMs, kCloudTimeoutMs, kCloudTimeoutMs, kCloudTimeoutMs);

    HINTERNET hConn = WinHttpConnect(hSess, kClockHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConn) { WinHttpCloseHandle(hSess); *outNote = "连接失败"; return false; }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", kClockPath, nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        WINHTTP_FLAG_SECURE);
    if (!hReq) { WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess); *outNote = "建请求失败"; return false; }

    // 防缓存：★ 这里**没有** WINHTTP_DISABLE_CACHING 可用 ——
    //   该常量在 winhttp.h 里根本不存在（它是 WinINet 的概念：
    //   HTTP 缓存层属于 WinINet，WinHTTP 是精简栈，自身不缓存响应）。
    //   真正的缓存风险来自**中间代理**，靠请求头显式声明 no-cache 才是正确做法。
    static const wchar_t* kNoCacheHdr =
        L"Cache-Control: no-cache, no-store\r\nPragma: no-cache\r\n";

    // headers 长度传 (DWORD)-1 表示"由 WinHttp 自行计算该字符串长度"
    if (WinHttpSendRequest(hReq, kNoCacheHdr, (DWORD)-1L, nullptr, 0, 0, 0) &&
        WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len, WINHTTP_NO_HEADER_INDEX);
        if (status == 200) {
            std::string body;
            DWORD avail = 0;
            while (WinHttpQueryDataAvailable(hReq, &avail) && avail > 0 && body.size() < 256) {
                char buf[128];
                DWORD rd = 0;
                if (!WinHttpReadData(hReq, buf, (avail < sizeof(buf)) ? avail : sizeof(buf), &rd) || rd == 0)
                    break;
                body.append(buf, rd);
            }
            // 解析：取第一段连续数字
            size_t i = 0;
            while (i < body.size() && (body[i] < '0' || body[i] > '9')) ++i;
            size_t j = i;
            while (j < body.size() && body[j] >= '0' && body[j] <= '9') ++j;
            if (j > i) {
                uint64_t v = 0;
                for (size_t k = i; k < j; ++k) v = v * 10ull + (uint64_t)(body[k] - '0');
                // 合理性：必须是"本世纪初~下世纪初"之间的 Unix 毫秒
                if (v > 946684800000ull && v < 4102444800000ull) {
                    *outServerMs = v;
                    ok = true;
                } else {
                    *outNote = "返回时间超出合理范围";
                }
            } else {
                *outNote = "响应体无数字";
            }
        } else {
            *outNote = "HTTP " + std::to_string((int)status);
        }
    } else {
        *outNote = "请求失败（网络不可达/超时）";
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);
    return ok;
}

// 连取 3 次取**最小值**。
//   为什么取最小：往返延迟只会让估算值偏大（我们以为服务器"更晚"了），
//   所以最小的那一次最接近真值 —— 这是抗网络抖动最省事的正确做法。
static bool FetchCloudBest(uint64_t* outMs, std::string* outNote) {
    uint64_t best = 0;
    int okCount = 0;
    std::string lastNote = "未查询";
    for (int i = 0; i < 3; ++i) {
        uint64_t t0 = MonoMs();
        uint64_t srv = 0;
        std::string note;
        if (HttpFetchTimeOnce(&srv, &note)) {
            uint64_t t1 = MonoMs();
            uint64_t rtt = (t1 >= t0) ? (t1 - t0) : 0;
            // 往返折半校正：服务器在往返中点生成响应
            uint64_t est = srv + rtt / 2;
            if (best == 0 || est < best) best = est;
            ++okCount;
        } else {
            lastNote = note;
        }
    }
    if (okCount == 0) { *outNote = lastNote; return false; }
    *outMs = best;
    *outNote = "成功（3 次取最小，" + std::to_string(okCount) + "/3 次响应）";
    return true;
}

void SubmitExternalAnchor(uint64_t serverMs, const char* src) {
    if (serverMs == 0) return;
    // ★ 只接受更大的值：单调不减。小的直接忽略（可能是重放/攻击者回退）。
    uint64_t cur = T1Ms();
    if (serverMs <= cur) return;
    // 采纳：把锚点重设为 serverMs（等价于把 T1 抬到 serverMs）
    g_anchorT1.store(serverMs, std::memory_order_relaxed);
    g_anchorMono.store(MonoMs(), std::memory_order_relaxed);
    g_inited.store(true, std::memory_order_release);
    SaveState(serverMs);
    std::lock_guard<std::mutex> lk(g_noteMtx);
    g_lastCloudNote = std::string("采纳外部锚点（") + (src ? src : "unknown") + "）";
}

bool SyncCloudNow() {
    if (!g_cloudEnabled.load(std::memory_order_relaxed)) {
        std::lock_guard<std::mutex> lk(g_noteMtx);
        g_lastCloudNote = "已禁用";
        return false;
    }
    // 频率限制：10 分钟内最多一次
    uint64_t nowMono = MonoMs();
    uint64_t last = g_lastCloudTryMono.load(std::memory_order_relaxed);
    if (last != 0 && (nowMono - last) < kCloudMinIntervalMs) {
        std::lock_guard<std::mutex> lk(g_noteMtx);
        g_lastCloudNote = "节流中（未满 10 分钟）";
        return false;
    }
    g_lastCloudTryMono.store(nowMono, std::memory_order_relaxed);

    uint64_t serverMs = 0;
    std::string note;
    bool ok = FetchCloudBest(&serverMs, &note);

    {
        std::lock_guard<std::mutex> lk(g_noteMtx);
        g_lastCloudNote = note;
    }
    if (!ok) return false;

    SubmitExternalAnchor(serverMs, "silverfox-clock");
    return true;
}

// ===========================================================================
//  生命周期
// ===========================================================================

bool Init() {
    uint64_t nowMono = MonoMs();
    uint64_t nowWall = RawWallMs();
    uint64_t nowBoot = BootTimeMs();

    // 双冗余读取：两处都尝试，取 t1 **更大**的那个（保守）。
    ClockState sf, sr;
    bool hf = LoadFromFile(&sf);
    bool hr = LoadFromReg(&sr);
    if (!hf && !hr) {
        // 首次运行：用系统时钟初始化（此后运行期不再依赖系统时钟）
        uint64_t init = nowWall;
        g_anchorT1.store(init, std::memory_order_relaxed);
        g_anchorMono.store(nowMono, std::memory_order_relaxed);
        g_inited.store(true, std::memory_order_release);
        SaveState(init);
        std::lock_guard<std::mutex> lk(g_noteMtx);
        g_lastCloudNote = "首次运行（已用系统时钟建立基线）";
        LogDbgC("[clock] 首次初始化时间基线");
        return true;
    }
    ClockState st;
    if (hf && hr)      st = (sf.t1 >= sr.t1) ? sf : sr;   // 取更大者
    else if (hf)       st = sf;
    else               st = sr;

    // ---- 判断是否重启（双重判据）----
    // 判据一（铁证）：单调时钟不会倒退，故 nowMono < monoAtSave 必然重启过。
    // 判据二：系统启动时刻反推值的偏移。
    bool sameBoot = false;
    if (nowMono >= st.monoAtSave) {
        uint64_t btDiff = (nowBoot > st.bootTimeMs) ? (nowBoot - st.bootTimeMs)
                                                    : (st.bootTimeMs - nowBoot);
        sameBoot = (btDiff <= kBootTimeToleranceMs);
    }

    uint64_t newT1;
    bool needCloud = false;      // 仅在"确认可疑"时置位，函数末尾统一处理
    if (sameBoot) {
        // ★ 未重启（服务自身重启）：纯单调推进，**完全不需要系统时钟**。
        //   这是最可靠的路径 —— 系统时钟此刻无论被改成什么，都不影响结果。
        newT1 = st.t1 + (nowMono - st.monoAtSave);
    } else {
        // 重启过：必须用系统时钟估算「关机了多久」——
        // 这是唯一必须读系统时钟的时刻（也是本题的第一个关键认知）。
        if (nowWall >= st.t1) {
            uint64_t gap = nowWall - st.t1;
            if (gap <= kMaxPlausibleGapMs) {
                newT1 = nowWall;                        // 合理 → 采纳
            } else {
                newT1 = st.t1;                          // 不合理 → 拒绝采纳，时间冻结
                NoteAnomaly("重启后系统时钟大幅前跳 " + std::to_string(gap / 86400000ull) +
                            " 天，超过可信上限 → 拒绝采纳，时间基准冻结并触发云端校验");
                needCloud = true;                       // 既然已判定可疑，交给云端旁站定夺
            }
        } else {
            // 系统时钟比上次记录的 T1 还早 → 明确回退（改时钟的经典手法）
            uint64_t back = st.t1 - nowWall;
            newT1 = st.t1;                              // ★ 绝不倒退
            NoteAnomaly("系统时钟回退 " + std::to_string(back / 86400000ull) +
                        " 天 → 已忽略，时间基准保持不减");
            needCloud = true;
        }
    }

    g_anchorT1.store(newT1, std::memory_order_relaxed);
    g_anchorMono.store(nowMono, std::memory_order_relaxed);
    g_inited.store(true, std::memory_order_release);

    // 采样基线也一并种下（避免 Tick 首次采样把"从 Init 到现在"算成跳变）
    g_lastMono.store(nowMono, std::memory_order_relaxed);
    g_lastWall.store(nowWall, std::memory_order_relaxed);
    g_tickSeeded.store(true, std::memory_order_release);

    // 可疑场景才联网；成功会抬高 T1（SubmitExternalAnchor 内部已保存）
    if (needCloud && g_cloudEnabled.load(std::memory_order_relaxed))
        SyncCloudNow();

    // 统一保存最终值（云端若已抬高，这里存的就是抬高后的值）
    SaveState(g_anchorT1.load(std::memory_order_relaxed));

    LogDbgC(("[clock] 时间基线就绪：T1=" + std::to_string(g_anchorT1.load()) +
             " boot=" + std::string(sameBoot ? "同" : "异") +
             " 漂移=" + std::to_string((int64_t)(nowWall - g_anchorT1.load())) + "ms").c_str());
    return true;
}

void Tick() {
    if (!g_inited.load(std::memory_order_acquire)) return;

    uint64_t nowMono = MonoMs();
    uint64_t nowWall = RawWallMs();

    if (!g_tickSeeded.load(std::memory_order_acquire)) {
        g_lastMono.store(nowMono, std::memory_order_relaxed);
        g_lastWall.store(nowWall, std::memory_order_relaxed);
        g_tickSeeded.store(true, std::memory_order_release);
        return;
    }

    uint64_t lastMono = g_lastMono.load(std::memory_order_relaxed);
    uint64_t lastWall = g_lastWall.load(std::memory_order_relaxed);
    g_lastMono.store(nowMono, std::memory_order_relaxed);
    g_lastWall.store(nowWall, std::memory_order_relaxed);

    uint64_t monoDelta = (nowMono >= lastMono) ? (nowMono - lastMono) : 0;

    // ---- 阶段 0：本地漂移检测（零成本、零联网）----
    // 比较「系统时钟推进量」与「单调时钟推进量」——
    // 两者在正常机器上应当几乎相等；差异就是时钟被动的量。
    int64_t drift;
    if (nowWall >= lastWall) {
        int64_t wallDelta = (int64_t)(nowWall - lastWall);
        drift = wallDelta - (int64_t)monoDelta;
    } else {
        // 采样间隔内系统时钟倒退 = 强信号
        int64_t back = (int64_t)(lastWall - nowWall);
        drift = -(back + (int64_t)monoDelta);
    }

    // 累积偏差（系统时钟 vs T1）—— 与增量漂移互补：
    // 增量检测抓"一次性跳变"，累积检测抓"持续偏差"。
    int64_t cum = (int64_t)((int64_t)nowWall - (int64_t)T1Ms());
    g_driftMs.store(cum, std::memory_order_relaxed);

    uint64_t aDrift = (drift < 0) ? (uint64_t)(-drift) : (uint64_t)drift;
    uint64_t aCum   = (cum < 0) ? (uint64_t)(-cum) : (uint64_t)cum;
    uint64_t worst  = (aDrift > aCum) ? aDrift : aCum;

    if (worst < kLogThresholdMs) return;         // 正常抖动 → 静默

    // ---- 阶段 0 分档判定 ----
    const char* tag = "小幅";
    if      (worst >= kJumpWarn3Ms) tag = "≥10 年";
    else if (worst >= kJumpWarn2Ms) tag = "≥5 年";
    else if (worst >= kJumpWarn1Ms) tag = "≥1 年";

    bool big = (worst >= g_bigJumpMs.load(std::memory_order_relaxed));

    // ★ 只有大幅篡改才进告警链 —— 小幅偏差走普通日志，
    //   否则 NTP 抖动会产生噪音淹没真信号（误报治理的同一思路）。
    if (big) {
        NoteAnomaly(std::string("系统时间被大幅修改（") + tag +
                    "，增量=" + std::to_string(drift) + "ms 累积=" + std::to_string(cum) + "ms）");
    } else {
        LogDbgC(("[clock] 时钟小幅偏差 " + std::string(tag) +
                   "（增量=" + std::to_string(drift) + "ms 累积=" + std::to_string(cum) + "ms）").c_str());
    }

    // ---- 阶段 1：仅在超阈值时联网查时钟站 ----
    if (big && g_cloudEnabled.load(std::memory_order_relaxed))
        SyncCloudNow();
}

// ===========================================================================
//  状态查询
// ===========================================================================

bool        ClockSane()     { return g_inited.load() && g_anomalyCount.load() == 0; }
int64_t     DriftMs()       { return g_driftMs.load(); }
uint32_t    AnomalyCount()  { return g_anomalyCount.load(); }

const char* LastAnomaly() {
    std::lock_guard<std::mutex> lk(g_noteMtx);
    return g_lastAnomaly.c_str();
}

const char* LastCloudNote() {
    std::lock_guard<std::mutex> lk(g_noteMtx);
    return g_lastCloudNote.c_str();
}

const char* StatePathUtf8() {
    static std::string s = StatePathA();
    return s.c_str();
}

const char* RegPathWide() {
    return "HKLM\\SOFTWARE\\SilverFoxGuard\\Clock";
}

void SetCloudEnabled(bool on)            { g_cloudEnabled.store(on); }
void SetBigJumpThresholdMs(uint64_t ms)  { if (ms > 0) g_bigJumpMs.store(ms); }

void ResetForTest() {
    g_anchorT1.store(0);
    g_anchorMono.store(0);
    g_inited.store(false);
    g_lastMono.store(0);
    g_lastWall.store(0);
    g_tickSeeded.store(false);
    g_anomalyCount.store(0);
    g_lastCloudTryMono.store(0);
    g_driftMs.store(0);
    std::lock_guard<std::mutex> lk(g_noteMtx);
    g_lastAnomaly.clear();
    g_lastCloudNote = "未查询";
}

// ---------------------------------------------------------------------------
//  回归测试专用钩子
// ---------------------------------------------------------------------------

void DebugIsolatePersistence(const wchar_t* dirW) {
    std::wstring dir = (dirW && dirW[0]) ? dirW : L"";
    {
        std::lock_guard<std::mutex> lk(g_dirMtx);
        g_stateDirOverride = dir;
    }
    // 隔离时一并停掉注册表 —— 否则 HKLM 里的真实基线会盖过测试注入值
    g_regDisabled.store(!dir.empty(), std::memory_order_relaxed);
    if (!dir.empty()) CreateDirectoryW(dir.c_str(), nullptr);
}

void DebugInjectState(uint64_t t1, uint64_t monoAtSave, uint64_t bootTimeMs) {
    ClockState s;
    memset(&s, 0, sizeof(s));
    s.magic = kMagic;
    s.version = kVersion;
    s.t1 = t1;
    s.monoAtSave = monoAtSave;
    s.bootTimeMs = bootTimeMs;
    s.flags = 0;
    s.check = Checksum(s);          // 自算校验和，走的是与生产完全相同的路径
    SaveToFile(s);
    SaveToReg(s);                   // 未隔离时同样写；隔离时内部自动跳过
}

uint64_t DebugReadPersistedT1() {
    ClockState sf, sr;
    bool hf = LoadFromFile(&sf);
    bool hr = LoadFromReg(&sr);
    if (hf && hr) return (sf.t1 >= sr.t1) ? sf.t1 : sr.t1;
    if (hf) return sf.t1;
    if (hr) return sr.t1;
    return 0;
}

}}
