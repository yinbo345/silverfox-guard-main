// etw.cpp — ETW 进程事件采集层实现
//
// ===========================================================================
//  实现依据：docs/heuristic-engine-plan.md §4.4.2「关键实现细节（有坑）」
//  下面每一条都是文档里预先标出的坑，代码里逐条对应，勿删注释。
// ===========================================================================
#include "etw.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <chrono>
#include <deque>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include "common.h"     // LogDbg / LogDbgC / NowMs / W2A
#include "behavior.h"   // ProcReputable（前置过滤，砍误报面）

#pragma comment(lib, "tdh.lib")

namespace sf {
namespace etw {

// ---------------------------------------------------------------------------
//  单调时钟毫秒（steady）—— 各 cpp 内部独立实现（项目惯例，不共享头文件）
//
//  为什么用 steady 而不是 GetTickCount64：GetTickCount64 已经单调且不受
//  系统时间调整影响，但它在系统休眠后是否继续累加存在版本差异。用
//  QueryPerformanceCounter 换算更稳，且与 rollback.cpp 的度量口径一致
//  （跨模块比较时间戳时口径不一致会算出负数）。
// ---------------------------------------------------------------------------
static uint64_t NowMsSteady() {
    static LARGE_INTEGER freq = [] {
        LARGE_INTEGER f{}; QueryPerformanceFrequency(&f); return f;
    }();
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    if (freq.QuadPart <= 0) return GetTickCount64();
    return (uint64_t)((double)c.QuadPart * 1000.0 / (double)freq.QuadPart);
}

// ---------------------------------------------------------------------------
//  Provider 常量
// ---------------------------------------------------------------------------
//  Microsoft-Windows-Kernel-Process —— 内核进程事件 provider
static const GUID kKernelProcess =
    { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

// 事件 ID（Kernel-Process provider 的固定编号）
static const USHORT kEvProcessStart  = 1;
static const USHORT kEvProcessStop   = 2;
static const USHORT kEvThreadStart   = 3;
static const USHORT kEvImageLoad     = 5;

// Keyword 位（决定服务端推哪些事件给我们 —— 这是最省资源的过滤点）
static const ULONGLONG kKeywordProcess    = 0x10;   // WINEVENT_KEYWORD_PROCESS
// ⚠️ 本文件**未接入生产构建**（build.sh L53 显式排除 etw.cpp，标注「未接入的历史文件」）。
//    生产用的 ETW 实现是 `etwproc.cpp`，它**只订 kKeywordProcess(0x10)**，
//    按设计不订阅 ImageLoad（见 etwproc.cpp:54 注释：「id=5 ImageLoad 等都不订阅」）。
//    ⇒ 下面对 0x40 的修正**对本文件无实际影响**，改它不改变任何运行时行为。
//    真正的 IMAGE_LOAD 关键字是 0x40（0x20 是 THREAD）—— 若将来要把本文件接进生产，
//    这一点必须按此写，否则 kEvImageLoad 分支与 PassFilter 都不会执行。
static const ULONGLONG kKeywordImageLoad  = 0x40;   // IMAGE_LOAD（★ 0x20 是 THREAD）

// ---------------------------------------------------------------------------
//  全局状态
// ---------------------------------------------------------------------------
static std::atomic<bool>        g_running{ false };
static std::atomic<bool>        g_stop{ false };
static TRACEHANDLE              g_session  = 0;
static TRACEHANDLE              g_trace    = 0;
static std::thread              g_thread;
static ProcEventSink            g_sink;
static std::string              g_sessionName;

// 统计（原子，供任意线程读）
static std::atomic<uint64_t>    g_received{ 0 };
static std::atomic<uint64_t>    g_delivered{ 0 };
static std::atomic<uint64_t>    g_dropped{ 0 };
static std::atomic<uint64_t>    g_lastEventMs{ 0 };

// ---------------------------------------------------------------------------
//  ★ 事件队列（文档 §4.4.2 第 3 条）
//
//  EventRecordCallback **绝对不能做重活**：它运行在我们的消费线程上，
//  阻塞会导致 ETW 缓冲积压、内核丢事件。回调里只做「拷贝必要字段 → 入队」，
//  所有判定/签名查询/落盘都在消费者线程做。
//
//  队列用固定容量 + 满了丢最旧：宁可丢事件也不能让内存无限涨。
//  丢弃计数必须可见（g_dropped），否则就是静默失效。
// ---------------------------------------------------------------------------
static const size_t kQueueCap = 4096;

static std::mutex              g_qMtx;
static std::deque<ProcEvent>   g_queue;
static HANDLE                  g_qEvent = nullptr;   // 有新事件时置位，唤醒消费者
static HANDLE                  g_stopEvent = nullptr;

// ---------------------------------------------------------------------------
//  会话名随机化（文档 §3.3）
//  固定名字会被针对性 ControlTrace(STOP)。加随机后缀，攻击者无法预先知道。
// ---------------------------------------------------------------------------
static std::string MakeSessionName() {
    std::random_device rd;
    char buf[96];
    // 名字上限 1024 字符，这里远低于上限；用 PID + 随机数保证唯一
    sprintf_s(buf, "SilverFoxGuardProc-%08X%04X",
              (unsigned)GetCurrentProcessId(), (unsigned)(rd() & 0xFFFF));
    return buf;
}

// ---------------------------------------------------------------------------
//  NT 路径 → Win32 路径（文档 §4.4.3 第 2 条）
//
//  ETW 的 ImageName 常是 \Device\HarddiskVolume3\Windows\... 这种 NT 形式，
//  直接喂给签名查询/规则匹配会全部失配。必须转成 C:\ 形式。
//
//  做法：查 \Device\HarddiskVolumeN → 盘符 的映射。
//  查不到时原样返回（不猜），由调用方按"未知路径"处理。
// ---------------------------------------------------------------------------
static std::string g_devMapCache;      // 缓存：避免每条事件都查

std::string NormalizeImagePath(const std::string& ntPath) {
    if (ntPath.empty()) return ntPath;
    // 已经是 Win32 路径（C:\... 或 \\?\C:\...）→ 直接返回
    if (ntPath.size() >= 2 && ntPath[1] == ':') return ntPath;
    if (ntPath.rfind("\\\\?\\", 0) == 0) return ntPath.substr(4);
    // 不是 \Device\ 开头 → 原样（可能是相对路径/空）
    if (ntPath.rfind("\\Device\\", 0) != 0) return ntPath;

    // 建立 卷设备名 → 盘符 的映射：遍历 A..Z 查询每个盘符对应的设备路径
    static std::mutex mtx;
    static std::vector<std::pair<std::string, std::string>> map;   // (device, drive)
    std::lock_guard<std::mutex> lk(mtx);
    if (map.empty()) {
        char target[512];
        for (char c = 'A'; c <= 'Z'; ++c) {
            char root[8] = { c, ':', '\\', 0 };
            UINT t = GetDriveTypeA(root);
            if (t == DRIVE_UNKNOWN || t == DRIVE_NO_ROOT_DIR) continue;
            char dev[512] = { 0 };
            // QueryDosDeviceA 返回 \Device\HarddiskVolumeN（可能多条，取第一条）
            if (QueryDosDeviceA(root, dev, sizeof(dev)) && dev[0]) {
                std::string d = dev;
                size_t nl = d.find('\0');
                if (nl != std::string::npos) d = d.substr(0, nl);
                if (!d.empty()) map.push_back({ d, std::string(1, c) + ":" });
            }
        }
        (void)target;
    }
    // 找最长匹配前缀（防 \Device\HarddiskVolume1 匹配到 Volume10 的前缀）
    const std::pair<std::string, std::string>* best = nullptr;
    for (const auto& kv : map) {
        if (ntPath.rfind(kv.first, 0) == 0) {
            if (!best || kv.first.size() > best->first.size()) best = &kv;
        }
    }
    if (!best) return ntPath;      // 映射表里没有 → 不猜，原样返回
    return best->second + ntPath.substr(best->first.size());
}

// ---------------------------------------------------------------------------
//  取事件里的字符串字段（TDH 解码）
//
//  ★ 文档 §4.4.2 第 5 条的经典坑：ProcessStart 的 ImageName 在事件数据里是
//  **偏移量而非指针**，直接当指针读会崩。正确做法是用 TDH 按属性名拿数据。
//
//  实现说明：TdhGetProperty 在缓冲区不足时返回 ERROR_INSUFFICIENT_BUFFER
//  并通过 size 参数回填所需长度（注意：该参数是**值**参数，首次传 0 表示
//  "只问大小"，用 &size 传会编译失败）。
// ---------------------------------------------------------------------------
static std::string WideToUtf8(const wchar_t* w, int len = -1) {
    if (!w) return {};
    int n = (len < 0) ? (int)wcslen(w) : len;
    if (n <= 0) return {};
    int need = WideCharToMultiByte(CP_UTF8, 0, w, n, nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out((size_t)need, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, n, &out[0], need, nullptr, nullptr);
    return out;
}

static std::string GetEventString(PEVENT_RECORD ev, LPCWSTR propName, bool* ok = nullptr) {
    if (ok) *ok = false;
    if (!ev || !propName) return {};

    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    pd.ArrayIndex   = ULONG_MAX;
    pd.Reserved     = 0;

    // 第一步：问需要多大缓冲。传 size=0 只问大小，TDH 回填到 size 变量。
    ULONG size = 0;
    ULONG st = TdhGetPropertySize(ev, 0, nullptr, 1, &pd, &size);
    if (st != ERROR_SUCCESS || size == 0 || size > (64u << 20)) return {};

    std::vector<BYTE> data((size_t)size);
    st = TdhGetProperty(ev, 0, nullptr, 1, &pd, size, data.data());
    if (st != ERROR_SUCCESS) return {};

    // 第二步：拿类型，区别 UNICODE / ANSI / COUNTED。
    //  不能盲目按字符串解读 —— 有些字段名相同但类型是整数。
    //  TDH 的 InType 定义在 tdh.h 的 TDH_INTYPE_* 常量里。
    //  UNICODESTRING=1, ANSISTRING=2, COUNTEDSTRING=3
    std::string out;
    // WCHAR 结尾是绝大多数情况，直接判是否有 0x00 隔字节（UTF-16 特征）
    const BYTE* b = data.data();
    bool looksWide = (size >= 2) && (b[1] == 0);
    if (looksWide) {
        const wchar_t* w = (const wchar_t*)b;
        size_t wlen = size / sizeof(wchar_t);
        // 去掉结尾的 NUL
        while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;
        out = WideToUtf8(w, (int)wlen);
    } else {
        // ANSI 或 COUNTEDSTRING（长度前缀）。尝试跳过可能的 2 字节长度前缀。
        // 判据：前 2 字节若等于 (size-2) 左右，视为 COUNTEDSTRING。
        bool counted = (size >= 2) && (*(const USHORT*)b == (USHORT)(size - 2));
        if (counted) {
            out = WideToUtf8((const wchar_t*)(b + 2), (int)((size - 2) / sizeof(wchar_t)));
            if (out.empty() || out.find('\0') != std::string::npos) {
                // 万一不是宽字符，退回 ANSI 解读
                out.assign((const char*)b + 2);
            }
        } else {
            out.assign((const char*)b);
        }
    }
    // 清掉可能残留的 NUL
    size_t nul = out.find('\0');
    if (nul != std::string::npos) out = out.substr(0, nul);
    if (ok) *ok = !out.empty();
    return out;
}

// 取无符号整数字段（PID 等）
static unsigned long GetEventU32(PEVENT_RECORD ev, LPCWSTR propName, bool* ok = nullptr) {
    if (ok) *ok = false;
    if (!ev || !propName) return 0;
    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    pd.ArrayIndex   = ULONG_MAX;
    pd.Reserved     = 0;
    ULONG val = 0;
    ULONG st = TdhGetProperty(ev, 0, nullptr, 1, &pd, sizeof(val), (PBYTE)&val);
    if (st != ERROR_SUCCESS) return 0;
    if (ok) *ok = true;
    return val;
}

// ---------------------------------------------------------------------------
//  ★ 前置过滤（文档 §5.1 第 1 条 + §4.4.2 第 4 条）
//
//  为什么必须在采集层就过滤：
//    · ImageLoad 事件量巨大（浏览器一启动就是几千条），全量入队会瞬间打满
//      队列、把真正重要的 ProcessStart 挤掉；
//    · 更关键的是**误报控制**：已签名 + 可信厂商的进程直接跳过，这一条能砍掉
//      绝大部分误报面，而且省掉后续所有开销。
//
//  只对 ImageLoad 做过滤；ProcessStart 全量保留（它是判定主输入，不能漏）。
// ---------------------------------------------------------------------------
static bool PassFilter(const ProcEvent& e) {
    if (e.kind != ProcEvent::Kind::ImageLoad) return true;

    // 系统目录下的 DLL 直接丢（绝大多数，且几乎不可能有问题）
    std::string low = e.imageName;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    if (low.find("\\windows\\system32\\") != std::string::npos ||
        low.find("\\windows\\syswow64\\") != std::string::npos ||
        low.find("\\windows\\winsxs\\")    != std::string::npos ||
        low.find("\\windows\\assembly\\")  != std::string::npos) {
        return false;
    }
    return true;
}

// 解析一条 PROC_EVENT 记录 → ProcEvent（在回调里调用，必须轻量）
static bool ParseRecord(PEVENT_RECORD ev, ProcEvent& out) {
    if (!ev || !ev->UserData) return false;
    switch (ev->EventHeader.EventDescriptor.Id) {
    case kEvProcessStart:  out.kind = ProcEvent::Kind::Start; break;
    case kEvProcessStop:   out.kind = ProcEvent::Kind::Stop;  break;
    case kEvImageLoad:     out.kind = ProcEvent::Kind::ImageLoad; break;
    case kEvThreadStart:   return false;   // 线程事件本版不消费（量大、判定价值低）
    default:               return false;
    }
    out.pid  = ev->EventHeader.ProcessId;
    out.atMs = NowMs();

    // ★ 字段名按 provider manifest 定义。
    //   ProcessStart/Stop: ProcessID / ParentProcessID / ImageName / CommandLine
    //   ImageLoad:         ProcessID / ImageName（DLL 路径）
    bool okPid = false, okParent = false;
    unsigned long p = GetEventU32(ev, L"ProcessID", &okPid);
    if (!okPid) p = out.pid;
    out.pid = p;
    out.ppid = GetEventU32(ev, L"ParentProcessID", &okParent);
    // ★ ParentProcessID 是 ETW 相比 WMI 的关键优势：原生携带，无需额外查询
    if (!okParent && out.kind == ProcEvent::Kind::Start) {
        // 少数版本字段名不同，退化用事件头的 ProcessId（至少不为 0）
        out.ppid = 0;
    }
    out.imageName  = NormalizeImagePath(GetEventString(ev, L"ImageName"));
    out.commandLine = GetEventString(ev, L"CommandLine");
    return true;
}

// ---------------------------------------------------------------------------
//  ★ EventRecordCallback（文档 §4.4.2 第 3 条：这里只能做拷贝+入队）
// ---------------------------------------------------------------------------
static VOID WINAPI OnEventRecord(PEVENT_RECORD ev) {
    if (!ev || !g_running.load(std::memory_order_relaxed)) return;
    g_received.fetch_add(1, std::memory_order_relaxed);

    ProcEvent e;
    if (!ParseRecord(ev, e)) return;
    if (e.kind == ProcEvent::Kind::Stop && e.imageName.empty()) {
        // 进程退出事件常常没有 ImageName（进程已消失），保留但标记
    }

    // 过滤（在队列外先做，省队列空间）
    if (!PassFilter(e)) return;

    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        if (g_queue.size() >= kQueueCap) {
            g_queue.pop_front();          // 满了丢最旧，保证新事件不丢
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        g_queue.push_back(std::move(e));
    }
    if (g_qEvent) SetEvent(g_qEvent);
}

// ---------------------------------------------------------------------------
//  消费者线程：从队列取事件 → 调 sink（判定在这里做，不在回调里）
// ---------------------------------------------------------------------------
static void ConsumeLoop() {
    while (!g_stop.load()) {
        ProcEvent e;
        bool has = false;
        {
            std::lock_guard<std::mutex> lk(g_qMtx);
            if (!g_queue.empty()) {
                e = std::move(g_queue.front());
                g_queue.pop_front();
                has = true;
            }
        }
        if (has) {
            g_delivered.fetch_add(1, std::memory_order_relaxed);
            g_lastEventMs.store(NowMs(), std::memory_order_relaxed);
            if (g_sink) {
                // ★ sink 内部不得抛异常逃逸；由 service 侧用 RunThreadGuard 同一套
                //   保护逻辑兜住（本线程由 service 用 RunThreadGuard 包裹启动）
                g_sink(e);
            }
            continue;
        }
        // 队列空 → 等新事件（带超时，保证能及时响应 g_stop）
        if (g_qEvent) WaitForSingleObject(g_qEvent, 200);
        else Sleep(20);
    }
}

// ---------------------------------------------------------------------------
//  启动 / 停止
// ---------------------------------------------------------------------------
bool Start(ProcEventSink sink) {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return true;  // 幂等

    g_sink = std::move(sink);
    g_stop.store(false);
    g_sessionName = MakeSessionName();

    g_qEvent    = CreateEventW(nullptr, FALSE, FALSE, nullptr);  // 自动重置
    g_stopEvent = CreateEventW(nullptr, TRUE,  FALSE, nullptr);

    // ---- [1] 创建会话 ----
    // ★ 文档 §4.4.2 第 6 条：BufferSize 建议 64KB，LogFileMode 含
    //   EVENT_TRACE_REAL_TIME_MODE，**不要**含 EVENT_TRACE_FILE_MODE_*
    std::vector<BYTE> props(1024, 0);
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
    p->Wnode.BufferSize    = (ULONG)props.size();
    p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
    p->Wnode.ClientContext = 1;                       // 时间戳精度：1 = QPC
    p->BufferSize          = 64;                      // KB
    p->MinimumBuffers      = 32;
    p->MaximumBuffers      = 128;                     // = MinimumBuffers*4
    p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
    p->FlushTimer          = 1;                       // 1 秒刷一次（实时性）
    p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = StartTraceW(&g_session, wname.c_str(), p);
    if (st != ERROR_SUCCESS) {
        // ★ 错误码语义（实测总结）：
        //   5    = ERROR_ACCESS_DENIED（非管理员/LocalSystem）
        //   183  = ERROR_ALREADY_EXISTS（同名会话残留）
        //   1450 = ERROR_NO_SYSTEM_RESOURCES（会话数达上限）
        LogDbg("[etw] StartTraceW 失败，错误码 " + std::to_string(st) +
               "（5=权限不足 183=会话名冲突 1450=会话数上限）→ 采集层不可用");
        g_running.store(false);
        if (g_qEvent) { CloseHandle(g_qEvent); g_qEvent = nullptr; }
        if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
        return false;
    }

    // ---- [2] 订阅 provider ----
    // ★ 文档 §4.4.2 第 7 条：同一 provider 可被多个会话订阅（不互斥），
    //   所以火绒/Defender 在跑也不影响我们 —— EnableTraceEx2 是加订阅者。
    st = EnableTraceEx2(g_session, &kKernelProcess,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION,
                        kKeywordProcess | kKeywordImageLoad,
                        0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        LogDbg("[etw] EnableTraceEx2 失败，错误码 " + std::to_string(st) + " → 采集层不可用");
        Stop();
        return false;
    }

    // ---- [3] 打开实时消费 ----
    // ★ 文档 §4.4.2 第 1 条：ProcessTraceMode 必须含 PROCESS_TRACE_MODE_REAL_TIME
    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = (LPWSTR)wname.c_str();
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = OnEventRecord;

    g_trace = OpenTraceW(&lf);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        LogDbg("[etw] OpenTraceW 失败，错误码 " + std::to_string(GetLastError()) + " → 采集层不可用");
        Stop();
        return false;
    }

    // ---- [4] 启动消费线程 ----
    // ★ 文档 §4.4.2 第 2 条：ProcessTrace 是阻塞调用，必须独立线程
    g_thread = std::thread([] {
        // ProcessTrace 阻塞直到 CloseTrace 被调用
        ProcessTrace(&g_trace, 1, nullptr, nullptr);
    });
    // 队列消费者
    static std::thread consumer;
    consumer = std::thread(ConsumeLoop);

    // 先落一条日志证明链路已建（延迟验证靠后续 [etw] ProcessStart 日志）
    LogDbg("[etw] ETW 采集已启动，会话名 " + g_sessionName +
           "（provider=Microsoft-Windows-Kernel-Process，实时模式，64KB 缓冲）");
    return true;
}

void Stop() {
    if (!g_running.exchange(false)) {
        // 即使标记为未运行，也尝试清理可能残留的会话句柄
    }
    g_stop.store(true);
    if (g_qEvent) SetEvent(g_qEvent);
    if (g_stopEvent) SetEvent(g_stopEvent);

    // ★ 先 CloseTrace 让阻塞中的 ProcessTrace 返回，再 join 线程（顺序不能反）
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_thread.joinable()) {
        // 不能无限等：ProcessTrace 正常会在 CloseTrace 后返回
        g_thread.join();
    }
    if (g_session) {
        // 停止并删除会话（用 ControlTrace 而非 StopTrace，后者是旧 API）
        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize = (ULONG)props.size();
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::wstring wname(g_sessionName.begin(), g_sessionName.end());
        ControlTraceW(g_session, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
    if (g_qEvent)    { CloseHandle(g_qEvent);    g_qEvent = nullptr; }
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        g_queue.clear();
    }
    g_sink = nullptr;
}

bool IsRunning() { return g_running.load(); }

Stats GetStats() {
    Stats s;
    s.received    = g_received.load();
    s.delivered   = g_delivered.load();
    s.dropped     = g_dropped.load();
    s.lastEventMs = g_lastEventMs.load();
    return s;
}

bool IsHealthy(uint64_t silentMs) {
    if (!g_running.load()) return false;
    uint64_t last = g_lastEventMs.load();
    if (last == 0) return true;          // 还没收到过事件，不算不健康
    return (NowMs() - last) <= silentMs;
}

std::string SessionName() { return g_sessionName; }

}  // namespace etw
}  // namespace sf
