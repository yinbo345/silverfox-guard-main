// netwatch.cpp — 网络外联采集层实现
//
// ===========================================================================
//  实现依据：docs/six-class-detection-plan.md §七「阶段 0 探针实测」
//  下面每条注释都对应一处实测踩过的坑，勿删。
// ===========================================================================
#include "netwatch.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common.h"    // LogDbg / LogDbgC
#include "sfstop.h"    // StopHandle / IsStopRequested

#pragma comment(lib, "tdh.lib")

namespace sf {
namespace netwatch {

// ---------------------------------------------------------------------------
//  单调时钟毫秒（与 etw.cpp / rollback.cpp 同口径）
//  ⚠️ 跨模块比较时间戳时口径必须一致，否则会算出负数（历史踩坑）。
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
//  Provider 常量（实测确认的 GUID 与 keyword）
// ---------------------------------------------------------------------------
//  Microsoft-Windows-Kernel-Network
static const GUID kKernelNetwork =
    { 0x7DD42A49, 0x5329, 0x4832, { 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88 } };

// 事件 ID：只关心 TCP 连接建立
static const USHORT kEvTcpConnect = 10;
//  id=11 / 18 = 收发数据、id=12/15 = SYN 参数/重传、id=13 = 断开
//  这些**不订阅**（事件量大、信息与 id=10 重复）。
//  id=34 是 IPv6 的 TCP 连接建立 —— 用同一份 provider 的不同事件 ID 推过来，
//  但 keyword 相同，所以订阅时一并收到，靠事件 ID 分派。

// Keyword 位：0x10 = KERNEL_NETWORK_KEYWORD_IPV4，0x20 = KERNEL_NETWORK_KEYWORD_IPV6
//  ★ 两个都订，才能做到 v4/v6 双栈覆盖（银狐系 C2 多为 v4，但隧道类会用 v6）。
static const ULONGLONG kKeywordIpv4 = 0x10;
static const ULONGLONG kKeywordIpv6 = 0x20;

// id=34：IPv6 TCP 连接建立（实测存在，地址是 16 字节 binary）
static const USHORT kEvTcpConnectV6 = 34;

// ---------------------------------------------------------------------------
//  全局状态
// ---------------------------------------------------------------------------
static std::atomic<bool>  g_running{ false };
static std::atomic<bool>  g_stop{ false };

static TRACEHANDLE        g_session = 0;
static TRACEHANDLE        g_trace   = 0;
static std::thread        g_thread;
static std::thread        g_consumer;
static ConnSink           g_sink = nullptr;
static std::string        g_sessionName;

static std::atomic<uint64_t> g_received{ 0 };
static std::atomic<uint64_t> g_delivered{ 0 };
static std::atomic<uint64_t> g_dropped{ 0 };
static std::atomic<uint64_t> g_parseFail{ 0 };
static std::atomic<uint64_t> g_lastEventMs{ 0 };
static std::atomic<uint64_t> g_startMs{ 0 };   // 本次 Start 的时刻（IsHealthy 启动宽限期用）

// IsHealthy 的启动宽限期：进程刚起、还没等到第一条事件时算「待机健康」；
// 超过此窗口仍零事件 = 采集面哑火（见 IsHealthy 的「哑巴兜底」修正）。
// 口径与 iowatch.cpp 的 kStartupGraceMs 保持一致。
static const uint64_t kStartupGraceMs = 60000;

// 队列：回调只入队，消费线程出队做判定（沿用 etw.cpp 的两段式）
static const size_t kQueueCap = 4096;
static std::mutex         g_qMtx;
static std::deque<ConnEvent> g_queue;
static HANDLE             g_qEvent    = nullptr;
static HANDLE             g_stopEvent = nullptr;

// ★★ 2026-10-02（铁律 35）：会话名由「随机后缀」改回**固定名**。
//   理由与 etwproc.cpp / iowatch.cpp 完全一致：随机名让每次重建都换新名
//   ⇒ 残留只增不减（实测 netwatch 64 个名 / 只退出 68→部分重叠仍属长期累积）
//   ⇒ 累积撞 1450 后内核 provider 订阅表劣化 ⇒ 事件静默不来、唯 OS 重启可清。
//   固定名后：重建即覆盖同一会话，残留无处累积；配合 PurgeStaleSession() + 183 有限重试。
static const char* kSessionName = "SilverFoxGuardNet";

static std::string MakeSessionName() {
    return std::string(kSessionName);
}

// 清理"同名残留会话"（ControlTraceW 第一参数传 0；4201=本就没有同名会话，正常）。
static void PurgeStaleSession() {
    if (g_sessionName.empty()) return;
    std::vector<BYTE> props(1024, 0);
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
    p->Wnode.BufferSize = (ULONG)props.size();
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ControlTraceW(0, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
    if (st == ERROR_SUCCESS) {
        LogDbg("[netwatch] 已清理同名残留会话（" + g_sessionName + "）");
    }
}

// ---------------------------------------------------------------------------
//  ★ 地址解析（实测踩坑最集中处）
// ---------------------------------------------------------------------------

// IPv4：4 字节大端 → "a.b.c.d"
// ⚠️ 绝不能 memcpy 成 uint32 再按主机序格式化 —— 会得到反序 IP
//    （例如 192.168.1.35 变成 35.1.168.192）。必须逐字节拼。
static std::string Ipv4ToString(const BYTE* b) {
    char buf[24];
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", (unsigned)b[0], (unsigned)b[1],
             (unsigned)b[2], (unsigned)b[3]);
    return std::string(buf);
}

// IPv6：16 字节 → 冒号十六进制。
// 不做 :: 压缩（RFC 5952 压缩规则较繁，且本模块只用于匹配比对与展示，
// 完整 8 组写法更利于人工核对日志）。匹配时统一走规范化函数。
static std::string Ipv6ToString(const BYTE* b) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return std::string(buf);
}

// 取无符号整数字段（PID / 端口）
static bool GetEventU32(PEVENT_RECORD ev, LPCWSTR propName, ULONG* out) {
    if (!ev || !propName || !out) return false;
    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    pd.ArrayIndex   = ULONG_MAX;
    pd.Reserved     = 0;
    ULONG val = 0;
    ULONG st = TdhGetProperty(ev, 0, nullptr, 1, &pd, sizeof(val), (PBYTE)&val);
    if (st != ERROR_SUCCESS) return false;
    *out = val;
    return true;
}

// 取二进制地址字段（v4 是 4 字节、v6 是 16 字节）
static bool GetEventAddr(PEVENT_RECORD ev, LPCWSTR propName, BYTE* out, ULONG outCap, ULONG* outLen) {
    if (!ev || !propName || !out) return false;
    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    pd.ArrayIndex   = ULONG_MAX;
    pd.Reserved     = 0;

    ULONG size = 0;
    ULONG st = TdhGetPropertySize(ev, 0, nullptr, 1, &pd, &size);
    if (st != ERROR_SUCCESS || size == 0 || size > outCap) return false;
    st = TdhGetProperty(ev, 0, nullptr, 1, &pd, size, out);
    if (st != ERROR_SUCCESS) return false;
    if (outLen) *outLen = size;
    return true;
}

// 端口转换：**大端 uint16 → 主机序**
// 实测：dport=01BB 表示 443，即网络字节序。必须用 ntohs 语义手工拼，
// 不能直接当主机序读（直接读会得到 0xBB01 = 47873）。
static uint16_t Ntohs16(uint16_t be) {
    return (uint16_t)(((be & 0x00FF) << 8) | ((be & 0xFF00) >> 8));
}

// ---------------------------------------------------------------------------
//  ★ 前置过滤：丢掉必然无价值的外联
//  与 etw.cpp 的 PassFilter 同理 —— 在采集层砍掉噪声，队列才不会被挤爆。
// ---------------------------------------------------------------------------
static bool PassFilter(const ConnEvent& e) {
    // 回环地址：本机进程间通信，与恶意外联无关
    if (e.remoteIp.rfind("127.", 0) == 0) return false;
    if (e.remoteIp == "0.0.0.0") return false;
    // IPv6 回环 ::1
    if (e.isV6 && e.remoteIp == "0000:0000:0000:0000:0000:0000:0000:0001") return false;
    // 端口 0：不是有效连接
    if (e.remotePort == 0) return false;
    // 本机局域网/私有段暂不丢 —— 内网横向移动（蠕虫类）同样是信号，
    // 交由上层判定决定是否关注。丢早了会漏掉横向移动线索。
    return true;
}

// ---------------------------------------------------------------------------
//  解析一条网络事件（在回调里调用，必须轻量：只做取值 + 转换）
// ---------------------------------------------------------------------------
static bool ParseRecord(PEVENT_RECORD ev, ConnEvent& out) {
    if (!ev || !ev->UserData) return false;

    USHORT id = ev->EventHeader.EventDescriptor.Id;
    const bool v6 = (id == kEvTcpConnectV6);
    if (!v6 && id != kEvTcpConnect) return false;   // 其它事件一概不管

    // PID：事件头里的 ProcessId 通常就是发起连接的进程
    out.pid  = (unsigned long)ev->EventHeader.ProcessId;
    out.atMs = NowMsSteady();
    out.isV6 = v6;

    // PID 也可以从属性里取（部分版本事件头给的是 0）
    ULONG pidProp = 0;
    if (GetEventU32(ev, L"PID", &pidProp) && pidProp != 0) out.pid = (unsigned long)pidProp;

    // 对端地址
    BYTE addr[16] = {0};
    ULONG alen = 0;
    if (!GetEventAddr(ev, L"daddr", addr, sizeof(addr), &alen)) return false;

    if (v6 || alen == 16) {
        out.isV6 = true;
        out.remoteIp = Ipv6ToString(addr);
    } else if (alen == 4) {
        out.remoteIp = Ipv4ToString(addr);
    } else {
        return false;   // 未知地址宽度
    }

    // 对端端口（大端 uint16）
    ULONG dport = 0;
    if (!GetEventU32(ev, L"dport", &dport)) return false;
    out.remotePort = Ntohs16((uint16_t)(dport & 0xFFFF));
    return true;
}

// ---------------------------------------------------------------------------
//  ★ EventRecordCallback：只做拷贝 + 入队（严禁在此做磁盘 I/O / 加长时间锁）
// ---------------------------------------------------------------------------
static VOID WINAPI OnEventRecord(PEVENT_RECORD ev) {
    if (!ev || !g_running.load(std::memory_order_relaxed)) return;

    USHORT id = ev->EventHeader.EventDescriptor.Id;
    if (id != kEvTcpConnect && id != kEvTcpConnectV6) return;   // 双保险过滤
    g_received.fetch_add(1, std::memory_order_relaxed);

    ConnEvent e;
    if (!ParseRecord(ev, e)) {
        g_parseFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    if (!PassFilter(e)) return;

    g_lastEventMs.store(e.atMs, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        if (g_queue.size() >= kQueueCap) {
            g_queue.pop_front();          // 满了丢最旧（保新不保全）
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        g_queue.push_back(e);
    }
    if (g_qEvent) SetEvent(g_qEvent);
}

// ---------------------------------------------------------------------------
//  消费线程：出队 → 外发给 sink
// ---------------------------------------------------------------------------
static void ConsumeLoop() {
    std::vector<ConnEvent> batch;
    batch.reserve(32);
    while (!g_stop.load()) {
        batch.clear();
        {
            std::lock_guard<std::mutex> lk(g_qMtx);
            while (!g_queue.empty() && batch.size() < 32) {
                batch.push_back(g_queue.front());
                g_queue.pop_front();
            }
        }
        if (batch.empty()) {
            if (g_qEvent) WaitForSingleObject(g_qEvent, 200);
            else Sleep(20);
            continue;
        }
        if (g_sink) {
            for (const auto& e : batch) {
                g_sink(e);
                g_delivered.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  启动 / 停止
// ---------------------------------------------------------------------------
bool Start(ConnSink sink) {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return true;   // 幂等

    g_sink = sink;
    g_stop.store(false);
    g_startMs.store(NowMsSteady());          // IsHealthy 启动宽限期起点
    g_sessionName = MakeSessionName();

    g_qEvent    = CreateEventW(nullptr, FALSE, FALSE, nullptr);   // 自动重置
    g_stopEvent = CreateEventW(nullptr, TRUE,  FALSE, nullptr);

    // [1] 创建会话
    //  ★ 固定名 ⇒ 先清同名残留；清完仍可能因内核尚未回收而 183 ⇒ 有限重试（≤3 次，每次等 200ms）。
    //    ⚠️ 重试硬上限：无限重试 = 卡死启动路径。
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ERROR_SUCCESS;
    bool  started = false;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        PurgeStaleSession();
        if (attempt > 1) Sleep(200);

        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize    = (ULONG)props.size();
        p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 1;                // 1 = QPC 时间戳
        p->BufferSize          = 64;               // KB（实测 25 条/秒，绰绰有余）
        p->MinimumBuffers      = 32;
        p->MaximumBuffers      = 128;
        p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        p->FlushTimer          = 1;                // 1 秒刷一次（实时性）
        p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

        st = StartTraceW(&g_session, wname.c_str(), p);
        if (st == ERROR_SUCCESS) { started = true; break; }
        g_session = 0;
        if (st == ERROR_ALREADY_EXISTS) {
            LogDbg("[netwatch] StartTraceW 撞同名会话（183，第 " + std::to_string(attempt) +
                   "/3 次），清理后重试");
            continue;
        }
        break;
    }
    if (!started) {
        // 错误码语义：5=权限不足 / 183=会话名冲突 / 1450=会话数上限
        LogDbg("[netwatch] StartTraceW 失败，错误码 " + std::to_string(st) +
               "（5=权限不足 183=会话名冲突 1450=会话数上限）→ 网络采集层不可用，其它事件源不受影响");
        g_running.store(false);
        if (g_qEvent)    { CloseHandle(g_qEvent);    g_qEvent = nullptr; }
        if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
        return false;
    }

    // [2] 订阅 provider（v4 + v6 两个 keyword 一起订）
    st = EnableTraceEx2(g_session, &kKernelNetwork,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION,
                        kKeywordIpv4 | kKeywordIpv6,
                        0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        LogDbg("[netwatch] EnableTraceEx2 失败，错误码 " + std::to_string(st) + " → 网络采集层不可用");
        Stop();
        g_running.store(false);
        return false;
    }

    // [3] 打开实时消费
    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = (LPWSTR)wname.c_str();
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = OnEventRecord;

    g_trace = OpenTraceW(&lf);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        LogDbg("[netwatch] OpenTraceW 失败，错误码 " + std::to_string(GetLastError()) + " → 网络采集层不可用");
        Stop();
        g_running.store(false);
        return false;
    }

    // [4] ProcessTrace 阻塞，必须独立线程；消费另起一个
    g_thread = std::thread([] { ProcessTrace(&g_trace, 1, nullptr, nullptr); });
    g_consumer = std::thread(ConsumeLoop);

    LogDbg("[netwatch] 网络外联采集已启动，会话名 " + g_sessionName +
           "（provider=Microsoft-Windows-Kernel-Network，仅 id=10 TCP 连接建立，v4+v6）");
    return true;
}

void Stop() {
    g_running.store(false);
    g_stop.store(true);
    if (g_qEvent)    SetEvent(g_qEvent);
    if (g_stopEvent) SetEvent(g_stopEvent);

    // ★ 顺序不能反：先 CloseTrace 让阻塞中的 ProcessTrace 返回，再 join
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_thread.joinable()) g_thread.join();
    if (g_consumer.joinable()) g_consumer.join();

    if (g_session) {
        // ★ 2026-10-02：显式 DISABLE_PROVIDER —— 旧实现只有 ENABLE、无 DISABLE，
        //   注销仅靠 STOP 隐式副作用；STOP 失败/崩溃时内核侧留下"已订阅但无人消费"
        //   记录，随残留累积。显式关一次幂等，失败不致命。
        EnableTraceEx2(g_session, &kKernelNetwork,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION,
                       kKeywordIpv4 | kKeywordIpv6, 0, 0, nullptr);
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
    s.parseFail   = g_parseFail.load();
    s.lastEventMs = g_lastEventMs.load();
    return s;
}

bool IsHealthy(uint64_t silentMs) {
    if (!g_running.load()) return false;
    uint64_t last  = g_lastEventMs.load();
    uint64_t start = g_startMs.load();
    if (last == 0) {
        // ★ 2026-10-03 修正（铁律 24「哑巴兜底」同族，照 iowatch.cpp:994 的已验证修法）：
        //   原实现 `if (last == 0) return true;`
        //   ⇒ **从未收到过任何事件 = 健康** ⇒ 采集面彻底哑火时 0 告警，故障被完全掩盖。
        //   实证代价（Win10 虚拟机真样本那一轮）：挖矿进程 CPU 100% 烧了一整轮，
        //   而本函数一直报「健康」—— 挖矿必然连矿池、却零外联事件，是**最该报**的一次，
        //   恰恰被这条兜底吞掉了。
        //   改为只给启动宽限期内算「待机健康」，超窗仍零事件即判不健康。
        return (NowMsSteady() - start) <= kStartupGraceMs;
    }
    return (NowMsSteady() - last) <= silentMs;
}

std::string SessionName() { return g_sessionName; }

}  // namespace netwatch
}  // namespace sf
