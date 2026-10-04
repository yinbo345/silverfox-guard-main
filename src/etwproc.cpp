// etwproc.cpp — 进程创建事件采集层实现（照 netwatch.cpp 的 ETW 两段式范式）
//
// ===========================================================================
//  与 netwatch.cpp 的差异点（其余结构一一对应，勿"顺手统一"掉差异）：
//    · provider 换成 Microsoft-Windows-Kernel-Process，keyword 0x10；
//    · 只处理 id=1（ProcessStart），字段用 TDH 按名取（版本差异由 TDH 兜）；
//    · ImageFileName 是 UnicodeString（UTF-16LE），需转 UTF-8；
//    · 健康阈值 30 秒（进程事件比网络事件密）。
// ===========================================================================
#include "etwproc.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <cstring>     // memcpy（payload 偏移回退解析用）
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "common.h"    // LogDbg
#include "sfstop.h"    // StopHandle / IsStopRequested

#pragma comment(lib, "tdh.lib")

namespace sf {
namespace etwproc {

// ---------------------------------------------------------------------------
//  单调时钟毫秒（与 netwatch.cpp 同口径，逐字一致 —— 跨模块比较时间戳口径必须一致）
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
//  Microsoft-Windows-Kernel-Process（系统自带 manifest provider，Win8+ 可用）
static const GUID kKernelProcess =
    { 0x22FB2CD6, 0x0E7B, 0x422B, { 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16 } };

// 事件 ID：只关心 ProcessStart（id=1）。
//  id=2 ProcessStop / id=3 ThreadStart / id=5 ImageLoad 等都不订阅。
static const USHORT kEvProcessStart = 1;

// Keyword 位：0x10 = WINEVENT_KEYWORD_PROCESS（进程生命周期事件）。
static const ULONGLONG kKeywordProcess = 0x10;

// ---------------------------------------------------------------------------
//  全局状态（与 netwatch.cpp 同构）
// ---------------------------------------------------------------------------
static std::atomic<bool>  g_running{ false };
static std::atomic<bool>  g_stop{ false };

static TRACEHANDLE        g_session = 0;
static TRACEHANDLE        g_trace   = 0;
static std::thread        g_thread;
static std::thread        g_consumer;
static ProcSink           g_sink = nullptr;
static std::string        g_sessionName;

static std::atomic<uint64_t> g_received{ 0 };
static std::atomic<uint64_t> g_delivered{ 0 };
static std::atomic<uint64_t> g_dropped{ 0 };
static std::atomic<uint64_t> g_parseFail{ 0 };
static std::atomic<uint64_t> g_lastEventMs{ 0 };

// ★★ 2026-10-01：存活探针状态。
//   为什么放进本模块而不是 service.cpp：探针的"收到没收到"判据必须在
//   **事件解析这一层**就打上（OnEventRecord），若放到 sink 里判断，
//   一旦判定管线卡住或 sink 被换掉，探针就会误报"会话已死"→ 无谓重建。
static std::atomic<unsigned long> g_probePid{ 0 };
static std::atomic<bool>          g_probeSeen{ false };

// ★★ 2026-10-02：ProcessTrace 异常自愈状态（见头文件 TakeWmiFallbackRequest 的说明）。
//   g_restartTried：本世代（一次 Start 到一次 Stop）是否已经用过"强制重启一次"的额度。
//     ★ 必须是"一次性额度" —— 否则会话反复报错会变成无限重启循环（等于没有回退）。
//   g_wmiFallback ：二次失败后置位，等上层 TakeWmiFallbackRequest() 取走。
//   g_sessMtx     ：串行化"会话/句柄"的建立与拆除 —— 异常重启发生在 ProcessTrace 线程内，
//     而 Stop() 可能被别的线程同时调用，两者都会动 g_session / g_trace。
//     ★ 纪律：**绝不在持锁状态下 join 线程**（重启路径与 Stop 路径会互等成死锁）。
static std::atomic<bool>     g_restartTried{ false };
static std::atomic<bool>     g_wmiFallback{ false };
static std::atomic<uint64_t> g_ptErrors{ 0 };
static std::atomic<uint64_t> g_ptRestarts{ 0 };
static std::mutex            g_sessMtx;

static const size_t kQueueCap = 4096;
static std::mutex         g_qMtx;
static std::deque<ProcEvent> g_queue;
static HANDLE             g_qEvent    = nullptr;
static HANDLE             g_stopEvent = nullptr;

// ★★ 2026-10-02（铁律 35）：会话名由「随机后缀」改回**固定名**。
//   旧实现：`SilverFoxGuardProc-<PID><毫秒低16位>` —— 每次重建都换新名，
//   本意是"规避上一次崩溃残留的同名会话（183）"。但代价是致命的：
//     · 名字只增不减 ⇒ 残留永不被复用、越积越多（实测 etwproc 79 个名 / 只退出 55）；
//     · 累积撞上 1450（会话数上限）后，内核 provider 的订阅表劣化
//       ⇒ "会话建得起来、事件却一条不来"（一活三死、跨进程存活、唯 OS 重启可清）；
//     · 随机名**并不能**阻止针对性 STOP —— 恶意程序遍历会话即可拿到名字。
//   现在：固定名 ⇒ 重建就是覆盖同一个会话，残留无处累积；
//   再配合 PurgeStaleSession()（建会话前清同名残留）+ 撞 183 时有限重试，
//   既不留残留，也不再需要"换名绕过"。
static const char* kSessionName = "SilverFoxGuardProc";

static std::string MakeSessionName() {
    return std::string(kSessionName);
}

// ★ 清理"同名残留会话"：STOP 掉内核里可能与本次同名的旧会话。
//   ⚠️ ControlTraceW 第一参数传 **0**，不是 g_session —— 要清的是"内核里名字相同的
//      会话"，而我们手上的句柄此刻可能已是 0 / 或正是那个残留本身。
//   4201（ERROR_WMI_INSTANCE_NOT_FOUND）= 本就没有同名会话，属正常，不打印。
static void PurgeStaleSession() {
    if (g_sessionName.empty()) return;
    std::vector<BYTE> props(1024, 0);
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
    p->Wnode.BufferSize = (ULONG)props.size();
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ControlTraceW(0, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
    if (st == ERROR_SUCCESS) {
        LogDbg("[etwproc] 已清理同名残留会话（" + g_sessionName + "）");
    }
}

// ---------------------------------------------------------------------------
//  ★ 字段解析（TDH 按属性名取值 —— 版本差异由 TDH 兜，不手推偏移）
// ---------------------------------------------------------------------------

// 取无符号整数字段
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

// 取 UnicodeString 字段（UTF-16LE，TDH 给出原始字节）→ UTF-8
static bool GetEventString(PEVENT_RECORD ev, LPCWSTR propName, std::string* out) {
    if (!ev || !propName || !out) return false;
    PROPERTY_DATA_DESCRIPTOR pd;
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)propName;
    pd.ArrayIndex   = ULONG_MAX;
    pd.Reserved     = 0;

    ULONG size = 0;
    ULONG st = TdhGetPropertySize(ev, 0, nullptr, 1, &pd, &size);
    if (st != ERROR_SUCCESS) return false;
    if (size == 0) { out->clear(); return true; }       // 空串也是"取到了"
    if (size > 4096) return false;                       // 异常超长，防御
    std::vector<BYTE> raw(size);
    st = TdhGetProperty(ev, 0, nullptr, 1, &pd, size, raw.data());
    if (st != ERROR_SUCCESS) return false;

    // UTF-16LE → UTF-8（不含结尾 null；size 可能含 null 的 2 字节，按实长裁）
    int wlen = (int)(size / 2);
    const wchar_t* w = (const wchar_t*)raw.data();
    while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;     // 去尾部 null
    if (wlen <= 0) { out->clear(); return true; }
    int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return false;
    out->resize(n);
    WideCharToMultiByte(CP_UTF8, 0, w, wlen, &(*out)[0], n, nullptr, nullptr);
    return true;
}

// ---------------------------------------------------------------------------
//  前置过滤：丢掉必然无价值的进程创建
// ---------------------------------------------------------------------------
static bool PassFilter(const ProcEvent& e) {
    // 系统空闲/内核/会话0基础设施：判定层也会因拿不到路径跳过，这里早丢省队列
    if (e.pid == 0 || e.pid == 4) return false;
    return true;
}

// ---------------------------------------------------------------------------
//  ★ 属性名 dump（诊断用，只打前 3 条事件）
//  2026-09-23 实测 parseFail=recv（100% 解析失败）——必须先看清事件到底带哪些属性。
// ---------------------------------------------------------------------------
static void DumpEventSchema(PEVENT_RECORD ev) {
    ULONG sz = 0;
    if (TdhGetEventInformation(ev, 0, nullptr, nullptr, &sz) != ERROR_INSUFFICIENT_BUFFER) return;
    std::vector<BYTE> buf(sz);
    TRACE_EVENT_INFO* info = (TRACE_EVENT_INFO*)buf.data();
    if (TdhGetEventInformation(ev, 0, nullptr, info, &sz) != ERROR_SUCCESS) return;

    std::string names;
    for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
        const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
        if (p.NameOffset == 0) continue;
        names += (const char*)((const BYTE*)info + p.NameOffset);
        names += " ";
    }
    LogDbg("[etwproc] 事件 schema: id=" + std::to_string(ev->EventHeader.EventDescriptor.Id) +
           " version=" + std::to_string(ev->EventHeader.EventDescriptor.Version) +
           " opcode=" + std::to_string(ev->EventHeader.EventDescriptor.Opcode) +
           " payloadLen=" + std::to_string(ev->UserDataLength) +
           " 属性=[" + names + "]");
}

// ---------------------------------------------------------------------------
//  ★ payload 固定偏移回退解析（Kernel-Process id=1 ProcessStart）
//  当 TDH 按属性名取不到时兜底。布局（Win10 1607+ / Win11 实测稳定）：
//    [0]  NewProcessId    uint32
//    [4]  ParentProcessId uint32
//    [8]  SessionId       uint32
//    [12] Flags           uint32
//    [16] ImageFileName   UNICODE_STRING（uint16 字节长度 + UTF-16LE）
//  只做**初筛**用：拿到 pid 后仍会经 MakeEntityOfPid 复核，取不到就放弃 —— 不会误判。
// ---------------------------------------------------------------------------
static bool ParseByOffset(PEVENT_RECORD ev, ProcEvent& e) {
    const ULONG need = 18;   // 至少到 ImageFileName 的长度字段
    if (ev->UserDataLength < need) return false;
    const BYTE* u = (const BYTE*)ev->UserData;
    uint32_t pid = 0, ppid = 0;
    memcpy(&pid, u + 0, 4);
    memcpy(&ppid, u + 4, 4);
    if (pid == 0 || pid > 1000000) return false;   // 明显不合理 → 偏移不适用
    e.pid = pid;
    e.ppid = ppid;

    USHORT nlen = 0;
    memcpy(&nlen, u + 16, 2);
    if (nlen >= 2 && (ULONG)(18 + nlen) <= ev->UserDataLength) {
        int wlen = nlen / 2;
        const wchar_t* w = (const wchar_t*)(u + 18);
        while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;
        if (wlen > 0) {
            int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
            if (n > 0) {
                e.image.resize(n);
                WideCharToMultiByte(CP_UTF8, 0, w, wlen, &e.image[0], n, nullptr, nullptr);
            }
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
//  EventRecordCallback：只做拷贝 + 入队（严禁磁盘 I/O / 长锁）
//  解析直接内联在这里：字段按名取（TDH 兜版本差异），拿不到 PID 记 parseFail。
// ---------------------------------------------------------------------------
static VOID WINAPI OnEventRecord(PEVENT_RECORD ev) {
    if (!ev || !g_running.load(std::memory_order_relaxed)) return;
    USHORT id = ev->EventHeader.EventDescriptor.Id;
    if (id != kEvProcessStart) return;
    g_received.fetch_add(1, std::memory_order_relaxed);

    ProcEvent e;
    // ★ 2026-09-25 修正属性名（根因修复，勿"顺手改回"）：
    //   以本机 manifest 实测为准（Get-WinEvent -ListProvider
    //   "Microsoft-Windows-Kernel-Process"），Kernel-Process id=1 的真实字段名是
    //       ProcessID / ParentProcessID / ImageName
    //   —— 后两个 "ID" 是**全大写**，而且**没有** ImageFileName 这个字段。
    //   旧代码写的是 NewProcessId / ProcessId / ImageFileName。
    //   TdhGetProperty 的按名查找**区分大小写**，名字对不上就取不到值 ——
    //   这正是文件头注释里 2026-09-23 记录的「TDH 100% 解析失败、
    //   parseFail=recv、所有事件被丢弃」的根因（当时误判为"版本差异"，
    //   其实是名字写错了）。修好后 TDH 正常走通，不再依赖固定偏移。
    //   兜底列表保留旧名：万一将来微软改名，仍能取到。
    ULONG pid = 0, ppid = 0;
    GetEventU32(ev, L"ProcessID", &pid) ||
    GetEventU32(ev, L"NewProcessId", &pid);
    GetEventU32(ev, L"ParentProcessID", &ppid) ||
    GetEventU32(ev, L"ParentProcessId", &ppid);
    e.pid  = (unsigned long)pid;
    e.ppid = (unsigned long)ppid;
    GetEventString(ev, L"ImageName", &e.image) ||
    GetEventString(ev, L"ImageFileName", &e.image);
    e.atMs = NowMsSteady();

    // ★ 固定偏移兜底（保命路径，2026-09-23 实测它救过场）
    //   ① PID 完全没拿到 → 整条走偏移解析；
    //   ② PID 拿到了但 image/ppid 缺 → **只补缺口**，不覆盖 TDH 已取到的值。
    //   ②是为了避免"TDH 修好 PID 之后，反而丢掉偏移路径提供的 image"——
    //   那会把一个 bug 换成另一个更隐蔽的 bug。
    if (e.pid == 0) {
        ProcEvent fb;
        if (ParseByOffset(ev, fb)) {
            e = fb;
            e.atMs = NowMsSteady();
        } else {
            // 两条路都失败：dump 一次 schema 便于定位（节流前 3 条）
            static std::atomic<int> s_dump{ 0 };
            if (s_dump.fetch_add(1, std::memory_order_relaxed) < 3) DumpEventSchema(ev);
            g_parseFail.fetch_add(1, std::memory_order_relaxed);
            return;
        }
    } else {
        if (e.image.empty() || e.ppid == 0) {
            ProcEvent fb;
            if (ParseByOffset(ev, fb)) {
                if (e.image.empty()) e.image = fb.image;
                if (e.ppid == 0)     e.ppid  = fb.ppid;
            }
        }
        static std::atomic<int> s_dump2{ 0 };
        if (s_dump2.fetch_add(1, std::memory_order_relaxed) < 1) DumpEventSchema(ev);
    }
    if (!PassFilter(e)) return;

    // ★ 2026-10-01：存活探针 —— 探针进程的 ProcessStart 是"会话还活着"的铁证。
    //   打点位置刻意放在**解析成功之后、入队之前**：探针只关心"事件到达解析层"，
    //   不关心判定管线是否繁忙（那属于另一类健康问题）。也不受队列满/丢包影响。
    {
        const unsigned long probe = g_probePid.load(std::memory_order_relaxed);
        if (probe != 0 && e.pid == probe) g_probeSeen.store(true, std::memory_order_relaxed);
    }

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
//  消费线程：出队 → 外发给 sink（与 netwatch.cpp 同构）
// ---------------------------------------------------------------------------
static void ConsumeLoop() {
    std::vector<ProcEvent> batch;
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
//  ★★ 2026-10-02：会话建立 / 拆除（抽出 —— Start() 与"ProcessTrace 异常重启"共用）
// ---------------------------------------------------------------------------
//  ⚠️ 这两个函数**只碰 g_session / g_trace / g_sessionName**，不碰线程、事件与队列：
//     · Start() 里用：事件句柄已建好、线程还没起，失败由 Start 自己收尾；
//     · 异常重启路径里用：**本线程就是 ProcessTrace 线程**，且消费线程还活着 ——
//       所以在这里既不能 join 自己，也不能关掉 g_qEvent / g_stopEvent。
//  ⚠️ 都不加锁 —— 由调用方持 g_sessMtx（见 TraceWorker / Stop）。
// ---------------------------------------------------------------------------

// 拆除当前会话与 trace 句柄（幂等：全为 0 时是空操作）
static void TeardownSessionNoLock() {
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_session) {
        // ★ 2026-10-02：显式 DISABLE_PROVIDER —— 不要只靠 STOP 会话"隐式"注销。
        //   旧实现全工程只有 ENABLE_PROVIDER、**一处 DISABLE_PROVIDER 都没有**
        //   （已全工程 grep 确认），注销完全依赖 ControlTraceW(STOP) 的隐式副作用。
        //   当 STOP 失败 / 进程崩溃时，内核 provider 侧可能留下"已订阅但无人消费"的
        //   记录 —— 随残留会话一起累积。显式关一次是幂等的；失败不致命（会话照样 STOP），
        //   故不因它的返回码改变流程。
        EnableTraceEx2(g_session, &kKernelProcess,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, kKeywordProcess, 0, 0, nullptr);
        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize = (ULONG)props.size();
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::wstring wname(g_sessionName.begin(), g_sessionName.end());
        ControlTraceW(g_session, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
}

// 建立会话（StartTraceW → EnableTraceEx2 → OpenTraceW），用当前 g_sessionName。
// 任一步失败：就地收回已建部分（**不动线程/事件**）并返回 false。
static bool BuildSessionNoLock() {
    // [1] 创建会话
    //  ★ 固定名（见 MakeSessionName 说明）⇒ 必须先清同名残留，否则 StartTraceW 撞 183；
    //    且清完仍可能因"内核尚未真正回收旧会话"而 183，故做**有限重试**（≤3 次，每次等 200ms）。
    //    ⚠️ 重试必须硬上限 —— 无限重试 = 卡死启动路径（同族铁律：重试须硬上限 + 计数器）。
    ULONG st = ERROR_SUCCESS;
    bool  started = false;
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());   // 循环外声明：[3] 打开消费时还要用
    for (int attempt = 1; attempt <= 3; ++attempt) {
        PurgeStaleSession();
        if (attempt > 1) Sleep(200);               // 给内核回收旧会话留时间

        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize    = (ULONG)props.size();
        p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 1;                // 1 = QPC 时间戳
        p->BufferSize          = 64;               // KB
        p->MinimumBuffers      = 32;
        p->MaximumBuffers      = 128;
        p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        // ★★ 2026-10-02：**移除 EVENT_TRACE_SYSTEM_LOGGER_MODE 分支**。
        //   该模式曾是"内核 provider 需 System Logger 才能实时投递"的候选手段，
        //   但实测日志里它被启用 **18 次、18 次全无效**；更糟的是 System Logger 是
        //   **持久会话**（要求注册为 AutoLogger、跨重启存活）—— 正是残留的直接来源之一。
        //   既无效又会制造持久残留 ⇒ 彻底剔除（连同 service.cpp 的调用与头文件声明）。
        p->FlushTimer          = 1;
        p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

        st = StartTraceW(&g_session, wname.c_str(), p);
        if (st == ERROR_SUCCESS) { started = true; break; }
        g_session = 0;                             // 失败句柄不可用，别留给后续 ControlTrace

        if (st == ERROR_ALREADY_EXISTS) {          // 183：同名残留还没被回收
            LogDbg("[etwproc] StartTraceW 撞同名会话（183，第 " + std::to_string(attempt) +
                   "/3 次），清理后重试");
            continue;
        }
        break;                                     // 其它错误码：不重试
    }
    if (!started) {
        LogDbg("[etwproc] StartTraceW 失败，错误码 " + std::to_string(st) +
               "（5=权限不足 183=会话名冲突 1450=会话数上限）→ 回退 WMI 订阅");
        return false;
    }

    // [2] 订阅 provider（keyword 0x10 = 进程生命周期）
    st = EnableTraceEx2(g_session, &kKernelProcess,
                        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION,
                        kKeywordProcess,
                        0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        LogDbg("[etwproc] EnableTraceEx2 失败，错误码 " + std::to_string(st) + " → 回退 WMI 订阅");
        TeardownSessionNoLock();
        return false;
    }

    // [3] 打开实时消费
    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = (LPWSTR)wname.c_str();
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = OnEventRecord;

    g_trace = OpenTraceW(&lf);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        LogDbg("[etwproc] OpenTraceW 失败，错误码 " + std::to_string(GetLastError()) + " → 回退 WMI 订阅");
        TeardownSessionNoLock();
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  ★★ 2026-10-02：ProcessTrace 线程 —— 异常退出 → 强制重启一次 → 仍异常回退 WMI
// ---------------------------------------------------------------------------
//  判据（关键，别"顺手优化"成只看错误码）：
//    **只要不是「我们自己请求停」造成的返回，就算非正常退出。**
//    · 会话被外部 `logman stop` / 被恶意程序 ControlTrace 停掉时，ProcessTrace
//      **可能返回 ERROR_SUCCESS** —— 那是"有人把我们的会话弄没了"，绝不健康；
//    · 而服务主动停时 Stop() 是**先**置 g_stop、**再** CloseTrace ⇒ 那种返回
//      必然能看到 g_stop==true，不会被误判。
//    所以判据就是一句：`g_stop == false` 而 ProcessTrace 竟然返回了 → 异常。
static void TraceWorker() {
    for (;;) {
        TRACEHANDLE h;
        {
            std::lock_guard<std::mutex> lk(g_sessMtx);
            h = g_trace;
        }
        // ★ 取本地副本再调：ProcessTrace 不会回写该句柄，这样可避免与
        //   TeardownSessionNoLock 对 g_trace 的并发读写（数据竞争）。
        const ULONG r = ProcessTrace(&h, 1, nullptr, nullptr);

        if (g_stop.load(std::memory_order_relaxed)) return;    // 我们自己请求停的 → 正常收尾

        g_ptErrors.fetch_add(1, std::memory_order_relaxed);
        LogDbg("[etwproc] ⚠ ProcessTrace 非正常返回，错误码 " + std::to_string(r) +
               "（会话 " + g_sessionName + "，累计已收事件 " +
               std::to_string(g_received.load(std::memory_order_relaxed)) + " 条）");

        if (g_restartTried.exchange(true)) {
            // 额度已用完：第二次仍异常 → 放弃 ETW，请上层回退 WMI
            g_wmiFallback.store(true, std::memory_order_relaxed);
            g_running.store(false, std::memory_order_relaxed);
            LogDbg("[etwproc] ProcessTrace 重启后仍非正常返回 → 放弃 ETW，交上层回退 WMI 订阅");
            return;
        }

        {
            std::lock_guard<std::mutex> lk(g_sessMtx);
            if (g_stop.load(std::memory_order_relaxed)) return;  // 抢锁期间已被 Stop
            TeardownSessionNoLock();
            // ★ 固定名：不再"换新名"—— TeardownSessionNoLock 已显式 DISABLE_PROVIDER + STOP，
            //   BuildSessionNoLock 内部还会 PurgeStaleSession + 撞 183 重试，足以覆盖
            //   "旧会话尚未从内核消失"。**换名才是残留累积的根因**，此处一并去掉。
            if (BuildSessionNoLock()) {
                g_ptRestarts.fetch_add(1, std::memory_order_relaxed);
                LogDbg("[etwproc] 已强制重启 ETW 会话（会话名 " + g_sessionName + "），继续采集");
            } else {
                TeardownSessionNoLock();
                g_wmiFallback.store(true, std::memory_order_relaxed);
                g_running.store(false, std::memory_order_relaxed);
                LogDbg("[etwproc] ProcessTrace 异常后重建会话失败 → 放弃 ETW，交上层回退 WMI 订阅");
                return;
            }
        }
        // 回到循环顶部，用新句柄继续 ProcessTrace
    }
}

// ---------------------------------------------------------------------------
//  启动 / 停止（与 netwatch.cpp 同构；会话参数针对进程事件频率微调）
// ---------------------------------------------------------------------------
bool Start(ProcSink sink) {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return true;   // 幂等

    g_sink = sink;
    g_stop.store(false);
    g_restartTried.store(false);      // ★ 新世代：重置"强制重启一次"的额度
    g_wmiFallback.store(false);       // ★ 清掉上一世代遗留的回退请求
    g_sessionName = MakeSessionName();

    g_qEvent    = CreateEventW(nullptr, FALSE, FALSE, nullptr);   // 自动重置
    g_stopEvent = CreateEventW(nullptr, TRUE,  FALSE, nullptr);

    // [1..3] 建立会话（失败时 BuildSessionNoLock 已打印精确错误码并收回现场）
    bool built = false;
    {
        std::lock_guard<std::mutex> lk(g_sessMtx);
        built = BuildSessionNoLock();
    }
    if (!built) {
        g_running.store(false);
        if (g_qEvent)    { CloseHandle(g_qEvent);    g_qEvent = nullptr; }
        if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
        return false;
    }

    // [4] ProcessTrace 阻塞，必须独立线程（TraceWorker 内含"异常重启一次"的自愈）；
    //     消费另起一个
    g_thread   = std::thread(TraceWorker);
    g_consumer = std::thread(ConsumeLoop);

    LogDbg("[etwproc] 进程创建事件采集已启动（ETW），会话名 " + g_sessionName +
           "（provider=Microsoft-Windows-Kernel-Process，仅 id=1 ProcessStart；"
           "ProcessTrace 异常将自动重启一次，仍异常则回退 WMI）");
    return true;
}

void Stop() {
    g_running.store(false);
    g_stop.store(true);
    if (g_qEvent)    SetEvent(g_qEvent);
    if (g_stopEvent) SetEvent(g_stopEvent);

    // ★ 顺序不能反：先 CloseTrace 让阻塞中的 ProcessTrace 返回，再 join
    // ★ 也**绝不能持锁 join** —— TraceWorker 的异常重启路径要拿同一把锁，
    //   持锁 join 会与"抢锁后重建会话"的 worker 互等成死锁。
    {
        std::lock_guard<std::mutex> lk(g_sessMtx);
        TeardownSessionNoLock();
    }
    if (g_thread.joinable()) g_thread.join();
    if (g_consumer.joinable()) g_consumer.join();

    // 兜底再收一次（幂等）：正常路径下 worker 见 g_stop 即退、不会再建会话；
    // 但若真留下了一个，这里补收，避免会话泄漏到下一次 Start
    // （会撞 StartTraceW 183 名字冲突 / 1450 会话数上限）。
    {
        std::lock_guard<std::mutex> lk(g_sessMtx);
        TeardownSessionNoLock();
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

// ★★ 2026-10-02：一次性取走"请回退 WMI"请求（见头文件说明）。取走即清零。
bool TakeWmiFallbackRequest() {
    return g_wmiFallback.exchange(false, std::memory_order_relaxed);
}

Stats GetStats() {
    Stats s;
    s.received    = g_received.load();
    s.delivered   = g_delivered.load();
    s.dropped     = g_dropped.load();
    s.parseFail   = g_parseFail.load();
    s.lastEventMs = g_lastEventMs.load();
    s.ptErrors    = g_ptErrors.load();
    s.ptRestarts  = g_ptRestarts.load();
    return s;
}

bool IsHealthy(uint64_t silentMs) {
    if (!g_running.load()) return false;
    uint64_t last = g_lastEventMs.load();
    if (last == 0) return true;              // 还没收到过事件，不算不健康
    return (NowMsSteady() - last) <= silentMs;
}

// ---------------------------------------------------------------------------
//  ★★ 存活探针（2026-10-01 新增）—— 见头文件的长说明
// ---------------------------------------------------------------------------
//  设计纪律（三条，勿简化）：
//   ① **探针进程必须真的被创建**：只有"我们起了进程"才能保证"必然有一条
//      ProcessStart 应该到达"。看计数器做不到这一点（安静的系统没有事件）。
//   ② **探针起不来 → 返回 true（健康）**：宁可不自愈，也不可因环境问题
//      （System32 访问受限 / 进程数上限 / 沙箱）误判"会话已死"→ 无谓重建。
//      重建有代价（销毁会话 + 短暂盲窗），必须只由**阳性证据**触发。
//   ③ **超时窗口必须覆盖 ETW 缓冲刷盘**：本会话 `FlushTimer=1`，事件最迟约
//      1 秒到达；默认 6000ms 留了足够余量（实测正常情况下几十毫秒内就到）。
bool LivenessProbe(uint32_t waitMs, unsigned long* pidOut) {
    if (!g_running.load()) return false;

    // 选一个必然存在的无害程序：%SystemRoot%\System32\cmd.exe，退回 COMSPEC。
    wchar_t exe[MAX_PATH] = { 0 };
    UINT n = GetSystemDirectoryW(exe, MAX_PATH);
    std::wstring path = (n > 0) ? (std::wstring(exe, n) + L"\\cmd.exe") : std::wstring();
    if (path.empty() || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wchar_t cs[MAX_PATH] = { 0 };
        if (GetEnvironmentVariableW(L"COMSPEC", cs, MAX_PATH) > 0) path = cs;
    }
    if (path.empty() || GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        LogDbg("[etwproc] 存活探针：找不到可用的 cmd.exe，本次跳过（不判定为失效）");
        return true;
    }

    std::wstring cmd = L"\"" + path + L"\" /c exit";
    g_probeSeen.store(false, std::memory_order_relaxed);
    g_probePid.store(0, std::memory_order_relaxed);

    STARTUPINFOW si{};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cl(cmd.begin(), cmd.end());
    cl.push_back(L'\0');

    if (!CreateProcessW(nullptr, cl.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        const DWORD e = GetLastError();
        LogDbg("[etwproc] 存活探针：CreateProcessW 失败 err=" + std::to_string(e) +
               " → 本次跳过（不判定为失效）");
        return true;
    }
    // ★ 关键：**立刻**登记探针 PID，告诉 OnEventRecord"这条事件是探针的"。
    //   与 ETW 的到达时差：回调最早也要等缓冲区刷盘（≥ 几百微秒~1 秒），
    //   而这里在 CreateProcessW 返回后的微秒级完成 → 实际不存在竞态窗口。
    g_probePid.store(pi.dwProcessId, std::memory_order_relaxed);
    if (pidOut) *pidOut = pi.dwProcessId;

    bool seen = false;
    const ULONGLONG t0 = GetTickCount64();
    while (GetTickCount64() - t0 < (ULONGLONG)waitMs) {
        if (g_probeSeen.load(std::memory_order_relaxed)) { seen = true; break; }
        Sleep(50);
    }

    WaitForSingleObject(pi.hProcess, 3000);   // 收尸（cmd /c exit 秒退）
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    g_probePid.store(0, std::memory_order_relaxed);
    return seen;
}

bool IsProbePid(unsigned long pid) {
    if (pid == 0) return false;
    const unsigned long probe = g_probePid.load(std::memory_order_relaxed);
    return probe != 0 && probe == pid;
}

std::string SessionName() { return g_sessionName; }

}  // namespace etwproc
}  // namespace sf
