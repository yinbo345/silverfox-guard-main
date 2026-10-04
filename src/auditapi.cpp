// auditapi.cpp — 跨进程注入 / 内存加载采集层实现
//
// 范式严格对照 netwatch.cpp（网络）/ iowatch.cpp（文件+注册表）：
//   OpenTrace + ProcessTrace 独立线程；EID 分流；属性表驱动取值（不硬编码字段名，
//   避开 TDH 大小写敏感坑）；回调只入队 + 独立消费线程出队后调 sink。
//
// 为什么要"两段式"（回调只入队、消费线程出队）：ETW 回调线程不允许久留，
// 且我们在这里做 TDH 解析 + ImagePathOfPid（后者会 OpenProcess），必须在
// 消费线程做，不能堵 ETW 派发线程。
#include "auditapi.h"

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

#include "common.h"    // LogDbg
#include "behavior.h"  // ImagePathOfPid（补全发起/目标进程映像名）

#pragma comment(lib, "tdh.lib")

namespace sf {
namespace auditapi {

// ---------------------------------------------------------------------------
//  单调时钟毫秒（与 netwatch / iowatch / rollback 同口径）
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

static std::string W2U8(const wchar_t* w, int n = -1) {
    if (!w) return "";
    int m = WideCharToMultiByte(CP_UTF8, 0, w, n, nullptr, 0, nullptr, nullptr);
    if (m <= 1) return "";
    std::string s(m - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, n, &s[0], m, nullptr, nullptr);
    return s;
}

// ---------------------------------------------------------------------------
//  Provider 常量（本机 logman 实测确认，非网络抄写）
// ---------------------------------------------------------------------------
//  Microsoft-Windows-Kernel-Audit-API-Calls
static const GUID kProvider =
    { 0xE02A841C, 0x75A3, 0x4FA7, { 0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23 } };

// 关键字掩码：**本 provider 在 logman 中无 keyword 定义（事件 keyword=0），
// 必须以掩码 0 启用才能收到**（填全 1 反而收不到——经典陷阱）。
static const ULONGLONG kKeyword = 0;

// 事件 ID（由社区 Ghidra 解析 ntoskrnl 符号得出，见 survey 文档 §②-(d)）
static const USHORT kEvLoadImgCb = 1;   // PsSetLoadImageNotifyRoutine
static const USHORT kEvTerminate  = 2;   // NtTerminateProcess
static const USHORT kEvSymlink    = 3;   // NtCreateSymbolicLinkObject
static const USHORT kEvSetCtx     = 4;   // NtSetContextThread（铁证注入）
static const USHORT kEvOpenProc   = 5;   // NtOpenProcess
static const USHORT kEvOpenThread = 6;   // NtOpenThread

// Windows 访问掩码位（用于 OpenProcess/OpenThread 注入前兆判定）
static const uint32_t kAccessVmWrite       = 0x20;   // PROCESS_VM_WRITE
static const uint32_t kAccessVmOperation   = 0x8;    // PROCESS_VM_OPERATION
static const uint32_t kAccessCreateThread  = 0x2;    // PROCESS_CREATE_THREAD

// ---------------------------------------------------------------------------
//  全局状态
// ---------------------------------------------------------------------------
static std::atomic<bool>  g_running{ false };
static std::atomic<bool>  g_stop{ false };

static TRACEHANDLE        g_session = 0;
static TRACEHANDLE        g_trace   = 0;
static std::thread        g_thread;     // ProcessTrace 线程
static std::thread        g_consumer;   // 消费线程
static ApiSink            g_sink   = nullptr;
static std::string        g_sessionName;

static std::atomic<uint64_t> g_received{ 0 };
static std::atomic<uint64_t> g_delivered{ 0 };
static std::atomic<uint64_t> g_dropped{ 0 };
static std::atomic<uint64_t> g_parseFail{ 0 };
static std::atomic<uint64_t> g_lastEventMs{ 0 };

// ★ 2026-10-02：每个 EID 只打一次属性名清单（位图，bit(eid) 已打印）。
//   为什么必须做：本模块全靠 payload 字段名取值（kCandTgtPid 等），而"哪个字段是
//   真目标"这件事此前**只能靠猜** —— 实测 OpenThread(EID 6) 的 tgtPid 被解析成
//   **调用方自己**（tgt==src），疑似兜底候选里那条裸 L"ProcessId" 取错了字段；
//   而 tgt==src 会让 service 侧的 selfOp 守卫把事件整条丢掉 → **真注入被静默漏报**。
//   逐 EID 打一次真实属性名，就能把 EID↔字段映射钉死，不再靠推测。
static std::atomic<uint32_t> g_eidDumped{ 0 };

// 队列：回调只入队原始 EVENT_RECORD 的最小必要字段，消费线程出队做 TDH 解析 + sink
struct RawRec {
    USHORT eid = 0;
    ULONG  srcPid = 0;       // EVENT_HEADER.ProcessId
    ULONG  tgtPid = 0;       // payload TargetProcessId（取不到为 0）
    ULONG  tgtTid = 0;       // payload TargetThreadId
    uint32_t desiredAccess = 0;
    uint32_t returnCode = 0;
    bool    hasTgtPid = false;
    bool    hasTid = false;
    bool    hasAccess = false;
    bool    hasRet = false;
    uint64_t atMs = 0;
};

static const size_t kQueueCap = 4096;
static std::mutex         g_qMtx;
static std::deque<RawRec> g_queue;
static HANDLE             g_qEvent = nullptr;
static HANDLE             g_stopEvent = nullptr;

// ★★ 2026-10-02（铁律 35）：会话名由「随机后缀」改回**固定名**。
//   理由与 etwproc / iowatch / netwatch 一致：随机名 ⇒ 每次重建换新名 ⇒ 残留只增不减
//   ⇒ 累积撞 1450 后内核 provider 订阅表劣化 ⇒ 事件静默不来、唯 OS 重启可清。
//   固定名后：重建即覆盖同一会话；配合 PurgeStaleSession() + 183 有限重试。
static const char* kSessionName = "SilverFoxGuardApi";

static std::string MakeSessionName() {
    return std::string(kSessionName);
}

// 清理"同名残留会话"（ControlTraceW 第一参数传 0；4201=本就没有同名会话，正常）。
static void PurgeStaleSession() {
    if (g_sessionName.empty()) return;
    std::vector<BYTE> pb(sizeof(EVENT_TRACE_PROPERTIES) + g_sessionName.size() * 2 + 16);
    EVENT_TRACE_PROPERTIES* prop = (EVENT_TRACE_PROPERTIES*)pb.data();
    ZeroMemory(prop, sizeof(*prop));
    prop->Wnode.BufferSize = (ULONG)pb.size();
    prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ControlTraceW(0, wname.c_str(), prop, EVENT_TRACE_CONTROL_STOP);
    if (st == ERROR_SUCCESS) {
        LogDbg("[auditapi] 已清理同名残留会话（" + g_sessionName + "）");
    }
}

// ★ 显式 DISABLE_PROVIDER（幂等；失败不致命）。口径与 etwproc/iowatch/netwatch 一致：
//   旧实现只有 ENABLE、无 DISABLE，注销全靠 STOP 的隐式副作用。
static void DisableProvider() {
    if (!g_session) return;
    EnableTraceEx2(g_session, &kProvider, EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                   TRACE_LEVEL_INFORMATION, kKeyword, 0, 0, nullptr);
}

// ---------------------------------------------------------------------------
//  TDH 属性表驱动取值（避开大小写敏感坑：先用真实名字，再按真实名字取）
// ---------------------------------------------------------------------------
static bool ReadUlongByCandidates(PEVENT_RECORD ev,
                                  const TRACE_EVENT_INFO* info,
                                  const std::vector<std::wstring>& cands,
                                  ULONG* out) {
    const ULONG n = info->TopLevelPropertyCount;
    for (const auto& cand : cands) {
        for (ULONG i = 0; i < n; ++i) {
            const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
            if (p.NameOffset == 0) continue;
            std::wstring nm = (const wchar_t*)((const BYTE*)info + p.NameOffset);
            if (_wcsicmp(nm.c_str(), cand.c_str()) != 0) continue;
            PROPERTY_DATA_DESCRIPTOR pd{};
            pd.PropertyName = (ULONGLONG)(ULONG_PTR)nm.c_str();
            pd.ArrayIndex = ULONG_MAX;
            ULONG sz = 0;
            if (TdhGetPropertySize(ev, 0, nullptr, 1, &pd, &sz) != ERROR_SUCCESS) break;
            std::vector<BYTE> buf(sz ? sz : 4);
            if (TdhGetProperty(ev, 0, nullptr, 1, &pd, sz, buf.data()) != ERROR_SUCCESS) break;
            if (sz >= sizeof(ULONG)) { memcpy(out, buf.data(), sizeof(ULONG)); return true; }
        }
    }
    return false;
}

// 候选字段名（不同 Windows 版本/工具导出可能大小写不同，这里给常见形态）
static const std::vector<std::wstring> kCandTgtPid  = { L"TargetProcessId", L"ProcessId", L"TargetPid" };
static const std::vector<std::wstring> kCandTgtTid  = { L"TargetThreadId", L"ThreadId", L"TargetTid" };
static const std::vector<std::wstring> kCandAccess  = { L"DesiredAccess", L"AccessMask", L"DesiredAccessMask" };
static const std::vector<std::wstring> kCandRetCode = { L"ReturnCode", L"Status", L"NtStatus" };

// ---------------------------------------------------------------------------
//  ETW 回调：只解析最小字段入队（重活在消费线程做）
// ---------------------------------------------------------------------------
static VOID WINAPI OnEvent(PEVENT_RECORD ev) {
    if (!ev || !ev->UserData) return;
    GUID prov = ev->EventHeader.ProviderId;
    if (memcmp(&prov, &kProvider, sizeof(GUID)) != 0) return;

    const USHORT eid = ev->EventHeader.EventDescriptor.Id;
    if (eid < 1 || eid > 6) return;   // 只关心 1~6（7/8 关机通知低价值，留档不采）

    RawRec r{};
    r.eid    = eid;
    r.srcPid = ev->EventHeader.ProcessId;
    r.atMs   = NowMsSteady();

    // 只在确有 payload 时解析目标字段（id=1 回调注册可能没有 TargetProcessId）
    if (ev->UserDataLength >= 4) {
        ULONG sz = 0;
        DWORD rc = TdhGetEventInformation(ev, 0, nullptr, nullptr, &sz);
        if (rc == ERROR_INSUFFICIENT_BUFFER && sz > 0) {
            std::vector<BYTE> buf(sz);
            TRACE_EVENT_INFO* info = (TRACE_EVENT_INFO*)buf.data();
            if (TdhGetEventInformation(ev, 0, nullptr, info, &sz) == ERROR_SUCCESS) {
                ULONG v = 0;
                // ★ 2026-10-02：每个 EID 首次出现时把真实属性名清单打进日志（仅一次/EID）。
                //   一次性付出的 6 行日志，换来"EID↔字段"永久确定 —— 见 g_eidDumped 注释。
                {
                    const uint32_t bit = 1u << (eid & 31u);
                    if (!(g_eidDumped.fetch_or(bit) & bit)) {
                        std::string names;
                        const ULONG np = info->TopLevelPropertyCount;
                        for (ULONG i = 0; i < np; ++i) {
                            const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
                            if (p.NameOffset == 0) continue;
                            const wchar_t* wn = (const wchar_t*)((const BYTE*)info + p.NameOffset);
                            for (const wchar_t* q = wn; *q; ++q)
                                names += (char)((*q < 128) ? *q : '?');
                            names += ",";
                        }
                        LogDbg("[auditapi] EID=" + std::to_string(eid) +
                               " 属性名=[" + names + "]");
                    }
                }
                if (ReadUlongByCandidates(ev, info, kCandTgtPid, &v)) { r.tgtPid = v; r.hasTgtPid = true; }
                if (ReadUlongByCandidates(ev, info, kCandTgtTid, &v)) { r.tgtTid = v; r.hasTid = true; }
                if (ReadUlongByCandidates(ev, info, kCandAccess, &v)) { r.desiredAccess = v; r.hasAccess = true; }
                if (ReadUlongByCandidates(ev, info, kCandRetCode, &v)) { r.returnCode = v; r.hasRet = true; }
            } else {
                g_parseFail.fetch_add(1);
            }
        }
    }

    g_received.fetch_add(1);
    g_lastEventMs.store(r.atMs);

    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        if (g_queue.size() >= kQueueCap) { g_queue.pop_front(); g_dropped.fetch_add(1); }
        g_queue.push_back(r);
    }
    if (g_qEvent) SetEvent(g_qEvent);
}

// ---------------------------------------------------------------------------
//  消费线程：出队 → 补全映像名 → 调 sink
// ---------------------------------------------------------------------------
static void ConsumerLoop() {
    while (!g_stop.load()) {
        RawRec r;
        {
            std::unique_lock<std::mutex> lk(g_qMtx);
            if (g_queue.empty()) {
                lk.unlock();
                if (WaitForSingleObject(g_qEvent, 500) == WAIT_TIMEOUT) continue;
                lk.lock();
                if (g_queue.empty()) continue;
            }
            r = g_queue.front();
            g_queue.pop_front();
        }

        ApiEvent e{};
        switch (r.eid) {
            case kEvLoadImgCb: e.op = ApiOp::LoadImageCallback; break;
            case kEvTerminate:  e.op = ApiOp::TerminateProcess;  break;
            case kEvSymlink:    e.op = ApiOp::CreateSymlink;    break;
            case kEvSetCtx:     e.op = ApiOp::SetContextThread; break;
            case kEvOpenProc:   e.op = ApiOp::OpenProcess;      break;
            case kEvOpenThread: e.op = ApiOp::OpenThread;       break;
            default:            e.op = ApiOp::Unknown;          break;
        }
        e.eid = r.eid;
        e.hasAccess = r.hasAccess;
        e.hasRet = r.hasRet;
        e.srcPid = r.srcPid;
        e.tgtPid = r.hasTgtPid ? r.tgtPid : 0;
        e.tgtTid = r.hasTid ? r.tgtTid : 0;
        e.desiredAccess = r.desiredAccess;
        e.returnCode = r.returnCode;
        e.atMs = r.atMs;
        // 补全发起 / 目标映像名（与进程台账 join —— 这是本路事件价值的来源）
        //
        // ★★★ 2026-10-02 加门控 —— 这是「自我放大反馈环」的根因修复：
        //   原实现**对每一条事件无条件**调两次 sf::ImagePathOfPid，而该函数内部是
        //   OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)（behavior.cpp:1238）。
        //   于是：**我们每消费一条 NtOpenProcess 事件，就自己再产生 1~2 条
        //   NtOpenProcess 事件**，重新进同一队列 → 自己喂自己。
        //   实测 5 分钟窗口 OpenProcess=1,719,591（≈5732 条/秒），
        //   且数字完全自洽于"我们看到的 OpenProcess 几乎全部由我们自己产生"：
        //     · 采到≈2×投递（丢队列 51%）  ← 我们生成 2×，回来一半被丢
        //     · OpenProcess/s ≈ 2×投递/s
        //   代价：真实事件被这股自噪声挤进 51% 的丢弃区 → **判定退化成概率性的**。
        //
        //   门控判据 = 该事件**有可能**通过注入判定，与 service.cpp 的
        //   injCapProc / injCapThr / setCtx 三条判据严格一致：
        //     · SetContextThread  —— 铁证注入，不看掩码（对应 setCtx）
        //     · OpenProcess        —— 需 CREATE_THREAD + (VM_OPERATION|VM_WRITE)
        //     · OpenThread         —— 需 SUSPEND_RESUME + (GET_CONTEXT|SET_CONTEXT)
        //   不满足者**即便查了映像名也不会进入判定**（service 侧同一门控直接跳过），
        //   故本改动**语义零损失**，而自噪声归零。
        //   ⚠️ 真实注入（掩码含 0x2 + 内存/上下文位）照旧会查名、照旧会判定。
        //   ⚠️ auditapiq 的展示不再依赖这里补名：该命令改为**查询时**按需补全
        //      （见 mod_auditapi.cpp），人工触发、不构成反馈环。
        const uint32_t kProcInjBits = 0x0002u | (0x0008u | 0x0020u);
        const uint32_t kThrInjBits  = 0x0002u | (0x0008u | 0x0010u);
        bool couldJudge = (e.op == ApiOp::SetContextThread);
        if (!couldJudge && e.hasAccess) {
            if (e.op == ApiOp::OpenProcess)
                couldJudge = ((e.desiredAccess & kProcInjBits) == kProcInjBits);
            else if (e.op == ApiOp::OpenThread)
                couldJudge = ((e.desiredAccess & kThrInjBits) == kThrInjBits);
        }
        // src==tgt 的自开自不算跨进程注入（service 侧 selfOp 守卫同样排除）→ 连名都不必查
        if (couldJudge && e.tgtPid != 0 && e.tgtPid != e.srcPid) {
            e.srcImage = sf::ImagePathOfPid(r.srcPid);
            e.tgtImage = sf::ImagePathOfPid(e.tgtPid);
        }

        g_delivered.fetch_add(1);
        if (g_sink) g_sink(e);
    }
}

// ---------------------------------------------------------------------------
//  启动 / 停止
// ---------------------------------------------------------------------------
bool Start(ApiSink sink) {
    if (g_running.load()) return true;
    g_sink = sink;
    g_stop.store(false);

    g_sessionName = MakeSessionName();
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());  // ASCII→宽字符（与 iowatch 同形）
    g_qEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);

    // [1] 创建会话（实时模式）
    //  ★ 固定名 ⇒ 先清同名残留；撞 183 时有限重试（≤3 次，每次等 200ms）。⚠️ 重试硬上限。
    std::vector<BYTE> pb(sizeof(EVENT_TRACE_PROPERTIES) + g_sessionName.size() * 2 + 16);
    EVENT_TRACE_PROPERTIES* prop = (EVENT_TRACE_PROPERTIES*)pb.data();
::ZeroMemory(prop, sizeof(*prop));
    prop->Wnode.BufferSize = (ULONG)pb.size();
    prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    prop->Wnode.ClientContext = 1;                 // QPC
    prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG rc = ERROR_SUCCESS;
    bool  started = false;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        PurgeStaleSession();
        if (attempt > 1) Sleep(200);
        rc = StartTraceW(&g_session, wname.c_str(), prop);
        if (rc == ERROR_SUCCESS) { started = true; break; }
        g_session = 0;
        if (rc == ERROR_ALREADY_EXISTS) {
            LogDbg("[auditapi] StartTrace 撞同名会话（183，第 " + std::to_string(attempt) +
                   "/3 次），清理后重试");
            continue;
        }
        break;
    }
    if (!started) {
        LogDbg("[auditapi] StartTrace rc=" + std::to_string(rc) + "（需 SYSTEM/管理员）—— 降级为不可用");
        return false;
    }

    // [2] 订阅 provider（keyword=0：事件 keyword=0 必须以掩码 0 收；填全 1 反而收不到）
    ENABLE_TRACE_PARAMETERS en{};
    en.Version = ENABLE_TRACE_PARAMETERS_VERSION_2;
    rc = EnableTraceEx2(g_session, &kProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, kKeyword, 0, 0, &en);
    if (rc != ERROR_SUCCESS) {
        LogDbg("[auditapi] EnableTrace rc=" + std::to_string(rc) + " keyword=0 → 降级为不可用");
        DisableProvider();
        ControlTraceW(g_session, nullptr, prop, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
        return false;
    }

    // [3] 打开 trace
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = (LPWSTR)wname.c_str();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_REAL_TIME;
    log.EventRecordCallback = OnEvent;
    g_trace = OpenTraceW(&log);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        LogDbg("[auditapi] OpenTrace 失败 → 降级为不可用");
        DisableProvider();
        ControlTraceW(g_session, nullptr, prop, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
        return false;
    }

    g_running.store(true);
    g_thread = std::thread([] { ProcessTrace(&g_trace, 1, nullptr, nullptr); });
    g_consumer = std::thread(ConsumerLoop);
    LogDbg("[auditapi] 注入/跨进程事件采集已启动，provider=Kernel-Audit-API-Calls(kw=0)");
    return true;
}

void Stop() {
    if (!g_running.load()) return;
    g_stop.store(true);
    if (g_stopEvent) SetEvent(g_stopEvent);
    if (g_qEvent) SetEvent(g_qEvent);
    if (g_session) {
        // ★ 2026-10-02：显式 DISABLE_PROVIDER（口径与其它三模块一致）。
        DisableProvider();
        std::vector<BYTE> pb(sizeof(EVENT_TRACE_PROPERTIES) + g_sessionName.size() * 2 + 16);
        EVENT_TRACE_PROPERTIES* prop = (EVENT_TRACE_PROPERTIES*)pb.data();
::ZeroMemory(prop, sizeof(*prop));
        prop->Wnode.BufferSize = (ULONG)pb.size();
        prop->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        prop->Wnode.ClientContext = 1;
        prop->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        prop->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(g_session, nullptr, prop, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
    if (g_consumer.joinable()) g_consumer.join();
    if (g_thread.joinable()) g_thread.join();
    if (g_qEvent) { CloseHandle(g_qEvent); g_qEvent = nullptr; }
    if (g_stopEvent) { CloseHandle(g_stopEvent); g_stopEvent = nullptr; }
    g_running.store(false);
}

bool IsRunning() { return g_running.load(); }

bool IsHealthy(uint64_t silentMs) {
    if (!g_running.load()) return false;
    uint64_t last = g_lastEventMs.load();
    if (last == 0) return true;   // 刚启动，给宽容期
    uint64_t now = NowMsSteady();
    // 用系统启动后的毫秒单调量比较（atMs 已是 QPC 转换的毫秒）
    return (now - last) < silentMs;
}

Stats GetStats() {
    Stats s;
    s.received  = g_received.load();
    s.delivered = g_delivered.load();
    s.dropped   = g_dropped.load();
    s.parseFail = g_parseFail.load();
    s.lastEventMs = g_lastEventMs.load();
    return s;
}

std::string SessionName() { return g_sessionName; }

// ---------------------------------------------------------------------------
//  诊断环形缓冲（auditapiq 命令）
// ---------------------------------------------------------------------------
static std::mutex         g_recentMtx;
static std::deque<ApiEvent> g_recent;

std::vector<ApiEvent> Recent(size_t maxCount) {
    std::lock_guard<std::mutex> lk(g_recentMtx);
    std::vector<ApiEvent> out;
    size_t n = g_recent.size();
    if (maxCount && maxCount < n) n = maxCount;
    auto it = g_recent.end();
    std::advance(it, -(long)n);
    for (auto i = it; i != g_recent.end(); ++i) out.push_back(*i);
    return out;
}

void ClearRecent() {
    std::lock_guard<std::mutex> lk(g_recentMtx);
    g_recent.clear();
}

// 由 service.cpp 的 sink 在喂完上层后回捞进环形缓冲（保持对外 API 纯净）
void PushRecent(const ApiEvent& e) {
    std::lock_guard<std::mutex> lk(g_recentMtx);
    if (g_recent.size() >= kRecentCap) g_recent.pop_front();
    g_recent.push_back(e);
}

}  // namespace auditapi
}  // namespace sf
