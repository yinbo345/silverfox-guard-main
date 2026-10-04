// guardcheck.cpp — 能力看门狗实现
//
//  背景与设计理由见 guardcheck.h。这里只讲实现上三个必须注意的点：
//
//  1) **静默阈值取各源自己的默认值**，不另设一套 —— 否则看门狗和被看门狗
//     的口径会漂移，出现「源认为自己健康、看门狗说它停摆」或反之。
//     （iowatch 120s / netwatch 60s / auditapi 120s / etwproc 30s）
//
//  2) **启动宽限只压「停摆」，不压「降级」** ——
//        宽限期内报 Grace 是为了不吵；降级（resmon 单核口径）是**事实**
//        且从第一秒就成立，不该被宽限藏起来。
//
//  3) **状态变化才打** —— 每分钟重复同一条会把日志变成噪声，而噪声会让
//     看门狗自己被无视（同铁律 24 的教训：可观测性过量等于不可观测）。
#include "guardcheck.h"

#include "common.h"        // LogDbg
#include "sfstop.h"        // IsStopRequested / StopHandle
#include "etwproc.h"       // IsRunning / GetStats
#include "iowatch.h"       // IsRunning / IsHealthy / GetStats
#include "netwatch.h"      // IsRunning / IsHealthy / GetStats
#include "auditapi.h"      // IsRunning / IsHealthy / GetStats
#include "resmon.h"        // IsRunning / SingleCoreMode

#include <atomic>
#include <vector>
#include <sstream>
#include <thread>

namespace sf {
namespace guardcheck {

namespace {

// 启动宽限：服务起来后这段时间内，任何源都可能被合法地"还没收到第一个事件"
const uint64_t kStartGraceMs = 90ULL * 1000ULL;
// 汇总打印周期
const uint64_t kSummaryMs = 5ULL * 60ULL * 1000ULL;
// 静默阈值：与各源 IsHealthy 的默认值保持一致（见文件头第 1 点）
const uint64_t kSilentEtwproc  = 30ULL * 1000ULL;
const uint64_t kSilentIowatch  = 120ULL * 1000ULL;
const uint64_t kSilentNetwatch = 60ULL * 1000ULL;
const uint64_t kSilentAuditapi = 120ULL * 1000ULL;

// ★ 时基：必须与各源 Stats::lastEventMs 同源，否则算出的「静默时长」是错的。
//   netwatch 的 NowMsSteady() 用的就是 GetTickCount64，这里保持一致。
static uint64_t NowMs() { return (uint64_t)GetTickCount64(); }

std::atomic<uint64_t> g_startMs{ 0 };
std::thread            g_thr;
std::atomic<bool>      g_running{ false };

bool InGrace() {
    const uint64_t s = g_startMs.load();
    return s != 0 && (NowMs() - s) < kStartGraceMs;
}

SrcStatus Mk(const char* name, SrcState st, const std::string& detail) {
    SrcStatus s;
    s.name = name; s.state = st; s.detail = detail;
    return s;
}

// 事件型源的通用判据：线程在否 / 宽限 / 静默
SrcStatus ProbeEventSrc(const char* name, bool running, uint64_t lastEventMs,
                        uint64_t silentMs, const char* srcTag) {
    if (!running)
        return Mk(name, SrcState::Stalled, std::string("采集线程已退出（") + srcTag + "）");
    if (InGrace())
        return Mk(name, SrcState::Grace, "启动宽限内");
    if (lastEventMs == 0)
        return Mk(name, SrcState::Stalled,
                  "已过启动宽限但**从未收到任何事件** —— 采集层多半没在工作");
    if (NowMs() - lastEventMs > silentMs)
        return Mk(name, SrcState::Stalled,
                  "静默 " + std::to_string((NowMs() - lastEventMs) / 1000) + " 秒（阈值 " +
                  std::to_string(silentMs / 1000) + " 秒）");
    return Mk(name, SrcState::Full, "");
}

}  // namespace

const char* StateName(SrcState s) {
    switch (s) {
        case SrcState::Disabled: return "未启用";
        case SrcState::Grace:    return "宽限中";
        case SrcState::Full:     return "满血";
        case SrcState::Degraded: return "降级";
        case SrcState::Stalled:  return "停摆";
    }
    return "?";
}

Report Probe() {
    Report r;
    auto put = [&](const SrcStatus& s) {
        if (r.count < 10) r.src[r.count++] = s;
        switch (s.state) {
            case SrcState::Full:     ++r.full; break;
            case SrcState::Degraded: ++r.degraded; break;
            case SrcState::Stalled:  ++r.stalled; break;
            case SrcState::Grace:    ++r.grace; break;
            case SrcState::Disabled: ++r.disabled; break;
        }
    };

    // ① 进程创建（ETW）
    {
        const auto st = etwproc::GetStats();
        put(ProbeEventSrc("进程创建", etwproc::IsRunning(), st.lastEventMs,
                          kSilentEtwproc, "etwproc"));
    }
    // ② 文件与注册表（ETW）
    {
        const auto st = iowatch::GetStats();
        put(ProbeEventSrc("文件与注册表", iowatch::IsRunning(), st.lastEventMs,
                          kSilentIowatch, "iowatch"));
    }
    // ③ 网络外联（ETW）
    {
        const auto st = netwatch::GetStats();
        put(ProbeEventSrc("网络外联", netwatch::IsRunning(), st.lastEventMs,
                          kSilentNetwatch, "netwatch"));
    }
    // ④ 跨进程注入（ETW）
    {
        const auto st = auditapi::GetStats();
        put(ProbeEventSrc("跨进程注入", auditapi::IsRunning(), st.lastEventMs,
                          kSilentAuditapi, "auditapi"));
    }
    // ⑤ 进程资源监控（轮询，非事件型）
    {
        const char* nm = "进程资源监控";
        if (!resmon::IsRunning()) {
            put(Mk(nm, SrcState::Stalled, "监控线程已退出（resmon）"));
        } else if (resmon::SingleCoreMode()) {
            // ★ 这就是今天那条事故的可见化：单核口径是**降级**（阈值更严），
            //   不是停摆，也不是满血。必须显式说出来，否则没人知道它在降级跑。
            put(Mk(nm, SrcState::Degraded,
                    "单核口径：阈值收紧为 CPU≥90% / 持续≥180s（判据严于多核）"));
        } else {
            put(Mk(nm, SrcState::Full, ""));
        }
    }
    return r;
}

std::string SummaryJson() {
    const Report r = Probe();
    std::ostringstream ss;
    ss << "{\"ok\":" << (r.allFull() ? "true" : "false")
       << ",\"count\":" << r.count
       << ",\"full\":" << r.full
       << ",\"degraded\":" << r.degraded
       << ",\"stalled\":" << r.stalled
       << ",\"grace\":" << r.grace
       << ",\"disabled\":" << r.disabled
       << ",\"sources\":[";
    for (unsigned i = 0; i < r.count; ++i) {
        if (i) ss << ",";
        ss << "{\"name\":\"" << r.src[i].name
           << "\",\"state\":\"" << StateName(r.src[i].state) << "\"";
        if (!r.src[i].detail.empty())
            ss << ",\"detail\":\"" << r.src[i].detail << "\"";
        ss << "}";
    }
    ss << "]}";
    return ss.str();
}

std::string SummaryText() {
    const Report r = Probe();
    std::ostringstream ss;
    ss << "满血 " << r.full << " / 降级 " << r.degraded << " / 停摆 " << r.stalled
       << " / 宽限 " << r.grace << " / 未启用 " << r.disabled;
    for (unsigned i = 0; i < r.count; ++i) {
        const SrcStatus& s = r.src[i];
        if (s.state == SrcState::Full) continue;
        ss << "\n    · " << s.name << " = " << StateName(s.state);
        if (!s.detail.empty()) ss << "（" << s.detail << "）";
    }
    return ss.str();
}

namespace {

void WatchThread() {
    LogDbg("[guardcheck] 能力看门狗已启动：启动宽限 " +
           std::to_string(kStartGraceMs / 1000) + " 秒，汇总周期 " +
           std::to_string(kSummaryMs / 60000) + " 分钟");
    uint64_t n = 0;
    // 上一轮的状态，用于「变化才打」
    std::vector<SrcState> prev;
    for (;;) {
        if (sf::IsStopRequested()) break;
        if (WaitForSingleObject(sf::StopHandle(), 5000) != WAIT_TIMEOUT) break;

        const Report r = Probe();
        std::vector<SrcState> cur;
        for (unsigned i = 0; i < r.count; ++i) cur.push_back(r.src[i].state);

        // 宽限结束后才逐路播报，避免开机 spam
        if (!InGrace() && !cur.empty()) {
            if (prev.empty()) {
                for (unsigned i = 0; i < r.count; ++i) {
                    const SrcStatus& s = r.src[i];
                    if (s.state == SrcState::Full) continue;
                    LogDbg(std::string("[guardcheck] 初始状态 ") + s.name + " = " +
                           StateName(s.state) +
                           (s.detail.empty() ? "" : "（" + s.detail + "）"));
                }
            } else {
                for (unsigned i = 0; i < r.count && i < prev.size(); ++i) {
                    if (cur[i] == prev[i]) continue;
                    const SrcStatus& s = r.src[i];
                    LogDbg(std::string("[guardcheck] ★状态变化 ") + s.name + "：" +
                           StateName(prev[i]) + " → " + StateName(s.state) +
                           (s.detail.empty() ? "" : "（" + s.detail + "）"));
                }
            }
        }
        prev = cur;

        // ★ 探测轮次的**全量**记录（含满血源）。
        //   为什么默认口径是「变化才打」而这里要全量：默认口径把「满血」这档
        //   完全静默掉，于是「进程创建」从开机满血到关机一次都不会出现 ——
        //   事后无法区分「一直满血」与「刚满血」。这正是上轮的实际问题：
        //   日志一切正常、实际整条检测没在工作。
        //
        //   代价控制：每 5 秒一行、5 路 ⇒ 约 1.7 KB/分钟 ⇒ 2.4 MB/天。
        //   这个量级在可接受范围（主日志本就有周期统计），而它换来的
        //   是「哪几路在工作」随时可查 —— 不必等出事才回头猜。
        {
            std::string line = "[guardcheck] 探测轮次 " + std::to_string(n);
            for (unsigned i = 0; i < r.count; ++i) {
                const SrcStatus& s = r.src[i];
                line += " | " + s.name + "=" + StateName(s.state);
                if (!s.detail.empty()) line += "(" + s.detail + ")";
            }
            LogDbg(line);
        }

        if (++n % (kSummaryMs / 5000) == 0)
            LogDbg("[guardcheck] 周期汇总：" + SummaryText());
    }
    LogDbg("[guardcheck] 能力看门狗线程已退出");
}

}  // namespace

void Start() {
    if (g_running.load()) return;
    g_startMs.store(NowMs());
    g_running.store(true);
    g_thr = std::thread(WatchThread);
}

void Stop() {
    if (!g_running.load()) return;
    if (g_thr.joinable()) g_thr.join();
    g_running.store(false);
}

}  // namespace guardcheck
}  // namespace sf
