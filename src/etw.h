// etw.h — ETW 进程事件采集层（Kernel-Process provider 实时订阅）
//
// ===========================================================================
//  设计依据：docs/heuristic-engine-plan.md 第 4.4 节「ETW 采集层详细设计」
// ===========================================================================
//  这是「阶段 1：采集层替换」的实现 —— 目标是把进程创建的发现延迟
//  从 WMI 的 1500~3000ms 压到 1~5ms，**判定逻辑完全不变**。
//
//  【为什么这一步价值最大】
//  银狐的投递链是秒级完成的：宿主进程创建 → 读载荷解包（50~300ms）→
//  注入（100~800ms）→ 写自启动（500ms~2s）→ 建 C2（1~5s）。
//  WMI 的 3 秒轮询意味着平均 1.5 秒后才开始判定 —— 那时注入已经完成，
//  我们看到的是"尸体"而不是"正在作案"。持久化那一步（最要命的一步）
//  在 ETW 到位后几乎必然能赶上。
//
//  【硬边界（必须诚实认知，不得在文案里宣称）】
//  纯用户态**无法同步阻止进程创建**。ETW 是事后通知，事件到达时进程已存在。
//  我们能做到的极限是「毫秒级发现 → 立刻处置」，不是「根本不让它创建」。
//  要做前者必须写内核驱动（PsSetCreateProcessNotifyRoutineEx），本版不做，
//  理由见方案 §3.4（驱动需 EV 签名 + WHQL，且一个内核 bug 就能让用户机器起不来）。
//
//  【为什么"ETW 会被 patch 绕过"不必过度焦虑】
//  ETW 是 provider → session → consumer 的解耦模型。恶意进程 patch 自己的
//  EtwEventWrite 只能让**它自己**不再发事件，无法关掉我们的会话，也无法阻止
//  内核组件（Ps 内核事件）发出的通知。要全系统关掉需要管理员 + 知道会话
//  GUID/名字 —— 我们用随机化会话名阻断这条路。
// ===========================================================================
#pragma once
#include <string>
#include <functional>

namespace sf {
namespace etw {

// ---------------------------------------------------------------------------
//  采集到的进程事件（归一化后的形态，判定层只认这个结构）
// ---------------------------------------------------------------------------
struct ProcEvent {
    enum class Kind { Start, Stop, ImageLoad };

    Kind          kind = Kind::Start;
    unsigned long pid  = 0;
    unsigned long ppid = 0;          // ★ 原生带父进程 ID —— 这是 ETW 相比 WMI 的关键优势
    std::string   imageName;         // 映像路径（NT 路径形式，需转换，见 NormalizeImagePath）
    std::string   commandLine;       // ProcessStart 事件带命令行
    uint64_t      atMs = 0;          // 事件时间（steady ms）
};

// 事件回调。★ 在 ETW 消费线程上调用 —— 实现方**不得做重活**
// （判定、签名查询、落盘一律丢到别的线程），否则 ETW 缓冲积压丢事件。
using ProcEventSink = std::function<void(const ProcEvent&)>;

// ---------------------------------------------------------------------------
//  生命周期
// ---------------------------------------------------------------------------
// 启动采集。sink 会被消费线程高频调用。
// 返回 false 表示订阅失败（权限/会话冲突/API 错误），调用方应降级到 WMI。
// ★ 必须在管理员/LocalSystem 下调用（实测普通用户 GetLastError=5）。
bool Start(ProcEventSink sink);

// 停止采集并回收会话（幂等）
void Stop();

// 是否正在运行
bool IsRunning();

// 统计（供 GUI / 日志展示，验证"延迟真的降下来了"）
struct Stats {
    uint64_t received  = 0;   // 收到的原始事件数（含被过滤掉的）
    uint64_t delivered = 0;   // 通过过滤、投递给 sink 的事件数
    uint64_t dropped   = 0;   // 因队列满被丢弃的事件数（★ 必须可见，否则是静默失效）
    uint64_t lastEventMs = 0; // 最近一次收到事件的时刻（用于健康检查）
};
Stats GetStats();

// 健康检查：超过 silentMs 毫秒没有收到任何事件视为异常（订阅可能静默失效）
bool IsHealthy(uint64_t silentMs = 30000);

// 会话名（随机化，防止被针对性关闭）
std::string SessionName();

}  // namespace etw
}  // namespace sf
