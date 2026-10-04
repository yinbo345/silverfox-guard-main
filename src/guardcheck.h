// guardcheck.h — 能力看门狗：八路事件源的「是否满血」自检
//
// ================================================================
//  ★ 为什么必须有（2026-10-03 Win10 单核虚拟机实测，真实事故）
// ================================================================
//  那一轮 `resmon` 的日志明写：
//      [resmon] 逻辑处理器数=1 < 门槛 2 ⇒ 跳过 CPU 占用判定
//  ⇒ **整个挖矿检测在那台机器上全程不工作**（73 轮扫描全 0）。
//  而同期日志里：线程在跑、周期统计每分钟都在打、没有任何报错。
//  ⇒ **从日志上完全看不出「它没在工作」。**
//
//  同族三条（今天全部实测确认）：
//      ① resmon   `cores < coresMin ⇒ return 0`  —— 整条能力被关
//      ② netwatch `last == 0 ⇒ 判健康`          —— 从未收到 = 健康
//      ③ 行为层   命令行读空 ⇒ 用映像路径顶替    —— 规则恒 0 分且不报错
//  三条的共同形态：**「拿不到」被当成「没问题」**，而日志里看不见。
//
// ================================================================
//  本模块做一件事：把每一路「满血 / 降级 / 停摆」变成**显式可查**的状态
// ================================================================
//  判据（每一路独立算，不做总括结论）：
//      满血   = 线程在跑 + 未处于降级口径 + 宽限期已过
//      降级   = 在跑，但判据被收紧（resmon 单核口径 / 启动宽限内 / 无可信签名降权）
//      停摆   = 线程不在跑，或超过静默阈值仍无事件
//      宽限   = 服务启动后的固定时间内一律报「宽限中」，不算异常
//
//  【设计纪律：不制造噪音】
//      · 启动宽限内绝不报停摆（否则每次开机都一串假警）；
//      · 状态**变化时**才打一行（不是每分钟重复同一条）；
//      · 每 5 分钟汇总一行，一眼看出「八路各是什么状态」；
//      · 降级**不是故障**（单核收紧口径是设计），只报事实不报错误。
#ifndef SF_GUARDCHECK_H
#define SF_GUARDCHECK_H

#include <string>

namespace sf {
namespace guardcheck {

// 每一路的状态
enum class SrcState {
    Disabled = 0,   // 该源未启用（配置关 / 编译未接入）
    Grace,          // 启动宽限中（不算异常）
    Full,           // 满血
    Degraded,       // 在跑但判据被收紧
    Stalled,        // 停摆：在跑但超静默阈值无事件 / 线程已退
};

const char* StateName(SrcState s);

// 一路的快照
struct SrcStatus {
    std::string name;      // 事件源名（与日志里的 [xxx] 前缀一致）
    SrcState    state = SrcState::Disabled;
    std::string detail;    // 人可读的原因（降级/停摆时必填）
};

// 全部八路 + 总计
struct Report {
    SrcStatus src[10];
    unsigned  count    = 0;      // 实际纳管的源数
    unsigned  full     = 0;
    unsigned  degraded = 0;
    unsigned  stalled  = 0;
    unsigned  grace    = 0;
    unsigned  disabled = 0;
    bool      allFull() const { return stalled == 0 && degraded == 0; }
};

// 采一次当前状态（不落日志，供调用方决定要不要打）
Report Probe();

// 人可读摘要（管道 resmonq / 周期统计共用同一份口径）
std::string SummaryJson();
std::string SummaryText();

// 启动后打一份完整清单；此后由守护线程每 5 分钟打一行状态变化 + 汇总
void Start();
void Stop();

}  // namespace guardcheck
}  // namespace sf

#endif  // SF_GUARDCHECK_H
