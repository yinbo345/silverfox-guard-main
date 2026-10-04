#ifndef SF_RESMON_H
#define SF_RESMON_H

// ================================================================
//  进程资源监控（挖矿检测的最后一道兜底）
//
//  ★ 为什么必须有（2026-10-03 Win10 虚拟机真样本实测）：
//    那一轮挖矿进程 CPU 100% 烧了一整轮，主防**零告警**。根因链有四环：
//      ① 命令行读不到（Win10 上 PEB 时序问题）⇒ `stratum+tcp`/`xmrig` 规则全落空
//      ② `service.cpp` 的 `if (!hitIp && !hitPort) return;`
//         ⇒ 矿池地址不在那 13 条 C2 IP 里 ⇒ **连接事件当场丢弃，连日志都不打**
//      ③ `netwatch.cpp` 的 `if (last == 0) return true;` ⇒ 从未收到事件 = 「健康」
//      ④ ★ 本模块要补的就是这一环：**全工程此前没有任何进程 CPU 监控**
//         （`GetProcessTimes` 只在 sandbox.cpp 里用过，且是量沙箱进程，不是量全机）
//
//  ★ 为什么 CPU 占用是挖矿**最稳**的特征（比外联更稳）：
//    - 攻击者**可以**换矿池、改端口、用 HTTPS 隧道（让 ①②③ 全部失效）；
//      但挖矿的**本质是持续做哈希运算** ⇒ CPU 必然长期占用。
//    - 正常程序的高 CPU 是**突发**的（编译/解包/压缩），挖矿是**持续**的
//      ⇒ 用「持续占用」而不是「瞬时峰值」做判据，天然能区分。
//    - 这也是正规沙软的标准判据（西瓜 / PYAS 都有资源阈值规则）。
//
//  判据（全部满足才报，避免误伤正常高负载程序）：
//    ① 连续 N 个采样周期（本模块默认 6 个 × 5s = 30s）单进程 CPU ≥ 阈值（默认 60%）
//    ② 该累计占用时长 ≥ 60s（挖矿是持续负载，一次编译不会持续 60s 满载）
//    ③ 信誉门放行（浏览器/系统组件/自家进程不参与）
//    ④ ★★ 单核机器（2026-10-03 修正）：**降阈值 + 收紧持续时长**，而**不是整条跳过**。
//       原实现是 `cores < coresMin ⇒ return 0`（完全不扫）。实测代价：
//       用户的 Win10 虚拟机就是单核 ⇒ 日志明写「逻辑处理器数=1 < 门槛 2 ⇒ 跳过
//       CPU 占用判定」⇒ **整个挖矿检测在那台机器上全程不工作**，而这正是最需要它的场景。
//       为什么降阈值是安全的：`pct` 是**按逻辑核归一**的（见 resmon.cpp），
//       单核机上「一个进程 100%」确实常态 ⇒ 把阈值抬到 90% 让只有「几乎独占 CPU 且
//       持续很久」才入选；同时把持续时长从 60s 抬到 180s（单核误报的主因是
//       各种短时任务恰好撞在采样点上）。
//
//  ★ 硬纪律：CPU 高**只是旁证**，不单独定罪。处置仍走统一判定链
//   （JudgeProcess + 信誉门 + 落账四连），本模块只负责「把可疑的高占用进程挑出来」。
// ================================================================

#include <string>

namespace sf {
namespace resmon {

struct Config {
    unsigned    sampleIntervalMs = 5000;    // 采样周期
    unsigned    minSamples       = 6;       // 连续命中多少个周期才算「持续」
    unsigned    cpuPercent       = 60;      // 单进程 CPU 阈值（按逻辑核归一）
    unsigned    minSustainSec    = 60;      // 持续占用下限（秒）
    // ★ 2026-10-03 修正：单核不再「整条跳过」，改为「收紧判据」。
    //   singleCorePercent  = 单核时的 CPU 阈值（比多核高 —— 单核上 100% 是常态）
    //   singleCoreSustain  = 单核时的持续时长下限（比多核长 —— 短时任务更容易撞上）
    //   singleCoreSamples  = 单核时需要的连续命中轮数（比多核多一轮）
    //   ★ coresMin 保留但仅用于**日志标注**（让日志能说清当前处于哪种口径）。
    unsigned    coresMin         = 2;       // 低于此核数进入「单核口径」（不再跳过）
    unsigned    singleCorePercent = 90;
    unsigned    singleCoreSustain = 180;
    unsigned    singleCoreSamples = 9;
    bool        enabled          = true;
};

void SetConfig(const Config& c);
Config GetConfig();

// 启动 / 停止监控线程
bool Start();
void Stop();
bool IsRunning();

// 立即跑一轮扫描（供测试与管道命令调用；不依赖定时线程）
// 返回本轮挑出的「持续高 CPU 且不可信」的进程数。
unsigned ScanOnce();

struct Hit {
    unsigned long pid       = 0;
    std::string   imagePath;
    unsigned      cpuPercent = 0;   // 归一化后的百分比（100 = 吃满一个核）
    unsigned      sustainSec = 0;
    unsigned long cores      = 0;
};
std::string FormatHits();           // 给管道/日志用的可读摘要

// ★ 2026-10-03 新增（能力看门狗用）：当前是否处于「单核收紧口径」。
//   为什么需要：单核口径是**降级运行**（阈值 60%→90%、持续 60s→180s），
//   判据比多核严 ⇒ 实际能力弱于名义值。看门狗要把「哪些源在降级」显式报出来，
//   否则就重演今天这幕：日志一切正常、实际整条检测没在工作。
bool SingleCoreMode();

}  // namespace resmon
}  // namespace sf

#endif  // SF_RESMON_H
