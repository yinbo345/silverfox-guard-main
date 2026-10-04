// etwproc.h — 进程创建事件采集层（实时防护第一事件源，2026-09-23 由 WMI 升级为 ETW）
//
// ===========================================================================
//  这个模块解决什么问题
// ===========================================================================
//  旧的进程创建订阅走 WMI（__InstanceCreationEvent WITHIN 3）：
//    · WITHIN 3 意味着**最多 3 秒延迟** —— 银狐载荷落地后 3 秒内可能已经
//      完成注入、自删、改名，等 WMI 把事件送来窗口已经过了；
//    · 每 60 秒重建订阅，重建间隙（3 秒）存在盲窗；
//    · WMI 是拉模型轮询，CPU 与延迟都不占优。
//
//  升级为 ETW（Microsoft-Windows-Kernel-Process）后：
//    · **零轮询**：内核在进程创建的瞬间推送事件，毫秒级到达；
//    · 无重建间隙；
//    · 判定管线完全复用（拿到 PID 后仍走 sf::MakeEntityOfPid → JudgeProcess，
//      命令行/父子链/签名信誉全部照旧）。
//
//  ★ 回退契约（银泊指定）：ETW 订阅失败（权限不足 / 会话数上限 / provider
//    enable 失败）时，由调用方（service.cpp 的 ProcessWatch）**回退到旧 WMI
//    订阅**，防护不出现空窗。本模块只负责"试"，不负责兜底。
//
// ===========================================================================
//  为什么 Kernel-Process 事件里拿不到命令行也不影响判定
// ===========================================================================
//  Kernel-Process id=1（ProcessStart）payload 只有进程 ID、父进程 ID 与
//  映像文件名（部分版本带完整路径）。命令行判定不受影响：
//  service.cpp 的 HandleNewProcess 拿到 PID 后调 sf::MakeEntityOfPid(pid)
//  （内部打开进程句柄读 PEB，LocalSystem 权限可读绝大多数进程），
//  命令行、父子链照旧可得 —— 判定口径与 WMI 路径完全一致。
//
// ===========================================================================
//  字段解析方式（为什么用 TDH 而不是固定偏移）
// ===========================================================================
//  netwatch 的 id=10（TCP connect）payload 布局跨版本稳定，可以按偏移读；
//  但 Kernel-Process id=1 的 payload 在不同 Windows 版本间字段顺序有差异
//  （1607 / 19041 / 22H2 各不相同），按偏移读必然踩坑。
//  因此本模块用 TdhGetProperty **按属性名取值**（NewProcessId /
//  ParentProcessId / ImageFileName），由 TDH 负责版本差异。
//
//  线程范式：与 netwatch 完全一致（回调只入队 + 独立消费线程），勿自创。
#pragma once

#include <string>
#include <cstdint>

namespace sf {
namespace etwproc {

// 一条"进程创建"记录（从 Kernel-Process id=1 解析而来）
struct ProcEvent {
    unsigned long pid  = 0;   // 新进程 PID
    unsigned long ppid = 0;   // 父进程 PID（取不到为 0）
    std::string   image;      // 映像名/路径（ETW 给的是文件名，可能无路径；UTF-8）
    uint64_t      atMs = 0;   // 单调时钟毫秒（与其它模块同口径）
};

// 判定结果回调：在消费线程上调用。
// ⚠️ 回调里会做 OpenProcess + NtQuery（MakeEntityOfPid）—— 进程创建频率低
//    （每秒个位数~几十个），这是可接受的；但**严禁磁盘 I/O 与长等待**。
using ProcSink = void(*)(const ProcEvent&);

// 启动采集。返回 false 表示 ETW 会话创建/enable 失败 —— 调用方必须回退 WMI。
bool Start(ProcSink sink);

void Stop();
bool IsRunning();

struct Stats {
    uint64_t received  = 0;   // 收到的 id=1 事件总数
    uint64_t delivered = 0;   // 通过 sink 外发的条数
    uint64_t dropped   = 0;   // 队列满丢弃数
    uint64_t parseFail = 0;   // 解析失败（TDH 取不到关键属性）
    uint64_t lastEventMs = 0;
    // ★★ 2026-10-02 新增：ProcessTrace 自愈的可观测性（配合下方 TakeWmiFallbackRequest）
    //    这两个计数器与"强制重启"逻辑配对 —— 没有它们，自愈动作会变成新的静默行为。
    uint64_t ptErrors   = 0;  // ProcessTrace **非正常返回**的累计次数
    uint64_t ptRestarts = 0;  // 因 ProcessTrace 异常而**强制重启会话**的累计次数
};
Stats GetStats();

// ---------------------------------------------------------------------------
//  ★★ 2026-10-02：ProcessTrace 异常自愈 —— 「报错退出 → 强制重启一次 → 仍失败回退 WMI」
// ---------------------------------------------------------------------------
//  为什么需要（这是补一个真实缺陷，不是加功能）：
//    `ProcessTrace()` 的返回值**原来被丢弃**（它跑在一个匿名线程里，没有任何人看它
//    的返回码）。于是会话一旦被外部停掉、或内核侧出错让它返回，就变成
//    「线程静默结束、g_running 仍是 true、IsRunning() 仍报活着」—— 事件不再来，
//    而链路上下没有任何一处知道。这正是本工程反复出现的同一族毛病：
//    **能观察到"没有输出"，但代码不观察**（同 §铁律 30 的 ETW 静默失效）。
//
//  现在的行为（三段）：
//    ① ProcessTrace 非正常返回（**我们没请求停，它却返回了**——不看具体错误码，
//       凡不是"我们自己 CloseTrace"造成的退出都算）→ 记日志（带错误码与已收条数）；
//    ② **强制重启一次**：拆除旧会话（显式 DISABLE_PROVIDER + STOP）→
//       重新 StartTraceW / EnableTraceEx2 / OpenTraceW（**固定会话名**下会先清同名残留、
//       撞 183 时有限重试）→ 继续 ProcessTrace；
//    ③ 第二次仍非正常返回 → 置位"请回退 WMI"标志，并把 IsRunning() 置 false
//       —— 由调用方接管（service.cpp::ProcessWatch 会改走 WMI 兜底，防护不出现空窗）。
//
//  调用方契约：发现 `IsRunning()==false` 时调本函数**取走并清零**该标志。
//    返回 true  = 采集层因 ProcessTrace 连续异常而放弃，**应当回退 WMI**；
//    返回 false = 只是正常停止（服务在停 / 上层主动 Stop），别误判成故障。
//  ★ 一次性（take）语义：同一次失败不会被重复消费，避免上层反复重建/反复回退。
bool TakeWmiFallbackRequest();

// 健康检查：进程创建事件在桌面机上每秒都有（Explorer 各类后台活动），
// 静默 30 秒视为异常（比 netwatch 的 60 秒严格）。
//
// ⚠️⚠️ **不要用它做"会话活着吗"的判据**（2026-10-01 血的教训）。
//   本函数只看"距上一条事件多久"，而 `lastEventMs==0`（从没收到过任何事件）
//   被当成"健康" → 一个**从启动第一天起就哑火**的会话会被判成完全健康。
//   实测：`recv=0` 持续 4 天，而每次重启都打印"采集已启动（ETW）"。
//   **正解 = LivenessProbe()**（下面的主动探针）—— 它能区分
//   「会话死了」与「系统真的安静」，本函数不能。
bool IsHealthy(uint64_t silentMs = 30000);

// ---------------------------------------------------------------------------
//  ★★ 存活探针（2026-10-01 新增，P0 修复的核心）
// ---------------------------------------------------------------------------
//  做法：起一个**无害子进程**（`cmd.exe /c exit`），然后等 ETW 是否把它的
//        ProcessStart 报回来。
//    · 收到了   → 会话**确实在推送事件**（活的）
//    · 超时没收到 → 会话句柄还在、但事件不再到达（**静默失效**）
//  为什么必须是"主动起进程"而不是"看最近有没有事件"：**静态桌面也可能几十秒
//  一个进程都不创建**，光看计数器分不出"死"与"安静"；而我们起的探针进程
//  **必然**产生一条 ProcessStart —— 这是唯一可靠的判据。
//  ★ 与「日志会静默丢行」同族：能观察到"没有输出"，但代码不观察 → 静默 4 天。
//
//  返回 true  = 健康（或探针自身起不来，此时**宁可判健康也不误重建**）
//  返回 false = 探针进程起来了，但 waitMs 内 ETW 没报到它 → 判定会话已死
//  pidOut：可选，回传探针进程 PID（供日志核对）。
bool LivenessProbe(uint32_t waitMs = 6000, unsigned long* pidOut = nullptr);

// 判断某个 PID 是否是我们自己起的存活探针 —— sink 侧用它**跳过**探针进程，
// 免得每分钟一次的自产 cmd.exe 走判定管线（既噪声，又可能被父子链规则误判）。
bool IsProbePid(unsigned long pid);

// ---------------------------------------------------------------------------
//  ★★ 2026-10-02：会话命名与残留治理（铁律 35）
// ---------------------------------------------------------------------------
//  会话名固定为 "SilverFoxGuardProc"（**不再带随机后缀**，取舍说明见 etwproc.cpp）。
//  StartTraceW 前会 PurgeStaleSession() 清理同名残留；撞 183 时有限重试 3 次；
//  拆除路径显式 DISABLE_PROVIDER 后再 STOP。
//  （原 SetSystemLoggerMode/GetSystemLoggerMode 已删除：EVENT_TRACE_SYSTEM_LOGGER_MODE
//    实测启用 18 次全部无效，且它是**跨重启存活的持久会话** = 残留的直接来源。）
std::string SessionName();

}  // namespace etwproc
}  // namespace sf
