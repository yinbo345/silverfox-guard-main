// auditapi.h — 跨进程注入 / 内存加载事件采集层（实时防护第七事件源，2026-09-30）
//
// ===========================================================================
//  这个模块解决什么问题
// ===========================================================================
//  调研（docs/realtime-protection-survey.md §②-(d)）指出：我们此前的实时事件源
//  覆盖的是进程出生(etwproc) / 网络外联(netwatch) / 文件落地+注册表(iowatch) /
//  引导扇区(bootguard) —— 但**跨进程注入、进程镂空、内存加载无文件**这一整类
//  攻击动作**完全空白**。这类动作正是银狐/银行木马/窃密软件通用的「卡片之间
//  做的事」：落地一个良性外壳，再注入/镂空进浏览器、lsass、聊天软件。
//
//  Microsoft-Windows-Kernel-Audit-API-Calls 这路 ETW 正好补上它。它**只发出**
//    · id=4  NtSetContextThread          —— 远程线程上下文改写 = 铁证注入
//    · id=5  NtOpenProcess               —— 句柄申请（access mask 含
//              VM_WRITE|VM_OPERATION|CREATE_THREAD = 注入前兆）
//    · id=6  NtOpenThread                —— 同上（线程）
//    · id=1  注册镜像加载回调            —— 有驱动在装监控/反监控
//    · id=2  跨进程终止                  —— 杀软/浏览器被关
//    · id=3  符号链接创建                —— 设备对象伪装（免驱动攻击通用前置）
//
// ===========================================================================
//  ★ 实测依据（不是查文档抄的）
// ===========================================================================
//  · provider GUID = {E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23}
//      —— 本机 `logman query providers "Microsoft-Windows-Kernel-Audit-API-Calls"`
//         实测确认，与调研文档一致。
//  · keyword：**本 provider 在 logman 里没有任何 keyword 定义**（只列出 level
//      0x04），即事件 keyword = 0。ETW 投递规则：keyword=0 的事件**只有**在
//      会话以 keyword 掩码 0 启用时才会下发；填全 1 反而收不到。故本模块订阅
//      掩码用 0（这是经典陷阱，已踩坑式确认）。
//  · 采集前提：与 iowatch 一致，**任何 SYSTEM/管理员级 ETW 会话即可采集**，
//      无需 PPL、无需驱动、无需 ELAM 签名。我们的服务正是 SYSTEM。
//
//  ★★ 关键坑（与 Kernel-File/Registry 同理）：本 provider 事件体里**没有
//     发起进程名**，只有 TargetProcessId / DesiredAccess / ReturnCode。
//     发起进程必须取 **EVENT_HEADER.ProcessId**（内核在发起线程上下文记日志，
//     事件头带的就是该线程所属进程）。本模块用 behavior.h 的 ImagePathOfPid
//     补全 source/target 双方映像名，做"与进程台账 join"。
//
//  ★★ 能力边界（写卡片文案时必须守住）：纯 ETW 事后通知，且 payload 稀疏。
//     单看这一路毫无意义——它**只有和进程台账拼起来才有价值**。所以本模块
//     定位是**采集 + 关联维度**，不是新的白名单判据。判定必须经 behavior.cpp
//     的评分层（沿用加权打分 + 阈值 30/55），绝不在此新增任何字符串/名单式判据。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sf {
namespace auditapi {

// 事件语义（由 EID 推导）
enum class ApiOp {
    Unknown = 0,
    LoadImageCallback,   // 1 注册镜像加载回调（驱动装监控/反监控）
    TerminateProcess,    // 2 跨进程终止（杀软/浏览器被关）
    CreateSymlink,       // 3 符号链接创建（设备对象伪装）
    SetContextThread,    // 4 远程线程上下文改写 = 注入（铁证）
    OpenProcess,         // 5 句柄申请（注入前兆看 access mask）
    OpenThread,          // 6 线程打开（同上）
};

// 一条注入/跨进程操作记录
struct ApiEvent {
    ApiOp         op     = ApiOp::Unknown;
    unsigned      eid    = 0;  // 原始 EID（1~6）。op 由 eid 映射而来，但 eid 更原始，
                               // ★ 保留它是因为 2026-10-02 的一条取证教训：
                               //   告警行只打 level/score/src/tgt 时，一条
                               //   「我方服务对 msedge/svchost 的注入类操作」无法定性
                               //   —— 全树没有任何一处 OpenThread / 注入掩码调用，
                               //   却反复出现该告警，此时**必须**知道它是 4/5/6 里的哪一个。
    unsigned long srcPid = 0;  // 发起进程 PID（EVENT_HEADER.ProcessId）
    unsigned long tgtPid = 0;  // 目标进程 PID（payload TargetProcessId；无则 0）
    unsigned long tgtTid = 0;  // 目标线程 TID（id=4 SetContextThread）
    uint32_t      desiredAccess = 0;  // OpenProcess/OpenThread 的访问掩码
    uint32_t      returnCode    = 0;  // NTSTATUS（0=成功）
    // ★ hasXxx 与取值是两个概念：desiredAccess==0 既可能是"掩码真的是 0"，
    //   也可能是"TdhGetProperty 没取到"。只看数字会把两者混为一谈，
    //   而判定分支恰好全靠掩码位 → 必须能区分，否则误判来源不可查。
    bool          hasAccess = false;  // 访问掩码是否真的从 payload 解析出来
    bool          hasRet    = false;  // NTSTATUS 是否真的解析出来
    std::string   srcImage;     // 发起进程映像名（ImagePathOfPid 补全）
    std::string   tgtImage;     // 目标进程映像名（同上）
    uint64_t      atMs = 0;     // 单调时钟毫秒（与其它模块同口径）
};

// 采集回调：在**消费线程**上调用（不是 ETW 回调线程）。
// ⚠️ 回调里**严禁磁盘 I/O 与长等待**。
using ApiSink = void(*)(const ApiEvent&);

// 启动采集。返回 false = ETW 会话创建/订阅失败（上层应记日志降级，不静默）。
bool Start(ApiSink sink);

void Stop();
bool IsRunning();
bool IsHealthy(uint64_t silentMs = 120000);

struct Stats {
    uint64_t received    = 0;   // 订阅后收到的事件总数
    uint64_t delivered   = 0;   // 通过 sink 外发的条数
    uint64_t dropped     = 0;   // 队列满丢弃数（保新不保全）
    uint64_t parseFail   = 0;   // 事件体解析失败（关键字段取不到）
    uint64_t lastEventMs = 0;
};
Stats GetStats();

std::string SessionName();

// 诊断：最近事件环形缓冲（供 auditapiq 命令回捞，银泊不翻日志即见）
std::vector<ApiEvent> Recent(size_t maxCount);
void ClearRecent();
// 由 service.cpp 的 sink 在喂完上层后回写环形缓冲（保持 Recent/Start API 纯净）
void PushRecent(const ApiEvent&);
static const size_t kRecentCap = 256;

}  // namespace auditapi
}  // namespace sf
