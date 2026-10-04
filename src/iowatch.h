// iowatch.h — 文件系统 / 注册表写操作采集层（实时防护第五事件源，2026-09-25）
//
// ===========================================================================
//  这个模块解决什么问题
// ===========================================================================
//  银泊指出：「拿不到遥测的原因是因为我们的 ETW 没有订阅全部权限，跨境全跨
//  文件操作没有订阅。」
//
//  复核属实，而且比"少订一路"更严重 —— 现有四个事件源覆盖的是：
//      etwproc   → 进程出生（谁起来了）
//      netwatch  → 网络外联（连出去了）
//      LandedAlert → 落地捕获（目录里出现了新文件）
//      bootguard → 引导扇区
//  唯独**文件被改写与被改名**这一件事，我们从来没有看到过。后果：
//    · 勒索的画像动作是"批量改名/覆写"，我们只能靠回滚引擎的事后统计猜；
//    · 银狐载荷落地后会改名、自删、把配置写进 %APPDATA% —— 这些全在盲区；
//    · 行为学习线（docs/behavior-ml-plan.md）拿不到「落地→执行」之间的中间
//      行为序列，序列挖掘缺少最关键的一段 token。
//
//  本模块订阅两路 ETW provider 把这段补上：
//    Microsoft-Windows-Kernel-File     文件创建 / 改名 / 删除（**含完整路径**）
//    Microsoft-Windows-Kernel-Registry 注册表建键 / 写值 / 删值（自启动写入）
//
// ===========================================================================
//  ★ 权威字段表（实测，不是查文档抄的）
// ===========================================================================
//  来源：`Get-WinEvent -ListProvider "Microsoft-Windows-Kernel-File"` 的
//  EventMetadata.Template —— 即 provider manifest 里的事件模板本身。
//  完整导出见 docs/etw-schema-dump.txt（137 行，三个 provider 全量）。
//
//  ⚠️ 为什么这一步必须先做：TdhGetProperty 按属性名取值**区分大小写**。
//     etwproc.cpp 曾把 Kernel-Process id=1 的 ImageName 写成 ImageFileName、
//     ProcessID 写成 ProcessId，结果 TDH 100% 取不到值（2026-09-23 实测），
//     只能靠固定偏移兜底活着。本模块因此**不硬编码字段名**，改为：
//     先读事件自带的属性表（TRACE_EVENT_INFO）拿到**真实名字**，再用真实名字
//     去取值 —— 名字写错这类事故从此不可能发生。
//
//  Kernel-File（keyword 位来自本机 logman query providers 实测）：
//    EID 10  kw=FILENAME(0x10)              FileKey, FileName     文件名建立
//    EID 11  kw=FILENAME(0x10)              FileKey, FileName     文件名移除
//    EID 12  kw=CREATE(0x80)|FILEIO(0x20)   …, FileName           打开/创建
//    EID 26  kw=DELETE_PATH(0x400)          …, FilePath           删除路径
//    EID 27  kw=RENAME_SETLINK_PATH(0x800)  …, FilePath           改名路径
//    EID 28  kw=RENAME_SETLINK_PATH(0x800)  …, FilePath           改名路径
//    EID 30  kw=CREATE_NEW_FILE(0x1000)     …, FileName           **新建文件**
//
//  Kernel-Registry：
//    EID 1   kw=CreateKey(0x1000)     BaseName, RelativeName       建键
//    EID 3   kw=DeleteKey(0x4000)     KeyName                      删键
//    EID 5   kw=SetValueKey(0x100)    KeyName, ValueName, CapturedData, PreviousData
//    EID 6   kw=DeleteValueKey(0x200) KeyName, ValueName            删值
//    EID 11  kw=SetInformationKey(0x40) KeyName
//
//  ★★ 关键坑：Kernel-File / Kernel-Registry 的事件体里**没有 ProcessId**。
//     它们只有 Irp / FileObject / FileKey / IssuingThreadId。
//     发起进程必须取 **EVENT_HEADER.ProcessId**（内核在发起线程上下文里
//     记日志，事件头带的就是该线程所属进程）。
//
// ===========================================================================
//  能力边界（写卡片文案与文档时必须守住）
// ===========================================================================
//  纯用户态 + ETW 是**事后通知**：我们看到 id=30 时文件已经建好了。
//  所以本模块的定位是**遥测采集**，不是阻断。
//  V1 刻意**不做任何自动处置** —— 只把事实采上来（谁·在什么时候·对哪个
//  路径·做了什么），处置判断留给上层与后续的模型评分。理由：新增一路高频
//  事件源如果同时新增自动终止逻辑，误报风险会成倍放大，而本项目最大的
//  质量红线就是误报（见 docs/behavior-ml-plan.md 与 §四误报治理）。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sf {
namespace iowatch {

// 事件语义。★ 说明：由 keyword 位 + EID 推导，是**提示**而非铁证。
//   EID 10/11 是文件系统的"名字建立/移除"通知（keyword 就是 FILENAME）：
//   新建文件会发 10，删除会发 11，改名则**成对**出现（旧名 11 + 新名 10）。
//   因此单看一条 10/11 无法断定是"新建"还是"改名"，需要配对判断 ——
//   V1 不猜，统一记 Created/Deleted 并按 kindSrc 标明依据，交给下游配对。
// ★★★ 2026-10-02 重大事故修复：新增 Opened，EID 12 不再算「Created」
//   事故：EID 12（kw=CREATE）的语义是**「打开 / 创建」**——它带 CreateOptions，
//   因此被用来观测「覆盖写」。但它对**每一次 CreateFile（哪怕只是读一下）**都发。
//   旧代码 `case kEvFileCreate: e.kind = Kind::Created;` 把「打开」等同于
//   「新建」→ service.cpp 的落地哨兵判据 `kind == Created` 对**全系统每一次
//   文件打开**成立 → NotifyExternalLanded → 1.5s 重探 → 判成「刚落地」→
//   右腿送检 → **锁住原件**。
//   实证（guard.log 2026-10-02 16:39 / 16:45 两批，共 12 条送检封锁）：被锁的
//   是 cmd.exe / conhost.exe / sc.exe / powershell.exe / dsregcmd.exe / msra.exe
//   / TieringEngineService.exe / refsdedupsvc.exe（全为微软正版组件，只是被
//   打开了一下），以及银泊桌面上的 OneMail.exe / OneMail_Manager.exe、PortableGit
//   的 grep.exe —— 全是**几个月前就存在**的文件。连本工程 dist\SilverFoxGuardSvc.exe
//   被编译过程读了一下都进了「落地初筛命中」。同时把沙箱每小时 12 次的送检额度
//   全烧光（日志里可见「已达限流上限」）。
//   「落地」的定义必须是**命名空间里出现了一个新名字**，只认 EID 30（新建文件）
//   与 EID 10（名字建立）；EID 12 归 Opened，只做遥测，**不得进入落地链**。
enum class Kind {
    Unknown = 0,
    Created,        // 新建：**只认 EID 30（CreateNewFile）**与 keyword NewFile
    Renamed,        // 改名（有明确的 RENAME_SETLINK_PATH 依据）
    Deleted,        // 删除
    Opened,         // ★ 2026-10-02：EID 12「打开/创建」+ EID 10「名字建立」——**都不是**落地事件
};

// kind 的判定依据（便于下游决定可信度：eid 级是硬依据，name 级是软依据）
enum class KindSrc {
    None = 0,
    ByEid,          // 由事件 ID 直接判定（如 30=新建、26=删除、27/28=改名）
    ByKeyword,      // 由 keyword 位判定
    ByNameNotify,   // EID 10/11 的名字通知（软依据，改名需配对）
};

// 一条文件/注册表操作记录
struct IoEvent {
    Kind         kind    = Kind::Unknown;
    KindSrc      kindSrc = KindSrc::None;
    bool         registry = false;   // true = 注册表事件，false = 文件事件
    unsigned long pid    = 0;        // 发起进程 PID（取 EVENT_HEADER.ProcessId）
    unsigned long tid    = 0;        // 发起线程 TID（排查用）
    unsigned short eid   = 0;
    std::string  path;               // 已归一化的 DOS 路径 / HKLM\... 形式（UTF-8）
    std::string  rawPath;            // 内核原样路径（\Device\HarddiskVolume3\...）
    std::string  valueName;          // 注册表 ValueName（写值/删值事件才有）
    std::string  procName;           // 发起进程映像名（尽力而为，取不到为空）
    int          infoClass     = 0;  // 注册表 InfoClass / 文件 InfoClass
    int          createOptions = 0;  // 文件 CreateOptions（判是否覆盖写）
    uint64_t     atMs          = 0;  // 单调时钟毫秒（与其它模块同口径）
};

// 采集回调：在**消费线程**上调用（不是 ETW 回调线程）。
// ⚠️ 回调里**严禁磁盘 I/O 与长等待** —— 它挡住整条消费队列。
using IoSink = void(*)(const IoEvent&);

// 启动采集。返回 false = ETW 会话创建/订阅失败。
// 与 etwproc 不同：本模块**没有 WMI 兜底**（文件写操作没有等价的 WMI 事件源），
// 所以失败后上层只应记日志降级，不要试图回退。
bool Start(IoSink sink);

void Stop();
bool IsRunning();
bool IsHealthy(uint64_t silentMs = 120000);

struct Stats {
    uint64_t receivedFile  = 0;   // 收到的文件事件总数（订阅后）
    uint64_t receivedReg   = 0;   // 收到的注册表事件总数
    uint64_t delivered     = 0;   // 通过 sink 外发的条数
    uint64_t dropped       = 0;   // 队列满丢弃数（保新不保全）
    uint64_t parseFail     = 0;   // 事件体解析失败（属性表读不到关键字段）
    uint64_t noPathField   = 0;   // 无路径字段事件（EID 12/30 Create 类，manifest 如此，非故障）
    uint64_t filteredSelf  = 0;   // 丢弃：本进程自己造成的（防自噬日志）
    uint64_t filteredNoise = 0;   // 丢弃：系统目录/缓存等高噪路径
    uint64_t deduped       = 0;   // 丢弃：短窗口内重复的同一 (进程,路径,动作)
    uint64_t lastEventMs   = 0;
};
Stats GetStats();

std::string SessionName();

// 诊断：最近事件环形缓冲（上限 kRecentCap 条，供 iowatchq 命令回捞）。
// 用途：银泊在不看日志的情况下，能直接看到"到底采到了什么"。
std::vector<IoEvent> Recent(size_t maxCount);
void ClearRecent();
static const size_t kRecentCap = 1024;   // ★ 2026-10-02（#617）：256→1024，注册表事件涌入后仍够回捞

// ---- 路径归一化（也对外暴露，供上层复用）----
// 内核给的路径形如 `\Device\HarddiskVolume3\Users\x\a.exe` 或 `\??\C:\...`，
// 归一化成 `C:\Users\x\a.exe`。映射表懒加载一次（QueryDosDevice）。
// 注册表路径 `\REGISTRY\MACHINE\SOFTWARE\...` → `HKLM\SOFTWARE\...`。
std::string NormalizeFilePath(const std::string& kernelPath);
std::string NormalizeRegPath(const std::string& kernelPath);

}  // namespace iowatch
}  // namespace sf
