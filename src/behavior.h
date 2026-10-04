// behavior.h — 进程行为判定层（实时防护的判定核心）
//
// ===========================================================================
//  设计依据（不凭空造规则，每条规则可追溯到来源）
// ===========================================================================
//  查了卡巴斯基 System Watcher 白皮书、Microsoft Defender 引擎文档与安全博客、
//  Bitdefender ATC 官方说明、360 云主防口径、火绒银狐病毒分析文章后，共同结论是：
//    · 没有一家大厂靠「命令行里有某个字符串」判定 —— 那是最容易被绕过的一层；
//    · 卡巴 BSS 匹配的是**行为流序列**，且与 Web/IM/防火墙组件**交换信息**做全局关联，
//      并明确对「可信程序执行不安全代码」（白利用）也告警 —— 签名只降权、不放行；
//    · Defender 明确说跨进程聚合事件，**不只是父子进程**（注入会切断父子关系），
//      并承认存在「专家编写规则」（Smart rules engine）；
//    · Bitdefender ATC 是**打分制**：每项可疑行为加权累加，过阈值才拦，分三档阈值；
//    · 卡巴与 360 的规则都**随病毒库热更新**，不硬编码在程序里。
//
//  因此本模块采用如下结构（对齐业界骨架）：
//    ① 归一化层 —— 命令行去混淆（去引号/空白/拼接字面量/大小写折叠），
//                   让 "From"+"Base64" 这类绕过失效；
//    ② 硬规则层 —— 只放「正常情况几乎不可能出现」的确凿恶意语义，命中即拦；
//    ③ 评分层   —— 多信号加权累加，过阈值才判（对齐 Bitdefender ATC）；
//    ④ 信誉层   —— 签名/来源/路径可信度**调权重**，而不是直接放行（对齐卡巴）；
//    ⑤ 可信发起者校验 —— 豁免必须基于**身份验证**，不能基于可伪造的字符串。
//
//  安全产品铁律：误报比漏报更致命（误报会让用户直接卸载）。故阈值偏高、宁可漏。
// ===========================================================================
#pragma once
#include <string>
#include <vector>

namespace sf {

// ---------------------------------------------------------------------------
//  判定结果
// ---------------------------------------------------------------------------
struct ProcVerdict {
    int         level = 0;   // 0=正常 1=可疑（记录/告警） 2=高危（可拦截）
    int         score = 0;   // 评分层累计分数（level 由 score 与硬规则共同决定）
    std::string tag;         // 机器可读标签（如 office-spawn-host）
    std::string reason;      // 中文原因（直接展示给用户）
    bool        hard = false;// true = 硬规则命中（跳过评分直接定档）
};

// ---------------------------------------------------------------------------
//  进程实体 —— 判定所需的全部输入。由事件源（WMI / 文件监控 / 注册表监控）填充。
//  为什么要做成结构体而不是散参数：判定需要的信息会随规则演进增加，
//  散参数会导致每加一个维度就改一遍所有调用点。
// ---------------------------------------------------------------------------
struct ProcEntity {
    std::string imagePath;       // 进程映像全路径
    std::string commandLine;     // 完整命令行（★ 2026-10-03 起：取不到就是空，不再拿 imagePath 顶替）
    std::string parentImagePath; // 父进程映像全路径（取不到则为空）
    unsigned long pid      = 0;
    unsigned long parentPid = 0;

    // ---- 命令行读取诊断（2026-10-03 Win10 适配新增）----
    //  旧实现读空时静默降级 commandLine=imagePath，导致「规则没命中」与「命令行没取到」
    //  在日志里长得一模一样（铁律 41：静默漏报）。现在把过程显式记下来：
    //    cmdStrategy = 0 读取失败  1 直读 PEB  2 走 Ldr 链表兜底
    //  判定层可据此打点，日志能区分「Windows 版本/时序不兼容」与「真无命令行」。
    int         cmdStrategy = 0;

    // ---- 可选：由 FillTrustInfo() 填充，缺省时判定层自行补全 ----
    int         signState = -1;      // -1=未检测 0=未签名 1=已签名
    std::string signerName;          // 签名者显示名（能取到时）

    // ---- 放行后监控标记：由沙箱放行档（clean/suspicious）登记、进程创建
    //      事件源查观察名单后置位。受观察进程的「已可疑行为」会被判定层
    //      直接升为高危处置（对抗反沙箱逃逸）。默认 false，不影响既有判定。 ----
    bool        observed = false;
};

// ---------------------------------------------------------------------------
//  主入口：三路综合判定（取命中里的最高等级 / 最高分）
// ---------------------------------------------------------------------------
ProcVerdict JudgeProcess(const ProcEntity& e);

// 兼容旧签名的重载（内部补齐 ProcEntity 后调用上面那个）
ProcVerdict JudgeProcess(const std::string& imagePath,
                         const std::string& commandLine,
                         const std::string& parentImagePath);

// 单独判定：父子进程链（例：winword.exe → powershell.exe）
ProcVerdict JudgeParentChain(const std::string& parentImagePath,
                             const std::string& childImagePath,
                             const std::string& childCommandLine);

// 单独判定：命令行（供文件落地 / 计划任务 / 注册表启动项等其他事件源复用）
ProcVerdict JudgeCommandLine(const std::string& commandLine,
                             const std::string& imagePath);

// ---------------------------------------------------------------------------
//  实时注入信号（来自 Audit-API-Calls ETW，auditapi.cpp 调用）
// ---------------------------------------------------------------------------
//  auditapi 采集到「sourcePid 对 targetImage 做了注入类操作」时，把 source 进程
//  交给本函数做**补充分数**：沿用既有评分层（JudgeProcess 基线），仅当
//    · 注入指向敏感目标（lsass / 浏览器 / 聊天软件 / 自身服务 / 系统关键进程），且
//    · 源进程非可信厂商签名（ProcReputable 为假）
//  才额外加权并升档（对齐 Bitdefender ATC 的分值阈值：55=可疑 / 130=高危）。
//  ★ 铁律：不在此新增任何字符串 / 名单式判据 —— 只是给评分层加一个权重信号。
//  返回该 source 进程补判后的 ProcVerdict（由调用方决定是否告警 / 处置）。
//  · setContextThread=true  → id=4 NtSetContextThread（铁证注入，无需看 access mask）
//  · setContextThread=false → id=5/6 的 NtOpenProcess/OpenThread，需 access mask
//      含 VM_WRITE|VM_OPERATION|CREATE_THREAD 才算"具备注入能力"的前兆。
//  ★ 访问掩码口径分两套 —— PROCESS_* 与 THREAD_* 是**互不相同的位定义**，切勿混用：
//    · InjHandleKind::Process（NtOpenProcess）前兆 = CREATE_THREAD(0x2) + (VM_OP(0x8)|VM_WRITE(0x20))
//    · InjHandleKind::Thread （NtOpenThread ）前兆 = SUSPEND_RESUME(0x2) + (SET_CTX(0x10)|GET_CTX(0x8))
//    旧版把 PROCESS_ 位套用在 OpenThread 上 → 语义错位（THREAD_SUSPEND_RESUME 恰为 0x2，
//    但线程侧要的是 THREAD_SET_CONTEXT=0x10，与 PROCESS_VM_OPERATION=0x8 不是一回事）。
enum class InjHandleKind {
    Process,   // NtOpenProcess（PROCESS_* 访问位）
    Thread,    // NtOpenThread （THREAD_*  访问位）
};
ProcVerdict JudgeInjectionActivity(unsigned long sourcePid,
                                   const std::string& targetImage,
                                   uint32_t desiredAccess,
                                   bool setContextThread,
                                   InjHandleKind kind = InjHandleKind::Process);

// ---------------------------------------------------------------------------
//  归一化：命令行去混淆。这是抗绕过的关键层 ——
//  攻击者用 '"From"+"Base64"' / 'p^o^w^e^r^s^h^e^l^l' / ' -e nc ' 等手法干扰
//  字符串匹配，归一化后这些手法全部失效。导出供测试与复用。
// ---------------------------------------------------------------------------
std::string NormalizeCommandLine(const std::string& raw);

// ---------------------------------------------------------------------------
//  可信发起者校验（替代旧版「命令行含某字符串即豁免」的危险做法）
//
//  旧做法：看到命令行含 "chrome-extension://" 就返回 level 0 —— 攻击者只要往
//  自己命令行里塞一个 "--parent-window=0" 就能把整条判定链洗白。
//  新做法：豁免必须验证**发起者身份**：
//    · 父进程确实是浏览器，且**该文件带有效数字签名**（证明确是浏览器本体）；
//    · 且命令行里出现的是真实的 Native Messaging 管道名（\\.\pipe\...）。
//  两者同时满足才豁免 —— 攻击者要伪造就得先拿到浏览器的签名。
// ---------------------------------------------------------------------------
bool IsTrustedBrowserHost(const std::string& parentImagePath,
                          const std::string& commandLine);

// ---------------------------------------------------------------------------
//  签名查询：读文件 Authenticode 签名者名称（失败返回空串）。
//  结果带进程内缓存，避免同一路径反复调用 WinVerifyTrust（有磁盘 IO）。
// ---------------------------------------------------------------------------
bool FileIsSigned(const std::string& path, std::string* outSignerName = nullptr);

// ---------------------------------------------------------------------------
//  进程信誉门：知名厂商签名 / 可信安装路径 → 不可终止。
//  仅供「终止进程」决策前调用（回滚/WmiSink/bootguard 三处终止点），
//  不参与评分调权（评分有自己的信誉层）。
// ---------------------------------------------------------------------------
bool ProcReputable(const std::string& exePath);

// ---------------------------------------------------------------------------
//  规则外置化（对齐卡巴 / 360 的热更新做法）
//  从 data\behavior_rules.txt 加载附加规则，格式每行：
//      H|level|tag|needle|中文原因        ← 硬规则（命令性子串匹配）
//      S|weight|tag|needle|中文原因       ← 评分项
//      W|shell 名                         ← 白名单（父进程名，豁免父子链判定）
//  以 # 开头为注释；空行忽略。加载失败静默回退内置规则（不阻断启动）。
// ---------------------------------------------------------------------------
bool LoadExternalRules(const std::string& filePath);
void ClearExternalRules();     // 供测试重复加载

// ---------------------------------------------------------------------------
//  PID 辅助
// ---------------------------------------------------------------------------
std::string ImagePathOfPid(unsigned long pid);
unsigned long ParentPidOfPid(unsigned long pid);
// 由 PID 直接构造完整实体（含命令行 —— 命令行需读目标进程 PEB，权限不足时为空）
ProcEntity MakeEntityOfPid(unsigned long pid);

}  // namespace sf
