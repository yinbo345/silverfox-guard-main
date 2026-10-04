#pragma once
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include "iocs.h"   // 引擎版本常量（iocs::ENGINE_VERSION，纯头文件）

// 单条发现
struct Finding {
    std::string category;  // 进程 / 注册表 / 计划任务 / 网络 / 文件 / Defender / WMI
    std::string severity;  // 高 / 中 / 低
    std::string title;     // 简短标题
    std::string detail;    // 详细说明
    std::string ioc;       // 命中的 IOC 原文
    // 关联文件的绝对路径（仅供「一键清除」精确定位；非文件类发现为空）。
    // 注意：不要从 detail 里反解路径——detail 是给人看的中文描述，格式随时会变。
    std::string path;
    int weight = 0;        // 风险权重（由评分引擎按证据强度赋值，见 WeightOf）
};

// 一次完整扫描的结果
struct ScanResult {
    std::string timestamp;  // 本地时间串
    // 两态：normal（环境正常）/ infected（环境异常，即疑似中银狐）
    std::string status;
    int score = 0;          // 风险分：按证据强度赋权累计（高=60/中=30/低=10 基线 + 上下文微调）
    bool hardProof = false; // 是否命中铁证（已知 C2 活跃连接 / 已知银狐进程 / 银狐标记文件 / 自身完整性失败）
    std::string engine = iocs::ENGINE_VERSION;   // 引擎版本
    // ★ 默认初值（2026-09-23 修复）：engine 原先只在扫描完成
    //   （`g_result = std::move(r)`，见 scanner.cpp RunFullScan/RunQuickScan）
    //   那一刻才被赋值。服务重启后、首轮扫描完成前，g_result.engine 一直是空串
    //   → 主界面「引擎版本」显示成「—」（银泊实拍发现）。
    //   版本号是编译期常量，构造时就有值才是正确语义 —— 与扫描进度无关。
    //   顺带堵住另一条隐患：任何路径构造出的 ScanResult（如 GuardTick 的局部 r）
    //   整体赋给 g_result 时，也不会再把 engine 清成空。
    bool selfCheck = true;  // 程序自身完整性校验是否通过（自保）
    std::vector<Finding> findings;
    std::string error;      // 扫描过程致命错误（若有）
};

// 全局最新结果（被 HTTP 线程与扫描线程共享）
extern ScanResult g_result;
extern std::mutex g_resultMutex;

// 执行一次全量扫描并写入 g_result
void RunFullScan();

// 快速清除预扫：只扫进程+文件（清除目标的全部来源），秒级返回
// ⚠️ 会做磁盘遍历（递归 Desktop/Downloads/Temp 等落点）——**只允许「清除前预扫」调用**。
//    定时器请用 RunGuardTick()。
void RunQuickScan();

// 轻量巡检（定时器专用）：进程 + 注入 + 注册表 + 服务 + 计划任务。
// 纯内存 / 注册表读取，**零磁盘遍历**，秒级完成。结果合并进 g_result
// （保留上一轮全盘扫出的「文件」类 finding，不被冲掉）。
void RunGuardTick();

// 初始化 COM 等（main 启动时调用一次）
void ScannerInit();
void ScannerCleanup();

// P3 主动防御：单文件快速启发式判定（供 WMI 进程创建监听调用）。
// 与全盘文件扫描共享同一套启发式（随机名/落地位置/家族串/PE 静态/签名），
// 返回：0=正常或豁免；1=中危旁证；2=高危（随机名+可疑位置+PE 异常或盘根或家族特征串）。
int QuickProbeExecutable(const std::string& path);

// ---------------------------------------------------------------------------
//  ★ 深度内容判定（2026-09-24）—— 消除「扫描链路 vs 实时链路」的口径差
// ---------------------------------------------------------------------------
// 【背景 · 虚拟机实战实证】
//   同一个 YouDaoX64.exe：
//     · 全盘扫描链路  → level=2 / 300 分（命中 probe 引擎的家族串 + INNO 特征）
//     · 实时链路      → 只有「1 级旁证：落地高发区，命名正常」
//   两条链路的判定能力**不对等**，实时链路看着文件却认不出来。
//
// 【本函数做什么】
//   直接调用 probe.cpp 的完整内容判定引擎（sf::ScanTargetFile：家族特征串 /
//   PE 结构 / 熵 / 导入表 / 递归解包），把扫描链路的判定能力搬到实时链路。
//
// 【为什么必须限流】
//   完整引擎会读整文件（含解包），比 QuickProbeExecutable 重两个数量级。
//   所以：① 只对可执行/脚本/归档类扩展名跑；② 超过 kDeepProbeMaxBytes 直接跳过
//   （宁可不判，也不让实时线程被一个大文件拖住 —— 那是可被利用的 DoS 面）。
//   调用方还应叠加「文件新鲜度」门（见 IsFreshlyCreated）进一步收窄。
int DeepProbeExecutable(const std::string& path,
                        std::string* outTitle = nullptr,
                        int* outScore = nullptr);

// ---------------------------------------------------------------------------
//  ★ 进程出生卡（2026-09-24）—— 与命令行内容完全无关的通用判据
// ---------------------------------------------------------------------------
// 【为什么需要】银狐载荷的命令行"很干净"（随机名 exe，无参数），所有基于
//   命令行/家族串的特征规则集体失效。必须有一条**不看命令行**的判据：
//     ① 镜像文件有多新（刚落地 5 分钟内就被拉起 = 投递链的典型节奏）
//     ② 有没有有效签名（银狐载荷不可能有 Authenticode 签名）
//     ③ 谁把它拉起来的（脚本宿主 / 解压器 / 邮件客户端 / 浏览器 = 内容解释器）
//   三者组合才判高危 —— 单看任一条都会大面积误伤（用户刚下载的绿软、
//   自解压安装包、无签名的开源工具）。
//
// 返回：0=无结论；1=旁证（只记录）；2=高危（可处置）。
// outReason 回填命中理由（进日志与卡片文案，便于误报回溯）。
//
// ★ corroborationLv（2026-09-24 误报压制新增）——「独立旁证等级」，调用方传入。
//   语义：**在本判据之外**，同一文件已经拿到的判定等级（来自文件启发式
//   QuickProbeExecutable / 内容引擎 DeepProbeExecutable / 行为规则 JudgeProcess），
//   0 表示没有旁证。
//   用途：「父进程是内容解释器」这一条**单独不足以判高危** —— 那个名单里 40 多个
//   宿主全是日常操作的父进程（7z 解压绿软、MSI 安装子程序、python 跑刚 build 的
//   产物、Electron 应用自更新）。改为「解释器父链 + 至少一条独立旁证」才升高危，
//   这是标准的证据叠加原则。详见 scanner.cpp 中 BirthCardLevel 的现场注释。
//   注意：pass-by-value 默认值 0 → 不传参的调用方行为 = 「只看父链，不判高危」，
//   即"更保守"的那一侧，符合"宁可少报也不误杀"的收敛方向。
int BirthCardLevel(const std::string& imagePath,
                   const std::string& parentImagePath,
                   std::string* outReason,
                   int corroborationLv = 0);

// 文件创建时间距今是否不超过 maxAgeSec 秒。
// 取不到创建时间（权限/非 NTFS/异常）时返回 false —— 无结论，不参与判定。
bool IsFreshlyCreated(const std::string& path, uint64_t maxAgeSec);

// 文件是否带可信 Authenticode 签名（进程内缓存，复用扫描链路的判定与缓存）。
// ★ 为什么要对外暴露：实时链路要用它做「无签名」判据。若在 service.cpp 里
//   另写一套验签，就又是一次「同一判据维护两份」——本项目反复踩过的坑
//   （scanner.cpp 的规则三副本就是这么来的）。
bool IsFileSignatureTrusted(const std::string& path);

// ---------------------------------------------------------------------------
//  ★ 版本资源豁免（2026-09-24 误报压制）—— 「无签名但正常」的救命判据
// ---------------------------------------------------------------------------
// 【为什么需要】
//   上一轮加的 5 项通用判据（落地捕获全域化 / 实时内容 probe / 进程出生卡 /
//   持久化面 / 落地→执行升档）都以「无有效签名」为前置条件。但现实是：
//   **绝大多数正常程序没有 Authenticode 签名** —— 绿软、自编译作品、开源工具、
//   家用小软件、Electron 自打包应用。于是"无签名"这一条直接把海量正常程序
//   推到高危档，误报率必然爆掉。
//
// 【本判据】
//   读 PE 的二进制版本资源（VersionInfo，**不加载、不执行**），只要
//   CompanyName / ProductName / FileDescription / OriginalFilename 任一非空、
//   长度 >= 3、不是明显占位串（TODO / Unknown / N/A / 未命名 …）、且含字母或 CJK
//   （排除 "1.0.0.0"、"----" 这类），即视为「正常交付物」。
//
// 【为什么它不放过真载荷】
//   银狐的 stub 载荷是极简壳 —— 版本资源**一个字段都没有**（连语言块都可能缺席）。
//   而正常程序几乎总有一个 ProductName。所以这条判据的鉴别力主要来自
//   「有 / 完全没有」，而不是"内容像不像厂商"。
//
// 【权威来源】与签名判定同源同缓存策略：进程内缓存 + 锁外做 I/O（见 scanner.cpp）。
bool HasVendorInfo(const std::string& path);

// 父进程是否为「用户交互外壳」（explorer.exe / 任务管理器 / 开始菜单 / 搜索）。
// 用途：这类父进程意味着**用户自己双击运行的**（例如从资源管理器点开一个文件），
// 属于明确的人类意图，实时链路不该按"投递链"处置 —— 见 service.cpp 的落地升档门。
bool IsUserInteractiveHost(const std::string& imagePath);

// ---------------------------------------------------------------------------
//  ★ 影子模式（ai_observe）复用的三个只读判据（2026-09-25）
// ---------------------------------------------------------------------------
// 【为什么要把它们导出来】
//   AI 引擎的 48 维特征里，第 3 维（文件名随机）/ 第 41 维（ADS）/
//   第 36~37 维（落地新鲜度）分别对应 scanner.cpp 内部**已经存在**的三条判据。
//   若在影子模式里另写一份，就又是一次「同一判据维护两份」—— 本项目反复
//   踩过的坑（规则库三副本 / gui.html 四副本 / IsFileSignatureTrusted 的教训：
//   扫描链路与实时链路口径不一致，同一个 YouDaoX64.exe 一边判 2 级一边判 1 级）。
//   所以这里只做**薄封装**：内部三个 static 函数原封不动，只导出语义相同的入口。
//
// ⚠️ 这三个都会**碰文件系统**（CreateFileA / GetFileInformationByHandle /
//    FindFirstStreamW）。它们是给影子模式的**异步观测线程**用的，
//   绝不允许出现在实时拦截的同步路径上 —— 那条路径有明确的延迟预算
//    （这也正是 BuildFeatures 做成纯函数、把 I/O 全部推给调用方的原因）。
//
// ⚠️ 返回「无结论」与返回「false」含义不同。尤其 FileCreatedAgeSec 的 -1，
//    调用方必须原样传给 FeatureInput.createdAtAgeSec（它接受 -1 = 未知），
//    不要自己折算成 0 —— 那会把"读不到时间"伪装成"刚刚创建"，
//    凭空给可疑度加分（本项目在 prebackup 的 10 分钟保护期上踩过一次同类坑）。

// 文件名是否「短随机名」——与 QuickProbeExecutable / IsSuspExe 内部**同一条判据**。
// 传完整路径或裸文件名都可以（内部取 basename）。
// 语义：去掉 .exe 后长度 5~9、全字母数字、且**数字穿插在字母中间**
//       （即某个数字后面还有字母）。
//   命中：mR1R73Ho / 8t89la / o3M07I1
//   不命中：YouDaoX64 / vcruntime140 / python39（数字是尾缀版本号，属正常命名）
//       —— spoolsv / conhost / msedge（纯小写系统名）也不命中。
// 注意：**纯字母**的随机名（sDhCOy / lTJIjejz）单看文件名无法与正常词区分，
// 由 IsSuspExe 的「父目录随机名」规则兜底；本函数不负责那一条。
bool IsShortRandomFileName(const std::string& pathOrName);

// 文件是否由「可信发布者」签名（Authenticode，缓存结果）。用于区分正经厂商安装器
// 与无签名的恶意安装包 —— 名字正常与否不作数，有没有可信签名才是关键判据。
// 2026-09-27 由 static 提升为导出：落地捕获的自动送检触发需要复用同一套签名判定，
// 不能各写一份（否则"可信签名"的口径会悄悄漂移）。
bool SigTrustedCached(const std::string& path);

// 文件是否带**可疑** NTFS 备用数据流（ADS）。
// 已排除系统与常见软件合法使用的流（Zone.Identifier 来源标记 / WriteData /
// Encryptable 的 EFS 标记 / Office 的 SummaryInformation 与 GUID 流 /
// SmartScreen …），所以返回 true 就是真·可疑流，可直接当证据用。
// 内部返回的是可疑流名（宽字符），这里只暴露"有没有"——影子模式的特征是 bool。
bool FileHasSuspiciousAds(const std::string& path);

// 文件创建时间距今的秒数。**取不到返回 -1**（无结论）。
// 时钟回拨 / 时间戳落在未来 → 返回 0（当作"极新"：攻击者能改时间戳，
// 但改不出"未来"）。与 IsFreshlyCreated 共用同一个 FileCreationMs，
// 所以「新」的定义不会在两处漂移。
long long FileCreatedAgeSec(const std::string& path);

// 大小写不敏感子串查找（ASCII）
bool ci_contains(const std::string& hay, const std::string& needle);
bool ci_ends_with(const std::string& str, const std::string& suffix);
std::string to_lower(const std::string& s);
