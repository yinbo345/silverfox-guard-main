// aifeat.h — AI 引擎的输入侧契约：特征向量
//
// ===========================================================================
//  定位：AI 引擎是规则引擎的**第二意见**，不是它的替代品
// ===========================================================================
//  现有 behavior.cpp 是「87 条硬规则 + 22 条评分项 + 阈值」的规则引擎，
//  它有两个结构性的天花板：
//    · 打分是**线性累加** —— 抓不到「单独看不出问题、组合起来很可疑」的模式
//      （例：无签名 + 刚落地 + 从 %TEMP% 拉起 + 父进程是脚本宿主，每一项都能
//        各自找到正常解释，四项同时出现的概率却极低）。
//    · 权重是**人手调**的常数 —— 无法从"事后发现判错了"的案例里自动变好。
//  所以 AI 引擎的价值在于组合弱信号与从纠错中学习，而不是"更聪明地识字面量"。
//
//  ⚠️ 因此本文件把规则引擎的**输出**也列为特征（见 kF_RuleHardHit / kF_RuleScore …）。
//     这不是"作弊"：AI 引擎的目标是「预测规则引擎会不会判错」，
//     规则引擎的结论当然是最强的输入之一。
//
// ===========================================================================
//  ★ 两条硬设计约束（改动前必读）
// ===========================================================================
//  1. BuildFeatures 必须是**纯函数**：不做任何文件 / 注册表 / 网络 I/O，
//     FeatureInput 里的东西全部由调用方事先算好。
//     理由：① 特征不纯就没法单元测试（跑一次测试要造一堆真实文件）；
//           ② 隐藏的磁盘 I/O 会出现在实时拦截路径上，而那条路径是有延迟预算的
//              （签名验证有缓存、PE 资源读取有一次 I/O，都是调用方决定要不要付的代价）。
//  2. 每个特征必须**一一对应真实存在的判据**，不能是"听起来合理"的占位。
//     本项目有一条「卡片能力核验法」：拿每个名词去 grep 全部源码，
//     命中注释但不命中代码 = 空壳。特征表同样适用 —— 列表里每一项都能指出
//     它由哪个函数算出（见 kFeatureNames 旁的注释）。
//     宁可只有 20 个真特征，也不要 64 个里 40 个是 0。
//
// ===========================================================================
//  值域约定
// ===========================================================================
//  所有特征取 float 且**归一化到 [0,1]**：
//    · bool 类     → 0 或 1
//    · 计数/长度类 → 除以一个经验上限后 clamp（上限写在特征名注释里）
//  统一值域的目的是让权重初始化、学习率、阈值这三样东西只需一套经验值。
//  未取到的特征填 **0**（不是 0.5）—— 0 表示"没有这个可疑迹象"，
//  对安全产品而言"证据缺失"应当偏向"不可疑"这一侧（误报比漏报更致命）。
#pragma once

#include <string>

namespace sf {
namespace ai {

// ---------------------------------------------------------------------------
//  维度
// ---------------------------------------------------------------------------
//  48 = 6 组 × 8。选这个数是因为：
//    · 够放当前全部真实信号，还留出扩展位；
//    · 是 8 的倍数，向量化与内存对齐友好；
//    · 48×4B = 192 字节，一次推理的内存足迹可以忽略不计。
//  改维度 = 模型格式不兼容，必须同时升 aimodel 的版本号。
constexpr int kFeatureDim = 48;

// 特征名表。用于①日志可读 ②导出训练集时写表头。
// **没有名字的特征向量等于一堆天书** —— 出问题时无法把"第 17 维偏大"
// 翻译成"到底是哪个信号偏大"。
extern const char* const kFeatureNames[kFeatureDim];

// ---------------------------------------------------------------------------
//  特征下标
// ---------------------------------------------------------------------------
//  用枚举常量而不是裸数字：以后调整顺序，改的是这里一处，
//  而不是散落在各处的 17 / 23 —— 后者改错不会报错，只会静默用错特征。
enum FeatIdx : int {
    // ---- 组 1：身份（来源：scanner.h 的签名/版本资源判定、路径语义）----
    kF_Signed            = 0,   // IsFileSignatureTrusted(imagePath)
    kF_SignedParent      = 1,   // IsFileSignatureTrusted(parentImagePath)
    kF_HasVendorInfo     = 2,   // HasVendorInfo(imagePath)  —— 「无签名但正常」的救命判据
    // ★ 实际判据是**两条并列取或**（此前注释写的"长度>=8/无元音辅音结构"两条都不是
    //   真实存在的判据，属"注释命中但代码不命中"的空壳描述，2026-09-25 校正）：
    //     ① aifeat.cpp 内部的 NameLooksRandom —— 去扩展名后 8~32 字符、>=4 个数字、
    //        无 3 连元音、不含 30 个常见软件词根（弱信号，保守）；
    //     ② 调用方传入的 in.fileNameIsRandom —— 影子模式从 scanner.h 的
    //        IsShortRandomFileName() 取（去 .exe 后 5~9 字符、数字穿插字母中间，
    //        即实时判定用的那条"短随机名"判据）。
    //   两条互为补充：② 认短随机名，① 认长随机名。**不要在这里再写第三份。**
    kF_NameRandomish     = 3,
    kF_NameIsSystemName  = 4,   // 文件名撞系统进程名（svchost/rundll32/…）
    kF_InSystemDir       = 5,   // System32 / SysWOW64 / WinSxS
    kF_InProgramFiles    = 6,   // Program Files / Program Files (x86)
    kF_InUserWritable    = 7,   // %TEMP% / %APPDATA% / %LOCALAPPDATA% / ProgramData / Users\Public

    // ---- 组 2：路径细节 ----
    // ★ 注意：本文件注释一律不得以反斜杠结尾。MSVC 会把「行尾反斜杠」当作
    //   行继续符（warning C4010），把下一行整行吞进注释 —— 只报 /W3 警告，
    //   却会让下一个枚举项凭空消失，表现为莫名其妙的 C2065。写路径时把
    //   反斜杠写在中间位置，或改用正斜杠/文字描述。
    kF_InTempDir         = 8,   // 路径含 Temp 或 Tmp 目录
    kF_InStartupDir      = 9,   // 启动文件夹（持久化高发地）
    kF_InDownloads       = 10,  // 路径含 Downloads 目录
    kF_InRootOfDrive     = 11,  // 直接躺在盘符根目录（形如 C: 后紧跟文件名）
    kF_PathDepth         = 12,  // 路径层数 / 16
    kF_ExtIsExe          = 13,
    kF_ExtIsScript       = 14,  // ps1/vbs/vbe/js/jse/wsf/wsh/bat/cmd/hta
    kF_ExtIsDll          = 15,

    // ---- 组 3：命令行形态（来源：behavior.cpp 的归一化层与评分项）----
    kF_HasHttpUrl        = 16,
    kF_UrlIsPayload      = 17,  // URL 末尾跟可执行/脚本扩展名
    kF_HasBase64         = 18,
    kF_HasEncodedCommand = 19,  // -enc / -encodedcommand
    kF_HasExecPolicyBypass = 20,// bypass
    kF_HasNoProfile      = 21,  // -nop / -noprofile
    kF_HasHiddenWindow   = 22,  // hidden
    kF_CmdLen            = 23,  // 命令行长度 / 1024
    kF_CmdQuoteCount     = 24,  // 引号对数 / 8（正常的带空格路径 1~2 对）
    kF_CmdChainCount     = 25,  // 命令分隔符（& | ; ）数 / 8
    kF_CmdHasCaret       = 26,  // 出现 ^ 或大量重复分隔符（去混淆前的痕迹）
    kF_CmdCaseNoise      = 27,  // 大小写无规律切换（混淆脚本常见）

    // ---- 组 4：父子关系（来源：behavior.cpp 的父子链判定 + 解释器父链）----
    kF_ParentIsExplorer  = 28,
    kF_ParentIsOffice    = 29,  // winword/excel/powerpnt/outlook/wps
    kF_ParentIsBrowser   = 30,
    kF_ParentIsIM        = 31,  // wechat/qq/dingtalk/feishu
    kF_ParentIsScriptHost= 32,  // cmd/powershell/wscript/cscript/mshta
    kF_ParentIsInterp    = 33,  // python/node/java/ruby（只算 1 级旁证）
    kF_ParentIsLolbin    = 34,  // rundll32/regsvr32/mshta/installutil/msiexec
    kF_ParentSameDir     = 35,  // 父子同目录（释放器画像的一个弱信号）

    // ---- 组 5：时间与落地（来源：scanner.h IsFreshlyCreated、rollback.h QuerySoftLanded）----
    kF_FreshlyCreated    = 36,  // 映像创建时间 <= 600s
    kF_VeryFresh         = 37,  // <= 60s
    kF_SoftLanded        = 38,  // 软件自写区 10 分钟内落地后被无签名执行（升档门信号）
    kF_SoftLandedSysZone = 39,  // 上一项中的"软件自写区"成立（Downloads/桌面不算）
    kF_FileSizeLog       = 40,  // log2(字节) / 32 —— stub 载荷通常很小
    kF_HasAds            = 41,  // 带 NTFS 备用数据流

    // ---- 组 6：规则引擎的既有结论（AI 的"对照组"）----
    kF_RuleHardHit       = 42,  // ProcVerdict.hard
    kF_RuleScore         = 43,  // ProcVerdict.score / 100
    kF_RuleLevel         = 44,  // ProcVerdict.level / 2
    kF_RuleHostUrl       = 45,  // tag == "host-url"
    kF_RuleMasquerade    = 46,  // tag == "masquerade"
    kF_RulePsFamily      = 47,  // tag ∈ {ps-encoded, ps-bypass, ps-nop, hidden}
};

// ---------------------------------------------------------------------------
//  特征向量
// ---------------------------------------------------------------------------
struct FeatureVector {
    float v[kFeatureDim];

    void Clear();                     // 全 0
    void Set(int idx, float val);     // 自动 clamp 到 [0,1]；越界下标被忽略
    void SetBool(int idx, bool val);
    float Get(int idx) const;

    // 紧凑文本：`0.000,1.000,...`（48 个字段，固定小数位）。
    // 用途是导出训练集与写进 sfdb 的 ai_observe.feat —— 用文本而不是二进制，
    // 是为了让"导出来看一眼"这件事不需要任何工具（能直接 grep / 粘进表格）。
    // FromText 严格校验字段个数：**多一个或少一个都拒**（见 .cpp 里的理由）。
    // ⚠️ ToText 只保留 3 位小数，所以文本往返的误差是 5e-4 量级；
    //    需要逐位精确时走内存里的 v[]，不要借文本转一圈。
    std::string ToText() const;
    bool FromText(const std::string& s);

    // 非零特征的可读摘要（日志用）："signed=0 hasVendorInfo=0 inTempDir=1 ..."
    std::string ToReadable() const;
};

// ---------------------------------------------------------------------------
//  输入：全部由调用方事先算好（见文件头约束 1）
// ---------------------------------------------------------------------------
//  刻意只放**平铺的原始事实**，不含任何"结论"：
//    - 想要 kF_NameRandomish 就传 fileNameIsRandom；
//    - 想要 kF_FreshlyCreated 就传 createdAtAgeSec = 120（范围判断在 BuildFeatures 里）。
//  为什么把"范围判断"留在 BuildFeatures：阈值属于AI引擎的输入定义，
//  改阈值应该改一处；如果把 IsFreshlyCreated(600) 的决定权交给调用方，
//  两个调用点就可能一个用 600、一个用 300 —— 同一特征两种含义。
struct FeatureInput {
    // 映像
    std::string imagePath;
    std::string commandLine;
    std::string parentImagePath;

    // 文件属性（取不到时保持默认 —— 默认值是"无迹象"这一侧）
    bool  signedImage        = false;
    bool  signedParent       = false;
    bool  hasVendorInfo      = false;
    // ★ 这三个字段有**现成的取值入口**，别自己在调用方现写（否则判据分叉）：
    //     fileNameIsRandom ← scanner.h  IsShortRandomFileName(imagePath)
    //     hasAds           ← scanner.h  FileHasSuspiciousAds(imagePath)
    //     createdAtAgeSec  ← scanner.h  FileCreatedAgeSec(imagePath)   （-1 原样传下来！）
    //   三者的正确性与"和实时判定同源"已由 src/tools/obsfeat_test.cpp 覆盖（21 项）。
    bool  fileNameIsRandom   = false;
    bool  hasAds             = false;
    long long fileSizeBytes  = -1;        // -1 = 未知
    long long createdAtAgeSec= -1;        // -1 = 未知；否则为距今秒数

    // 落地旁证（rollback.h QuerySoftLanded 的回查结果）
    int   softLandedLv       = 0;
    bool  softLandedSysZone  = false;

    // 规则引擎结论（behavior.h JudgeProcess 的输出）
    int   ruleLevel          = 0;
    int   ruleScore          = 0;
    bool  ruleHard           = false;
    std::string ruleTag;
};

// 纯函数：不做任何 I/O，同样的输入永远得到同样的输出。
//
// ★ 契约：所有路径特征都基于「`/` 归一化为 `\`、比较时不区分大小写」后的路径。
//   理由：`C:/Users/x/AppData/Local/Temp/a.exe` 是合法且可执行的路径，
//   若判据只认 `\temp\`，攻击者改一个字符就能让整组路径特征全部落空。
//   调用方不需要自己做归一化 —— BuildFeatures 在入口统一处理。
FeatureVector BuildFeatures(const FeatureInput& in);

// 把模型格式要求的输入维度与 kFeatureDim 对起来。模型维度不匹配时拒绝装载 ——
// 「用 32 维模型跑 48 维向量」这种错必须当场拒绝，否则前向计算会读越界或算错，
// 而算错的分数看起来完全正常（只是没有意义），属于最难发现的失败形态。
bool CheckDim(int modelInDim);

}  // namespace ai
}  // namespace sf
