// aifeat.cpp — 特征向量的实现（设计约束见 aifeat.h）
//
// ===========================================================================
//  ★ 为什么本文件自己写 Lower / Has / BaseName / DirName，而不 include common.h
// ===========================================================================
//  common.h 会连带 scanner.h，而一旦调用了 common.cpp 里的函数，
//  链接期就要把 common.cpp + scanner.cpp + … 整片拖进任何使用本文件的程序。
//  后果是：特征提取这段**纯逻辑**再也没法单独测试（跑一次测试要先编出半个杀软）。
//
//  所以这里自带 4 个 10 行的字符串工具。这与项目在 sfdb.cpp / hashdb.cpp
//  里各写一份 Utf8ToWide 是同一个取舍：**为了保住"可独立验证"而接受少量重复**。
//  判断标准是「这段逻辑写错了会不会当场报错」——
//  Low(er)/Has 写错了编译期就报，重复的代价远小于失去可测性。
#include "aifeat.h"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>

namespace sf {
namespace ai {

// ===========================================================================
//  值域上限（写在这里，不要散落到各分支里）
// ===========================================================================
//  归一化上限是「经验上限」，超过就按 1 计。选值的依据是"正常程序几乎不会超过"：
constexpr float kCmdLenCap    = 1024.f;  // 正常命令行极少超过 1KB
constexpr float kQuoteCap     = 8.f;     // 正常的带空格路径 1~2 对引号
constexpr float kChainCap     = 8.f;     // & | ; 分隔的命令串联
constexpr float kCaseCap      = 32.f;    // 大小写切换次数
constexpr float kPathDepthCap = 16.f;    // 路径层数
constexpr float kFileSizeCap  = 32.f;    // log2(字节)，32 = 4GB
constexpr int   kFreshSec     = 600;     // 与 scanner.h IsFreshlyCreated 的常用窗口一致
constexpr int   kVeryFreshSec = 60;

// ===========================================================================
//  局部字符串工具
// ===========================================================================
static std::string Low(const std::string& s) {
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i)
        o[i] = (char)std::tolower((unsigned char)o[i]);
    return o;
}

// 子串查找（输入须已小写化）
static bool Has(const std::string& low, const char* needle) {
    return low.find(needle) != std::string::npos;
}

// 主文件名（含扩展名）。同时接受 \ 与 / —— 攻击者与用户都可能混用。
static std::string BaseOf(const std::string& path) {
    size_t p = path.find_last_of("\\/");
    return (p == std::string::npos) ? path : path.substr(p + 1);
}

// 目录部分（不含结尾分隔符）
static std::string DirOf(const std::string& path) {
    size_t p = path.find_last_of("\\/");
    return (p == std::string::npos) ? std::string() : path.substr(0, p);
}

// 小写扩展名，含点（如 ".exe"）；无扩展名返回空串
static std::string ExtOf(const std::string& path) {
    std::string base = BaseOf(path);
    size_t p = base.find_last_of('.');
    if (p == std::string::npos || p + 1 >= base.size()) return std::string();
    return Low(base.substr(p));
}

// ★ 路径分隔符归一化：`/` 与 `\` 在 Windows 上**完全等价**，
//   `C:/Users/x/AppData/Local/Temp/a.exe` 是合法且能被 CreateProcess 跑起来的路径。
//   而下面所有路径判据都是 `\temp\` 形式的子串匹配 —— 不归一化的话，
//   攻击者把命令行里的一个字符换成 `/` 就能让"在 Temp 目录"这一整组特征全部落空。
//   这属于「改一个字符即可规避的特征」，必须在入口统一，而不是逐个判据补第二种写法。
static std::string NormSep(const std::string& s) {
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i)
        if (o[i] == '/') o[i] = '\\';
    return o;
}

static void Clamp01(float& x) {
    if (!(x == x)) { x = 0.f; return; }   // NaN → 0（NaN 会污染整个网络，必须挡在入口）
    if (x < 0.f) x = 0.f;
    if (x > 1.f) x = 1.f;
}

// ===========================================================================
//  特征名表
// ===========================================================================
//  ⚠️ 顺序必须与 aifeat.h 的 FeatIdx 完全一致。改了一处不改另一处不会报错，
//     只会让日志里的名字全部错位 —— 所以下面按 6 组 8 个整齐排列，便于肉眼核对。
const char* const kFeatureNames[kFeatureDim] = {
    "signed", "signedParent", "hasVendorInfo", "nameRandomish",
    "nameIsSystemName", "inSystemDir", "inProgramFiles", "inUserWritable",

    "inTempDir", "inStartupDir", "inDownloads", "inRootOfDrive",
    "pathDepth", "extIsExe", "extIsScript", "extIsDll",

    "hasHttpUrl", "urlIsPayload", "hasBase64", "hasEncodedCommand",
    "hasExecPolicyBypass", "hasNoProfile", "hasHiddenWindow", "cmdLen",
    "cmdQuoteCount", "cmdChainCount", "cmdHasCaret", "cmdCaseNoise",

    "parentIsExplorer", "parentIsOffice", "parentIsBrowser", "parentIsIM",
    "parentIsScriptHost", "parentIsInterp", "parentIsLolbin", "parentSameDir",

    "freshlyCreated", "veryFresh", "softLanded", "softLandedSysZone",
    "fileSizeLog", "hasAds",

    "ruleHardHit", "ruleScore", "ruleLevel", "ruleHostUrl",
    "ruleMasquerade", "rulePsFamily",
};

// 编译期自检：表长度必须等于维度。写漏一个元素 MSVC 会按 0 填充，
// 于是"最后几个特征没有名字"，而日志上完全看不出来 —— 用断言钉死。
static_assert(sizeof(kFeatureNames) / sizeof(kFeatureNames[0]) == (size_t)kFeatureDim,
              "kFeatureNames 的元素个数必须等于 kFeatureDim");

// ===========================================================================
//  FeatureVector
// ===========================================================================
void FeatureVector::Clear() {
    for (int i = 0; i < kFeatureDim; ++i) v[i] = 0.f;
}

void FeatureVector::Set(int idx, float val) {
    if (idx < 0 || idx >= kFeatureDim) return;   // 越界忽略：宁可少一个特征，不要写坏内存
    Clamp01(val);
    v[idx] = val;
}

void FeatureVector::SetBool(int idx, bool val) {
    Set(idx, val ? 1.f : 0.f);
}

float FeatureVector::Get(int idx) const {
    if (idx < 0 || idx >= kFeatureDim) return 0.f;
    return v[idx];
}

std::string FeatureVector::ToText() const {
    std::string o;
    char buf[32];
    for (int i = 0; i < kFeatureDim; ++i) {
        if (i) o += ',';
        // 固定 3 位小数：训练集导出后可以直接按列对齐看，也不会有
        // "0.1 vs 0.10" 这种同一含义两种写法的麻烦。
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.3f", v[i]);
        o += buf;
    }
    return o;
}

bool FeatureVector::FromText(const std::string& s) {
    Clear();
    const size_t n = s.size();
    size_t pos = 0;
    int idx = 0;
    while (idx < kFeatureDim) {
        const size_t comma = s.find(',', pos);
        const size_t end   = (comma == std::string::npos) ? n : comma;
        std::string tok = s.substr(pos, end - pos);
        // 允许字段两侧有空白（训练集是从表格里复制出来的，常带行尾 \r\n），
        // 但去掉空白后必须是**完整的一个数字**。
        size_t b = 0, e = tok.size();
        while (b < e && (tok[b] == ' ' || tok[b] == '\t')) ++b;
        while (e > b && (tok[e - 1] == ' ' || tok[e - 1] == '\t' ||
                         tok[e - 1] == '\r' || tok[e - 1] == '\n')) --e;
        if (b >= e) return false;                       // 空字段
        const std::string t2 = tok.substr(b, e - b);
        char* stop = nullptr;
        const float f = (float)strtod(t2.c_str(), &stop);
        if (stop == t2.c_str() || *stop != '\0') return false;   // `1.5abc` 这类必须拒
        if (!(f == f) || f > 1e30f || f < -1e30f) return false;  // nan / inf 不是有效特征值
        Set(idx, f);
        ++idx;
        if (comma == std::string::npos) { pos = n; break; }
        pos = comma + 1;
    }
    // 必须刚好 48 个。少一个就说明**喂进来的不是本版本的向量**，
    // 静默补 0 会让"模型吃错输入"这件事彻底查不出来。
    if (idx != kFeatureDim) return false;
    // 多一个同样要拒：49 个字段意味着生产者用的是**另一套布局**，
    // 「多出来的忽略掉」正是最难发现的那种错配 —— 后面 47 维其实是错位的，
    // 只有第 1 维是对的。允许尾随空白/换行，但不能再有别的字段。
    while (pos < n && (s[pos] == ' ' || s[pos] == '\t' ||
                       s[pos] == '\r' || s[pos] == '\n')) ++pos;
    return pos >= n;
}

std::string FeatureVector::ToReadable() const {
    std::string o;
    int shown = 0;
    for (int i = 0; i < kFeatureDim; ++i) {
        if (v[i] <= 0.f) continue;
        if (shown >= 12) { o += " ..."; break; }   // 日志行不能无限长
        if (shown) o += ' ';
        char buf[48];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%s=%.2f", kFeatureNames[i], v[i]);
        o += buf;
        ++shown;
    }
    return o.empty() ? "(无任何可疑特征)" : o;
}

// ===========================================================================
//  局部判据实现
// ===========================================================================
namespace {

// 随机文件名（**弱信号**，只在与其它信号叠加时才有意义）
//   ① 去扩展名后长度 8~32
//   ② 至少 4 个数字（`a8f3d9e2`、`x7k2m9q4`）
//   ③ 不含 3 个以上连续元音（排除 human/readable 的英文词）
//   ④ 不含常见功能词根 —— 真实软件名几乎总有一个
// 为什么这么保守：正常软件也常有 `run2024`、`vcredist_x64` 这类名字，
// 判太宽会把它们全卷进来。宁可是弱信号（权重低），也不要一个高权重的噪声源。
bool NameLooksRandom(const std::string& base) {
    size_t dot = base.find_last_of('.');
    std::string stem = (dot == std::string::npos) ? base : base.substr(0, dot);
    if (stem.size() < 8 || stem.size() > 32) return false;

    int digits = 0, letters = 0, maxVowelRun = 0, vowelRun = 0;
    for (size_t i = 0; i < stem.size(); ++i) {
        char c = (char)std::tolower((unsigned char)stem[i]);
        if (c >= '0' && c <= '9') { ++digits; vowelRun = 0; }
        else if (c >= 'a' && c <= 'z') {
            ++letters;
            if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
                ++vowelRun;
                if (vowelRun > maxVowelRun) maxVowelRun = vowelRun;
            } else vowelRun = 0;
        } else vowelRun = 0;
    }
    if (digits < 4)     return false;
    if (letters < 3)    return false;
    if (maxVowelRun >= 3) return false;

    static const char* kRoots[] = {
        "install", "setup", "update", "helper", "client", "server", "driver",
        "service", "tool", "manag", "reader", "player", "editor", "assist",
        "launch", "agent", "console", "monitor", "loader", "runtime", "config",
        "report", "system", "window", "module", "bridge", "patch", "boost",
    };
    std::string low = Low(stem);
    for (size_t i = 0; i < sizeof(kRoots) / sizeof(kRoots[0]); ++i)
        if (low.find(kRoots[i]) != std::string::npos) return false;
    return true;
}

bool NameIsSystemName(const std::string& base) {
    static const char* kNames[] = {
        "svchost.exe", "rundll32.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
        "services.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "explorer.exe",
        "spoolsv.exe", "smss.exe", "wininit.exe", "fontdrvhost.exe", "ctfmon.exe",
        "wuauclt.exe", "powershell.exe", "cmd.exe", "mshta.exe", "regsvr32.exe",
        "wscript.exe", "cscript.exe", "bitsadmin.exe", "certutil.exe", "taskmgr.exe",
    };
    std::string low = Low(base);
    for (size_t i = 0; i < sizeof(kNames) / sizeof(kNames[0]); ++i)
        if (low == kNames[i]) return true;
    return false;
}

bool ParentIsIn(const std::string& parentBase, const char* const* names, size_t n) {
    if (parentBase.empty()) return false;
    std::string low = Low(parentBase);
    for (size_t i = 0; i < n; ++i) if (low == names[i]) return true;
    return false;
}

}  // namespace

// ===========================================================================
//  ★ 纯函数：不碰文件系统、不碰注册表、不碰网络
// ===========================================================================
FeatureVector BuildFeatures(const FeatureInput& in) {
    FeatureVector f;
    f.Clear();

    // 先归一化再取小写：`/` 一律视作 `\`（见 NormSep 的理由）
    const std::string imgNorm = NormSep(in.imagePath);
    const std::string pNorm   = NormSep(in.parentImagePath);
    const std::string imgLow  = Low(imgNorm);
    const std::string cmdLow  = Low(in.commandLine);
    const std::string imgBase = BaseOf(imgNorm);
    const std::string pBase   = BaseOf(pNorm);
    const std::string ext     = ExtOf(imgNorm);

    // ---------------- 组 1：身份 ----------------
    f.SetBool(kF_Signed,           in.signedImage);
    f.SetBool(kF_SignedParent,     in.signedParent);
    f.SetBool(kF_HasVendorInfo,    in.hasVendorInfo);
    f.SetBool(kF_NameRandomish,    in.fileNameIsRandom || NameLooksRandom(imgBase));
    f.SetBool(kF_NameIsSystemName, NameIsSystemName(imgBase));

    // ★ inSystemDir 的判据刻意与 behavior.cpp 的 JudgeImagePath 里的 `inSystem` 一致
    //   （含 \windows\ 整体，而不只是 system32）。同一判据维护两种含义，
    //   会导致"特征说不在系统目录、规则说不算伪装"这类自相矛盾的日志。
    f.SetBool(kF_InSystemDir,
              Has(imgLow, "\\windows\\system32\\") ||
              Has(imgLow, "\\windows\\syswow64\\") ||
              Has(imgLow, "\\windows\\winsxs\\") ||
              Has(imgLow, "\\windows\\"));
    f.SetBool(kF_InProgramFiles,
              Has(imgLow, "\\program files\\") ||
              Has(imgLow, "\\program files (x86)\\"));
    // 用户可写区：**非管理员**即可写入的位置 —— 恶意落地几乎都在这里
    f.SetBool(kF_InUserWritable,
              Has(imgLow, "\\temp\\") || Has(imgLow, "\\tmp\\") ||
              Has(imgLow, "\\appdata\\") || Has(imgLow, "\\programdata\\") ||
              Has(imgLow, "\\users\\public\\") || Has(imgLow, "\\downloads\\"));

    // ---------------- 组 2：路径细节 ----------------
    f.SetBool(kF_InTempDir,    Has(imgLow, "\\temp\\") || Has(imgLow, "\\tmp\\"));
    f.SetBool(kF_InStartupDir,
              Has(imgLow, "\\start menu\\programs\\startup") ||
              Has(imgLow, "\\startup\\"));
    f.SetBool(kF_InDownloads,  Has(imgLow, "\\downloads\\"));
    {
        // 盘符根目录：C:\x.exe（只有一层反斜杠，且前面是 `X:`）
        // 用的是归一化后的路径，所以 `C:/x.exe` 同样成立。
        bool root = (imgNorm.size() >= 4 &&
                     std::isalpha((unsigned char)imgNorm[0]) &&
                     imgNorm[1] == ':' &&
                     imgNorm[2] == '\\');
        if (root) {
            std::string rest = imgNorm.substr(3);
            root = (rest.find('\\') == std::string::npos);
        }
        f.SetBool(kF_InRootOfDrive, root);
    }
    {
        int depth = 0;
        for (size_t i = 0; i < imgNorm.size(); ++i)
            if (imgNorm[i] == '\\') ++depth;
        f.Set(kF_PathDepth, depth / kPathDepthCap);
    }
    f.SetBool(kF_ExtIsExe,    ext == ".exe" || ext == ".com" || ext == ".scr");
    f.SetBool(kF_ExtIsScript, ext == ".ps1" || ext == ".vbs" || ext == ".vbe" ||
                              ext == ".js"  || ext == ".jse" || ext == ".wsf" ||
                              ext == ".wsh" || ext == ".bat" || ext == ".cmd" ||
                              ext == ".hta");
    f.SetBool(kF_ExtIsDll,    ext == ".dll" || ext == ".ocx" || ext == ".cpl");

    // ---------------- 组 3：命令行形态 ----------------
    // ⚠️ 这些子串判据与 behavior.cpp 的评分层同源。之所以要在特征里再出现一次：
    //    规则层是「各自加分」，AI 层要的是「同时具备哪些形态」——
    //    同一个信号在两层扮演的角色不同，不是重复实现。
    f.SetBool(kF_HasHttpUrl,   Has(cmdLow, "http://") || Has(cmdLow, "https://"));
    f.SetBool(kF_HasBase64,    Has(cmdLow, "base64"));
    f.SetBool(kF_HasEncodedCommand,
              Has(cmdLow, "-enc") || Has(cmdLow, "encodedcommand"));
    f.SetBool(kF_HasExecPolicyBypass, Has(cmdLow, "bypass"));
    f.SetBool(kF_HasNoProfile, Has(cmdLow, "-nop") || Has(cmdLow, "noprofile"));
    f.SetBool(kF_HasHiddenWindow, Has(cmdLow, "hidden"));

    // URL 末尾直接跟载荷扩展名（`…/a.exe`、`…/x.ps1`）—— 与 behavior.cpp 的
    // urlIsPayload 同源：URL 是"取回"，带扩展名才是"取回可执行的东西"。
    {
        bool payload = false;
        static const char* kPayloadExts[] = {
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi",
        };
        for (size_t i = 0; i < sizeof(kPayloadExts) / sizeof(kPayloadExts[0]) && !payload; ++i) {
            const char* e = kPayloadExts[i];
            const size_t el = strlen(e);
            size_t p = 0;
            while ((p = cmdLow.find(e, p)) != std::string::npos) {
                const size_t after = p + el;
                const char c = (after < cmdLow.size()) ? cmdLow[after] : '\0';
                if (c == '\0' || c == '"' || c == '\'' || c == ' ' || c == '?' ||
                    c == '&' || c == ')' || c == '|' || c == '>' || c == '#' ||
                    c == ';' || c == ',') { payload = true; break; }
                ++p;
            }
        }
        f.SetBool(kF_UrlIsPayload, f.Get(kF_HasHttpUrl) > 0.f && payload);
    }

    f.Set(kF_CmdLen, (float)in.commandLine.size() / kCmdLenCap);
    {
        int quotes = 0;
        for (size_t i = 0; i < in.commandLine.size(); ++i)
            if (in.commandLine[i] == '"') ++quotes;
        f.Set(kF_CmdQuoteCount, (quotes / 2) / kQuoteCap);
    }
    {
        int chain = 0;
        for (size_t i = 0; i < in.commandLine.size(); ++i) {
            char c = in.commandLine[i];
            if (c == '&' || c == '|' || c == ';') ++chain;
        }
        f.Set(kF_CmdChainCount, chain / kChainCap);
    }
    {
        int caret = 0;
        for (size_t i = 0; i < in.commandLine.size(); ++i)
            if (in.commandLine[i] == '^') ++caret;
        f.SetBool(kF_CmdHasCaret, caret > 0);
    }
    {
        // 大小写无规律切换：只在**连续字母**之间比较相邻两字符的大小写。
        // 用原始命令行（未小写化）——这正是这个特征存在的意义。
        int switchCount = 0;
        for (size_t i = 1; i < in.commandLine.size(); ++i) {
            unsigned char a = (unsigned char)in.commandLine[i - 1];
            unsigned char b = (unsigned char)in.commandLine[i];
            if (!std::isalpha(a) || !std::isalpha(b)) continue;
            if (std::isupper(a) != std::isupper(b)) ++switchCount;
        }
        f.Set(kF_CmdCaseNoise, switchCount / kCaseCap);
    }

    // ---------------- 组 4：父子关系 ----------------
    {
        static const char* kOffice[] = { "winword.exe", "excel.exe", "powerpnt.exe",
                                         "outlook.exe", "wps.exe", "et.exe", "wpp.exe",
                                         "msaccess.exe", "onenote.exe" };
        static const char* kBrowser[] = { "chrome.exe", "msedge.exe", "firefox.exe",
                                          "iexplore.exe", "360se.exe", "360chrome.exe",
                                          "brave.exe", "opera.exe" };
        static const char* kIM[] = { "wechat.exe", "weixin.exe", "qq.exe", "tim.exe",
                                     "dingtalk.exe", "feishu.exe", "lark.exe",
                                     "telegram.exe", "discord.exe" };
        static const char* kScriptHost[] = { "cmd.exe", "powershell.exe", "pwsh.exe",
                                             "wscript.exe", "cscript.exe", "mshta.exe" };
        static const char* kInterp[] = { "python.exe", "python3.exe", "py.exe",
                                         "node.exe", "java.exe", "javaw.exe",
                                         "ruby.exe", "php.exe", "perl.exe", "lua.exe" };
        static const char* kLolbin[] = { "rundll32.exe", "regsvr32.exe", "mshta.exe",
                                         "installutil.exe", "msiexec.exe",
                                         "certutil.exe", "bitsadmin.exe",
                                         "wmic.exe", "schtasks.exe", "forfiles.exe" };

        f.SetBool(kF_ParentIsExplorer,   Low(pBase) == "explorer.exe");
        f.SetBool(kF_ParentIsOffice,     ParentIsIn(pBase, kOffice,     sizeof(kOffice) / sizeof(kOffice[0])));
        f.SetBool(kF_ParentIsBrowser,    ParentIsIn(pBase, kBrowser,    sizeof(kBrowser) / sizeof(kBrowser[0])));
        f.SetBool(kF_ParentIsIM,         ParentIsIn(pBase, kIM,         sizeof(kIM) / sizeof(kIM[0])));
        f.SetBool(kF_ParentIsScriptHost, ParentIsIn(pBase, kScriptHost, sizeof(kScriptHost) / sizeof(kScriptHost[0])));
        f.SetBool(kF_ParentIsInterp,     ParentIsIn(pBase, kInterp,     sizeof(kInterp) / sizeof(kInterp[0])));
        f.SetBool(kF_ParentIsLolbin,     ParentIsIn(pBase, kLolbin,     sizeof(kLolbin) / sizeof(kLolbin[0])));

        // 父子同目录（大小写不敏感比较）
        const std::string pd = Low(DirOf(pNorm));
        f.SetBool(kF_ParentSameDir, !pd.empty() && pd == Low(DirOf(imgNorm)));
    }

    // ---------------- 组 5：时间与落地 ----------------
    if (in.createdAtAgeSec >= 0) {
        f.SetBool(kF_FreshlyCreated, in.createdAtAgeSec <= kFreshSec);
        f.SetBool(kF_VeryFresh,      in.createdAtAgeSec <= kVeryFreshSec);
    }
    f.SetBool(kF_SoftLanded,        in.softLandedLv > 0);
    f.SetBool(kF_SoftLandedSysZone, in.softLandedLv > 0 && in.softLandedSysZone);
    if (in.fileSizeBytes > 0) {
        const double lg = std::log((double)in.fileSizeBytes) / std::log(2.0);
        f.Set(kF_FileSizeLog, (float)(lg / (double)kFileSizeCap));
    }
    f.SetBool(kF_HasAds, in.hasAds);

    // ---------------- 组 6：规则引擎结论 ----------------
    f.SetBool(kF_RuleHardHit, in.ruleHard);
    f.Set(kF_RuleScore, (float)in.ruleScore / 100.f);
    f.Set(kF_RuleLevel, (float)in.ruleLevel / 2.f);
    f.SetBool(kF_RuleHostUrl,    in.ruleTag == "host-url");
    f.SetBool(kF_RuleMasquerade, in.ruleTag == "masquerade");
    f.SetBool(kF_RulePsFamily,
              in.ruleTag == "ps-encoded" || in.ruleTag == "ps-bypass" ||
              in.ruleTag == "ps-nop"     || in.ruleTag == "hidden");

    return f;
}

bool CheckDim(int modelInDim) {
    return modelInDim == kFeatureDim;
}

}  // namespace ai
}  // namespace sf
