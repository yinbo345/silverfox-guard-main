#pragma once
#include <cstddef>

// ============================================================================
//  iocs.h  —  银狐（SilverFox / 游蛇 / Void Arachne / SwimSnake）IOC 数据表
//
//  数据来源（多源交叉验证，均为公开威胁情报）：
//   1. CNCERT「银狐」木马专项打击行动 TOP10 恶意网络资产披露（2026-09）
//   2. 奇安信 / 安天 游蛇（SilverFox）技战术分析
//   3. Hexastrike《Silver Fox Abuses Stolen EV Certificates in AtlasCross RAT》
//      （2026-03，含 AtlasCross / PowerChell / Schools.exe / bifa668.com）
//   4. Breakglass Intelligence《ValleyRAT inside Fake Telegram》报告（2026-04）
//   5. FortiGuard / Knownsec 404 关于 ValleyRAT、Gh0st、Winos 4.0  lineage
//   6. zseagate/SilverFox-Scanner（MIT）windows_scanner.ps1 维测维度
//
//  设计原则：
//   - 进程名只收录「明确恶意」的载荷名，避免误杀 svchost.exe 等正常进程。
//   - IP/域名/路径/注册表为真实已披露 IOC；域名类无法在内网直接解析，
//     仅作参考展示，网络层以 IP+端口 精确匹配为主。
//   - 本表为「已知历史 IOC」，不能覆盖 0day；程序同时提供行为/路径启发式检测。
// ============================================================================

namespace iocs {

// 引擎版本（扩展联动时用于识别能力）
inline constexpr const char* ENGINE_VERSION = "1.0.0";

// ---- 进程名（大小写不敏感子串匹配；仅收录明确恶意载荷名）----
inline constexpr const char* PROC_NAMES[] = {
    "foxservice.exe",
    "xfolder32.exe",
    "svchost64.exe",
    "pXDc9LSz.exe",
    "pQpfOm.exe",
    "GjdLUhqZIJJB.exe",   // ValleyRAT 落地名（Breakglass 报告）
    "SingMusice.exe",      // ValleyRAT 相关
    "DesignAccent.exe",    // ValleyRAT 计划任务载荷（截图/隐写通信）
    "KhDzetMjQMsAGYw.exe", // 重命名后的 zpaqfranz 落地名（LOLBin）
    "Schools.exe",         // 被篡改的 Autodesk 组件（AtlasCross 投递）
};
inline constexpr std::size_t PROC_NAMES_N = sizeof(PROC_NAMES) / sizeof(PROC_NAMES[0]);

// 注：SodaMusicLauncher.exe 是字节跳动合法签名程序，仅作为 DLL 侧加载宿主被滥用，
// 不在进程名直接判定，改以「同目录出现未签名 powrprof.dll / wsc.dll」路径检测。

// ---- 常被银狐「侧加载 / DLL 劫持」滥用的系统同名 DLL ----
// 这些名字本身是 Windows 组件，正常只存在于 System32/SysWOW64；一旦出现在程序目录、用户目录、
// 临时目录等非系统位置，即为典型的「白利用」侧加载载荷。删除样本 EXE 时若不连它一起清除，
// 银狐可再次释放/重新下载同名 DLL 把样本重新拉起来。
// 说明：刻意不收 msvcp140/vcruntime140 这类 VC 运行库——便携软件常自带，误报率高。
inline constexpr const char* HIJACK_DLLS[] = {
    "version.dll", "winhttp.dll", "winmm.dll", "wtsapi32.dll", "secur32.dll",
    "dbghelp.dll", "dbgcore.dll", "profapi.dll", "cryptbase.dll", "msimg32.dll",
    "d3d9.dll", "d3d10.dll", "d3d11.dll", "dxgi.dll", "userenv.dll",
    "textshaping.dll", "uxtheme.dll", "nlaapi.dll", "riched20.dll", "comctl32.dll",
    "lpk.dll", "usp10.dll", "iphlpapi.dll", "powrprof.dll", "wsc.dll",
    "dwmapi.dll", "shcore.dll", "mpr.dll", "netutils.dll", "samcli.dll",
    "sechost.dll", "sspicli.dll", "bcryptprimitives.dll", "winspool.drv",
};
inline constexpr std::size_t HIJACK_DLLS_N = sizeof(HIJACK_DLLS) / sizeof(HIJACK_DLLS[0]);

// ---- 文件路径 / 文件名片段（大小写不敏感子串匹配）----
inline constexpr const char* PATH_FRAGMENTS[] = {
    "xfolder32",
    "nvsc.exe",
    "temp.key",
    "!!!文件恢复指南",
    "GitMndsetup",
    "WhatsAppBackup",
    "whatsapp_backup.lock",
    "bb.jpg",            // ValleyRAT 配置加载路径 C:\users\public\download\bb.jpg
    "powrprof.dll",      // 侧加载恶意 dll（配合 SodaMusicLauncher.exe）
    "wsc.dll",
    "Wxfun.dll",         // 注入微信的恶意 dll
    "wnBios",            // kernel rootkit PDB 签名
};
inline constexpr std::size_t PATH_FRAGMENTS_N = sizeof(PATH_FRAGMENTS) / sizeof(PATH_FRAGMENTS[0]);

// ---- 重点检查文件（存在即高度可疑）----
inline constexpr const char* WATCH_FILES[] = {
    "C:\\Program Files\\Internet Explorer\\nvsc.exe",
    "C:\\Program Files (x86)\\Internet Explorer\\nvsc.exe",
    "C:\\Windows\\System32\\temp.key",
    "C:\\Windows\\SysWOW64\\temp.key",
    "C:\\users\\public\\download\\bb.jpg",
    "C:\\ProgramData\\xfolder32",
    "C:\\Program Files (x86)\\GitMndsetup",
    "C:\\WhatsAppBackup\\WhatsAppData.zip",
    "C:\\ProgramData\\xfolder32\\xfolder32.exe",
};
inline constexpr std::size_t WATCH_FILES_N = sizeof(WATCH_FILES) / sizeof(WATCH_FILES[0]);

// ---- 重点扫描目录（递归检查内部文件是否命中 PATH_FRAGMENTS / 双后缀）----
inline constexpr const char* WATCH_DIRS[] = {
    "C:\\ProgramData",
    "C:\\Program Files (x86)\\GitMndsetup",
    "C:\\WhatsAppBackup",
    "C:\\Users\\Public\\Documents",
    "C:\\Users\\Public\\download",
    "C:\\Users\\Public",
};
inline constexpr std::size_t WATCH_DIRS_N = sizeof(WATCH_DIRS) / sizeof(WATCH_DIRS[0]);

// ---- 已知恶意 C2 IP（网络层精确匹配；命中即高危）----
inline constexpr const char* C2_IPS[] = {
    "177.4.3.92",
    "177.4.3.77",
    "177.4.3.54",
    "177.4.3.80",
    "177.4.3.34",
    "45.192.168.58",
    "148.66.19.186",
    "103.112.97.56",
    "104.143.42.150",
    "103.71.48.92",
    "61.111.250.139",  // bifa668.com（AtlasCross raw TCP C2）
    "118.107.43.65",   // ValleyRAT C2（CTG Server 香港）
    "8.218.109.247",   // 2026-09-11 实测样本 C2（被 8t89la.exe 经 NAT 外联 :18300）
};
inline constexpr std::size_t C2_IPS_N = sizeof(C2_IPS) / sizeof(C2_IPS[0]);

// ---- 已知恶意 C2 域名（仅参考展示；无法内网直连解析）----
inline constexpr const char* C2_DOMAINS[] = {
    "mlcrosoft.vip", "mlcro.net", "mlcro.my",   // 仿冒 microsoft 域名群
    "bifa668.com",
    "mugen888.com", "yyy16888.vip", "v-tal.net.br",
    "wtkblq.com", "lgtnfx.net", "wwkk1122.com",
    "9010.360sdgg.com",   // ValleyRAT wave1 C2
    "xqwmwru.top",        // WhatsApp 仿冒窃取器 C2
};
inline constexpr std::size_t C2_DOMAINS_N = sizeof(C2_DOMAINS) / sizeof(C2_DOMAINS[0]);

// ---- hosts 劫持检测：安全软件 / 系统防护 / 更新 官方域名 ----
// 银狐家族常把 360、腾讯管家、火绒、卡巴等官网，以及微软更新/Defender 域名
// 在 %SystemRoot%\System32\drivers\etc\hosts 中映射到 127.0.0.1 / 0.0.0.0，
// 以此屏蔽安全软件告警与更新。下列域名一旦被指向本地即高度可疑。
// 匹配规则：host 等于主体，或 host 以 "." + 主体 结尾（覆盖子域，且不会误中 evilmicrosoft.com 类）。
inline constexpr const char* PROTECTED_DOMAINS[] = {
    "360.cn", "360.com", "360safe.com", "qihoo.net", "qihoo.com",        // 360
    "qq.com", "tencent.com", "guanjia.qq.com",                          // 腾讯电脑管家
    "kingsoft.com", "duba.net", "ijinshan.com",                         // 金山毒霸
    "huorong.cn",                                                      // 火绒
    "kaspersky.com", "kaspersky-labs.com",                              // 卡巴斯基
    "symantec.com", "norton.com",                                       // 诺顿 / 赛门铁克
    "mcafee.com",                                                      // 迈克菲
    "bitdefender.com",                                                 // Bitdefender
    "avast.com",                                                       // Avast
    "avg.com",                                                         // AVG
    "eset.com",                                                        // ESET
    "trendmicro.com",                                                  // 趋势科技
    "microsoft.com", "windowsupdate.microsoft.com", "update.microsoft.com",
    "defender.microsoft.com", "windows.com",                            // MS 防护 / 系统更新
    "baidu.com",                                                       // 百度（含安全产品）
};
inline constexpr std::size_t PROTECTED_DOMAINS_N = sizeof(PROTECTED_DOMAINS) / sizeof(PROTECTED_DOMAINS[0]);

// ---- 可疑网络端口（与已知 C2 IP 配套；用于辅助判定）----
inline constexpr unsigned short C2_PORTS[] = {
    9899,  // bifa668 / AtlasCross
    5040,  // ValleyRAT
    8880,  // 游蛇历史 C2 端口
    7031,  // 103.71.48.92
};
inline constexpr std::size_t C2_PORTS_N = sizeof(C2_PORTS) / sizeof(C2_PORTS[0]);

// ---- ★★ 挖矿矿池常用端口（2026-10-03 新增，Win10 真样本实测补的洞）----
//  为什么必须单独一张表、不能并进 C2_PORTS：
//    语义完全不同。`C2_PORTS` 命中 = **铁证级**（配合 C2_IP 抬到 level 2 / score 200），
//    是「已知恶意基础设施」；矿池端口 = **可疑旁证**（7777 上跑着的不一定是矿，
//    可能有正常服务），单凭端口不能定罪。
//    并进去会让「连 7777 就终止」这种过宽处置落地 ⇒ 误杀面直接爆开。
//    ⇒ 端口只做**旁证**，必须与进程自身可疑（命令行/路径/信誉/行为判据）**叠加**才升级。
//
//  实证代价（2026-10-03 Win10 虚拟机真样本那一轮）：挖矿进程 CPU 100% 烧了一整轮，
//  主防**零告警**。根因链有两环，这一环是其中之一：
//    ① `service.cpp` 的 `if (!hitIp && !hitPort) return;`
//       ⇒ 矿池地址不在那 13 条 IP 里 ⇒ **连接事件当场丢弃，连一行日志都不打**
//       （铁律 24「哑巴兜底」：什么都不打 ⇒ 排障时是黑洞）；
//    ② 上一环的 netwatch 哑巴兜底（已修：60s 启动宽限 + 超窗判不健康）。
//  修完这一环，仍要靠 CPU 监控（正在做）才能兜住「不连已知矿池」的变种。
inline constexpr unsigned short MINER_PORTS[] = {
    3333,   // stratum 经典端口
    4444,
    5555,
    7777,   // 门罗币 cryptonight 主力矿池端口
    8888,
    14444,  // 以太坊 stratum
    45700,  // nanopool / monero
    45560,  // P2Pool / monero
    3334, 3335, 4443, 5556, 5566, 7778, 8899,  // 变体
};
inline constexpr std::size_t MINER_PORTS_N = sizeof(MINER_PORTS) / sizeof(MINER_PORTS[0]);

// 矿池协议特征串（命令行的形态判据；与端口互为佐证）
inline constexpr const char* MINER_PROTO_TOKENS[] = {
    "stratum+tcp", "stratum+ssl", "xmrig", "cpuminer", "minerd", "ethminer",
    "nbminer", "phoenixminer", "lolminer", "t-rex", "nanominer", "gminer",
    "cryptonight", "randomx", "rx/0", "donate-level", "nicehash",
};
inline constexpr std::size_t MINER_PROTO_TOKENS_N =
    sizeof(MINER_PROTO_TOKENS) / sizeof(MINER_PROTO_TOKENS[0]);

// ---- 注册表持久化位置（检查 Run / RunOnce / AppInit / IFEO）----
inline constexpr const char* REG_RUN_KEYS[] = {
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",  // AppInit_DLLs 在此
};
inline constexpr std::size_t REG_RUN_KEYS_N = sizeof(REG_RUN_KEYS) / sizeof(REG_RUN_KEYS[0]);

// ---- ★ IFEO（Image File Execution Options）劫持（2026-09-20 新增）----
// 主界面「扫描覆盖面」卡片自 v1.2 起就写着「注册表：自启动项 / IFEO 劫持 / 浏览器策略」，
// 但代码里**一行 IFEO 都没有**（grep "ifeo|Image File Execution|Debugger" 零命中）。
// 这是典型的"文案先行、实现缺席"——卡片在替程序吹牛。此处把它做成真的。
//
// 攻击原理：HKLM\...\Image File Execution Options\<某个exe> 下写一个 Debugger 值，
// 系统在启动该 exe 时会先运行 Debugger 指定的程序（原本这是给调试器用的）。
// 银狐/各类木马常用缺口（2026 年仍活跃）：
//   · 劫持 sethc.exe / utilman.exe / osk.exe / magnify.exe / narrator.exe
//     → 锁屏界面上按 Shift×5 / Win+U 即可拉出 SYSTEM 权限的任意程序（"粘滞键后门"）
//   · 劫持 taskmgr.exe / cmd.exe → 用户点任务管理器实际启动攻击者程序
//   · 劫持 msiexec.exe / svchost.exe → 更隐蔽的常驻
//
// 判定原则（避免误报）：
//   ① Debugger 值的路径必须指向**用户可写区域**（AppData / Temp / Users\Public /
//      ProgramData / Downloads）→ 正常软件绝不会把调试器指向这些地方；
//   ② 或指向不存在的文件（已被清理的残留劫持）；
//   ③ 若 Debugger 指向 Program Files / Windows 下的正常调试器路径，只记日志不报警。
inline constexpr const char* IFEO_KEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
// 最值得盯的被劫持宿主（值名固定为 "Debugger"）
inline constexpr const char* IFEO_HOT_TARGETS[] = {
    "sethc.exe",      // 粘滞键 —— 锁屏界面 Shift×5 拉出
    "utilman.exe",    // 轻松访问 —— 锁屏界面 Win+U 拉出
    "osk.exe",        // 屏幕键盘
    "magnify.exe",    // 放大镜
    "narrator.exe",   // 讲述人
    "displayswitch.exe",
    "atbroker.exe",
    "taskmgr.exe",    // 任务管理器
    "cmd.exe",
    "powershell.exe",
    "explorer.exe",
    "svchost.exe",
    "msiexec.exe",
    "rundll32.exe",
    "regedit.exe",
    "mmc.exe",
    "control.exe",
};
inline constexpr std::size_t IFEO_HOT_TARGETS_N = sizeof(IFEO_HOT_TARGETS) / sizeof(IFEO_HOT_TARGETS[0]);

// 用户可写区域片段：Debugger 指向这里 = 几乎确定是劫持
inline constexpr const char* USER_WRITABLE_HINTS[] = {
    "\\appdata\\", "\\temp\\", "\\users\\public\\", "\\programdata\\",
    "\\downloads\\", "\\desktop\\", "\\documents\\", "\\$recycle.bin\\",
    "\\windows\\temp\\", "\\roaming\\", "\\local\\microsoft\\windows\\inetcache\\",
};
inline constexpr std::size_t USER_WRITABLE_HINTS_N = sizeof(USER_WRITABLE_HINTS) / sizeof(USER_WRITABLE_HINTS[0]);

// ---- ★ 浏览器策略劫持（2026-09-20 新增）----
// 同样是卡片里早就写了、代码里没有的能力。
// 攻击原理：Chrome/Edge 会读取注册表 Policies\...\ 下的强制策略，
// 木马借此静默安装自己的扩展、改主页/搜索引擎、把攻击者证书装进信任列表。
// 这些策略**用户无法在浏览器界面里改回去**（会显示"由贵单位管理"），
// 是银狐一类木马维持浏览器驻留的常见手段。
//
// 判定原则：策略键下的值是不是"指向外部可写路径/陌生 URL"，而不是有策略就报——
// 企业环境（域策略）下存在策略属正常，全部报警会淹没真实发现。
inline constexpr const char* BROWSER_POLICY_KEYS[] = {
    "SOFTWARE\\Policies\\Google\\Chrome",
    "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionInstallForcelist",
    "SOFTWARE\\Policies\\Google\\Chrome\\ExtensionSettings",
    "SOFTWARE\\Policies\\Microsoft\\Edge",
    "SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionInstallForcelist",
    "SOFTWARE\\Policies\\Microsoft\\Edge\\ExtensionSettings",
    "SOFTWARE\\Policies\\Mozilla\\Firefox",
};
inline constexpr std::size_t BROWSER_POLICY_KEYS_N = sizeof(BROWSER_POLICY_KEYS) / sizeof(BROWSER_POLICY_KEYS[0]);

// 强制安装扩展列表（ExtensionInstallForcelist 的每个值就是一条扩展 ID）——
// 这些值意味着"用户在浏览器里看不到、也删不掉"的扩展
inline constexpr const char* BROWSER_FORCE_EXT_VALUE = "1";   // 值名从 1 开始编号

// 浏览器主页/搜索劫持值名
inline constexpr const char* BROWSER_HIJACK_VALUES[] = {
    "HomepageLocation",
    "HomepageIsNewTabPage",
    "NewTabPageLocation",
    "RestoreOnStartup",
    "RestoreOnStartupURLs",
    "DefaultSearchProviderSearchURL",
    "DefaultSearchProviderName",
    "ProxyMode",
    "ProxyServer",
    "ProxyPacUrl",
    "AuthServerWhitelist",           // 把凭据送去攻击者服务器
    "SSLErrorOverrideAllowed",       // 允许忽略证书错误
};
inline constexpr std::size_t BROWSER_HIJACK_VALUES_N = sizeof(BROWSER_HIJACK_VALUES) / sizeof(BROWSER_HIJACK_VALUES[0]);

// 注册表值名/数据中需警惕的片段
// 注：已移除 "silverfox"——那是安全厂商给木马家族起的代号，真实样本不会自称 silverfox，
// 反而与我们自己的程序名 SilverFoxGuardSvc 撞名，造成自误报。自排除另有统一白名单兜底。
inline constexpr const char* REG_VALUE_FRAGMENTS[] = {
    "xfolder32", "foxservice", "svchost64",
    "GitMndsetup", "WhatsAppBackup", "nvsc", "temp.key",
    ".pdf.exe", ".doc.exe", ".jpg.exe", ".txt.exe", ".png.exe",
};
inline constexpr std::size_t REG_VALUE_FRAGMENTS_N = sizeof(REG_VALUE_FRAGMENTS) / sizeof(REG_VALUE_FRAGMENTS[0]);

// ---- PowerShell / Python 持久化特征（银狐 2026+ 常用"落地即执行"脚本持久化，不落 PE）----
// 判定原则：不靠单一关键词，必须「解释器 + 可疑动作/位置」组合才报，避免日常脚本误报。
// ① PowerShell 强特征：-enc/-e base64、IEX/Invoke-Expression、DownloadString、FromBase64、
//    -WindowStyle Hidden、-NonInteractive（银狐/远控 loader 标配参数）。
inline constexpr const char* PS_STRONG_FRAGMENTS[] = {
    "-enc ", "-e ", "-encodedcommand", "invoke-expression", "iex(", "iex ",
    "downloadstring", "frombase64string", "-windowstyle", "-noninteractive", "hidden",
    "webclient", "start-process -windowstyle hidden",
};
inline constexpr std::size_t PS_STRONG_FRAGMENTS_N = sizeof(PS_STRONG_FRAGMENTS) / sizeof(PS_STRONG_FRAGMENTS[0]);

// ② Python 强特征：-c "内联代码" 或 指向 AppData/Temp 的 .py/.pyw 脚本（无窗口运行用 pythonw）。
inline constexpr const char* PY_STRONG_FRAGMENTS[] = {
    "pythonw", ".pyw", "\\appdata\\", "\\temp\\", " -c ", "pyinstaller",
};
inline constexpr std::size_t PY_STRONG_FRAGMENTS_N = sizeof(PY_STRONG_FRAGMENTS) / sizeof(PY_STRONG_FRAGMENTS[0]);
// 需要「解释器 + 至少一个恶意动作特征」才能判（脚本关键字；不含纯 .py 文件名——脚本本体合法存在）
inline constexpr const char* PY_SCRIPT_FRAGMENTS[] = {
    "socket", "ctypes", "crypt", "base64", "urllib", "requests", "subprocess",
    "winreg", "ctypes.windll", "http", "download", "exfil", "keylog",
};
inline constexpr std::size_t PY_SCRIPT_FRAGMENTS_N = sizeof(PY_SCRIPT_FRAGMENTS) / sizeof(PY_SCRIPT_FRAGMENTS[0]);

// ---- 计划任务名 / 描述片段 ----
inline constexpr const char* TASK_FRAGMENTS[] = {
    "SilverFox", "Task1", "DesignAccent", "GitMndsetup",
    "WhatsAppBackup",
};
inline constexpr std::size_t TASK_FRAGMENTS_N = sizeof(TASK_FRAGMENTS) / sizeof(TASK_FRAGMENTS[0]);

// 计划任务重点文件夹（PowerChell 常在 \Microsoft\Windows\AppID\ 下建任务）
inline constexpr const char* TASK_FOLDERS[] = {
    "\\",                              // 根
    "\\Microsoft\\Windows\\AppID",      // PowerChell 执行线索
};
inline constexpr std::size_t TASK_FOLDERS_N = sizeof(TASK_FOLDERS) / sizeof(TASK_FOLDERS[0]);

// ---- 双后缀诱饵扩展名（高风险：文档伪装成 exe）----
inline constexpr const char* DOUBLE_EXT[] = {
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
    ".txt.exe", ".jpg.exe", ".png.exe", ".rar.exe", ".zip.exe",
    ".ppt.exe", ".pptx.exe", ".html.exe",
};
inline constexpr std::size_t DOUBLE_EXT_N = sizeof(DOUBLE_EXT) / sizeof(DOUBLE_EXT[0]);

// ---- WMI 事件订阅过滤名片段（root\subscription __EventFilter）----
inline constexpr const char* WMI_FILTER_FRAGMENTS[] = {
    "SilverFox", "Task1", "Fox", "Guard", "Update", "Check",
};
inline constexpr std::size_t WMI_FILTER_FRAGMENTS_N = sizeof(WMI_FILTER_FRAGMENTS) / sizeof(WMI_FILTER_FRAGMENTS[0]);

// ---- 情报参考备注（不参与扫描，仅展示给用户/扩展）----
inline constexpr const char* INTEL_NOTES[] = {
    "失陷指征：RC4 密钥 qQ996545（Gh0st/Winos 系）；C2 握手标识字节 53 46 75 63 6b 00 00 00（'SFuck'）。",
    "被盗 EV 证书指纹 2C1D12F8BBE0827400A8440AF74FFFA8DCC8097C（DUC FABULOUS CO.,LTD，有效期至 2027-05）。",
    "线索举报邮箱：silverfox@cert.org.cn（CNCERT 银狐专项）。",
    "本程序 IOC 为历史已知项，无法覆盖 0day；若怀疑中毒请以专业杀软/应急为准。",
};
inline constexpr std::size_t INTEL_NOTES_N = sizeof(INTEL_NOTES) / sizeof(INTEL_NOTES[0]);

}  // namespace iocs
