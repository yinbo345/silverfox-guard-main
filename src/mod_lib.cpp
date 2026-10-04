// mod_lib.cpp — 云库下载更新链（病毒库四步线第 3 步）
//
// ===========================================================================
//  它做什么
// ===========================================================================
//  从官网基址取 `meta.json`，与本地库的**内容版本号**比对；需要更新时下载
//  `<name>.sfh` + `<name>.sfh.sig` 到 `cloud\<name>.sfh.tmp`，过四道校验，
//  然后交给 `sf::hashshare::InstallCloudLibs()` 原子换装。
//
//  三条命令：`libstat`（状态）/ `libcheck`（只查不装）/ `libupdate`（查+装）。
//
// ===========================================================================
//  ★★ 分工铁律：本文件**不碰** `cloud\<name>` 正式库文件
// ===========================================================================
//  本文件只写 `cloud\<name>.sfh.tmp`。理由不是洁癖，是**结构上的安全**：
//
//    · `mod_sfdb` 是三本库的唯一所有权方（`unique_ptr<HashDb>` + `shared_mutex`）。
//      如果这里也去动正式文件，就等于出现了**第二个写入方** —— 而"两个写入方
//      都以为自己是对的"这类问题在这里的后果是：库文件被换成半截的，
//      而 mmap 它的那个进程（可能正是我们自己）看到的是**未定义内容**。
//    · 分成两半之后，"下载失败"最坏的结果是**磁盘上多一个 .tmp 文件**；
//      正式库连字节都不会变。防护不可能因为一次网络故障而**降级**。
//
//  ∴ 「替换 + 重载」只能走 `hashshare::InstallCloudLibs()`（写锁内一次性完成
//     "卸 → 换 → 装 → 判定 → 失败回滚"）。
//
// ===========================================================================
//  ★ 四道校验，以及第 ② 道为什么拿**签名文件**当期望值
// ===========================================================================
//   ① HTTP 200 + 单文件字节上限（下载函数内硬性中止）
//   ② 算 .tmp 的 SHA-256，必须 == **签名文件里写的 sha256**
//   ③ libsig::VerifyLibFile(.tmp, .tmp.sig, sha) == kOk
//   ④ HashDb::Open(.tmp) 成功 **且** contentVersion >= 本地现有版本
//
//  ★★ 第 ② 道的期望值**不能**来自 `meta.json`：
//     `meta.json` 是我们自己发的普通文件，谁都能改，改了不会被发现 ——
//     拿它当期望值等于**没有校验**，只是多了一层看起来很像校验的代码。
//     而签名文件里的 `sha256` 是被 ECDSA 签名**覆盖**的
//     （签名对象 `"SFH1-SIG-V1\n"+keyId+"\n"+sha256`，见 libsig.h ①），
//     所以它才是密码学可信的"发布清单"。
//
//  ★ 第 ④ 道的版本号取自**库头**（`HashDb::Open` 之后的 Stats），不取 meta.json：
//     会被真正装载的是库文件，判据就该来自库文件本身。
//
// ===========================================================================
//  ★★ 三态 action：绝不用 ok:false 表达「已是最新」
// ===========================================================================
//     "installed"      装了新库并重载
//     "already-latest" 已是最新（**成功**，只是没动作）
//     "failed"         这次没成功，但**旧库还在正常服务**
//     "busy"           已有一次更新在跑（防止两个连接同时写同名的 .tmp）
//
//  ★ 「下载失败但旧库还在用」必须是 `ok:true` + `action:"failed"`，
//    **不能**报 `ok:false`：那会让调用方（GUI）显示成"病毒库坏了"，
//    而实际上防护一点没降级 —— 这是**假故障**，与"假成功"同样有害，
//    而且更难查（因为一切真的都正常）。
//
// ===========================================================================
//  ★ 自动路径只 `libcheck`，不做 `libupdate`（v1 取舍）
// ===========================================================================
//  自动检查无人看着。一旦出现「下载 → 校验失败 → 回滚」的循环，日志会滚动刷屏
//  而没有人会发现。所以自动路径发现新版本时**只记一行日志 + 置 pendingUpdate**，
//  把实际下载留给 `libupdate`（或将来 GUI 上的按钮）。
//  ⚠️ 因此**不要**在任何界面文案里写"已自动更新" —— 那是不成立的。
//
// ===========================================================================
//  ★ 节流用**单调时钟**（GetTickCount64），不用墙上时钟
// ===========================================================================
//  改系统时间是规避行为监测的头号手段。若节流用 `time()`，攻击者把时钟往前拨
//  就能让检查永不触发（或被反复触发）。单调时钟跨不过重启 —— 那没关系：
//  重启后本来就该重新检查一次（`kFirstCheckDelayMs` 兜住"开机网络没就绪"）。

#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#include "module.h"
#include "common.h"        // LogDbg / JsonString / JsonGetString / JsonGetInt64 / WriteFramed
#include "hashshare.h"     // GetLibInfo / InstallCloudLibs / CloudDirUtf8 / LibsJsonSnapshot
#include "libsig.h"        // ParseSigFile / VerifyLibFile / SigPathFor / ResultText
#include "hashdb.h"        // 第④道校验：把 .tmp 当库打开读版本号
#include "pehash.h"        // FileSha256
#include "sfstop.h"        // sf::IsStopRequested（Run 线程退出范式）

#include <atomic>
#include <cstdio>
#include <mutex>
#include <string>
#include <vector>

namespace {

// ===========================================================================
//  常量
// ===========================================================================
// 库基址（**不含末尾斜杠**）。
// ★★ 2026-09-26 银泊拍板：病毒库托管 = **独立站**，绝不并进官网。
//    本基址指向独立的 Cloudflare Pages 项目 silverfoxguard-libs
//    （https://silverfoxguard-libs.pages.dev），与官网 silverfoxguard-website
//    是两个项目、两套部署、两个域名 —— 官网的 /lib/ 路径从未部署过库文件
//    （SPA 回退假 200），也不要再往那边规划。
// ★ slug 仍是三处共用常量：本文件、hashbuild 的 --slug 默认值、
//   （独立站侧）lib/ 目录名。不一致的后果是 404 —— 代码会把它当网络故障，
//   排查方向直接跑偏，所以 meta.json 带 slug 字段做交叉校验。
const char* const kDefaultLibBaseUrl =
    "https://silverfoxguard-libs.pages.dev/lib/8c41d7a2e6b35f90";

constexpr DWORD     kDefaultTimeoutMs      = 8000;      // 比时钟的 3s 长：库是大文件
constexpr long long kDefaultMaxDownloadMb  = 512;       // 单文件上限
constexpr int       kDefaultIntervalHours  = 6;
constexpr DWORD     kFirstCheckDelayMs     = 5 * 60 * 1000;   // 启动后 5 分钟首查
constexpr DWORD     kMaxBackoffMs          = 60 * 60 * 1000;  // 退避上限 1 小时
constexpr long long kMetaMaxBytes          = 1024 * 1024;     // meta.json 上限 1 MB
constexpr DWORD     kRunTickMs             = 1000;            // Run 线程轮询间隔

// 三本库 → 远端文件名。
// ★ 顺序必须与 hashshare.h 的 kLibIdx* 一致（idx 决定目标文件名）。
struct Slot {
    int         idx;
    const char* file;         // 远端/本地共用的文件名
    // meta.json 里指向它 SHA-256 的字段名；nullptr = 这本库**不参与云端更新**
    const char* metaKey;
    bool        downloadable; // false = 只用于读本地状态展示，永不由云端下发
    const char* note;         // 不下发的理由（原样报给 libcheck 的调用方）
};
const Slot kSlots[5] = {
    { sf::hashshare::kLibIdxMalSha, "malicious.sfh",     "shaSha256", true,  "" },
    // ★★ 可信库**刻意不从云端下发** —— 这不是"还没做"，是设计。
    //    trusted.sfh 是「确定干净」白名单，它只参与展示、**不参与判定降权**
    //    （见 hashshare.h 里 HitTrusted 的注释）。一旦让它可被远端改写，
    //    就等于「远端能放松本地判定」，直接违反云库那条铁律：
    //    **只能加严、绝不放松**。
    //
    //  ★ 这条限制必须钉在**代码**里，不能靠"meta.json 里恰好没有 truSha256"
    //    这个巧合 —— 巧合是会变的：哪天有人给 hashbuild 补上 truSha256
    //    （很自然的想法："三本库都该有哈希"），本地就会开始下载可信库，
    //    而且**不报任何错**：签名照验、库照装、日志照绿。
    //    上线后表现为"白名单被远端悄悄放宽"，事后极难追查。
    //    所以：要让可信库可下发，必须显式改这里的 false。
    { sf::hashshare::kLibIdxTruSha, "trusted.sfh",       nullptr,     false,
      "可信库不由云端下发（设计如此）：远端若能改写白名单，就等于远端能放松本地判定" },
    { sf::hashshare::kLibIdxMalImp, "malicious_imp.sfh", "impSha256", true,  "" },
    { sf::hashshare::kLibIdxMalMd5, "malicious_md5.sfh",  "md5Sha256", true,  "" },
    { sf::hashshare::kLibIdxMalSha1,"malicious_sha1.sfh", "sha1Sha256",true,  "" },
};

// ===========================================================================
//  字符串/编码小工具
// ===========================================================================
// ★ 内部路径统一 UTF-8，而 GetFileAttributesA / CreateFileA 按 ANSI 解释 ——
//   中文用户名（C:\Users\银泊\…）下会静默失败，动作被跳过且日志无痕（铁律 §4）。
//   所以一律先转宽再调 *W。
std::wstring W(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ★ 反方向：宽 → UTF-8。必须走 WideCharToMultiByte(CP_UTF8)。
//   曾经这里写成 std::string(path.begin(), path.end())（把 wchar_t 迭代器往
//   std::string 里塞）—— 那会把每个 wchar_t 的**低字节**当成一个 char 拷过去，
//   MSVC 只给一条 C4244 警告（不报错）。后果是「中文用户名 → 路径变乱码」，
//   而它是**静默**的：字符串拼出来了、看着像路径，只是打不开，
//   日志里也只会看到一串问号 —— 正是铁律 §4 要防的那一类。
//   所以凡宽转窄一律走本函数，不要用迭代器构造函数。
std::string U8(const std::wstring& w) {
    if (w.empty()) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(),
                                      nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

bool StartsWith(const std::string& s, const char* p) {
    const size_t n = strlen(p);
    return s.size() >= n && s.compare(0, n, p) == 0;
}

std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// 十六进制判等（大小写不敏感）。库的 SHA-256 在不同来源可能大小写不同，
// 而"大小写不同"被判成"内容不符"会造出一类完全无法解释的假故障。
bool HexEqualsCi(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool IsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

bool PathExistsW(const std::string& utf8) {
    return GetFileAttributesW(W(utf8).c_str()) != INVALID_FILE_ATTRIBUTES;
}

// ===========================================================================
//  配置（lib_rules.txt）
// ===========================================================================
// 沿用 rollback 的外置配置惯例：key=value、`#` 行尾注释、**单条非法不影响其它条**。
struct Config {
    bool        enabled        = true;
    std::string baseUrl        = kDefaultLibBaseUrl;
    int         intervalHours  = kDefaultIntervalHours;
    DWORD       timeoutMs      = kDefaultTimeoutMs;
    long long   maxDownloadMb  = kDefaultMaxDownloadMb;
    // ★ 非法值计数。配置的失败形态是**零症状**的（"看起来用了你的配置，
    //   实际没用"），所以必须有一个数字能被 `libstat` 报出来。
    long long   warnCount      = 0;
    std::string warnFirst;
    std::string configPath;      // 实际加载到的那一份（空 = 用内置默认值）
};

Config g_cfg;
std::mutex g_cfgMu;

std::wstring ExeDirW() {
    wchar_t buf[MAX_PATH * 2] = {0};
    const DWORD n = GetModuleFileNameW(nullptr, buf, (DWORD)(sizeof(buf) / sizeof(buf[0])));
    if (n == 0 || n >= (DWORD)(sizeof(buf) / sizeof(buf[0]))) return std::wstring();
    std::wstring p(buf, n);
    const size_t pos = p.find_last_of(L"\\/");
    return (pos == std::wstring::npos) ? std::wstring() : p.substr(0, pos);
}

// 按序取第一个存在的候选路径：
//   <exe目录>\data\lib_rules.txt → <exe目录>\lib_rules.txt → <data>\lib_rules.txt
// 最后那个 `<data>` 与 mod_sfdb 的 DataDirW() 是同一个目录
// （%ProgramData%\SilverFoxGuard），但这里不引它 —— 配置要在 Init 最早阶段
// 就能读到，不该依赖另一个分体先跑完。
std::wstring FindConfigPathW() {
    std::vector<std::wstring> cands;
    const std::wstring exe = ExeDirW();
    if (!exe.empty()) {
        cands.push_back(exe + L"\\data\\lib_rules.txt");
        cands.push_back(exe + L"\\lib_rules.txt");
    }
    wchar_t pd[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH) > 0)
        cands.push_back(std::wstring(pd) + L"\\SilverFoxGuard\\lib_rules.txt");
    for (size_t i = 0; i < cands.size(); ++i) {
        if (GetFileAttributesW(cands[i].c_str()) != INVALID_FILE_ATTRIBUTES) return cands[i];
    }
    return std::wstring();
}

bool ReadTextFileW(const std::wstring& path, std::string& out, size_t maxBytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    out.clear();
    char buf[4096];
    DWORD rd = 0;
    while (ReadFile(h, buf, sizeof(buf), &rd, nullptr) && rd > 0) {
        out.append(buf, rd);
        if (out.size() > maxBytes) { out.clear(); CloseHandle(h); return false; }
    }
    CloseHandle(h);
    return true;
}

// ★ 配置解析失败**绝不静默回退默认值**（同 hashbuild::ParseBuiltAt 的纪律）：
//   记一行日志 + warnCount++。否则"我以为改了配置"会变成一个查不出来的状态。
void LoadConfig() {
    std::lock_guard<std::mutex> lk(g_cfgMu);
    Config c;   // 从默认值起
    c.warnCount = 0;

    const std::wstring path = FindConfigPathW();
    if (path.empty()) {
        sf::LogDbg("[lib] 未找到 lib_rules.txt，使用内置默认值（自动检查开启，间隔 6 小时）");
        g_cfg = c;
        return;
    }
    c.configPath = U8(path);   // 仅供 libstat 显示（UTF-8，中文路径也看得见）

    std::string text;
    if (!ReadTextFileW(path, text, 256 * 1024)) {
        c.warnCount = 1;
        c.warnFirst = "配置文件读取失败，已全部使用内置默认值";
        sf::LogDbg("[lib] ！！lib_rules.txt 读取失败，改用默认值：" + c.configPath);
        g_cfg = c;
        return;
    }

    size_t lineNo = 0;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t eol = text.find('\n', pos);
        if (eol == std::string::npos) eol = text.size();
        std::string line = text.substr(pos, eol - pos);
        pos = eol + 1;
        ++lineNo;

        // 去注释（# 之后全丢）与首尾空白
        const size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        line = Trim(line);
        if (line.empty()) continue;

        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            ++c.warnCount;
            if (c.warnFirst.empty())
                c.warnFirst = "第 " + std::to_string(lineNo) + " 行缺少 '='，已跳过";
            continue;
        }
        std::string k = Trim(line.substr(0, eq));
        std::string v = Trim(line.substr(eq + 1));

        // ★ 每条各用 try/catch：单条非法**不影响其它条**。
        //   std::stoi 对 "6x" 会成功（只读前缀）—— 这正是那种"看起来生效了"
        //   的坑，所以下面用"整串都是数字"的前置检查，不用 stoi 的宽容行为。
        auto isAllDigits = [](const std::string& s) {
            if (s.empty()) return false;
            for (size_t i = 0; i < s.size(); ++i)
                if (s[i] < '0' || s[i] > '9') return false;
            return true;
        };

        if (k == "enabled") {
            if (v == "1" || v == "true" || v == "on")       c.enabled = true;
            else if (v == "0" || v == "false" || v == "off") c.enabled = false;
            else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "enabled 取值非法（应为 1/0/true/false/on/off）：" + v; }
        } else if (k == "base_url") {
            std::string u = v;
            while (!u.empty() && u[u.size() - 1] == '/') u.erase(u.size() - 1);   // 规范化：去尾斜杠
            if (StartsWith(u, "http://") || StartsWith(u, "https://")) c.baseUrl = u;
            else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "base_url 必须以 http:// 或 https:// 开头：" + v; }
        } else if (k == "check_interval_hours") {
            if (isAllDigits(v) && v.size() <= 4) c.intervalHours = std::atoi(v.c_str());
            else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "check_interval_hours 应为非负整数小时：" + v; }
        } else if (k == "timeout_ms") {
            if (isAllDigits(v) && v.size() <= 7) {
                const long long ms = std::atoll(v.c_str());
                if (ms >= 500 && ms <= 600000) c.timeoutMs = (DWORD)ms;
                else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "timeout_ms 超出合理范围（500~600000）：" + v; }
            } else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "timeout_ms 应为整数毫秒：" + v; }
        } else if (k == "max_download_mb") {
            if (isAllDigits(v) && v.size() <= 5) {
                const long long mb = std::atoll(v.c_str());
                if (mb >= 1 && mb <= 4096) c.maxDownloadMb = mb;
                else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "max_download_mb 超出合理范围（1~4096）：" + v; }
            } else { ++c.warnCount; if (c.warnFirst.empty()) c.warnFirst = "max_download_mb 应为整数 MB：" + v; }
        } else {
            ++c.warnCount;
            if (c.warnFirst.empty()) c.warnFirst = "未知配置项（已忽略）：" + k;
        }
    }

    if (c.warnCount > 0)
        sf::LogDbg("[lib] ！！lib_rules.txt 有 " + std::to_string(c.warnCount) +
                   " 处问题（首条：" + c.warnFirst + "）—— 已按默认值继续，详见 libstat.configWarn");

    g_cfg = c;
    sf::LogDbg("[lib] 配置已加载：" + c.configPath +
               "；enabled=" + (c.enabled ? "1" : "0") +
               " interval=" + std::to_string(c.intervalHours) + "h" +
               " timeout=" + std::to_string((long long)c.timeoutMs) + "ms");
}

Config CfgCopy() {
    std::lock_guard<std::mutex> lk(g_cfgMu);
    return g_cfg;
}

// ===========================================================================
//  运行时状态
// ===========================================================================
struct State {
    ULONGLONG startTick      = 0;    // Init 时刻（单调）
    ULONGLONG lastCheckTick  = 0;    // 上次检查完成时刻（0 = 还没查过）
    ULONGLONG lastUpdateTick = 0;
    long long failStreak     = 0;    // 连续失败次数（决定退避）
    bool      pendingUpdate  = false;// 自动检查发现新版本，等人工 libupdate
    long long remoteVersion  = 0;
    std::string remoteVersionText;
    long long checkOk = 0, checkFail = 0, updateOk = 0, updateFail = 0;
    std::string lastCheckResult;
    std::string lastUpdateResult;
    std::string lastError;
};
State g_st;
std::mutex g_stMu;

// ★ 同一时刻只允许一次更新在跑。
//   不加这个的话，两个管道连接同时 libupdate 会**各自写同名的 .tmp**
//   （`malicious.sfh.tmp`）—— 一个在写、另一个在改名，结果是
//   "库装上了但内容是谁的说不清"。
std::atomic<bool> g_busy{false};

struct BusyGuard {
    bool held = false;
    BusyGuard() { held = !g_busy.exchange(true); }
    ~BusyGuard() { if (held) g_busy.store(false); }
};

// ===========================================================================
//  URL 与 HTTP
// ===========================================================================
// ★★ 2026-09-25 修：原实现**从不剥掉端口**，把 "127.0.0.1:8791"
//    整个当主机名交给 WinHttpConnect，而端口恒用下面硬编码的
//    INTERNET_DEFAULT_HTTP(S)_PORT → SendRequest 直接失败，
//    GetLastError = **87（ERROR_INVALID_PARAMETER）**。
//
//    为什么这个 bug 特别值得记一笔：**它只在 URL 带显式端口时才发作**。
//    正式基址 `https://silverfoxguard.dpdns.org/lib/<slug>` 没有端口 →
//    一切正常；所以按"正式环境跑通就算过"的思路，这个 bug 会一直潜伏，
//    直到哪天有人把库放到一个非默认端口（预发环境 / 自建镜像 / 内网源）——
//    那时症状是"取库永远失败"，而错误文案还告诉你是网络问题。
//    实测证据（C:\temp\probe_winhttp.c 用例 G/H）：
//      host="127.0.0.1:8791" port=80  → 失败 err=87
//      host="127.0.0.1"      port=8791 → HTTP 200
//
//    所以这里除了剥端口，还顺手支持 **IPv6 字面量** `[::1]:8791` 形态 ——
//    不作弊式地"再 find(':') 一次"，因为那会把 IPv6 地址切坏。
bool SplitUrl(const std::string& url, bool& https, std::wstring& host, DWORD& outPort,
              std::wstring& path, std::string& err) {
    std::string u = Trim(url);
    https = true;
    if (StartsWith(u, "https://"))      u = u.substr(8);
    else if (StartsWith(u, "http://")) { u = u.substr(7); https = false; }
    else { err = "URL 必须以 http:// 或 https:// 开头"; return false; }

    const size_t slash = u.find('/');
    std::string hp = (slash == std::string::npos) ? u : u.substr(0, slash);   // host[:port]
    const std::string p = (slash == std::string::npos) ? std::string("/") : u.substr(slash);

    // ---- 分离 host 与 port ----
    std::string h;
    std::string portTxt;
    if (!hp.empty() && hp[0] == '[') {
        // IPv6 字面量：[::1] 或 [::1]:8791
        const size_t close = hp.find(']');
        if (close == std::string::npos) { err = "URL 的 IPv6 主机缺少 ']'"; return false; }
        h = hp.substr(1, close - 1);
        const std::string rest = hp.substr(close + 1);
        if (!rest.empty()) {
            if (rest[0] != ':') { err = "URL 的 IPv6 主机后应为 ':端口'"; return false; }
            portTxt = rest.substr(1);
        }
    } else {
        const size_t colon = hp.find(':');
        if (colon == std::string::npos) {
            h = hp;
        } else {
            h = hp.substr(0, colon);
            portTxt = hp.substr(colon + 1);
        }
    }

    if (h.empty()) { err = "URL 缺少主机名"; return false; }

    // 端口：空 = 按协议取默认；给了就必须是合法数字 ——
    // ★ 非法端口**报错**而不是悄悄回落成默认端口。悄悄回落会让
    //   "配错端口"表现为"连到了另一台服务器"，那是查不出来的。
    if (portTxt.empty()) {
        outPort = https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    } else {
        if (portTxt.size() > 5) { err = "URL 端口过长：" + portTxt; return false; }
        for (size_t i = 0; i < portTxt.size(); ++i)
            if (portTxt[i] < '0' || portTxt[i] > '9') { err = "URL 端口含非数字字符：" + portTxt; return false; }
        const long long pv = std::atoll(portTxt.c_str());
        if (pv < 1 || pv > 65535) { err = "URL 端口超出 1~65535：" + portTxt; return false; }
        outPort = (DWORD)pv;
    }

    host = W(h);
    path = W(p);
    if (host.empty() || path.empty()) { err = "URL 主机或路径转换失败"; return false; }
    return true;
}

// ★ WinHTTP 失败时的**诚实**文案。
//   原实现无论什么原因都写「网络不可达 / 超时 / TLS 失败」—— 那是**凭空编原因**：
//   本次实锤的失败原因是 err=87（主机名非法，端口没剥），与网络毫无关系，
//   却让排查方向直接偏到代理设置上去（我自己就先怀疑了 AUTOMATIC_PROXY）。
//   所以这里只做一件事：把**真实错误码**摆出来，再给出已知码的提示。
//   「不知道就说不知道」比「猜一个听起来合理的原因」有用得多。
std::string WinHttpErrText(DWORD e) {
    const char* hint = "";
    switch (e) {
        case 87:    hint = "（ERROR_INVALID_PARAMETER —— 主机名/端口/路径非法，先看 URL 解析）"; break;
        case 12002: hint = "（ERROR_WINHTTP_TIMEOUT —— 超时）"; break;
        case 12007: hint = "（ERROR_WINHTTP_NAME_NOT_RESOLVED —— 域名解析不了）"; break;
        case 12029: hint = "（ERROR_WINHTTP_CANNOT_CONNECT —— 连不上）"; break;
        case 12175: hint = "（ERROR_WINHTTP_SECURE_FAILURE —— 证书/TLS 问题）"; break;
        case 12178: hint = "（ERROR_WINHTTP_AUTODETECTION_FAILED —— 自动代理探测失败）"; break;
        case 12180: hint = "（ERROR_WINHTTP_AUTO_PROXY_SERVICE_ERROR —— 自动代理服务出错）"; break;
        default: break;
    }
    return "WinHTTP 错误 " + std::to_string((long long)e) + hint;
}

// 一次 GET。
//   toFile=true  → 流式写入 dstUtf8；失败时**删掉半截文件**（留着它会被
//                  下半段流程当成"下载成功"）
//   toFile=false → 收进 outBody（上限 maxBytes）
// maxBytes <= 0 表示不限。
bool HttpGet(const std::string& url, DWORD timeoutMs, long long maxBytes,
             bool toFile, const std::string& dstUtf8,
             std::string& outBody, DWORD& outStatus, std::string& err) {
    outStatus = 0;
    bool https = true;
    std::wstring host, path;
    DWORD port = INTERNET_DEFAULT_HTTPS_PORT;
    if (!SplitUrl(url, https, host, port, path, err)) return false;

    HINTERNET hSess = WinHttpOpen(L"SilverFoxGuard/1.0 (lib)",
                                  WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                  WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSess) { err = "WinHttpOpen 失败"; return false; }
    WinHttpSetTimeouts(hSess, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    // ★ 端口用 SplitUrl 解析出来的，**不再硬编码 INTERNET_DEFAULT_***。
    //   原实现恒传默认端口，同时又把 ":8791" 留在主机名里 → 双重错，
    //   而且只在 URL 带端口时发作（见 SplitUrl 上方的实测记录）。
    HINTERNET hConn = WinHttpConnect(hSess, host.c_str(), (INTERNET_PORT)port, 0);
    if (!hConn) {
        WinHttpCloseHandle(hSess);
        err = "连接失败（" + WinHttpErrText(GetLastError()) + "，host=" + U8(host) +
              " port=" + std::to_string((long long)port) + "）";
        return false;
    }

    HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr,
                                        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                        https ? WINHTTP_FLAG_SECURE : 0);
    if (!hReq) {
        const DWORD le = GetLastError();
        WinHttpCloseHandle(hConn); WinHttpCloseHandle(hSess);
        err = "建请求失败（" + WinHttpErrText(le) + "）";
        return false;
    }

    // 防缓存：★ WinHTTP 里**没有** WINHTTP_DISABLE_CACHING 这个常量（那是 WinINet
    // 的概念，WinHTTP 是精简栈、自身不缓存）。真正的风险来自中间代理，
    // 靠显式请求头声明 no-cache 才是正确做法。库文件尤其不能拿到缓存副本 ——
    // 一个被缓存的库就是**过期的库**。
    static const wchar_t* kNoCacheHdr =
        L"Cache-Control: no-cache, no-store\r\nPragma: no-cache\r\n";

    bool ok = false;
    if (WinHttpSendRequest(hReq, kNoCacheHdr, (DWORD)-1L, nullptr, 0, 0, 0) &&
        WinHttpReceiveResponse(hReq, nullptr)) {
        DWORD status = 0, len = sizeof(status);
        WinHttpQueryHeaders(hReq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &len,
                            WINHTTP_NO_HEADER_INDEX);
        outStatus = status;
        if (status != 200) {
            // 404 单独说清楚：最常见的成因是 slug 不一致或文件没部署。
            err = (status == 404) ? "HTTP 404（文件不存在：基址/slug/文件名对不上？）"
                                  : ("HTTP " + std::to_string((long long)status));
        } else {
            HANDLE f = INVALID_HANDLE_VALUE;
            bool openOk = true;
            if (toFile) {
                f = CreateFileW(W(dstUtf8).c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                if (f == INVALID_HANDLE_VALUE) {
                    openOk = false;
                    err = "无法创建暂存文件（错误码 " +
                          std::to_string((long long)GetLastError()) + "）";
                }
            }
            if (openOk) {
                bool ioOk = true;
                long long total = 0;
                std::string body;
                for (;;) {
                    DWORD avail = 0;
                    if (!WinHttpQueryDataAvailable(hReq, &avail) || avail == 0) break;
                    char buf[16384];
                    const DWORD want = (avail < (DWORD)sizeof(buf)) ? avail : (DWORD)sizeof(buf);
                    DWORD rd = 0;
                    if (!WinHttpReadData(hReq, buf, want, &rd) || rd == 0) {
                        err = "读取响应体中断"; ioOk = false; break;
                    }
                    total += (long long)rd;
                    if (maxBytes > 0 && total > maxBytes) {
                        err = "响应体超过上限（" + std::to_string(maxBytes) + " 字节）";
                        ioOk = false; break;
                    }
                    if (toFile) {
                        DWORD wr = 0;
                        if (!WriteFile(f, buf, rd, &wr, nullptr) || wr != rd) {
                            err = "写入暂存文件失败（错误码 " +
                                  std::to_string((long long)GetLastError()) + "）";
                            ioOk = false; break;
                        }
                    } else {
                        body.append(buf, rd);
                    }
                }
                if (toFile) CloseHandle(f);
                if (ioOk) {
                    ok = true;
                    if (!toFile) outBody = body;
                }
            }
        }
    } else {
        // ★ 不再编造原因。原先是 "请求失败（网络不可达 / 超时 / TLS 失败）" ——
        //   连"网络"这个词都是猜的。这里只报真实错误码。
        err = "请求失败（" + WinHttpErrText(GetLastError()) + "）";
    }

    WinHttpCloseHandle(hReq);
    WinHttpCloseHandle(hConn);
    WinHttpCloseHandle(hSess);

    // ★ 失败后必须删掉半截文件：它是 .tmp，会被下一次流程当作"已下载完成"。
    if (toFile && !ok && PathExistsW(dstUtf8)) {
        SetFileAttributesW(W(dstUtf8).c_str(), FILE_ATTRIBUTE_NORMAL);
        DeleteFileW(W(dstUtf8).c_str());
    }
    return ok;
}

// ===========================================================================
//  meta.json
// ===========================================================================
struct MetaInfo {
    bool        ok = false;
    std::string err;
    std::string slug;
    long long   version = 0;
    std::string versionText;
    long long   builtAtUnix = 0;
    long long   shaCount = 0, impCount = 0, md5Count = 0, sha1Count = 0;   // 纯信息字段，**不是必需项**（见 ParseMeta）
    std::string shaSha256, impSha256, md5Sha256, sha1Sha256;               // 空 = 本次发布不含这本库
    // ★ 刻意**不解析** truSha256：可信库不由云端下发，理由见 kSlots 里那条长注释。
    //   解析一个用不到的字段本身没害，但它是一种诱惑 ——
    //   "既然都读出来了，那不如用起来"，而用起来正是要防的那件事。
};

// ★ 字段存在性必须单独判：`JsonGetInt64` 对**不存在的键**返回 0，
//   于是"没有 version 字段"与"version = 0"不可区分 —— 这正是静默降级。
bool HasKey(const std::string& j, const char* k) {
    return j.find(std::string("\"") + k + "\":") != std::string::npos;
}

MetaInfo ParseMeta(const std::string& body) {
    MetaInfo m;
    // 严格：缺关键字段就整体失败，不做"缺了当默认"的宽容处理。
    //
    // ★ 必需字段只有这三个 —— 它们在 hashbuild.cpp 里是**无条件**写出的。
    //   特别注意**不要**把 `shaCount` 放进来：`hashbuild --only imp` 时
    //   biSha.built == false → **不写 shaCount**（也不写 shaSha256）。
    //   把那种 meta.json 判成"结构不对"，后果是：云端明明发布了新库，
    //   本地却报字段缺失并且**永不更新** —— 一个纯粹的假故障，
    //   而且症状看着像"官网部署有问题"，会把人往错方向带。
    const char* kRequired[] = { "schema", "slug", "version" };
    for (size_t i = 0; i < sizeof(kRequired) / sizeof(kRequired[0]); ++i) {
        if (!HasKey(body, kRequired[i])) {
            m.err = std::string("meta.json 缺少必需字段：") + kRequired[i];
            return m;
        }
    }
    m.slug          = sf::JsonGetString(body, "slug");
    m.version       = sf::JsonGetInt64(body, "version");
    m.versionText   = HasKey(body, "versionText") ? sf::JsonGetString(body, "versionText") : std::string();
    m.builtAtUnix   = HasKey(body, "builtAtUnix") ? sf::JsonGetInt64(body, "builtAtUnix") : 0;
    m.shaCount      = HasKey(body, "shaCount")    ? sf::JsonGetInt64(body, "shaCount")   : 0;
    m.impCount      = HasKey(body, "impCount")    ? sf::JsonGetInt64(body, "impCount")   : 0;
    m.md5Count      = HasKey(body, "md5Count")    ? sf::JsonGetInt64(body, "md5Count")   : 0;
    m.sha1Count     = HasKey(body, "sha1Count")   ? sf::JsonGetInt64(body, "sha1Count")  : 0;
    m.shaSha256     = HasKey(body, "shaSha256")   ? sf::JsonGetString(body, "shaSha256") : std::string();
    m.impSha256     = HasKey(body, "impSha256")   ? sf::JsonGetString(body, "impSha256") : std::string();
    m.md5Sha256     = HasKey(body, "md5Sha256")   ? sf::JsonGetString(body, "md5Sha256") : std::string();
    m.sha1Sha256    = HasKey(body, "sha1Sha256")  ? sf::JsonGetString(body, "sha1Sha256") : std::string();

    // 哈希字段若存在就必须是合法 64 位 hex —— 一个被写坏的清单比没有清单更危险：
    // 它会让我们去下"内容永远对不上"的文件，然后每次都失败，而原因看起来像网络问题。
    if (!m.shaSha256.empty() && !IsHex64(m.shaSha256)) { m.err = "meta.json 的 shaSha256 不是 64 位十六进制"; return m; }
    if (!m.impSha256.empty() && !IsHex64(m.impSha256)) { m.err = "meta.json 的 impSha256 不是 64 位十六进制"; return m; }
    if (!m.md5Sha256.empty() && !IsHex64(m.md5Sha256)) { m.err = "meta.json 的 md5Sha256 不是 64 位十六进制"; return m; }
    if (!m.sha1Sha256.empty() && !IsHex64(m.sha1Sha256)) { m.err = "meta.json 的 sha1Sha256 不是 64 位十六进制"; return m; }

    // ★ 真正该被要求的是「至少有一本库的哈希」—— 这才等价于"这份清单能指导更新"。
    //   比"必须有某个具体字段名"更贴近意图，也不会被 --only 之类的开关改变。
    if (m.shaSha256.empty() && m.impSha256.empty() && m.md5Sha256.empty() && m.sha1Sha256.empty()) {
        m.err = "meta.json 里没有任何库的哈希（shaSha256 / impSha256 / md5Sha256 / sha1Sha256 都是空）"
                "—— 这份清单无法判断该更新什么";
        return m;
    }

    m.ok = true;
    return m;
}

// 从基址推出 slug（基址末段）。用于与 meta.slug 对账。
std::string SlugOfBaseUrl(const std::string& base) {
    std::string u = base;
    while (!u.empty() && u[u.size() - 1] == '/') u.erase(u.size() - 1);
    const size_t pos = u.find_last_of('/');
    return (pos == std::string::npos) ? std::string() : u.substr(pos + 1);
}

// 本次发布清单里，这本库的期望哈希 —— 只回答"远端有没有新版本"这一个问题。
//
// ★ 必须说清楚它**不是**校验用的期望值：这里读的是 meta.json，而
//   **meta.json 不参与任何安全校验**（谁都能改它）。真正用于校验的期望值
//   来自 `.sfh.sig` 里的 sha256 —— 那一份被 ECDSA 签名覆盖，见 VerifyStagedLib()。
//   把两者搞混的后果是"拿一个可篡改的值去校验一个要防篡改的文件"，
//   校验环节还在，但已经不对任何人生效。
//
// 返回空串 = 本次发布不含这本库 → 调用方按"跳过"处理（不是错误）。
std::string WantHashFor(const Slot& s, const MetaInfo& m) {
    if (!s.metaKey) return std::string();                 // 不可下发的槽位
    if (strcmp(s.metaKey, "shaSha256") == 0) return m.shaSha256;
    if (strcmp(s.metaKey, "impSha256") == 0) return m.impSha256;
    if (strcmp(s.metaKey, "md5Sha256") == 0) return m.md5Sha256;
    if (strcmp(s.metaKey, "sha1Sha256") == 0) return m.sha1Sha256;
    return std::string();                                 // 未知字段名 → 当空处理
}

// ===========================================================================
//  第 ②③④ 道校验
// ===========================================================================
struct VerifyReport {
    bool        ok = false;
    int         stage = 0;        // 失败在第几道（1~4）；0 = 全过
    std::string detail;
    long long   contentVersion = 0;
    std::string contentVersionText;
    long long   count = 0;
    std::string sha256;           // .tmp 的实际哈希（也是签名覆盖的那个值）
};

VerifyReport VerifyStagedLib(const std::string& tmpLibUtf8, long long localVersion) {
    VerifyReport r;
    const std::string tmpSigUtf8 = sf::libsig::SigPathFor(tmpLibUtf8);

    // ---- ② 哈希：期望值来自**签名文件**（它是被 ECDSA 覆盖的发布清单）----
    r.stage = 2;
    std::string sigText;
    if (!ReadTextFileW(W(tmpSigUtf8), sigText, 64 * 1024)) {
        r.detail = "读不到暂存签名文件：" + tmpSigUtf8;
        return r;
    }
    sf::libsig::SigFile sf;
    std::string perr;
    if (!sf::libsig::ParseSigFile(sigText, sf, perr)) {
        r.detail = "暂存签名文件格式非法：" + perr;
        return r;
    }
    std::string actual;
    if (!sf::pehash::FileSha256(tmpLibUtf8, actual) || actual.empty()) {
        r.detail = "无法计算暂存库的 SHA-256（读不到 / 无权限）";
        return r;
    }
    r.sha256 = actual;
    if (!HexEqualsCi(actual, sf.libSha256)) {
        // ★ 这条与 kBadSignature 是两个不同的结论，不要合并：
        //   这里说明"下载到的东西不是发布清单里的那份"（链路中间被替换 /
        //   CDN 发错 / 我们下错了版本），而签名本身还没验。
        r.detail = "库内容与签名清单不符：实际 sha256=" + actual.substr(0, 16) +
                   "…，签名自称 sha256=" + sf.libSha256.substr(0, 16) + "…";
        return r;
    }

    // ---- ③ 签名（fail-closed：任何非 kOk 都拒）----
    r.stage = 3;
    std::string det;
    const sf::libsig::Result vr = sf::libsig::VerifyLibFile(tmpLibUtf8, tmpSigUtf8, actual, det);
    if (vr != sf::libsig::kOk) {
        r.detail = std::string("验签未通过[") + sf::libsig::ResultText(vr) + "]：" + det;
        return r;
    }

    // ---- ④ 格式 + 版本（判据取自**库头**，不取 meta.json）----
    r.stage = 4;
    {
        sf::hashdb::HashDb probe;
        if (!probe.Open(tmpLibUtf8)) {
            r.detail = "暂存库无法作为病毒库打开：" + probe.LastError();
            return r;
        }
        const sf::hashdb::Stats st = probe.GetStats();
        r.count              = st.count;
        r.contentVersion     = st.contentVersion;
        r.contentVersionText = st.contentVersionText;
        probe.Close();

        if (st.contentVersion < localVersion) {
            // ★ 防降级。版本号是"发布方声明的内容代次"，装一个更旧的库等于
            //   让本机的判定能力**倒退**，而这不会有任何症状（库在、能查、
            //   只是查不到新样本）。
            r.detail = "拒绝降级：云端库版本 " + std::to_string(st.contentVersion) +
                       "（" + st.contentVersionText + "）< 本地 " +
                       std::to_string(localVersion);
            return r;
        }
    }

    r.stage = 0;
    r.ok    = true;
    r.detail = "四道校验通过";
    return r;
}

// ===========================================================================
//  检查（取 meta.json 并与本地比对）—— libcheck 与 libupdate 共用
// ===========================================================================
struct CheckOutcome {
    bool        networkOk = false;
    DWORD       httpStatus = 0;
    MetaInfo    meta;
    std::string reason;
    int         needCount = 0;                 // 需要下载的库数
    std::vector<std::string> needFiles;        // 需要下载的文件名
    std::vector<std::string> skipped;          // "文件（原因）"
};

CheckOutcome FetchAndCompare(const std::string& baseUrl, const Config& cfg) {
    CheckOutcome o;

    // slug 自检：基址末段必须与 meta.slug 一致。这是"部署错目录"与
    // "访问错路径"的分水岭 —— 不一致时下到的 meta 可能属于另一套库。
    const std::string urlSlug = SlugOfBaseUrl(baseUrl);

    DWORD status = 0;
    std::string body, err;
    const std::string metaUrl = baseUrl + "/meta.json";
    if (!HttpGet(metaUrl, cfg.timeoutMs, kMetaMaxBytes, false, std::string(), body, status, err)) {
        o.reason = "取 meta.json 失败：" + err + "（" + metaUrl + "）";
        o.httpStatus = status;
        return o;
    }
    o.httpStatus = status;
    o.networkOk  = true;

    o.meta = ParseMeta(body);
    if (!o.meta.ok) {
        o.reason = o.meta.err + "（" + metaUrl + "）";
        o.networkOk = false;
        return o;
    }
    if (!urlSlug.empty() && !o.meta.slug.empty() && o.meta.slug != urlSlug) {
        o.reason = "slug 不一致：基址末段=\"" + urlSlug + "\"，meta.slug=\"" + o.meta.slug +
                   "\" —— 基址或部署目录对不上，拒绝继续";
        o.networkOk = false;
        return o;
    }

    // 逐本比对：远端哈希 == 本地哈希 → 已有同一份内容，不必下
    for (size_t i = 0; i < sizeof(kSlots) / sizeof(kSlots[0]); ++i) {
        const Slot& s = kSlots[i];

        // ★ 先判「不可下发」，且它的理由与「不在清单里」**必须分开报**：
        //   一个是设计禁止（永远如此），一个是本次没发布（下次可能就有）。
        //   混成一句"不在本次发布清单里"，调用方会把"可信库永不更新"
        //   误读成"这次碰巧没更新" —— 下次看到恶意库更新了，
        //   自然会以为可信库也该跟着更新，然后去查一个根本不存在的机制。
        if (!s.downloadable) {
            o.skipped.push_back(std::string(s.file) + "（" + s.note + "）");
            continue;
        }

        const std::string want = WantHashFor(s, o.meta);
        if (want.empty()) {
            // 不在本次发布清单里 = 本次不更新这本，**不是错误**。
            o.skipped.push_back(std::string(s.file) + "（不在本次发布清单里）");
            continue;
        }
        sf::hashshare::LibInfo li;
        if (!sf::hashshare::GetLibInfo(s.idx, li)) {
            o.skipped.push_back(std::string(s.file) + "（取本地状态失败）");
            continue;
        }
        if (!li.sha256.empty() && HexEqualsCi(li.sha256, want)) {
            o.skipped.push_back(std::string(s.file) + "（本地已是同一份内容）");
            continue;
        }
        o.needFiles.push_back(s.file);
    }
    o.needCount = (int)o.needFiles.size();
    o.reason = o.needCount > 0
             ? ("发现 " + std::to_string(o.needCount) + " 本库需要更新")
             : "已是最新";
    return o;
}

// ===========================================================================
//  返回给调用方的 JSON
// ===========================================================================
std::string LocalVersionsJson() {
    std::string j = "[";
    for (size_t i = 0; i < sizeof(kSlots) / sizeof(kSlots[0]); ++i) {
        sf::hashshare::LibInfo li;
        const bool have = sf::hashshare::GetLibInfo(kSlots[i].idx, li);
        if (i) j += ',';
        j += "{\"idx\":" + std::to_string(kSlots[i].idx);
        j += ",\"file\":" + sf::JsonString(kSlots[i].file);
        j += ",\"loaded\":" + std::string(have && li.loaded ? "true" : "false");
        j += ",\"count\":" + std::to_string(have ? li.count : 0);
        j += ",\"contentVersion\":" + std::to_string(have ? li.contentVersion : 0);
        j += ",\"contentVersionText\":" + sf::JsonString(have ? li.contentVersionText : std::string());
        j += ",\"sha256\":" + sf::JsonString(have ? li.sha256 : std::string());
        j += ",\"sigOk\":" + std::string(have && li.sigOk ? "true" : "false");
        // ★ 下面两条是给**界面**用的结构化信息，不是给日志看的散文。
        //   「哪本库参与云端下发」是**服务端的设计知识**。界面若靠匹配 err 文案
        //   （"未下发"）来猜，哪天文案改了，界面就开始**静默说谎** ——
        //   把"设计上不下发"显示成"下载失败"，或者反过来。
        //   而这一条的误导性在于：用户看到「2/3 · 未下发」，会去查网络、查官网，
        //   查一个根本不存在的故障。所以必须由服务端**明说**，界面只负责显示。
        j += ",\"downloadable\":" + std::string(kSlots[i].downloadable ? "true" : "false");
        j += ",\"note\":" + sf::JsonString(kSlots[i].note);
        j += '}';
    }
    j += "]";
    return j;
}

std::string MetaJson(const MetaInfo& m) {
    std::string j = "{";
    j += "\"version\":" + std::to_string(m.version);
    j += ",\"versionText\":" + sf::JsonString(m.versionText);
    j += ",\"builtAtUnix\":" + std::to_string(m.builtAtUnix);
    j += ",\"shaCount\":" + std::to_string(m.shaCount);
    j += ",\"impCount\":" + std::to_string(m.impCount);
    j += ",\"slug\":" + sf::JsonString(m.slug);
    j += '}';
    return j;
}

std::string StrArray(const std::vector<std::string>& v) {
    std::string j = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) j += ',';
        j += sf::JsonString(v[i]);
    }
    j += "]";
    return j;
}

// ===========================================================================
//  命令：libstat
// ===========================================================================
bool CmdLibStat(HANDLE h, const std::string& /*req*/) {
    const Config c = CfgCopy();
    State st;
    {
        std::lock_guard<std::mutex> lk(g_stMu);
        st = g_st;
    }

    const ULONGLONG now   = GetTickCount64();
    const ULONGLONG since = (now >= st.startTick) ? (now - st.startTick) : 0;

    long long firstDelayRemainMs = 0;
    if (since < kFirstCheckDelayMs) firstDelayRemainMs = (long long)(kFirstCheckDelayMs - since);

    // 距下次自动检查还有多久。★ 这里把"退避"和"常规间隔"算清楚报出来 ——
    //   否则"为什么一直不检查"只能靠读代码。
    long long nextInMs = -1;
    if (c.enabled && c.intervalHours > 0) {
        const long long intervalMs = (long long)c.intervalHours * 3600 * 1000;
        const long long delayMs = (st.failStreak > 0)
            ? ((intervalMs * 2 < (long long)kMaxBackoffMs) ? intervalMs * 2 : (long long)kMaxBackoffMs)
            : intervalMs;
        if (st.lastCheckTick == 0) {
            nextInMs = firstDelayRemainMs;
        } else {
            const long long last = (long long)((now >= st.lastCheckTick) ? (now - st.lastCheckTick) : 0);
            nextInMs = (last >= delayMs) ? 0 : (delayMs - last);
        }
    }

    std::string j = "{\"cmd\":\"libstat\",\"ok\":true,\"data\":{";

    // ---- 配置 ----
    j += "\"enabled\":" + std::string(c.enabled ? "true" : "false");
    j += ",\"baseUrl\":" + sf::JsonString(c.baseUrl);
    j += ",\"baseSlug\":" + sf::JsonString(SlugOfBaseUrl(c.baseUrl));
    j += ",\"intervalHours\":" + std::to_string(c.intervalHours);
    j += ",\"timeoutMs\":" + std::to_string((long long)c.timeoutMs);
    j += ",\"maxDownloadMb\":" + std::to_string(c.maxDownloadMb);
    j += ",\"configPath\":" + sf::JsonString(c.configPath);
    // ★ configWarn 必须能看见：配置的失败形态是零症状的（"看起来用了你的配置"）。
    j += ",\"configWarn\":" + std::to_string(c.warnCount);
    j += ",\"configWarnFirst\":" + sf::JsonString(c.warnFirst);

    // ---- 运行时 ----
    j += ",\"busy\":" + std::string(g_busy.load() ? "true" : "false");
    j += ",\"uptimeMs\":" + std::to_string((long long)since);
    j += ",\"firstDelayRemainMs\":" + std::to_string(firstDelayRemainMs);
    j += ",\"sinceLastCheckMs\":" + std::to_string(st.lastCheckTick == 0 ? -1 : (long long)(now - st.lastCheckTick));
    j += ",\"nextCheckInMs\":" + std::to_string(nextInMs);
    j += ",\"sinceLastUpdateMs\":" + std::to_string(st.lastUpdateTick == 0 ? -1 : (long long)(now - st.lastUpdateTick));
    j += ",\"failStreak\":" + std::to_string(st.failStreak);
    // ★ pendingUpdate：自动检查发现了新版本，但**没有自动下载**（v1 取舍）。
    //   界面文案必须说"发现新版本，可手动更新"，**不能**说"已自动更新"。
    j += ",\"pendingUpdate\":" + std::string(st.pendingUpdate ? "true" : "false");
    j += ",\"remoteVersion\":" + std::to_string(st.remoteVersion);
    j += ",\"remoteVersionText\":" + sf::JsonString(st.remoteVersionText);
    j += ",\"checkOk\":" + std::to_string(st.checkOk);
    j += ",\"checkFail\":" + std::to_string(st.checkFail);
    j += ",\"updateOk\":" + std::to_string(st.updateOk);
    j += ",\"updateFail\":" + std::to_string(st.updateFail);
    j += ",\"lastCheckResult\":" + sf::JsonString(st.lastCheckResult);
    j += ",\"lastUpdateResult\":" + sf::JsonString(st.lastUpdateResult);
    j += ",\"lastError\":" + sf::JsonString(st.lastError);
    j += ",\"cloudDir\":" + sf::JsonString(sf::hashshare::CloudDirUtf8());

    // ---- 三本库现状（与 hashstat.libs 同构，同一个序列化入口）----
    j += ",\"local\":" + LocalVersionsJson();
    j += ",\"libs\":" + sf::hashshare::LibsJsonSnapshot();
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//  命令：libcheck
// ===========================================================================
bool CmdLibCheck(HANDLE h, const std::string& req) {
    Config c = CfgCopy();
    const std::string urlOverride = sf::JsonGetString(req, "url");
    std::string base = urlOverride.empty() ? c.baseUrl : urlOverride;
    while (!base.empty() && base[base.size() - 1] == '/') base.erase(base.size() - 1);

    const CheckOutcome o = FetchAndCompare(base, c);

    {
        std::lock_guard<std::mutex> lk(g_stMu);
        g_st.lastCheckTick = GetTickCount64();
        if (o.networkOk) {
            ++g_st.checkOk;
            g_st.failStreak    = 0;
            g_st.remoteVersion = o.meta.version;
            g_st.remoteVersionText = o.meta.versionText;
            g_st.pendingUpdate = (o.needCount > 0);
            g_st.lastCheckResult = o.reason;
        } else {
            ++g_st.checkFail;
            ++g_st.failStreak;
            g_st.lastCheckResult = o.reason;
            g_st.lastError = o.reason;
        }
    }

    std::string j = "{\"cmd\":\"libcheck\",\"ok\":true,\"data\":{";
    // ★ 三态。**不用 ok:false 表达"已是最新"** —— 那是成功，只是没动作。
    const char* action = !o.networkOk ? "failed" : (o.needCount > 0 ? "update-available" : "already-latest");
    j += "\"action\":" + sf::JsonString(action);
    j += ",\"checked\":" + std::string(o.networkOk ? "true" : "false");
    j += ",\"upToDate\":" + std::string((o.networkOk && o.needCount == 0) ? "true" : "false");
    j += ",\"updateAvailable\":" + std::string((o.networkOk && o.needCount > 0) ? "true" : "false");
    j += ",\"httpStatus\":" + std::to_string((long long)o.httpStatus);
    j += ",\"baseUrl\":" + sf::JsonString(base);
    j += ",\"reason\":" + sf::JsonString(o.reason);
    j += ",\"remote\":" + MetaJson(o.meta);
    j += ",\"needFiles\":" + StrArray(o.needFiles);
    j += ",\"skipped\":" + StrArray(o.skipped);
    j += ",\"local\":" + LocalVersionsJson();
    j += ",\"libs\":" + sf::hashshare::LibsJsonSnapshot();
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//  命令：libupdate
// ===========================================================================
bool CmdLibUpdate(HANDLE h, const std::string& req) {
    // ★ busy 保护：两个连接同时更新会各自写同名 .tmp
    BusyGuard busy;
    if (!busy.held) {
        std::string j = "{\"cmd\":\"libupdate\",\"ok\":true,\"data\":{";
        j += "\"action\":\"busy\"";
        j += ",\"updated\":false,\"rolledBack\":false";
        j += ",\"reason\":" + sf::JsonString("已有一次更新在进行中，本次未执行");
        j += ",\"downloads\":[]";
        j += ",\"local\":" + LocalVersionsJson();
        j += ",\"libs\":" + sf::hashshare::LibsJsonSnapshot();
        j += "}}";
        sf::WriteFramed(h, j);
        return true;
    }

    Config c = CfgCopy();
    const std::string urlOverride = sf::JsonGetString(req, "url");
    std::string base = urlOverride.empty() ? c.baseUrl : urlOverride;
    while (!base.empty() && base[base.size() - 1] == '/') base.erase(base.size() - 1);
    const bool force = (sf::JsonGetInt(req, "force") == 1);

    const std::string cloudDir = sf::hashshare::CloudDirUtf8();

    // 回包的公共尾部
    auto finish = [&](const char* action, bool updated, bool rolledBack,
                      const std::string& reason,
                      const std::vector<std::string>& downloads,
                      const std::string& libsJson) {
        std::string j = "{\"cmd\":\"libupdate\",\"ok\":true,\"data\":{";
        j += "\"action\":" + sf::JsonString(action);
        j += ",\"updated\":" + std::string(updated ? "true" : "false");
        j += ",\"rolledBack\":" + std::string(rolledBack ? "true" : "false");
        j += ",\"reason\":" + sf::JsonString(reason);
        j += ",\"downloads\":" + StrArray(downloads);
        j += ",\"local\":" + LocalVersionsJson();
        j += ",\"libs\":" + std::string(libsJson.empty() ? sf::hashshare::LibsJsonSnapshot() : libsJson);
        j += "}}";
        sf::WriteFramed(h, j);
    };

    // 结束并记账
    auto done = [&](const char* action, const std::string& reason,
                    const std::vector<std::string>& downloads,
                    const std::string& libsJson, bool rolledBack) {
        {
            std::lock_guard<std::mutex> lk(g_stMu);
            g_st.lastUpdateTick = GetTickCount64();
            g_st.lastUpdateResult = reason;
            if (strcmp(action, "installed") == 0) {
                ++g_st.updateOk;
                g_st.pendingUpdate = false;
                g_st.failStreak = 0;
            } else if (strcmp(action, "failed") == 0) {
                ++g_st.updateFail;
                g_st.lastError = reason;
            }
        }
        finish(action, strcmp(action, "installed") == 0, rolledBack, reason, downloads, libsJson);
        return true;
    };

    if (cloudDir.empty()) {
        return done("failed", "云库目录尚未就绪（sfdb 分体未初始化）", std::vector<std::string>(), std::string(), false);
    }

    // -----------------------------------------------------------------------
    //  0. 清理上一次失败留下的 .tmp 残骸
    // -----------------------------------------------------------------------
    //  ★ 必须做：残留的半成品会被下半段流程当成"已经下好的文件"。
    //    删除失败（文件被占用）只记日志、不阻断。
    {
        for (size_t i = 0; i < sizeof(kSlots) / sizeof(kSlots[0]); ++i) {
            const std::string lib = kSlots[i].file;
            const std::string tmpLib = cloudDir + "\\" + lib + ".tmp";
            const std::string tmpSig = tmpLib + ".sig";
            if (PathExistsW(tmpLib)) {
                SetFileAttributesW(W(tmpLib).c_str(), FILE_ATTRIBUTE_NORMAL);
                if (!DeleteFileW(W(tmpLib).c_str()))
                    sf::LogDbg("[lib] 残留 .tmp 删除失败（可能被占用）：" + tmpLib);
            }
            if (PathExistsW(tmpSig)) {
                SetFileAttributesW(W(tmpSig).c_str(), FILE_ATTRIBUTE_NORMAL);
                if (!DeleteFileW(W(tmpSig).c_str()))
                    sf::LogDbg("[lib] 残留 .sig.tmp 删除失败（可能被占用）：" + tmpSig);
            }
        }
    }

    // -----------------------------------------------------------------------
    //  1. 取清单并比对
    // -----------------------------------------------------------------------
    const CheckOutcome o = FetchAndCompare(base, c);
    if (!o.networkOk) {
        // ★ 检查失败 = 旧库照常工作 → action:"failed" 且 ok:true（不是假故障）
        return done("failed", o.reason, std::vector<std::string>(), std::string(), false);
    }

    // 决定要下哪几本：needFiles 是按 kSlots 顺序的子集
    std::vector<sf::hashshare::LibInstallItem> installs;
    std::vector<std::string> downloads;
    std::vector<std::string> toFetch;      // 远端文件名
    std::vector<int>         toFetchIdx;

    for (size_t i = 0; i < sizeof(kSlots) / sizeof(kSlots[0]); ++i) {
        const Slot& s = kSlots[i];
        if (!s.downloadable) continue;              // 设计上永不更新（理由见 kSlots）
        const std::string want = WantHashFor(s, o.meta);
        if (want.empty()) continue;                 // 不在清单里：跳过（不是错误）

        bool need = true;
        if (!force) {
            sf::hashshare::LibInfo li;
            if (sf::hashshare::GetLibInfo(s.idx, li) && !li.sha256.empty() &&
                HexEqualsCi(li.sha256, want)) {
                need = false;                        // 本地已是同一份内容
            }
        }
        if (need) { toFetch.push_back(s.file); toFetchIdx.push_back(s.idx); }
        else      downloads.push_back(std::string(s.file) + "：跳过（本地已是同一份内容）");
    }

    if (toFetch.empty()) {
        return done("already-latest", "所有在清单内的库都已是本地内容", downloads,
                    std::string(), false);
    }

    // -----------------------------------------------------------------------
    //  2. 下载 + 四道校验（**全部通过后才动手换库**）
    // -----------------------------------------------------------------------
    //  ★ 关键设计：下载与校验阶段任何一步失败，**一个正式文件都不动**。
    //    这比"边下边换、出错回滚"更安全 —— 不进入临界区，就没有回滚失败的可能。
    const long long maxBytes = c.maxDownloadMb * 1024 * 1024;

    for (size_t k = 0; k < toFetch.size(); ++k) {
        const std::string file   = toFetch[k];
        const int         idx    = toFetchIdx[k];
        const std::string tmpLib = cloudDir + "\\" + file + ".tmp";
        const std::string tmpSig = tmpLib + ".sig";

        auto failHere = [&](const std::string& why) {
            downloads.push_back(file + "：失败 —— " + why);
            // 清掉本次下载的残骸，避免污染下一次
            if (PathExistsW(tmpLib)) { SetFileAttributesW(W(tmpLib).c_str(), FILE_ATTRIBUTE_NORMAL); DeleteFileW(W(tmpLib).c_str()); }
            if (PathExistsW(tmpSig)) { SetFileAttributesW(W(tmpSig).c_str(), FILE_ATTRIBUTE_NORMAL); DeleteFileW(W(tmpSig).c_str()); }
            return done("failed", "下载或校验失败（" + file + "）：" + why, downloads, std::string(), false);
        };

        // ---- ① HTTP + 大小上限 ----
        DWORD st = 0;
        std::string err;
        if (!HttpGet(base + "/" + file, c.timeoutMs, maxBytes, true, tmpLib, err, st, err)) {
            return failHere(std::string("下载库失败：") + err);
        }
        if (!HttpGet(base + "/" + file + ".sig", c.timeoutMs, 64 * 1024, true, tmpSig, err, st, err)) {
            return failHere(std::string("下载签名失败：") + err);
        }

        // ---- ②③④ ----
        sf::hashshare::LibInfo li;
        const long long localVer = sf::hashshare::GetLibInfo(idx, li) ? li.contentVersion : 0;
        const VerifyReport vr = VerifyStagedLib(tmpLib, localVer);
        if (!vr.ok) {
            return failHere("第 " + std::to_string(vr.stage) + " 道校验未通过：" + vr.detail);
        }

        installs.push_back(sf::hashshare::LibInstallItem{ idx, tmpLib });
        downloads.push_back(file + "：已下载并校验通过（" + std::to_string(vr.count) +
                            " 条，版本 " + vr.contentVersionText + "）");
        sf::LogDbg("[lib] " + file + " 下载并校验通过：版本=" + vr.contentVersionText +
                   " 条目=" + std::to_string(vr.count) + " sha256=" + vr.sha256.substr(0, 16) + "…");
    }

    // -----------------------------------------------------------------------
    //  3. 原子换装（卸 → 换 → 装 → 判定 → 失败回滚）
    // -----------------------------------------------------------------------
    const sf::hashshare::LibInstallResult ir = sf::hashshare::InstallCloudLibs(installs);
    if (!ir.ok) {
        downloads.push_back("换装失败：" + ir.detail);
        // ★ 回滚成功 = 旧库仍在服务 = **不是**防护降级，但也不是成功。
        //   action 用 "failed"，reason 里说清"已回滚"，并带上 rolledBack 字段。
        return done("failed", ir.detail, downloads, ir.libsJson, ir.rolledBack);
    }

    downloads.push_back(ir.detail);
    sf::LogDbg("[lib] 云库更新完成：" + ir.detail);
    return done("installed", ir.detail, downloads, ir.libsJson, false);
}

// ===========================================================================
//  命令表
// ===========================================================================
const sf::mod::CmdEntry kCmds[] = {
    { "libstat",   CmdLibStat   },
    { "libcheck",  CmdLibCheck  },
    { "libupdate", CmdLibUpdate },
};

// ===========================================================================
//  Init / Run / Stop
// ===========================================================================
bool InitLib() {
    LoadConfig();
    {
        std::lock_guard<std::mutex> lk(g_stMu);
        g_st.startTick = GetTickCount64();
    }
    const Config c = CfgCopy();
    sf::LogDbg(std::string("[lib] 云库更新链就绪：base=") + c.baseUrl +
               "；自动检查" + (c.enabled && c.intervalHours > 0 ? "开启" : "关闭") +
               "；启动后 " + std::to_string(kFirstCheckDelayMs / 60000) + " 分钟首次检查" +
               "；自动路径只查不装（发现新版本留给 libupdate）");
    return true;
}

// 自动检查线程：**只做 libcheck**。
// ★ 为什么自动路径不下载：无人看着时，"下载→校验失败→回滚"的循环会把日志
//   刷满而没人发现。发现新版本只记一行日志 + 置 pendingUpdate，
//   实际下载留给人工 `libupdate`（或将来 GUI 的按钮）。
void RunLib() {
    while (!sf::IsStopRequested()) {
        Sleep(kRunTickMs);
        if (sf::IsStopRequested()) break;

        const Config c = CfgCopy();
        if (!c.enabled || c.intervalHours <= 0) continue;

        const ULONGLONG now = GetTickCount64();
        State st;
        {
            std::lock_guard<std::mutex> lk(g_stMu);
            st = g_st;
        }
        // 启动后先等 kFirstCheckDelayMs：开机时网络栈可能还没就绪，
        // 立即失败会浪费一次，并污染"上次检查结果"的语义。
        if (now < st.startTick + kFirstCheckDelayMs) continue;

        const long long intervalMs = (long long)c.intervalHours * 3600 * 1000;
        // 退避：连续失败后推迟到 min(2×间隔, 1 小时)
        const long long delayMs = (st.failStreak > 0)
            ? ((intervalMs * 2 < (long long)kMaxBackoffMs) ? intervalMs * 2 : (long long)kMaxBackoffMs)
            : intervalMs;
        if (st.lastCheckTick != 0 &&
            (long long)(now - st.lastCheckTick) < delayMs) continue;

        // 复用 libcheck 的逻辑（用一个空句柄调不到 —— WriteFramed 会失败，
        // 所以这里直接调共享的检查函数，不经过命令层）
        if (g_busy.load()) continue;
        Config cc = CfgCopy();
        const CheckOutcome o = FetchAndCompare(cc.baseUrl, cc);
        {
            std::lock_guard<std::mutex> lk(g_stMu);
            g_st.lastCheckTick = GetTickCount64();
            if (o.networkOk) {
                ++g_st.checkOk;
                g_st.failStreak = 0;
                g_st.remoteVersion = o.meta.version;
                g_st.remoteVersionText = o.meta.versionText;
                g_st.pendingUpdate = (o.needCount > 0);
                g_st.lastCheckResult = o.reason;
            } else {
                ++g_st.checkFail;
                ++g_st.failStreak;
                g_st.lastCheckResult = o.reason;
                g_st.lastError = o.reason;
            }
        }
        if (!o.networkOk) {
            sf::LogDbg("[lib] 自动检查失败（" + std::to_string((long long)o.httpStatus) + "）：" + o.reason);
        } else if (o.needCount > 0) {
            // ★ 明写"未下载"：这条日志是将来判断"为什么库还是旧的"的关键
            sf::LogDbg("[lib] 自动检查：发现新版本 " + o.meta.versionText +
                       "（" + std::to_string(o.meta.version) + "），有 " +
                       std::to_string(o.needCount) + " 本库待更新。"
                       "**自动路径不下载**，请执行 libupdate 完成更新。");
        } else {
            sf::LogDbg("[lib] 自动检查：已是最新（版本 " +
                       (o.meta.versionText.empty() ? std::to_string(o.meta.version) : o.meta.versionText) + "）");
        }
    }
    sf::LogDbg("[lib] 自动检查线程已退出");
}

void StopLib() {
    // 线程已由主干 join。这里不做耗时操作（处于服务停止的同步路径上）。
    sf::LogDbg("[lib] 云库更新链已停止");
}

}  // namespace

namespace sf {
namespace mod {

// ★ 必须带 extern：`const` 在命名空间作用域默认内部链接，
//   漏了会在链接期报 LNK2001（modules_list.obj 找不到 kModule_lib）。
extern const Module kModule_lib = {
    "lib",
    InitLib,        // Init：读配置（失败不致命 —— 用内置默认值继续）
    RunLib,         // Run：自动检查线程（只查不装，见文件头）
    StopLib,        // Stop：仅记日志
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
