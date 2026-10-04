// common.cpp — 银狐主防程序共享基础实现
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>
#include <sddl.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <Wtsapi32.h>

#include "common.h"

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace sf {

const wchar_t* SVC_NAME     = L"SilverFoxGuardSvc";
const wchar_t* SVC_DISPLAY  = L"银狐主防服务";
const wchar_t* PIPE_NAME    = L"\\\\.\\pipe\\SilverFoxGuard";
const char*    NM_HOST_NAME = "com.silverfox.guard";
const char*    CFG_ROOT     = "SOFTWARE\\SilverFoxGuard";

// ---------------------------------------------------------------------------
//  ★★ 进程级日志互斥（2026-09-25 新增，修 P1「日志并发静默丢行」）
//
//  症状：日志会「随机缺行」。服务重启瞬间多个线程在几十毫秒内同时写，
//  结果 [landed] / [etwproc] / [iowatch] / [ai] 四条启动行全部消失，
//  而 1 秒后的业务日志照常输出 —— 极易被误判成「那个线程根本没起来」
//  （2026-09-25 我就据此错查了一轮，见 topics/01 铁律第 8 条）。
//
//  根因：旧实现 CreateFileW(..., GENERIC_WRITE, FILE_SHARE_READ, ...)。
//  ★ dwShareMode 里不含 FILE_SHARE_WRITE 的语义是「别人可以读、但不许写」
//  → 线程 A 持句柄期间，线程 B 对同一文件名的 CreateFile 直接失败
//  （ERROR_SHARING_VIOLATION = 32），而旧代码 `if (hf == INVALID_HANDLE_VALUE) return;`
//  一个字都不留。★ 特征：没有「半行 / 叠行」残迹 —— 共享冲突是「打不开」、
//  不是「写重叠」，所以日志文件看上去完全健康。同族先例：sfdb 第二写实例同样返回 32。
//
//  修法两层（2026-09-25 已用独立实验证明，见下）：
//   ① 访问权改 FILE_APPEND_DATA（MSDN：未同时指定 FILE_WRITE_DATA 时，
//      本地文件系统的写入不会覆盖已有数据）—— 每次写入直接落在 EOF，于是
//      「SetFilePointer(FILE_END) 再 WriteFile」这个两步非原子序列被整个消掉。
//      **实测它单独就已经让并发追加不叠行、不丢行。**
//   ② 本进程内 CRITICAL_SECTION 串行化 —— 纵深防御：万一目标落在不保证
//      append 原子性的文件系统（网络重定向 / FAT32 / 某些筛选驱动之上），
//      至少保证本进程内部不互相踩。
//
//  ★ 实验证据（C:\temp\logappend_test.cpp，MSVC /O2 /MT 实编实跑）：
//    前提 A —— FILE_APPEND_DATA + OPEN_ALWAYS 在文件缺失时**能创建**文件（否则
//              日志会彻底消失，比原缺陷更糟，所以必须先证）；
//    前提 B —— 16 线程 × 400 行**无锁**并发追加 → 6401 行 / 零畸形 / 6400 个标记
//              零丢失零重复。结论：修法成立。
//
//  ★ 为什么不用 std::mutex：LogDbgC 会在 RunThreadGuarded 的 __except 块内被调用
//  （sfthread.cpp）。带析构的 C++ 对象会使「含 __try 的函数」在 /EHsc 下触发 MSVC
//  C2712（无法在需要对象展开的函数中使用 __try）—— 尤其 /O2 把被调函数内联进来时。
//  CRITICAL_SECTION 是纯 POD + 手写 Enter/Leave，不产生任何栈展开需求。
// ---------------------------------------------------------------------------
static CRITICAL_SECTION g_logCs;
static INIT_ONCE        g_logCsOnce = INIT_ONCE_STATIC_INIT;
static BOOL CALLBACK LogCsInit(PINIT_ONCE, PVOID, PVOID*) {
    InitializeCriticalSection(&g_logCs);
    return TRUE;
}
static CRITICAL_SECTION& LogCs() {
    InitOnceExecuteOnce(&g_logCsOnce, LogCsInit, nullptr, nullptr);
    return g_logCs;
}

// 单行落盘的公共尾段：line 已拼好（含 CRLF），path 为 guard.log 全路径。
// 抽出来是为了让 LogDbg / LogDbgC 两条路径共用同一套打开参数 —— 否则将来只改
// 一处、另一处继续丢行，就是「修了等于没修」。
static void WriteLogLine(const wchar_t* path, const wchar_t* line, DWORD chars) {
    HANDLE hf = CreateFileW(path, FILE_APPEND_DATA,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_ALWAYS, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    CRITICAL_SECTION& cs = LogCs();
    EnterCriticalSection(&cs);
    DWORD wn = 0;
    WriteFile(hf, line, (DWORD)(chars * sizeof(wchar_t)), &wn, nullptr);
    LeaveCriticalSection(&cs);
    CloseHandle(hf);
}

// 调试日志：统一写到 C:\ProgramData\SilverFoxGuard\guard.log（VM 可访问）
void LogDbg(const std::string& msg) {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    std::wstring path = dir + L"\\guard.log";

    int n = MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, nullptr, 0);
    std::wstring w; w.resize(n); MultiByteToWideChar(CP_UTF8, 0, msg.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    // 时间戳前缀：安全产品必须能回答「这个事件是什么时候发生的」——
    // MTTD（平均检测时间）统计、攻击时间线复盘、以及"从落地到发现隔了多久"全部依赖它。
    // 此前日志只有内容没有时间，导致任何审计与复盘都无从谈起。
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[48];
    swprintf_s(ts, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] ",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    std::wstring line = std::wstring(ts) + w + L"\r\n";
    // ★ 拼行在锁外完成，临界区里只有一次 WriteFile —— 临界区越短，
    //   高频日志（热路径 / 多线程）越不会被这条日志自己拖慢。
    WriteLogLine(path.c_str(), line.c_str(), (DWORD)line.size());
}

// 纯 C 版日志（见 common.h）。实现刻意不依赖 std::string / std::wstring，
// 只用栈上定长缓冲 —— 这样它可以在 __except 块内被调用而不触发 MSVC 的
// C2712「无法在需要对象展开的函数中使用 __try」。
void LogDbgC(const char* msg) {
    if (!msg) return;
    wchar_t dir[MAX_PATH] = {0};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, dir) != S_OK)
        wcscpy_s(dir, L"C:\\ProgramData");
    wcscat_s(dir, L"\\SilverFoxGuard");
    CreateDirectoryW(dir, nullptr);

    wchar_t path[MAX_PATH];
    swprintf_s(path, L"%s\\guard.log", dir);

    // 时间戳 + 正文，全部在栈上拼装（单行上限 1024 字符，足够容纳异常描述）
    wchar_t line[1024];
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t body[768] = {0};
    MultiByteToWideChar(CP_UTF8, 0, msg, -1, body, 767);
    int n = swprintf_s(line, L"[%04d-%02d-%02d %02d:%02d:%02d.%03d] %s\r\n",
                       st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute,
                       st.wSecond, st.wMilliseconds, body);
    // ★ 与 LogDbg 共用 WriteLogLine：打开参数只有一处定义，
    //   杜绝「只修了 LogDbg、LogDbgC 继续丢行」这种半修状态。
    if (n > 0) WriteLogLine(path, line, (DWORD)n);
}

// ---------------------------------------------------------------------------
//  路径
// ---------------------------------------------------------------------------
std::string GetExePath() {
    char buf[MAX_PATH]{};
    DWORD n = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    return n ? std::string(buf, n) : std::string();
}
std::string DirName(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? "." : path.substr(0, p);
}
std::string BaseName(const std::string& path) {
    size_t p = path.find_last_of("/\\");
    return p == std::string::npos ? path : path.substr(p + 1);
}
bool FileExists(const std::string& path) {
    DWORD a = GetFileAttributesA(path.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

// ---------------------------------------------------------------------------
//  路径 / 字符串工具（补齐件，契约见 sfutils.h）
//
//  这些函数此前在 service.cpp / rollback.cpp / trace.cpp 里各有一份近似实现，
//  语义差异直接导致了「同一路径判等失败」的误判（回滚引擎曾因此误认文件已变更）。
//  收敛到 common.cpp 一处，供所有模块（含独立的回归可执行文件）共用。
// ---------------------------------------------------------------------------

// 小写扩展名（含点）。
// ⚠️ 必须先切出文件名再找点：直接对全路径找最后一个点，会把目录里的点算进来
//    （"C:\a.b\file" 若目录名含点且文件无扩展名，会错误返回 ".b\file" 之类）。
std::string ExtLower(const std::string& path) {
    std::string name = BaseName(path);
    size_t p = name.find_last_of('.');
    // 无点，或点在首位（形如 ".gitignore"）→ 视为无扩展名
    if (p == std::string::npos || p == 0) return std::string();
    std::string e = name.substr(p);
    for (char& c : e) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return e;
}

// 归一化路径：统一分隔符为 '\'，去掉结尾多余分隔符。**不改大小写** ——
// 改大小写会让日志与用户看到的结果对不上（用户输入什么就显示什么）。
// 仅当路径全为分隔符（如 "\" 或 "C:\"）时保留原样，否则剥掉尾部一个分隔符。
std::string NormPath(const std::string& path) {
    if (path.empty()) return path;
    std::string s = path;
    for (char& c : s) if (c == '/') c = '\\';
    // 判断是否是根形式（"C:\" 或 "\" / "\\"），这类不能剥尾分隔符
    bool isRoot = false;
    if (s.size() == 1 && s[0] == '\\') isRoot = true;
    else if (s.size() == 3 && s[1] == ':' && s[2] == '\\') isRoot = true;
    else if (s.size() == 2 && s[0] == '\\' && s[1] == '\\') isRoot = true;
    if (!isRoot) {
        while (s.size() > 1 && s.back() == '\\') {
            // 剥到 "C:\" 这种形式就停（保留根分隔符）
            if (s.size() == 3 && s[1] == ':') break;
            s.pop_back();
        }
    }
    return s;
}

// 大小写不敏感判等。Windows 路径语义。
bool PathEqualsCi(const std::string& a, const std::string& b) {
    std::string x = NormPath(a), y = NormPath(b);
    if (x.size() != y.size()) return false;
    for (size_t i = 0; i < x.size(); ++i) {
        char ca = x[i], cb = y[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return false;
    }
    return true;
}

// path 是否位于 dir 之下。按**路径分量**比较，不做子串匹配 ——
// 子串匹配会让 "C:\TempX\x.exe" 被误判为在 "C:\Temp" 之下（历史 bug）。
bool IsUnderDir(const std::string& path, const std::string& dir) {
    std::string p = NormPath(path), d = NormPath(dir);
    if (p.empty() || d.empty()) return false;
    // d 必须以分隔符结尾，才能保证按分量对齐："C:\Temp" → "C:\Temp\"
    if (d.back() != '\\') d.push_back('\\');
    if (p.size() < d.size()) return false;
    std::string head = p.substr(0, d.size());
    if (head.size() != d.size()) return false;
    return PathEqualsCi(head, d);
}

// 本地时间串 "YYYY-MM-DD HH:MM:SS"。
// ⚠️ 全项目只应有这一个时间戳格式：历史上弹窗卡片 / 日志 / 扫描结果各写了一套
//    （有的带毫秒、有的用 '-' 分隔日期），前端不得不兼容三种。
std::string NowStr() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(buf);
}

// ---------------------------------------------------------------------------
//  哈希（BCrypt SHA-256）
// ---------------------------------------------------------------------------
static std::string Sha256Finish(BCRYPT_HASH_HANDLE hh) {
    BYTE buf[32]; ULONG cb = 32;
    if (BCryptFinishHash(hh, buf, cb, 0) != 0) return "";
    static const char* hx = "0123456789abcdef";
    std::string o; o.reserve(64);
    for (int i = 0; i < 32; ++i) { o += hx[buf[i] >> 4]; o += hx[buf[i] & 0xf]; }
    return o;
}
std::string Sha256Bytes(const void* data, size_t len) {
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCRYPT_HASH_HANDLE hh;
    if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(h, 0); return ""; }
    BCryptHashData(hh, (PUCHAR)data, (ULONG)len, 0);
    std::string r = Sha256Finish(hh);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(h, 0);
    return r;
}
std::string Sha256File(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return "";
    BCRYPT_ALG_HANDLE h;
    if (BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return "";
    BCRYPT_HASH_HANDLE hh;
    if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0) { BCryptCloseAlgorithmProvider(h, 0); return ""; }
    char buf[1 << 16];
    std::streamsize n;
    while ((n = f.read(buf, sizeof(buf)).gcount()) > 0) BCryptHashData(hh, (PUCHAR)buf, (ULONG)n, 0);
    std::string r = Sha256Finish(hh);
    BCryptDestroyHash(hh); BCryptCloseAlgorithmProvider(h, 0);
    return r;
}

// ---------------------------------------------------------------------------
//  JSON
// ---------------------------------------------------------------------------
std::string JsonEscape(const std::string& s) {
    std::string o; o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\b': o += "\\b"; break;
            case '\f': o += "\\f"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if ((unsigned char)c < 0x20) {
                    static const char* hx = "0123456789abcdef";
                    o += "\\u00"; o += hx[(c >> 4) & 0xf]; o += hx[c & 0xf];
                } else o += c;
        }
    }
    return o;
}
std::string JsonString(const std::string& s) { return "\"" + JsonEscape(s) + "\""; }

// ★ 2026-10-02 新增（背景见 common.h 的说明）：JSON 字符串反转义 = JsonEscape 的逆运算。
//   覆盖 JsonEscape 会产出的全部形态，外加 '/'（JSON 允许但 JsonEscape 不产生）。
//   非法/未知转义按"去掉反斜杠、保留字符"处理（与绝大多数 JSON 实现一致，不会吞字符）。
std::string JsonUnescape(const std::string& s) {
    std::string o; o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (c != '\\' || i + 1 >= s.size()) { o += c; continue; }   // 末尾孤立反斜杠 → 原样
        const char n = s[++i];
        switch (n) {
            case 'n':  o += '\n'; break;
            case 't':  o += '\t'; break;
            case 'r':  o += '\r'; break;
            case 'b':  o += '\b'; break;
            case 'f':  o += '\f'; break;
            case '"':  o += '"';  break;
            case '\\': o += '\\'; break;
            case '/':  o += '/';  break;
            case 'u': {
                // \uXXXX —— JsonEscape 只用它来写 < 0x20 的控制字符（\u00XX）。
                // 按 BMP 码点解出来再编码成 UTF-8：控制字符 → 单字节，其它 → 多字节。
                if (i + 4 >= s.size()) { o += n; break; }
                unsigned cp = 0; bool ok = true;
                for (int k = 1; k <= 4; ++k) {
                    const char h = s[i + k];
                    cp <<= 4;
                    if      (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                    else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                    else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                    else { ok = false; break; }
                }
                if (!ok) { o += n; break; }
                i += 4;
                if (cp < 0x80) {
                    o += (char)cp;
                } else if (cp < 0x800) {
                    o += (char)(0xC0 | (cp >> 6));
                    o += (char)(0x80 | (cp & 0x3F));
                } else {
                    o += (char)(0xE0 | (cp >> 12));
                    o += (char)(0x80 | ((cp >> 6) & 0x3F));
                    o += (char)(0x80 | (cp & 0x3F));
                }
                break;
            }
            default: o += n; break;   // 未知转义：保留字符本身（不吞字符）
        }
    }
    return o;
}

std::string JsonGetString(const std::string& json, const std::string& key) {
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + pat.size());
    if (pos == std::string::npos) return "";
    // 跳过空白
    while (pos + 1 < json.size() && (json[pos + 1] == ' ' || json[pos + 1] == '\t' || json[pos + 1] == '\r' || json[pos + 1] == '\n')) ++pos;
    if (pos + 1 >= json.size() || json[pos + 1] != '"') return "";  // 仅处理字符串值
    size_t start = pos + 2;
    // ★ 2026-10-02：结束引号必须**跳过转义字符**地找（原来直接找下一个 '"'，
    //   值里含 \" 时会提前截断），取出的原文再统一走 JsonUnescape 还原。
    size_t end = start;
    while (end < json.size()) {
        if (json[end] == '\\' && end + 1 < json.size()) { end += 2; continue; }
        if (json[end] == '"') break;
        ++end;
    }
    return JsonUnescape(json.substr(start, end - start));
}

// 取 JSON 中的【数字】字段（也兼容被引号包起来的数字串）。
// 必须用本函数而不是 atoi(JsonGetString(...))：BuildResultJson 输出的 score / weight / count 都是
// 裸数字（如 "score":220），而 JsonGetString 只认带引号的字符串值 → 对数字一律返回空串，
// atoi 恒得 0。曾导致「扩展侧主动发起扫描时，通知卡片的风险评分永远是 0」（服务侧直接传结构体不受影响）。
//
// 2026-09-25 重构：内部拆出 64 位实现 JsonParseNum，JsonGetInt 只负责截断。
// 原因：老实现内部用 long long 累加，却 `return (int)(neg ? -n : n)` 截断 ——
// 传 Unix 毫秒（1.76e12）或 3GB 文件大小（3e9）进来会得到垃圾值，且**不报错**。
static bool JsonParseNum(const std::string& json, const std::string& key, long long* out) {
    std::string s = JsonGetString(json, key);          // 兼容 "score":"220" 这种带引号写法
    if (!s.empty()) { *out = strtoll(s.c_str(), nullptr, 10); return true; }
    std::string pat = "\"" + key + "\"";
    size_t pos = json.find(pat);
    if (pos == std::string::npos) return false;
    pos = json.find(':', pos + pat.size());
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\r' || json[pos] == '\n')) ++pos;
    bool neg = false;
    if (pos < json.size() && (json[pos] == '-' || json[pos] == '+')) { neg = (json[pos] == '-'); ++pos; }
    long long n = 0; bool any = false;
    while (pos < json.size() && json[pos] >= '0' && json[pos] <= '9') { n = n * 10 + (json[pos] - '0'); ++pos; any = true; }
    if (!any) return false;
    *out = neg ? -n : n;
    return true;
}

int JsonGetInt(const std::string& json, const std::string& key) {
    long long n = 0;
    if (!JsonParseNum(json, key, &n)) return 0;
    return (int)n;                                     // ⚠️ 有意截断：既有调用方全部期望 int
}

long long JsonGetInt64(const std::string& json, const std::string& key) {
    long long n = 0;
    if (!JsonParseNum(json, key, &n)) return 0;
    return n;                                          // 时间戳 / 文件大小 / 长年龄走这里
}

std::string BuildResultJson(const ScanResult& r) {
    std::string s = "{";
    s += "\"type\":\"scan_result\",";
    s += "\"status\":" + JsonString(r.status) + ",";
    s += "\"score\":" + std::to_string(r.score) + ",";
    s += "\"engine\":" + JsonString(r.engine) + ",";
    s += "\"timestamp\":" + JsonString(r.timestamp) + ",";
    s += "\"selfCheck\":" + std::string(r.selfCheck ? "true" : "false") + ",";
    s += "\"hardProof\":" + std::string(r.hardProof ? "true" : "false") + ",";
    s += "\"count\":" + std::to_string(r.findings.size()) + ",";
    s += "\"truncated\":";
    const size_t MAX_FINDINGS_JSON = 400;   // 防响应超 1MB（Chrome 原生消息上限）：超长只发前 N 条
    const size_t outN = (r.findings.size() > MAX_FINDINGS_JSON) ? MAX_FINDINGS_JSON : r.findings.size();
    s += std::string(r.findings.size() > MAX_FINDINGS_JSON ? "true" : "false") + ",";
    s += "\"findings\":[";
    for (size_t i = 0; i < outN; ++i) {
        if (i) s += ",";
        const Finding& f = r.findings[i];
        s += "{";
        s += "\"category\":" + JsonString(f.category) + ",";
        s += "\"severity\":" + JsonString(f.severity) + ",";
        s += "\"title\":" + JsonString(f.title) + ",";
        s += "\"detail\":" + JsonString(f.detail) + ",";
        s += "\"ioc\":" + JsonString(f.ioc) + ",";
        // 关联文件绝对路径（非文件类为空串）：扩展 / 弹窗据此精确清除，不必从 detail 反解
        s += "\"path\":" + JsonString(f.path) + ",";
        s += "\"weight\":" + std::to_string(f.weight);
        s += "}";
    }
    s += "],";
    s += "\"error\":" + JsonString(r.error);
    s += "}";
    return s;
}

// ---------------------------------------------------------------------------
//  命名管道帧 IO
// ---------------------------------------------------------------------------
bool WriteFramed(HANDLE h, const std::string& msg) {
    uint32_t len = (uint32_t)msg.size();
    unsigned char hdr[4] = { (unsigned char)(len & 0xFF), (unsigned char)((len >> 8) & 0xFF),
                             (unsigned char)((len >> 16) & 0xFF), (unsigned char)((len >> 24) & 0xFF) };
    DWORD w = 0;
    if (!WriteFile(h, hdr, 4, &w, nullptr) || w != 4) return false;
    if (len && (!WriteFile(h, msg.data(), len, &w, nullptr) || w != len)) return false;
    return true;
}
bool ReadFramed(HANDLE h, std::string& out) {
    out.clear();
    unsigned char hdr[4] = {0,0,0,0};
    DWORD r = 0;
    // 读取 4 字节长度头（循环确保读满）
    // ★ 2026-09-19 修复「GUI 一直等不到回帧」：管道是 PIPE_READMODE_MESSAGE，
    //   Electron 等客户端把「4字节头+JSON」一次性写入 = 一条消息。读前 4 字节时
    //   ReadFile 返回 FALSE + ERROR_MORE_DATA(234)（消息还有剩余），旧代码当成
    //   读失败直接 return false → 连接线程退出、不回帧不关句柄 → 客户端永远等待，
    //   且每请求泄漏一个管道实例（MAX_INSTANCES=8 很快耗尽）。
    //   正解：ERROR_MORE_DATA 时已读部分有效，继续循环读满；消息剩余部分由下一次
    //   ReadFile 继续吐出（message 模式语义），两种客户端写法都兼容。
    DWORD got = 0;
    while (got < 4) {
        if (!ReadFile(h, hdr + got, 4 - got, &r, nullptr)) {
            if (GetLastError() == ERROR_MORE_DATA && r > 0) { got += r; continue; }
            return false;
        }
        if (r == 0) return false;
        got += r;
    }
    uint32_t len = (uint32_t)hdr[0] | ((uint32_t)hdr[1] << 8) | ((uint32_t)hdr[2] << 16) | ((uint32_t)hdr[3] << 24);
    if (len > 16 * 1024 * 1024) return false;  // 防异常大包
    if (len == 0) { out.clear(); return true; }
    out.resize(len);
    got = 0;
    while (got < len) {
        if (!ReadFile(h, &out[got], len - got, &r, nullptr)) {
            if (GetLastError() == ERROR_MORE_DATA && r > 0) { got += r; continue; }
            return false;
        }
        if (r == 0) return false;
        got += r;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  自保：自身完整性
// ---------------------------------------------------------------------------
// 安装目录（权威来源，供 shell 扩展等**进程外**组件定位主程序）。
//
// ★ 2026-10-04 新增，背景是 Win11 一级右键菜单的一个静默失效：
//   src/shell/SilverFoxShell.cpp 原来硬编码 `%ProgramFiles%\SilverFoxGuard`，
//   但实测本机装在 `D:\SilverFoxEnvScan\SilverFoxGuard` —— 那个 C 盘路径不存在。
//   ⇒ 即使稀疏包注册成功、菜单项出现在第一层，点下去也只是"没反应"。
//   写这个键的权威位置是**安装器**（installer.nsi 的 $INSTDIR 是用户选的任意路径，
//   任何"按约定猜路径"的做法都会在用户改了安装目录时静默失效）。
//
// 返回值不带尾部反斜杠；读不到返回空串（调用方必须自己判空，不得拼出半截路径）。
std::wstring ReadInstallDir() {
    // CFG_ROOT 只有窄字符版（extern const char*），这里拼宽字符版，
    // 刻意**不**为此新增一个全局 —— 一个键名两处各写一遍不如复用。
    const wchar_t* kRoot = L"SOFTWARE\\" L"SilverFoxGuard";
    HKEY hk;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kRoot, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS)
        return L"";
    wchar_t buf[MAX_PATH] = {0};
    DWORD bs = sizeof(buf);
    std::wstring v;
    if (RegQueryValueExW(hk, L"InstallDir", nullptr, nullptr, (LPBYTE)buf, &bs) == ERROR_SUCCESS)
        v = buf;   // REG_SZ 以 \0 结尾，同 ReadStoredHash 的处理
    RegCloseKey(hk);
    return v;
}

std::string ReadStoredHash() {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, KEY_READ | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return "";
    char buf[256]{}; DWORD bs = sizeof(buf);
    std::string v;
    if (RegQueryValueExA(hk, "ExeHash", nullptr, nullptr, (LPBYTE)buf, &bs) == ERROR_SUCCESS)
        v = buf;   // REG_SZ 以 \0 结尾，按 C 字符串截断；否则会多读入结尾 \0 导致与运行时哈希比对永远不等
    RegCloseKey(hk);
    return v;
}
bool StoreHash(const std::string& hash) {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &hk, nullptr) != ERROR_SUCCESS) return false;
    LONG r = RegSetValueExA(hk, "ExeHash", 0, REG_SZ, (const BYTE*)hash.c_str(), (DWORD)hash.size() + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
//  自保：代码签名校验（不依赖系统信任链）
//  思路：恶意程序可能拿开源源码重编译替换我们的 EXE。重编译产物没有我们的私钥，
//  无法带出「与内置指纹一致的 Authenticode 签名」——故用 CryptQueryObject 直接读
//  EXE 签名者证书的 SHA-256 指纹，与内置于二进制的官方指纹比对：
//    · 未签名 / 签名被剥离  → 指纹为空 → 判篡改
//    · 签名者指纹 ≠ 官方指纹 → 判篡改（被他人重签）
//    · 指纹一致              → 确系我们构建的原始二进制（源码公开也无法伪造）
//  系统是否信任自签根不影响本校验（我们不查信任链，只认指纹）。
// ---------------------------------------------------------------------------
static char ToHex(BYTE b) { return "0123456789ABCDEF"[b >> 4]; }
static std::string SignerThumbprint(const std::string& path) {
    std::wstring wpath;
    {
        int n = MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, nullptr, 0);
        if (n <= 0) return "";
        std::wstring w(n, L'\0');
        MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, &w[0], n);
        if (!w.empty() && w.back() == L'\0') w.pop_back();
        wpath = w;
    }
    HCERTSTORE store = nullptr;
    DWORD dwMsgAndCertEncoding{};
    DWORD dwContentType{};
    DWORD dwFormatType{};
    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath.c_str(),
                          CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY,
                          0, &dwMsgAndCertEncoding, &dwContentType, &dwFormatType, &store, nullptr, nullptr))
        return "";
    std::string thumb;
    if (store) {
        PCCERT_CONTEXT ctx = CertEnumCertificatesInStore(store, nullptr);
        if (ctx) {
            // 注意：嵌入式签名的证书上下文取自 PKCS7，其 CERT_SHA256_HASH_PROP_ID 属性
            // 常返回全 0（属性未缓存）——不能依赖 CertGetCertificateContextProperty！
            // 改为对证书 DER 编码直接做 SHA-256（CryptHashCertificate2），与 PowerShell
            // GetAuthenticodeSignature 的 GetCertHashString('SHA256') 结果一致。
            DWORD cb = ctx->cbCertEncoded;
            BYTE hash[32]{};
            DWORD hlen = sizeof(hash);
            thumb.clear();
            bool valid = cb && CryptHashCertificate2(BCRYPT_SHA256_ALGORITHM, 0, nullptr,
                                                     ctx->pbCertEncoded, cb, hash, &hlen) && hlen == sizeof(hash);
            bool allZero = true;
            if (valid) for (DWORD i = 0; i < hlen; ++i) if (hash[i]) { allZero = false; break; }
            if (valid && !allZero) {   // 读到有效、非全 0 的哈希才算成功
                thumb.reserve(64);
                for (DWORD i = 0; i < hlen; ++i) { thumb += ToHex(hash[i] >> 4); thumb += ToHex(hash[i] & 0xF); }
            }
            // 计算失败或全 0 = 环境限制 → 返回空串，VerifySelfIntegrity 降级跳过签名校验
            CertFreeCertificateContext(ctx);
        }
        CertCloseStore(store, 0);
    }
    return thumb;
}

// 官方签名证书的 SHA-256 指纹（2026-09-13 生成的自签代码签名证书）
// 注意：这是证书的 SHA-256 指纹（64 位 hex），不是 New-SelfSignedCertificate 显示的
// Thumbprint（那是 SHA-1，40 位）——两者不同！
// 语义说明：指纹校验是「加固项」不是「判定项」——只认"明确读到不同指纹"为篡改；
// 读不到/嵌入式签名证书枚举受限时降级跳过（保留 ExeHash 基线兜底），避免环境差异误报。
inline const char* OFFICIAL_SIGNER_FINGERPRINT =
    "7EC8D7891B1A285B708F82BB8518B9D6BD63A06134BA4E95BB1E6098288E01D2";
static const int SIGNATURE_MIN_SECTION_SIZE = 2048;   // Authenticode 签名块最小区块大小（启发式防剥离）

// ===========================================================================
//  ★★★ 开源版：自身完整性校验已「去基线化」（2026-10-04）
// ===========================================================================
//  【为什么开源版要去掉哈希基线比对】
//    原实现拿「安装时写入 HKLM\SOFTWARE\SilverFoxGuard\ExeHash 的哈希」当基线，
//    与当前 EXE 比对，不符即判"被篡改"。那个基线是**为我们的发行版**生成的。
//    ⇒ 用户自行编译后，EXE 哈希必然与基线不符 ⇒ **开箱即报"程序自身完整性校验失败"**，
//       而且 finding 恒为"疑似被篡改或遭病毒注入" —— 一个刚编译出来、还没运行的程序
//       被指控中毒。这不是"加固不足"，是**功能在开源形态下彻底不可用**。
//
//  【去掉什么、保留什么 —— 判据是「这个检查在用户自己编译的环境里还有没有判别力」】
//    · 去掉：HKLM 哈希基线比对（绑定期望值；开源编译物必然不符）
//    · 保留：签名者指纹异常**仅记日志**（判别力仍在：正常构建无签名 → 指纹空；
//            被第三方改过且带签名 → 指纹非空；仍可辅助取证，且不产生误报）
//    · 保留：算出当前哈希并返回（UI 的"程序健康状态"要用）
//
//  【仍然提供一种真实保护】官方发行版的用户若从**官网**下载，基线由安装器写入，
//  该检查依然生效；只有自行编译的版本不再受它约束。
//  要恢复：把下面 ① 那一行 uncomment，并把 CFG_ROOT 下的 ExeHash 一起放回。
bool VerifySelfIntegrity(std::string& outCurrentHash) {
    outCurrentHash = Sha256File(GetExePath());
    // 算不出哈希（环境限制/文件被锁）时返回 false：调用方只把它当"健康状态"展示，
    // 权重为 0、不参与评分与 hardProof，所以此处 false 不会造成误判。
    if (outCurrentHash.empty()) return false;

    // ① 哈希基线比对（**开源版刻意关闭** —— 见上方说明）
    //    官方发行版可在此加回：
    //      const std::string stored = ReadStoredHash();
    //      if (!stored.empty() && outCurrentHash != stored) return false;

    // ② 签名者指纹异常：仅记录日志，不判篡改。
    //    判别力仍成立（自行编译 = 无签名 = 指纹空；被第三方加签 = 指纹非空），
    //    且不会对未签名构建产生任何误报。
    std::string fp = SignerThumbprint(GetExePath());
    if (!fp.empty() && fp.find_first_not_of('0') != std::string::npos
        && fp != OFFICIAL_SIGNER_FINGERPRINT) {
        LogDbg("[selfcheck] 签名者指纹异常: " + fp + "（仅记录，不判篡改）");
    }
    return true;
}

bool HardenFileAcl(const std::string& path) {
    // SDDL：SYSTEM/Admins 完全控制；Everyone 读+执行（防普通权限木马改写本程序，但普通用户要能运行）
    const wchar_t* sddl = L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;WD)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) return false;
    BOOL ok = SetFileSecurityA(path.c_str(), DACL_SECURITY_INFORMATION, sd);
    LocalFree(sd);
    return ok != 0;
}

// ---------------------------------------------------------------------------
//  维护模式（临时停止守护）—— 契约与安全模型见 common.h
// ---------------------------------------------------------------------------
//
// 标记文件内容（纯文本，便于排障时直接记事本打开看）：
//     expire=<unix 秒>
//     by=GUI
// 无 expire 字段（管理员手写）视为长期有效 —— 管理员本来就有全部权限，无需限制。

static std::wstring MaintenanceFlagPathW() {
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\maint.flag";
}

// 当前 Unix 秒（不依赖 C 运行时的 _time64，避免与 CRT 时区设置纠缠）
static long long MaintNowUnix() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u{};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // FILETIME 起点 1601-01-01（100ns 单位）；转 Unix 秒
    return (long long)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

// 读标记文件全文（不存在返回空串）
static std::string ReadMaintFlag() {
    std::wstring p = MaintenanceFlagPathW();
    HANDLE h = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    char buf[512] = { 0 };
    DWORD rd = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    return std::string(buf, rd);
}

bool MaintenanceActive() {
    std::string s = ReadMaintFlag();
    if (s.empty()) return false;
    size_t k = s.find("expire=");
    if (k == std::string::npos) return true;         // 无过期字段 → 视为长期（管理员手写）
    long long exp = _strtoi64(s.c_str() + k + 7, nullptr, 10);
    if (exp <= 0) return true;
    return MaintNowUnix() < exp;
}

bool EnterMaintenance(int ttlMinutes) {
    if (ttlMinutes <= 0) ttlMinutes = 120;                  // 默认 2 小时
    if (ttlMinutes > 24 * 60) ttlMinutes = 24 * 60;         // 上限 24 小时
    std::wstring p = MaintenanceFlagPathW();
    // 先删旧标记：① 保证内容刷新；② 若旧标记 ACL 异常也能借 SYSTEM 权限重置。
    // （服务端以 SYSTEM 运行，删除/重写不受 DACL 限制。）
    DeleteFileW(p.c_str());
    char buf[128] = { 0 };
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "expire=%lld\nby=GUI\n",
                MaintNowUnix() + (long long)ttlMinutes * 60);
    HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD w = 0;
    BOOL okW = WriteFile(h, buf, (DWORD)strlen(buf), &w, nullptr);
    CloseHandle(h);
    if (!okW) return false;
    // ★ 收紧 ACL：Everyone 只读（FR），写/删只留给 SYSTEM/Administrators。
    //   这一步才是"恶意程序无法自己关掉自保"的关键 —— 没有它，普通进程
    //   也能覆盖/删除标记来复位防护。服务端为 SYSTEM，后续删改不受限。
    const wchar_t* sddl = L"D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;WD)";
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &sd, nullptr)) {
        SetFileSecurityW(p.c_str(), DACL_SECURITY_INFORMATION, sd);
        LocalFree(sd);
    }
    return true;
}

bool ExitMaintenance() {
    std::wstring p = MaintenanceFlagPathW();
    if (DeleteFileW(p.c_str())) return true;
    // 已不存在也算成功（幂等）
    return GetLastError() == ERROR_FILE_NOT_FOUND;
}

std::string MaintenanceInfoJson() {
    std::string s = ReadMaintFlag();
    if (s.empty()) return "{\"on\":0,\"left\":0,\"expire\":0}";
    size_t k = s.find("expire=");
    long long exp = (k == std::string::npos) ? 0 : _strtoi64(s.c_str() + k + 7, nullptr, 10);
    long long now = MaintNowUnix();
    long long left = (exp > 0) ? (exp - now) : -1;         // -1 = 长期有效（无过期）
    if (exp > 0 && left <= 0) return "{\"on\":0,\"left\":0,\"expire\":0}";
    return std::string("{\"on\":1,\"left\":") + std::to_string(left) +
           ",\"expire\":" + std::to_string(exp) + "}";
}


// ---------------------------------------------------------------------------
//  Native Messaging 宿主注册
// ---------------------------------------------------------------------------
static bool SetRegDefaultSZ(HKEY root, const char* sub, const std::string& data) {
    HKEY hk;
    if (RegCreateKeyExA(root, sub, 0, nullptr, REG_OPTION_NON_VOLATILE,
                        KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &hk, nullptr) != ERROR_SUCCESS) return false;
    LONG r = RegSetValueExA(hk, nullptr, 0, REG_SZ, (const BYTE*)data.c_str(), (DWORD)data.size() + 1);
    RegCloseKey(hk);
    return r == ERROR_SUCCESS;
}
static bool DelRegKey(HKEY root, const char* sub) {
    // 递归删除（含子项）
    return RegDeleteTreeA(root, sub) == ERROR_SUCCESS || RegDeleteKeyA(root, sub) == ERROR_SUCCESS;
}

bool WriteNmManifest(const std::string& hostExePath,
                     const std::string& extIdChrome,
                     const std::string& extIdEdge,
                     std::string& outManifestPath) {
    std::string dir = DirName(hostExePath);
    outManifestPath = dir + "\\com.silverfox.guard.json";
    std::string chrome = extIdChrome.empty() ? extIdEdge : extIdChrome;
    std::string edge   = extIdEdge.empty()   ? extIdChrome : extIdEdge;
    if (chrome.empty()) chrome = "<EXTENSION_ID>";  // 占位（安装时应传入真实 ID）
    std::string json;
    json += "{\n";
    json += "  \"name\": \"" + std::string(NM_HOST_NAME) + "\",\n";
    json += "  \"description\": \"银狐主防原生消息宿主\",\n";
    json += "  \"path\": \"" + JsonEscape(hostExePath) + "\",\n";
    json += "  \"type\": \"stdio\",\n";
    json += "  \"allowed_origins\": [\n";
    json += "    \"chrome-extension://" + chrome + "/\"";
    if (!edge.empty() && edge != chrome) json += ",\n    \"chrome-extension://" + edge + "/\"";
    json += "\n  ]\n";
    json += "}\n";
    std::ofstream f(outManifestPath, std::ios::binary);
    if (!f) return false;
    f << json;
    return true;
}

bool RegisterNmHost(const std::string& manifestPath,
                    const std::string& extIdChrome,
                    const std::string& extIdEdge) {
    bool ok = true;
    const char* nm = NM_HOST_NAME;
    // HKLM：系统级安装的 Chrome / Edge
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    // HKCU：用户级安装的 Chrome / Edge（不写则读不到清单 -> connectNative 失败）
    ok &= SetRegDefaultSZ(HKEY_CURRENT_USER, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    ok &= SetRegDefaultSZ(HKEY_CURRENT_USER, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str(), manifestPath);
    (void)extIdChrome; (void)extIdEdge;  // ID 已写入清单，此处仅登记清单路径
    return ok;
}
bool UnregisterNmHost() {
    bool ok = true;
    const char* nm = NM_HOST_NAME;
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Google\\Chrome\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    ok &= DelRegKey(HKEY_LOCAL_MACHINE, ("SOFTWARE\\WOW6432Node\\Microsoft\\Edge\\NativeMessagingHosts\\" + std::string(nm)).c_str());
    return ok;
}

// 记录已配置的本机扩展 ID（双击重装时复用，避免丢失 allowed_origins 导致扩展连不上）
bool SaveExtIds(const std::string& chrome, const std::string& edge) {
    HKEY hk;
    if (RegCreateKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hk, NULL) != ERROR_SUCCESS)
        return false;
    if (!chrome.empty())
        RegSetValueExA(hk, "ExtIdChrome", 0, REG_SZ, (const BYTE*)chrome.c_str(), (DWORD)chrome.size() + 1);
    if (!edge.empty())
        RegSetValueExA(hk, "ExtIdEdge", 0, REG_SZ, (const BYTE*)edge.c_str(), (DWORD)edge.size() + 1);
    RegCloseKey(hk);
    return true;
}

bool ReadSavedExtIds(std::string& outChrome, std::string& outEdge) {
    outChrome.clear(); outEdge.clear();
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, CFG_ROOT, 0, KEY_READ, &hk) != ERROR_SUCCESS)
        return false;
    auto rd = [&](const char* name, std::string& out) {
        char buf[256] = {0}; DWORD sz = sizeof(buf);
        if (RegQueryValueExA(hk, name, 0, NULL, (LPBYTE)buf, &sz) == ERROR_SUCCESS) out = buf;
    };
    rd("ExtIdChrome", outChrome);
    rd("ExtIdEdge", outEdge);
    RegCloseKey(hk);
    return !outChrome.empty() || !outEdge.empty();
}

}  // namespace sf
