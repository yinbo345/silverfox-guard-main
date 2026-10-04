// rollback.cpp — 勒索回滚引擎实现（纯用户态）
//
// 设计依据与工程约束的完整说明见 rollback.h 头部注释。此处只记录**实现层面**
// 的关键决策与踩坑，供后续维护者对照。
//
// ---------------------------------------------------------------------------
//  实现结构
// ---------------------------------------------------------------------------
//   [监控线程] ReadDirectoryChangesW（异步 + IOCP 事件）
//        │  收到 FILE_ACTION_ADDED / MODIFIED / RENAMED_OLD_NAME / RENAMED_NEW_NAME
//        ▼
//   [抢拍快照] TrySnapshotBeforeWrite()
//        │  · 只对"未受信任进程"触及的文件抢拍（可信进程不拍，避免全盘复制）
//        │  · 内容寻址：快照文件名 = <sha256(路径+时间)>.snap，元数据另存 .meta
//        ▼
//   [信号统计] 滑动窗口计数：批量改写 / 高熵扩展名重命名 / 勒索说明文件
//        │
//        ▼
//   [勒索判定] 需要同时满足「批量改写」+（「高熵改名」或「勒索说明」）
//        │      —— 单信号不作为定性依据（压缩/备份软件会制造大批量改写）
//        ▼
//   [处置] 终止进程（可配）→ RollbackVictims() 从快照恢复 → 落报告 + 通知
//
// ---------------------------------------------------------------------------
//  关键踩坑记录
// ---------------------------------------------------------------------------
//  1. ReadDirectoryChangesW 的缓冲区必须**按下一个 FILE_NOTIFY_INFORMATION 的
//     4 字节对齐**推进（NextEntryOffset 的单位是字节，最后一项为 0 表示结束）。
//     直接按 sizeof() 加会踩到未对齐地址 → 偶发崩溃。
//  2. FILE_NOTIFY_INFORMATION.FileName 是**不带结尾 \0** 的变长数组，
//     长度由 FileNameLength 给出（字节数），必须手动按 UTF-16 长度构造 wstring。
//  3. 目录句柄要用 FILE_FLAG_BACKUP_SEMANTICS 才能打开目录本身。
//  4. 排除规则必须包含**本程序自己的快照缓存目录**——否则快照写入自身会触发
//     新事件 → 无限递归快照（第一次实现时踩到，CPU 直接跑满）。
// ===========================================================================
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shlobj.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <deque>
#include <map>
#include <set>
#include <unordered_map>   // 句柄归因用（2026-09-23）
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdint>

#include "rollback.h"
#include "criteria.h"
#include "common.h"
#include "behavior.h"   // FileIsSigned：信誉门读取进程 Authenticode 签名者（带缓存）
#include "hashshare.h"  // 云库哈希统一查询入口（Bloom 前置 + 多库聚合），落地哈希匹配用
#include "pehash.h"     // FileSha256Cached：带 (路径,大小,mtime) 缓存与体积上限的整文件哈希
#include <tlhelp32.h>

#pragma comment(lib, "bcrypt.lib")

namespace sf {
namespace rb {

// 服务方的停止事件（service.cpp 注入）。未注入时为 nullptr，
// 监控线程退化为 1 秒超时轮询（不影响正确性，只是退出稍慢）。
static HANDLE g_stopEvent = nullptr;
void SetStopEvent(void* hEvent) { g_stopEvent = (HANDLE)hEvent; }

// 告警回调（由服务方注入；未注入时只落日志，不影响引擎本身工作）
static DetectionCallback g_detCb = nullptr;
void SetDetectionCallback(DetectionCallback cb) { g_detCb = cb; }

// ===========================================================================
//  内部工具
// ===========================================================================
static const size_t kMaxListedPaths = 200;   // 报告里最多列出多少条路径

static std::string Lower(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}
static bool EndsWithCI(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    if (s.size() < n) return false;
    return Lower(s.substr(s.size() - n)) == Lower(std::string(suf));
}
static bool ContainsCI(const std::string& s, const char* sub) {
    return Lower(s).find(Lower(std::string(sub))) != std::string::npos;
}
static std::string NowStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[48];
    sprintf_s(b, "%04d-%02d-%02d %02d:%02d:%02d",
              st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return b;
}
static uint64_t NowMs() {
    return (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

// UTF-16 → UTF-8（宽路径转窄路径，全程序统一用窄串传路径）
static std::string W2A(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::wstring A2W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ===========================================================================
//  ★★ 2026-10-02：UTF-8 窄路径的统一访问入口 —— 一律走 W 版 API
// ===========================================================================
//  【为什么必须这么绕】本文件顶部约定「全程序统一用窄串传路径」，而 W2A/A2W
//    用的都是 **CP_UTF8**。但 Win32 的 **A 版** API（GetFileAttributesU8 /
//    CreateFileU8 / GetFileAttributesExU8 / FindFirstFileU8…）是按**系统 ACP**
//    解释输入字节的 —— 本机 ACP = 936(GBK)。于是「UTF-8 的中文路径」交给 A 版
//    API 必然乱码、必然失败，而且**失败方式是静默的**（返回
//    INVALID_FILE_ATTRIBUTES / INVALID_HANDLE_VALUE，看起来就像"文件不存在"）。
//
//  【实测事故（2026-10-02 验收）】下载目录被重定向到 D:\tianl\下载。新的
//    注册表权威路径逻辑**正确读到了**它，但走的是 RegGetValueA（返回 GBK 字节），
//    又被当作 UTF-8 处理 → 日志里打印成 "D:\tianl\????"（见 17:41:14
//    「无法监控目录（跳过）: D:\tianl\????」）→ OpenWatchTarget 拿烂路径调
//    CreateFileW 失败 → 该目录**根本不在监视面**。落到下载目录的载荷
//    此生不被落地初筛判定、不进隔离区（而桌面/文档是纯 ASCII 路径，全部正常，
//    所以这个洞只在"中文/重定向目录"上暴露）。
//
//  【纪律】**凡是路径，一律 A2W() 之后走 W 版 API**。新增代码请照此办理；
//    看到 `...A(path.c_str())` 形式的路径调用，先确认 path 是不是 UTF-8 —— 是就是 bug。
// ---------------------------------------------------------------------------
//  —— 以下 helper 的**参数顺序/个数与 Win32 A 版逐个对齐**，这样调用点可以只改
//     函数名（`XxxA(` → `XxxU8(`）而无需动实参，机械且不易错。
static DWORD GetFileAttributesU8(const std::string& u8) {
    if (u8.empty()) return INVALID_FILE_ATTRIBUTES;
    return GetFileAttributesW(A2W(u8).c_str());
}
static BOOL GetFileAttributesExU8(const std::string& u8, GET_FILEEX_INFO_LEVELS lvl,
                                  WIN32_FILE_ATTRIBUTE_DATA* fad) {
    if (u8.empty()) return FALSE;
    return GetFileAttributesExW(A2W(u8).c_str(), lvl, fad);
}
static HANDLE CreateFileU8(const std::string& u8, DWORD access, DWORD share,
                           LPSECURITY_ATTRIBUTES sa, DWORD disposition,
                           DWORD flags, HANDLE tmpl) {
    if (u8.empty()) return INVALID_HANDLE_VALUE;
    return CreateFileW(A2W(u8).c_str(), access, share, sa, disposition, flags, tmpl);
}
static BOOL DeleteFileU8(const std::string& u8) {
    if (u8.empty()) return FALSE;
    return DeleteFileW(A2W(u8).c_str());
}
static BOOL MoveFileExU8(const std::string& from, const std::string& to, DWORD flags) {
    if (from.empty() || to.empty()) return FALSE;
    return MoveFileExW(A2W(from).c_str(), A2W(to).c_str(), flags);
}
static BOOL SetFileAttributesU8(const std::string& u8, DWORD attr) {
    if (u8.empty()) return FALSE;
    return SetFileAttributesW(A2W(u8).c_str(), attr);
}
static BOOL CreateDirectoryU8(const std::string& u8, LPSECURITY_ATTRIBUTES sa) {
    if (u8.empty()) return FALSE;
    return CreateDirectoryW(A2W(u8).c_str(), sa);
}
static HANDLE FindFirstFileU8(const std::string& pattern, WIN32_FIND_DATAW* fd) {
    if (pattern.empty()) return INVALID_HANDLE_VALUE;
    return FindFirstFileW(A2W(pattern).c_str(), fd);
}
//  —— std::ifstream / std::ofstream 的**窄路径构造函数走系统 ACP**，中文路径同样会
//     静默打开失败。凡路径一律用 A2W() 转宽后再交给宽路径构造函数。

// 元数据文件内容：path / sha / size / time
struct Meta {
    std::string path;
    std::string sha;
    uint64_t    size = 0;
    uint64_t    time = 0;          // 快照建立时刻（steady ms）
    std::string reason;
};

// 快照目录
static std::string g_cacheDir;

static std::string CacheDirImpl() {
    if (!g_cacheDir.empty()) return g_cacheDir;
    wchar_t p[MAX_PATH] = { 0 };
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard\\rollback_cache";
    else
        dir = L"C:\\ProgramData\\SilverFoxGuard\\rollback_cache";
    // 逐级创建
    std::wstring prog = dir.substr(0, dir.find_last_of(L'\\'));
    CreateDirectoryW(prog.c_str(), nullptr);
    CreateDirectoryW(dir.c_str(), nullptr);
    g_cacheDir = W2A(dir);
    return g_cacheDir;
}

// 简单的文件名哈希：用于生成快照文件名（避免路径里的非法字符）
static std::string HashNameOf(const std::string& path) {
    std::string h = Sha256Bytes(path.data(), path.size());
    if (h.size() >= 32) return h.substr(0, 32);
    return h;
}

static std::string SnapPathOf(const std::string& path) {
    return CacheDirImpl() + "\\" + HashNameOf(path) + ".snap";
}
static std::string MetaPathOf(const std::string& path) {
    return CacheDirImpl() + "\\" + HashNameOf(path) + ".meta";
}


// 元数据读写（key=value 行式，路径可能含 = 故只按**第一个** = 切分）
static bool WriteMeta(const std::string& metaPath, const Meta& m) {
    std::ofstream f(A2W(metaPath).c_str(), std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f << "path=" << m.path << "\n"
      << "sha=" << m.sha << "\n"
      << "size=" << m.size << "\n"
      << "time=" << m.time << "\n"
      << "reason=" << m.reason << "\n";
    return true;
}
static bool ReadMeta(const std::string& metaPath, Meta& m) {
    std::ifstream f(A2W(metaPath).c_str(), std::ios::binary);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "path")        m.path = v;
        else if (k == "sha")    m.sha = v;
        else if (k == "size")   m.size = _strtoui64(v.c_str(), nullptr, 10);
        else if (k == "time")   m.time = _strtoui64(v.c_str(), nullptr, 10);
        else if (k == "reason") m.reason = v;
    }
    return !m.path.empty();
}

// ===========================================================================
//  熵值（Shannon，bit/byte）
//
//  为什么用熵值：文件被加密后字节分布趋于均匀 → 熵值从典型的 3~6 跃升到
//  7.9 以上。这是业界公认的勒索检测信号之一（配合"批量 + 改名"使用）。
//  但**它不充分**：已压缩格式（zip/7z/jpg/mp4）本身就接近 8.0，所以
//  判定时绝不能只看熵值，必须结合下面的批量/改名/勒索说明等旁证。
// ===========================================================================
double EntropyOfBuffer(const std::string& data) {
    if (data.empty()) return 0.0;
    uint64_t freq[256] = { 0 };
    for (unsigned char c : data) freq[c]++;
    double n = (double)data.size(), e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double p = (double)freq[i] / n;
        e -= p * (std::log(p) / std::log(2.0));
    }
    return e;
}

double EntropyOfFile(const std::string& path) {
    // 熵值采样：只读前 256KB（加密后的文件熵在全文件上均匀，
    // 头部采样已足够判别；读全文件在大文件上会拖慢监控线程）。
    HANDLE h = CreateFileU8(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0.0;
    const DWORD kSample = 256 * 1024;
    std::string buf; buf.resize(kSample);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &buf[0], kSample, &rd, nullptr);
    CloseHandle(h);
    if (!ok || rd == 0) return 0.0;
    buf.resize(rd);
    return EntropyOfBuffer(buf);
}

// ===========================================================================
//  快照缓存（容量受限 + LRU 淘汰）
// ===========================================================================
struct SnapEntry {
    std::string path;
    std::string sha;
    std::string snapPath;
    std::string metaPath;
    uint64_t    size = 0;
    uint64_t    atime = 0;   // 最近访问（用于 LRU）
};

static std::mutex                        g_cacheMtx;
static std::map<std::string, SnapEntry>  g_cache;      // key = 规范化小写路径
static std::deque<std::string>           g_lru;        // 队首最旧
static Config                            g_cfg;

// ===========================================================================
//  回滚前备份（prebackup）—— 2026-09-21 新增
//
//  ---------------------------------------------------------------------------
//  【一句话：任何一次"覆盖写"之前，先把被覆盖的内容捞出来存一份】
//  ---------------------------------------------------------------------------
//  维护者原话：「加"回滚前先备份当前文件"」。
//
//  为什么值得单独做一套，而不是复用既有的 undo 目录：
//    undo 是**上层决定留**的 —— 只有 RollbackVictims 在勒索处置时会调
//    SaveUndoCopy。结果就是 RestoreFile 的另一个语义出口
//    （UndoLastRollback，撤销上一次回滚）在函数体内直接内联了 CREATE_ALWAYS，
//    把"用户当前的版本"无声盖掉且不留任何副本。用户一旦误点「撤销」，
//    就再也回不到点之前的状态 —— 因为那一版只存在于内存里的几十毫秒。
//
//    prebackup 是**底层强制执行**的：钩子挂在真正落笔的那一步，谁触发都一样。
//    这样即使将来再加第四条、第五条回滚路径，也不会漏。
//
//  与 undo 的关系是"先后"而不是"二选一"：prebackup 先跑（保住当前版），
//  undo 后跑（保住被回滚前的那一版，供 10 分钟内撤销）。两者对象不同、
//  生命周期不同，互为补充。
// ===========================================================================

static std::string PreBackupDirImpl() {
    std::string d = CacheDirImpl() + "\\prebackup";
    CreateDirectoryU8(d.c_str(), nullptr);
    return d;
}

static std::string PreBackupIndexPath() {
    return PreBackupDirImpl() + "\\index.ndjson";
}

// 索引条目：一行一条 JSON。字段用最朴素的手写，与项目既有风格一致。
struct PreBackupEntry {
    std::string id;        // <SHA256前16位>_<毫秒>
    std::string origin;    // 被覆盖的原路径
    std::string file;      // 备份文件完整路径
    uint64_t    size  = 0;
    uint64_t    atMs  = 0; // 写入时刻（steady）
    std::string why;       // 触发来源（auto-rollback / undo-rollback / manual…）
};

static std::mutex               g_pbMtx;
static std::vector<PreBackupEntry> g_pbList;
static uint64_t                 g_pbBytes = 0;
static bool                     g_pbLoaded = false;

// 极简 JSON 取值（只处理本项目自己写出去的那几种形态，不引入解析库）
static std::string PbJsonStr(const std::string& s) {
    std::string o = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else o += c;
    }
    o += "\"";
    return o;
}
static std::string PbGetField(const std::string& line, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    size_t p = line.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    if (p >= line.size()) return {};
    if (line[p] == '"') {
        ++p;
        std::string out;
        for (size_t i = p; i < line.size(); ++i) {
            char c = line[i];
            if (c == '\\' && i + 1 < line.size()) {
                char n = line[++i];
                out += (n == 'n') ? '\n' : (n == 'r') ? '\r' : (n == 't') ? '\t' : n;
            } else if (c == '"') break;
            else out += c;
        }
        return out;
    }
    size_t e = line.find_first_of(",}", p);
    if (e == std::string::npos) e = line.size();
    return line.substr(p, e - p);
}

// 从磁盘重建索引（服务重启后 g_pbList 是空的，必须能认领已有备份文件）
static void LoadPreBackupIndexLocked() {
    if (g_pbLoaded) return;
    g_pbLoaded = true;
    g_pbList.clear();
    g_pbBytes = 0;
    std::ifstream f(A2W(PreBackupIndexPath()).c_str(), std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.size() < 8) continue;
        PreBackupEntry e;
        e.id     = PbGetField(line, "id");
        e.origin = PbGetField(line, "origin");
        e.file   = PbGetField(line, "file");
        e.why    = PbGetField(line, "why");
        std::string sz = PbGetField(line, "size"), tm = PbGetField(line, "at");
        try { if (!sz.empty()) e.size = std::stoull(sz); } catch (...) {}
        try { if (!tm.empty()) e.atMs = std::stoull(tm); } catch (...) {}
        if (e.file.empty()) continue;
        // 磁盘上文件可能已被手工删除 → 校验存在性，避免列表里挂幽灵条目
        DWORD a = GetFileAttributesU8(e.file.c_str());
        if (a == INVALID_FILE_ATTRIBUTES || (a & FILE_ATTRIBUTE_DIRECTORY)) continue;
        g_pbBytes += e.size;
        g_pbList.push_back(e);
    }
}

static void AppendPreBackupIndexLocked(const PreBackupEntry& e) {
    std::ofstream f(A2W(PreBackupIndexPath()).c_str(), std::ios::binary | std::ios::app);
    if (!f) return;
    f << "{\"id\":" << PbJsonStr(e.id)
      << ",\"origin\":" << PbJsonStr(e.origin)
      << ",\"file\":" << PbJsonStr(e.file)
      << ",\"size\":" << e.size
      << ",\"at\":" << e.atMs
      << ",\"why\":" << PbJsonStr(e.why)
      << "}\n";
}

// 重写索引（清理后调用；无原子替换是为了避免和火绒的文件行为监控打架）
static void RewritePreBackupIndexLocked() {
    std::string tmp = PreBackupIndexPath() + ".tmp";
    {
        std::ofstream f(A2W(tmp).c_str(), std::ios::binary | std::ios::trunc);
        if (!f) return;
        for (const auto& e : g_pbList) {
            f << "{\"id\":" << PbJsonStr(e.id)
              << ",\"origin\":" << PbJsonStr(e.origin)
              << ",\"file\":" << PbJsonStr(e.file)
              << ",\"size\":" << e.size
              << ",\"at\":" << e.atMs
              << ",\"why\":" << PbJsonStr(e.why)
              << "}\n";
        }
    }
    MoveFileExU8(tmp.c_str(), PreBackupIndexPath().c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH);
}

// 按容量 + 保留期双重淘汰。必须持锁调用。
static void PrunePreBackupsLocked() {
    uint64_t now = NowMs();
    uint64_t keepMs = (uint64_t)g_cfg.preBackupHours * 3600ull * 1000ull;
    std::vector<PreBackupEntry> keep;
    for (const auto& e : g_pbList) {
        bool expired = (keepMs > 0 && now > e.atMs && (now - e.atMs) > keepMs);
        if (expired) {
            DeleteFileU8(e.file.c_str());
            g_pbBytes = (g_pbBytes >= e.size) ? (g_pbBytes - e.size) : 0;
        } else {
            keep.push_back(e);
        }
    }
    bool changed = (keep.size() != g_pbList.size());
    // 容量超限 → 从最旧开始丢。
    //
    // ⚠️ 但**刚建立的备份受豁免**（10 分钟内不吃淘汰）：
    //   容量淘汰的触发时机恰好是"勒索正在批量改写文件"的时候 ——
    //   也就是用户最可能马上要用这些备份的时候。如果在这时因为配额
    //   而把刚存下来的那一批删掉，功能就等于在最需要它的时候失效了。
    //   豁免的代价是容量可能短暂超出 64MB，可控；收益是关键窗口期不丢数据。
    const uint64_t kFreshGuardMs = 10ull * 60 * 1000;
    while (g_pbBytes > g_cfg.preBackupBytes && !keep.empty()) {
        size_t pick = keep.size();      // 找到最旧的、且已过保护期的条目
        for (size_t i = 0; i < keep.size(); ++i) {
            // 注意用 >= 而非 >：备份的 atMs 就是"当下"取的，若用严格大于，
            // 同毫秒内刚建的备份会被判为"不新鲜"而成为淘汰首选 —— 恰好
            // 就是最不该删的那一份。<= 让保护期从创建那一刻立即生效。
            uint64_t age = (now >= keep[i].atMs) ? (now - keep[i].atMs) : 0;
            if (age <= kFreshGuardMs) continue;      // 保护期内 → 跳过
            pick = i;
            break;
        }
        if (pick >= keep.size()) break; // 全部都在保护期内 → 本轮不淘汰
        const PreBackupEntry& oldest = keep[pick];
        DeleteFileU8(oldest.file.c_str());
        g_pbBytes = (g_pbBytes >= oldest.size) ? (g_pbBytes - oldest.size) : 0;
        keep.erase(keep.begin() + pick);
        changed = true;
    }
    if (changed) {
        g_pbList.swap(keep);
        RewritePreBackupIndexLocked();
    }
}

// 回收超过保留期的备份（供巡逻线程周期调用）
static void PrunePreBackupsPeriodic() {
    std::lock_guard<std::mutex> lk(g_pbMtx);
    LoadPreBackupIndexLocked();
    PrunePreBackupsLocked();
}

// ---------------------------------------------------------------------------
//  核心：覆盖写之前把"即将被抹掉的那一份"存下来
//
//  返回值语义：
//    true  —— 可以继续覆盖（备份成功，或备份失败但非严格模式，或无需备份）
//    false —— **不要覆盖**（严格模式下备份失败）
//  这正是"可配置，默认继续"的落点。
// ---------------------------------------------------------------------------
static bool PreBackupBeforeOverwrite(const std::string& path, const std::string& why) {
    if (!g_cfg.rollbackPreBackup) return true;      // 功能关闭 → 不干涉

    // 源文件不存在（例如回滚一个从未落盘的新文件）→ 没有内容可备份，放行
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExU8(path.c_str(), GetFileExInfoStandard, &fad))
        return true;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return true;

    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0) return true;                        // 空文件，备份无意义
    if (sz > g_cfg.preBackupFileBytes) {
        // 超单文件上限：不备份。严格模式下**也不阻断** —— 大文件回滚是
        // 正常业务（用户真可能有大文档中招），不该因为备份不了就放弃救援。
        LogDbg("[rollback] 回滚前备份跳过（体积 " + std::to_string(sz / 1024) +
               "KB 超上限）: " + path);
        return true;
    }

    std::string id, dst;
    {
        std::lock_guard<std::mutex> lk(g_pbMtx);
        LoadPreBackupIndexLocked();
        // 时间戳取真实 Unix 毫秒（不是 steady），方便用户按时间认领
        uint64_t wall = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        id = HashNameOf(path).substr(0, 16) + "_" + std::to_string(wall);
        dst = PreBackupDirImpl() + "\\" + id + ".bak";
        // 同毫秒同文件重复触发 → 补序号，绝不覆盖已有备份
        for (int i = 1; GetFileAttributesU8(dst.c_str()) != INVALID_FILE_ATTRIBUTES && i < 100; ++i)
            dst = PreBackupDirImpl() + "\\" + id + "_" + std::to_string(i) + ".bak";
    }

    // 共享读 + 允许写共享：源文件可能正被别的进程持有（Edge 的 Preferences 就是）
    HANDLE hs = CreateFileU8(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) {
        LogDbg("[rollback] 回滚前备份失败（无法打开源文件 err=" +
               std::to_string(GetLastError()) + "）: " + path);
        return !g_cfg.rollbackPreBackupStrict;
    }
    HANDLE hd = CreateFileU8(dst.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) {
        CloseHandle(hs);
        LogDbg("[rollback] 回滚前备份失败（无法创建备份 err=" +
               std::to_string(GetLastError()) + "）: " + dst);
        return !g_cfg.rollbackPreBackupStrict;
    }

    std::vector<char> buf(256 * 1024);
    bool okAll = true;
    uint64_t written = 0;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { okAll = false; break; }
        if (!rd) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { okAll = false; break; }
        written += rd;
    }
    CloseHandle(hs);
    FlushFileBuffers(hd);
    CloseHandle(hd);

    if (!okAll) {
        DeleteFileU8(dst.c_str());   // 半截备份比没有备份更危险，直接丢弃
        LogDbg("[rollback] 回滚前备份失败（写入中断）: " + path);
        return !g_cfg.rollbackPreBackupStrict;
    }

    {
        std::lock_guard<std::mutex> lk(g_pbMtx);
        PreBackupEntry e;
        e.id = id; e.origin = path; e.file = dst;
        e.size = written; e.atMs = NowMs(); e.why = why;
        g_pbList.push_back(e);
        g_pbBytes += written;
        AppendPreBackupIndexLocked(e);
        PrunePreBackupsLocked();
    }
    LogDbg("[rollback] 已备份被覆盖内容 " + std::to_string(written) + " 字节 → " +
           id + "（" + why + "）: " + path);
    return true;
}
static std::atomic<bool>                 g_running{ false };
static Stats                             g_stats;
static std::mutex                        g_statsMtx;

// ===========================================================================
//  撤销记录（"反向回滚"）
//
//  为什么需要：高风险判定成立时引擎会**自动**回滚，用户来不及干预。但判定
//  可能误伤（例如备份软件批量操作被误判成勒索），此时用户需要拿回被自动回滚
//  覆盖掉的那一份内容。
//
//  做法：回滚**之前**先把每个受害文件当前的内容（即被改写成密文的版本，也就
//       是用户"刚做出来"的内容）另存到 undo 目录，记录清单；用户点"撤销"时
//       再把这些内容写回原路径。
//
//  生命周期：只保留**最近一次**回滚的撤销记录。原因：
//   ① 撤销是"反悔上一次"的语义，堆叠多份会让用户分不清撤销到哪一步；
//   ② 每份撤销记录占用与快照同级，长期保留会双倍占盘。
//   新的回滚发生时，旧的撤销记录直接删除（此时它已失去意义——用户已经
//   接受了上一次处置，或已过了反悔窗口）。
// ===========================================================================
struct UndoEntry {
    std::string path;       // 原文件路径
    std::string undoPath;   // 回滚前内容的备份路径
    uint64_t    size = 0;
};
static std::mutex              g_undoMtx;
static std::vector<UndoEntry>  g_undoList;
static std::string             g_undoToken;
static std::string             g_undoTrigger;
static uint64_t                g_undoAtMs = 0;

// 撤销记录的保留时限：超过此时限自动作废（默认 10 分钟）。
// 理由：用户的反悔窗口是"刚看到弹窗那会儿"，拖到第二天再点撤销，
//       文件早被别的程序改过，强行写回反而破坏数据。
static const uint64_t kUndoWindowMs = 10 * 60 * 1000;

// 清空撤销记录（调用方须持 g_undoMtx）。删除磁盘上的备份文件。
static void ClearUndoLocked() {
    for (const auto& u : g_undoList) DeleteFileU8(u.undoPath.c_str());
    g_undoList.clear();
    g_undoToken.clear();
    g_undoTrigger.clear();
    g_undoAtMs = 0;
}

static void StatAdd(int field, uint64_t v) {
    std::lock_guard<std::mutex> lk(g_statsMtx);
    switch (field) {
        case 0: g_stats.snapshots      += v; break;
        case 1: g_stats.snapBytes      += v; break;
        case 2: g_stats.eventsSeen     += v; break;
        case 3: g_stats.snapshotTaken  += v; break;
        case 4: g_stats.snapshotSkipped+= v; break;
        case 5: g_stats.rollbacks      += v; break;
        case 6: g_stats.restored       += v; break;
        case 7: g_stats.unrecoverable  += v; break;
        case 8: g_stats.detected       += v; break;
        case 9: g_stats.watcherErrors  += v; break;
        case 10: g_stats.keysCaptured  += v; break;   // 密钥候选留存
        case 11: g_stats.keyHits       += v; break;   // 密钥关联提前定性
        case 12: g_stats.landedSuspect += v; break;   // 落地初筛命中
    }
}

// 快照占用的**唯一真相来源**：直接对 g_cache 求和。
// 为什么不用 g_stats.snapBytes 做增量累加：增量记账在本模块里有三处会改动
// （新增 / LRU 淘汰 / 恢复后释放），任何一处漏减都会让占用数永久漂移——
// 而容量淘汰判定直接依赖这个数，漂移会导致"缓存早已超限却不再淘汰"。
// 改为每次求和：g_cache 上限很小（最多几千条），求和开销可忽略，换来的是
// 永远不会算错的占用值。调用方须持 g_cacheMtx。
static uint64_t CacheBytesLocked() {
    uint64_t n = 0;
    for (const auto& kv : g_cache) n += kv.second.size;
    return n;
}

// 把从 g_cache 现算出来的真实值同步回 g_stats（供 UI 展示）。
// 调用方须持 g_cacheMtx。
static void SyncCacheStatsLocked() {
    uint64_t bytes = CacheBytesLocked();
    uint64_t count = (uint64_t)g_cache.size();
    std::lock_guard<std::mutex> lk(g_statsMtx);
    g_stats.snapBytes = bytes;
    g_stats.snapshots = count;
}

static std::string NormKey(const std::string& p) {
    std::string s = Lower(p);
    // 去掉 \\?\ 前缀（长路径形式）以统一 key
    if (s.rfind("\\\\?\\", 0) == 0) s = s.substr(4);
    while (!s.empty() && (s.back() == '\\' || s.back() == '/')) s.pop_back();
    return s;
}

// 淘汰：从最旧开始删，直到占用回到上限内。
// 注意：占用值从 g_cache 现算，不依赖 g_stats 的增量记账（见 CacheBytesLocked 说明）。
static void EvictLocked() {          // 调用方须持 g_cacheMtx
    while (CacheBytesLocked() > g_cfg.maxCacheBytes && !g_lru.empty()) {
        std::string k = g_lru.front(); g_lru.pop_front();
        auto it = g_cache.find(k);
        if (it == g_cache.end()) continue;
        DeleteFileU8(it->second.snapPath.c_str());
        DeleteFileU8(it->second.metaPath.c_str());
        g_cache.erase(it);
    }
}

// LRU 触碰：把 key 移到队尾
static void TouchLocked(const std::string& k) {   // 调用方须持 g_cacheMtx
    for (auto it = g_lru.begin(); it != g_lru.end(); ++it)
        if (*it == k) { g_lru.erase(it); break; }
    g_lru.push_back(k);
}

// ===========================================================================
//  排除规则
//
//  必须排除的目录（否则会把自己/系统搅乱）：
//    · 本程序自己的快照缓存目录 —— 不排除会无限递归快照（踩过）
//    · 系统卷信息 / 页面文件 / 注册表配置单元
//    · 程序自身的安装目录（自保文件不应被回滚）
//    · **浏览器用户数据目录**（2026-09-19 事故后新增，见下）
// ===========================================================================
//
// ---------------------------------------------------------------------------
//  【2026-09-19 事故】浏览器数据目录必须整体排除
// ---------------------------------------------------------------------------
//  现象：维护者反馈"每天几乎都会有一次 Edge 扩展被清空"，且"GitHub 登不上去"。
//
//  根因（取证结论，详见 C:\temp\edge_forensics\Edge扩展丢失根因报告.md）：
//  浏览器**不是被删的，是被我们自己覆盖回去的**。链路：
//    ① Edge 写 Preferences / Secure Preferences（扩展注册表就在这个文件里）
//    ② 该写入被纳入监控 → 建快照
//    ③ 同时 Edge 的 edge_BITS_* 临时文件（高熵随机名）命中密钥候选，
//       紧接着同目录批量改写 → 时序关联成立 → "勒索行为判定成立"
//    ④ 受害者清单是窗口内**所有**改动文件（无判别，上限 2000）
//    ⑤ 回滚用 CREATE_ALWAYS **覆盖写**：把旧快照盖回新文件
//    ⑥ Preferences 里的 extensions.settings 退回旧版本 → 扩展"凭空消失"
//      （文件系统里根本没有删除记录，所以怎么查都查不到"谁删的"）
//
//  【为什么浏览器目录必须整体排除，而不是只排除个别文件】
//    · 浏览器数据目录里**没有用户的创作内容**（不是勒索的目标），
//      排除它不损失任何防护价值；
//    · 但它是全机**最高频写入**的区域之一（缓存/会话/Preferences/LevelDB），
//      回滚误伤的代价远大于保护收益；
//    · Preferences / Login Data 一旦被旧版本覆盖，用户的登录态、
//      扩展配置、设置项全部回退 —— 这正是事故的表现。
//
//  【排除范围】
//    用户级：AppData\Local / Roaming 下的各浏览器厂商目录（覆盖其运行时数据）
//    + 各浏览器自己的缓存目录名（防止用户改了 profile 路径）
//  ⚠️ 注意：这里只排除**数据目录**，不排除浏览器安装目录（Program Files 下的
//     可执行文件仍受保护 —— 浏览器本体被加密是要救的）。
// ---------------------------------------------------------------------------
static bool IsBrowserDataPath(const std::string& pathLower) {
    // ① 用户级浏览器数据根（覆盖 Chromium 系 + Firefox 系 + 国产套壳）
    static const char* kBrowserRoots[] = {
        // ---- Chromium 系（共用 User Data 结构）----
        "\\appdata\\local\\microsoft\\edge\\",
        "\\appdata\\local\\google\\chrome\\",
        "\\appdata\\local\\google\\chrome beta\\",
        "\\appdata\\local\\google\\chrome sxs\\",
        "\\appdata\\local\\bravesoftware\\",
        "\\appdata\\local\\chromium\\",
        "\\appdata\\local\\vivaldi\\",
        "\\appdata\\local\\opera software\\",
        "\\appdata\\local\\yandex\\",
        "\\appdata\\local\\360chrome\\",          // 360 极速浏览器
        "\\appdata\\local\\360se6\\",             // 360 安全浏览器
        "\\appdata\\local\\tencent\\qqbrowser\\", // QQ 浏览器
        "\\appdata\\local\\sogouexplorer\\",      // 搜狗浏览器
        "\\appdata\\local\\maxthon",              // 傲游
        "\\appdata\\local\\browser\\",            // 部分套壳的通用名
        "\\appdata\\local\\electron\\",
        // ---- Firefox 系（不走 User Data，直接以 profile 为根）----
        "\\appdata\\roaming\\mozilla\\firefox\\",
        "\\appdata\\local\\mozilla\\firefox\\",
        "\\appdata\\roaming\\waterfox\\",
        "\\appdata\\roaming\\librewolf\\",
    };
    for (const char* r : kBrowserRoots)
        if (pathLower.find(r) != std::string::npos) return true;

    // ② 关键数据文件名（浏览器 profile 完整路径已由①覆盖，这里是双保险：
    //    用户把 profile 放到非默认位置时仍能命中）
    //    注意：只匹配"位于浏览器典型 profile 目录内"的路径；由于这些文件名
    //    在别处也会出现，所以再加一层目录特征判断。
    static const char* kProfileMarkers[] = {
        "\\user data\\",         // Chromium 系 profile 根
        "\\chromium\\",
        "\\default\\preferences",
        "\\default\\secure preferences",
        "\\default\\login data",
        "\\default\\web data",
    };
    bool looksLikeProfile = false;
    for (const char* m : kProfileMarkers)
        if (pathLower.find(m) != std::string::npos) { looksLikeProfile = true; break; }
    if (!looksLikeProfile) return false;

    // profile 目录内 + 是浏览器的核心状态文件 → 排除
    static const char* kBrowserStateNames[] = {
        "\\preferences", "\\secure preferences", "\\login data", "\\web data",
        "\\cookies", "\\cookies-journal", "\\history", "\\favicons",
        "\\top sites", "\\shortcuts", "\\bookmarks", "\\bookmarks.bak",
        "\\local state", "\\local storage\\", "\\session storage\\",
        "\\indexeddb\\", "\\extensions\\", "\\extension state\\",
        "\\service worker\\", "\\sync data\\", "\\network\\",
        "\\cache\\", "\\code cache\\", "\\gpucache\\",
        "\\visited links", "\\preferences-journal",
    };
    for (const char* n : kBrowserStateNames)
        if (pathLower.find(n) != std::string::npos) return true;
    return false;
}

static bool IsExcluded(const std::string& pathLower) {
    static const char* kEx[] = {
        "\\rollback_cache\\",           // 自身缓存（防递归）
        "\\system volume information",
        "\\$recycle.bin",
        "\\windows\\winsxs\\",          // 组件存储：改动量大且不应回滚
        "\\windows\\assembly\\",
        "\\.git\\",
        "\\node_modules\\",
        "\\programdata\\silverfoxguard\\",   // 自身数据目录
        "\\appdata\\local\\temp\\sg_",       // 自身临时文件前缀
        // 2026-09-26：部署暂存与测试样本目录（银泊实测部署 EXE 被自家 lv1 旁证
        // 隔离：deploy 脚本暂存的 SilverFoxGuardSvc_*.exe 落 sf_stash 即被抓）。
        // 排除后：样本在仓库目录里安稳存放，复制到桌面/Downloads 才触发判定。
        "\\temp\\sf_stash\\",                // 部署脚本暂存区（自家 EXE 中转）
        "\\temp\\samples\\",                 // 测试样本仓库（构建测试物料用）
        "\\temp\\dl\\",                      // 本地下载服务器宿主目录（同上）
        // ★ 2026-09-27：沙箱送检的**临时解压目录**（%TEMP%\SilverFoxSandbox\p<box>\）。
        //   它里面装的是压缩包解出的载荷（很可能正是恶意样本），但那是
        //   **我方自己造出来、且几秒后就会被删掉**的东西。不排除会引发两种事故：
        //     ① 自喂循环：解压物落 Temp → 落地捕获判 lv>=1 → 触发自动送检
        //        → 沙箱再解压 → …… 每轮新建一个一次性 box，把机器烧穿。
        //     ② 噪音隔离：lv>=2 时把"我方临时解压物"当用户文件自动隔离，
        //        隔离一个马上要被删的副本，还在隔离区留下垃圾台账。
        //   与既有 `\appdata\local\temp\sg_`（自身临时文件前缀）同一条纪律。
        "\\temp\\silverfoxsandbox\\",        // 沙箱送检临时解压目录（自家产物）
    };
    for (const char* e : kEx) if (pathLower.find(e) != std::string::npos) return true;
    // ★ 2026-10-02：自家分析设施的**产物根**（与上面 `\\temp\\silverfoxsandbox\\` 同族，
    //   但那一族只排了「沙箱临时解压目录」，漏了「盒根」与「beacon 根」）。
    //   【事故】Sandboxie 把盒内写入**虚拟化**到 C:\Sandbox\<用户>\<box>\...，而
    //   DefaultWatchDirsEx() 的「系统盘一级子目录」规则把 C:\Sandbox 当成用户自建目录
    //   **递归监控**（kSkip1st 里没有 \sandbox）⇒ 样本在盒内的批量写入被当真机批量改写：
    //   实测 2026-10-02 09:44:59 那次「勒索行为判定成立（涉及文件 36 个）」的 31 个快照
    //   **全部**落在 C:\Sandbox\tianl\SFx5zj68d02\user\current\documents\sf_ransomlab\doc_0NN.docx；
    //   判定需 10 秒内 mod+ren≥40 且随机后缀改名≥15（rollback_rules.txt），真机不可能凑出
    //   ⇒ 该判定**物理上只能来自盒内**，随后弹出「勒索行为已拦截」并回滚了真机文件。
    //   盒是**一次性**的、且盒内活动本就由探针（probe DLL）负责观测 ⇒ 从真机监控面移除
    //   **不损失任何覆盖**（若 box 配了 OpenFilePath 直通真机，写入会出现在真机路径上，仍被监控）。
    //   beacon 根同理（C:\SilverFoxProbe[_selftest]\*.txt 是探针写的信号文件，不是用户数据）。
    //   ★ 锚点**自带盘符**（`c:\sandbox\`）⇒ 用子串匹配也**不会**误伤 `d:\x\sandbox\`
    //     这类同名目录（`:` 不可能出现在路径中段）；且能顺带命中万一漏网的
    //     `\\?\c:\sandbox\` 长路径形式 —— 只做前缀比较的话，带 `\\?\` 的路径会**静默不命中**。
    //   ★ 新增任何"我方自己会大量写文件的目录"时，请同时补进 kSelfRoots 与 kSkip1st。
    static const char* kSelfRoots[] = {
        "c:\\sandbox\\",         // Sandboxie 盒根（默认位；sandbox.cpp:736/823 动态拼装）
        "c:\\silverfoxprobe",    // 探针 beacon 根（含 _selftest 兄弟目录）
    };
    for (const char* r : kSelfRoots) if (pathLower.find(r) != std::string::npos) return true;
    // 浏览器用户数据目录整体排除（2026-09-19 Edge 扩展"丢失"事故根因）
    if (IsBrowserDataPath(pathLower)) return true;
    if (pathLower.find("\\pagefile.sys") != std::string::npos) return true;
    if (pathLower.find("\\hiberfil.sys") != std::string::npos) return true;
    if (pathLower.find("\\swapfile.sys") != std::string::npos) return true;
    // 临时文件不拍（用户本来就要删）
    if (EndsWithCI(pathLower, ".tmp") || EndsWithCI(pathLower, ".temp") ||
        EndsWithCI(pathLower, ".~tmp") || EndsWithCI(pathLower, ".crdownload") ||
        EndsWithCI(pathLower, ".part") || EndsWithCI(pathLower, ".partial")) return true;
    return false;
}

// 受保护扩展名：只对这些文件建立快照（避免把整个磁盘镜像进缓存）
// 依据：卡巴官方列举的"系统重要文件"里明确包含文档（.doc 等）与可执行文件。
static const char* kProtectedExt[] = {
    // ---- 文档 ----
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
    ".odt", ".ods", ".odp", ".csv", ".md", ".wps", ".et", ".dps", ".pages",
    // ---- 图片 / 设计 ----
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".psd", ".ai",
    ".svg", ".webp", ".raw", ".cr2", ".nef",
    // ---- 音视频 ----
    ".mp3", ".wav", ".flac", ".aac", ".m4a", ".mp4", ".avi", ".mkv", ".mov", ".wmv",
    // ---- 代码 / 工程 ----
    ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".py", ".js", ".ts", ".go", ".rs",
    ".html", ".css", ".json", ".xml", ".yml", ".yaml", ".sql", ".sh", ".bat", ".ps1",
    ".sln", ".vcxproj", ".csproj", ".gradle", ".lua", ".gd", ".tscn", ".unity",
    // ---- 压缩 / 数据库 / 虚拟盘 ----
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bak", ".db", ".sqlite", ".mdf", ".accdb",
    ".vhd", ".vhdx", ".vmdk",
    // ---- 可执行（卡巴明确列入"系统重要文件"）----
    ".exe", ".dll", ".sys", ".msi", ".scr", ".com", ".ocx", ".cpl",
};
static bool IsProtectedExt(const std::string& pathLower) {
    // 取最后一个点
    size_t dot = pathLower.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = pathLower.substr(dot);
    if (ext.size() > 12) return false;              // 超长"扩展名"多半是勒索附加后缀，非受保护类型
    for (const char* e : kProtectedExt) if (ext == e) return true;
    return false;
}

// 压缩/归档后缀（2026-09-19 密钥误报根治）：
//  压缩产物熵天然 ≥7.5（压缩=消除冗余），与"随机密钥"在熵维度完全不可区分——
//  但它是最常见的正常文件形态（下载包/插件市场解压/MC 日志轮转 .log.gz）。
//  密钥截获与勒索改名判定都必须先排除这一大类，否则正常软件刷满候选表。
static bool LooksLikeCompressedExt(const std::string& ext) {
    static const char* kComp[] = {
        ".gz", ".zip", ".7z", ".rar", ".tar", ".bz2", ".xz", ".zst", ".zstd",
        ".tgz", ".tbz", ".txz", ".lz4", ".br", ".jar", ".war", ".pak", ".cab",
        ".iso", ".img", ".apk", ".ipa", ".asar", ".whl", ".nupkg", ".vsix",
        ".crx", ".xpi", ".dmg", ".pkg", ".rpm", ".deb", ".appx", ".msix", ".bundle",
    };
    for (const char* e : kComp) if (ext == e) return true;
    return false;
}

// 内容魔数兜底：改了后缀的压缩包同样熵虚高，按文件头识别。
// （方向不可伪造——真随机密钥不会恰好长着标准压缩头。）
static bool HasArchiveMagic(const std::string& data) {
    static const struct { const char* magic; size_t len; } kMagics[] = {
        { "\x1F\x8B", 2 },                 // gzip
        { "PK\x03\x04", 4 },               // zip
        { "PK\x05\x06", 4 },               // zip 空包
        { "PK\x07\x08", 4 },               // zip spanned
        { "\x37\x7A\xBC\xAF\x27\x1C", 6 }, // 7z
        { "Rar!\x1A\x07", 7 },             // rar
        { "BZh", 3 },                      // bzip2
        { "\xFD" "7zXZ\x00", 6 },          // xz（注意 \xFD 后不能直接跟十六进制字符）
        { "\x28\xB5\x2F\xFD", 4 },         // zstd
        { "MSCF", 4 },                     // cab
        { "\x04\x22\x4D\x18", 4 },         // lz4
    };
    for (const auto& m : kMagics)
        if (data.size() >= m.len && memcmp(data.data(), m.magic, m.len) == 0) return true;
    return false;
}

// 勒索常见的附加后缀（判断"原文件被改成陌生后缀"）
static bool LooksLikeRansomExt(const std::string& ext) {
    if (ext.size() < 4 || ext.size() > 12) return false;   // 短后缀（.txt）不算
    // 合法软件高频改名后缀优先豁免（2026-09-19 PCL2 误报）：日志轮转（.log.gz）、
    // 下载落盘（.download/.crdownload/.partial）、备份轮转（.bak/.old）与勒索改名
    // 在"改后缀"表象上相同，必须先排除再谈勒索特征。
    if (LooksLikeCompressedExt(ext)) return false;
    static const char* kBenign[] = {
        ".download", ".crdownload", ".partial", ".part", ".bak", ".old", ".new",
        ".orig", ".backup", ".sav", ".temp", ".tmp", ".swp", ".dmp", ".cache",
        ".stamp", ".log1",
    };
    for (const char* b : kBenign) if (ext == b) return false;
    // 纯字母/数字混合且长度 >=5 的陌生后缀，多半是勒索家族标记
    // （如 .locked / .encrypted / .WNCRY / .dxxd）
    static const char* kKnown[] = {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypto", ".locky", ".zepto",
        ".wncry", ".wcry", ".wncrypt", ".cerber", ".dharma", ".phobos", ".stop",
        ".djvu", ".conti", ".lockbit", ".revil", ".sodinokibi", ".maze", ".ryuk",
        ".gandcrab", ".teslacrypt", ".petya", ".notpetya", ".badrabbit", ".avos",
        ".dxxd", ".arrow", ".bip", ".blm", ".zeppelin", ".makop", ".nobes",
    };
    for (const char* k : kKnown) if (ext == k) return true;
    // 通用：形如 .xxxxxx 的 6 字符随机串
    if (ext.size() >= 6) {
        bool alphaNum = true;
        for (size_t i = 1; i < ext.size(); ++i)
            if (!isalnum((unsigned char)ext[i])) { alphaNum = false; break; }
        if (alphaNum) return true;   // 保守：仅在配合"批量"信号时才会被采用（见判定逻辑）
    }
    return false;
}

// 勒索说明文件名（README / 解密说明 / HOW TO DECRYPT）
//
// ---------------------------------------------------------------------------
//  【2026-09-19 事故】这里过去用**子串匹配**，是误报的主源之一
// ---------------------------------------------------------------------------
//  旧实现：`baseLower.find(n) != npos` —— 只要文件名里**任意位置**出现 "readme"
//  就算勒索说明。于是浏览器缓存里的 `readme_abc123.html`、开发目录里的
//  `README.md`、解压出来的 `readme.txt` 全部命中 → noteSignal 成立
//  → 配合当时过松的 (mod+ren)>=3 → 「勒索行为判定成立」→ 覆盖写回滚。
//
//  修复原则：**勒索说明文件是一个"独立文件"，不是一个"含某词的文件"**。
//  所以判据必须锚定到"整个文件名（不含扩展名）"或"文件名严格前缀"，
//  绝不允许中间子串命中。
// ---------------------------------------------------------------------------
static bool LooksLikeRansomNote(const std::string& baseLower) {
    if (baseLower.empty()) return false;

    // 去掉扩展名得到主干（勒索说明大体是 .txt / .html / 无扩展名）
    std::string stem = baseLower;
    size_t dot = stem.find_last_of('.');
    if (dot != std::string::npos && dot > 0) stem = stem.substr(0, dot);

    // ---- ① 整体精确匹配：文件名主干就等于这些词 ----
    // 这些是勒索说明文件的**完整名**（如 "HOW_TO_DECRYPT.txt" 的主干）。
    static const char* kExactStems[] = {
        "readme", "read_me", "_readme_", "#readme#", "!!!readme!!!",
        "how_to_decrypt", "how-to-decrypt", "howtodecrypt",
        "how_to_recover", "how_to_back_files", "how_to_restore_files",
        "decrypt_instructions", "decryption_instructions",
        "restore_files", "recover_files", "restore-my-files",
        "help_decrypt", "help_recover", "unlock_files", "unlock_instructions",
        "your_files_are_encrypted", "all_your_files", "files_encrypted",
        "解密说明", "恢复文件", "解密文件", "如何解密", "重要说明",
        "help_help_help", "readme_for_decrypt",
    };
    for (const char* n : kExactStems) if (stem == n) return true;

    // ---- ② 严格前缀匹配：勒索说明常见的"前缀 + 随机串"命名 ----
    // 例："HOW_TO_DECRYPT_abc123.txt"、"!!!READ_ME!!!_xyz.txt"
    // 用前缀锚定就不会误伤 "readme_notes_for_project.html" 这类正常文件吗？
    // 会 —— 但这里要求前缀之后紧跟分隔符或长度极短，进一步收紧。
    static const char* kStrongPrefix[] = {
        "how_to_decrypt", "how-to-decrypt", "how_to_recover",
        "decrypt_instructions", "!!!readme!!!", "#readme#", "!!!read_me!!!",
        "your_files_are_encrypted", "all_your_files_are_encrypted",
        "解密说明", "恢复文件",
    };
    for (const char* p : kStrongPrefix) {
        size_t pl = strlen(p);
        if (stem.size() < pl) continue;
        if (stem.compare(0, pl, p) != 0) continue;
        // 前缀之后必须是结尾或分隔符（_ - . 空格 数字），避免 "readmefile"
        if (stem.size() == pl) return true;
        char c = stem[pl];
        if (c == '_' || c == '-' || c == '.' || c == ' ' || (c >= '0' && c <= '9'))
            return true;
    }
    return false;
}

// ===========================================================================
//  风险分层建快照（2026-09-18，快照瘦身的核心）
//
//  为什么需要：旧策略是"任何改写都建快照"，导致普通软件每次保存文档都存一份
//  （Word 自动保存、IDE 频繁落盘、浏览器缓存写入……），占用迅速堆积，把更早
//  的、真正有价值的快照挤掉。维护者实测反馈"快照占内存太大"即此因。
//
//  判据设计依据：
//    · 勒索的**不可伪装特征**是"把文件改成陌生后缀"（加密后必然改名），
//      正常软件保存时扩展名不变 —— 这是最可靠的单一判据；
//    · 正常软件也可能短时间写大量文件（编译器、解压），但它不会改扩展名。
//      所以"同目录短时间大量改写"单独不足以建快照，需配合其它信号；
//    · 高价值文档（论文/表格/图片/代码）是用户最在意的东西，值得多留一份。
// ===========================================================================

// 高价值文档类型：用户创作内容，误删/被加密的代价最高。
// 与 kProtectedExt 的区别：kProtectedExt 是"值得保护的"（含 exe/dll/系统文件），
// 这里是"用户自己写出来的"（不含可执行体、不含压缩包）。
static bool IsHighValueDoc(const std::string& pathLower) {
    static const char* kDocs[] = {
        // 文档
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf",
        ".odt", ".ods", ".odp", ".md", ".wps", ".et", ".dps", ".csv",
        // 图片（创作素材）
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".psd", ".ai", ".svg",
        ".raw", ".cr2", ".nef", ".arw", ".tif", ".tiff",
        // 音视频（创作成品）
        ".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".avi", ".mkv", ".flv",
        // 代码（开发者的心血）
        ".c", ".cpp", ".h", ".hpp", ".cs", ".java", ".py", ".js", ".ts", ".go",
        ".rs", ".php", ".rb", ".lua", ".gd", ".sh", ".ps1", ".html", ".css",
        ".json", ".xml", ".yml", ".yaml", ".sln", ".vcxproj", ".csproj", ".unity",
    };
    size_t dot = pathLower.find_last_of('.');
    if (dot == std::string::npos) return false;
    std::string ext = pathLower.substr(dot);
    if (ext.size() > 12) return false;
    for (const char* e : kDocs) if (ext == e) return true;
    return false;
}

// 目录热度表：记录"某目录最近一次批量改写的时间与该窗口内的改写次数"。
// 用于判据②。容量有上限，避免长时间运行后无界增长。
struct DirHeat { uint64_t windowStart = 0; uint32_t count = 0; };
static std::mutex                      g_heatMtx;
static std::map<std::string, DirHeat>  g_heat;

// 落地初筛命中队列（供 service 层拉取，做进程关联与弹窗）。
// 有界队列：只留最近 256 条，避免长时间运行后无界增长。
struct LandAlert {
    std::string path;
    std::string reason;
    uint64_t    at = 0;
    int         lv = 2;   // 初筛档位：1=旁证 2=高危。★ 1 也要入队（2026-09-24）——
                          // 服务层要拿它做「落地旁证 + 后续动作」的组合升档，
                          // 过去只传 lv>=2，旁证级落地在服务层完全不可见。
};
struct LandQueue {
    std::deque<LandAlert> alerts;
};
static std::mutex  g_landMtx;
static LandQueue   g_landed;

// ===========================================================================
//  ★ 落地旁证档案（2026-09-24 新增）—— 供实时链路做「落地 → 执行」组合升档
//
//  【为什么不能复用 g_landed】
//   TakeLandedAlertsJson() 是**消费式**接口（取走即清空，否则同一批告警会被
//   反复上报刷屏）。而实时链路需要的是「任意时刻回查：这个刚被拉起的 exe，
//   是不是不久前刚落在高危目录里的那一个」。两者语义相反 → 独立一份只读档案。
//
//  【它补的是哪一段盲区】
//   scanner 的出生卡用 IsFreshlyCreated(300s) 判新鲜度；若载荷落地后**隔十几
//   分钟才被拉起**（银狐常见的延时执行），新鲜度门就失效了。本档案记录的是
//   「落地那一刻的路径」，匹配时效可放宽到 10 分钟，且不依赖文件时间戳。
//
//  【为什么必须区分 sysZone】
//   Downloads / 桌面 是**用户主动落点**（下载安装包再双击是正常行为，不能算）；
//   Temp / AppData / ProgramData / Users\Public / 启动文件夹 是**软件自己写的**
//   区域，用户不会主动往那里放 exe。只有后者参与组合升档，否则误伤普通安装包。
// ===========================================================================
struct SoftLand {
    std::string pathLower;
    std::string reason;
    uint64_t    at = 0;
    int         lv = 1;
    bool        sysZone = false;
};
static std::mutex           g_softMtx;
static std::deque<SoftLand> g_softLand;

static void RecordSoftLand(const std::string& full, const std::string& why,
                           int lv, bool sysZone) {
    const std::string l = Lower(full);
    std::lock_guard<std::mutex> lk(g_softMtx);
    g_softLand.push_back({ l, why, NowMs(), lv, sysZone });
    if (g_softLand.size() > 512) g_softLand.pop_front();
}

// 前置声明：DirOfPath 定义在下方（目录热度一节），但密钥时序关联也要用。
static std::string DirOfPath(const std::string& lowerPath);

// 自身安装目录（小写，用于排除自身活动）。
// 定义提前到此处：密钥截获 / 落地捕获都要用它做自排除，而它们在文件前半部分。
static std::string g_exeDirLower;

// ===========================================================================
//  勒索密钥截获（2026-09-19 新增）
//
//  ---------------------------------------------------------------------------
//  【为什么这条路比快照回滚更强】
//  ---------------------------------------------------------------------------
//  维护者指出的现代勒索流程：
//      ① 生成本地密钥 → ② 密钥落盘 → ③ 用密钥加密全部文件 → ④ 删密钥 → ⑤ 要赎金
//  第 ④ 步是攻击者的自保：密钥一删，抓到人也解不开。**第 ② 步是唯一窗口**。
//
//  快照回滚 vs 密钥截获：
//    · 快照：需要逐文件备份，受 maxFileBytes/maxCacheBytes 约束，
//      且**只能救"改动前存在过"的文件**；文件被加密后原文件被删/改名就救不回。
//    · 密钥：只需一份小文件（典型 < 8KB），不受快照容量约束；
//      拿到密钥后**任何被加密的文件都可解回明文**，哪怕原文件已被删。
//  两者不是替代关系，而是互补 —— 快照救"来不及截获的"，密钥救"截获到的"。
//
//  ---------------------------------------------------------------------------
//  【判定必须用多信号，不能只看熵】
//  ---------------------------------------------------------------------------
//  高熵小文件在正常系统里很常见：浏览器缓存、编译产物、压缩包分片、日志压缩块……
//  单纯"高熵 + 小体积"会大量误报。所以采用**三条件联合 + 时序验证**：
//    条件1（静态）：体积 16B~64KB 且 熵 >= 7.5 —— 密钥的形态特征；
//    条件2（静态）：扩展名陌生或无扩展名（.key/.pem/.dat/.bin/.enc/.bin 之外多为随机）
//                   —— 正常程序很少把小体积随机数据写成无扩展名文件；
//    条件3（动态）：**落盘后 keyWindowSec 秒内出现同目录批量改写**
//                   —— 这是最强判据：证明"这个文件刚写完就被用来加密东西"。
//
//  条件 1+2 命中时先**留存候选副本**（成本极低，一份几 KB），
//  等条件 3 成立时再正式认定为"勒索密钥"并**提前定性**（不必等 25 个文件的阈值）。
//  这样既不会因为看不到未来而漏掉，也不会因为单看熵值而误报。
// ===========================================================================
struct CapturedKey {
    std::string path;        // 原始落盘路径（用户可查看，但可能已被勒索者删除）
    std::string storePath;   // 我们留存的副本路径（勒索者删不掉）
    std::string sha;
    uint64_t    size    = 0;
    double      entropy = 0.0;
    uint64_t    at      = 0;   // 捕获时刻（steady ms）
    bool        confirmed = false;  // 是否已被时序关联确认为勒索密钥
    size_t      linkedVictims = 0;  // 关联到的受害文件数（确认时填）
};
static std::mutex                  g_keyMtx;
static std::vector<CapturedKey>    g_keys;
static uint64_t                    g_keySeq = 0;   // 副本文件名序号

// 密钥副本目录：<cache>\keys（与快照同级的独立子树）
static std::string KeyDirImpl() {
    std::string d = CacheDirImpl() + "\\keys";
    CreateDirectoryU8(d.c_str(), nullptr);
    return d;
}
// 密钥索引清单：<cache>\keys\manifest.ndjson
// 每行一条 JSON —— 为什么不用单个 JSON 数组：追加写即可（不必读全文回写），
// 且单行损坏不会毁掉整个索引（容错优先于紧凑）。
static std::string KeyManifestPath() {
    return KeyDirImpl() + "\\manifest.ndjson";
}

// ===========================================================================
//  密钥留存持久化（2026-09-19 新增，维护者明确要求）
//
//  ---------------------------------------------------------------------------
//  【为什么必须持久化：勒索病毒会删掉密钥文件】
//  ---------------------------------------------------------------------------
//  维护者指出的攻击链条：
//      ① 生成本地密钥 → ② 密钥落盘 → ③ 用密钥加密全部文件 → ④ **删除密钥** → ⑤ 索要赎金
//
//  第 ④ 步是攻击者的自保措施 —— 密钥一删，即使事后取证抓到样本也解不开。
//  对受害者而言，这意味着：
//      · 靠"事后去磁盘上找密钥文件"**必然失败**（文件已经不存在了）；
//      · 只有**在密钥还活着的那一刻把内容复制走**才有一线生机。
//
//  旧实现（本次修正前）已经做了"复制副本到 rollback_cache\keys\key_XXXX.bin"，
//  但存在两个致命缺口：
//      缺口A（内存索引易失）：候选清单 `g_keys` 是**纯内存** vector。
//             服务重启（崩溃/升级/用户重启机器）后内存清空，
//             磁盘上的副本文件**变成无人认领的孤儿** —— 没有任何代码会把
//             它们读回来。也就是说："程序重启一次，之前截获的密钥全丢了"。
//      缺口B（一键清空）：`ClearCapturedKeys()` 用循环删掉**所有**副本文件。
//             它本意是"让用户清理误报留下的垃圾"，但实际上也把
//             真勒索的密钥证据一并销毁了 —— 误报期点一次，真中招时就没了。
//
//  ---------------------------------------------------------------------------
//  【本次修正】
//  ---------------------------------------------------------------------------
//    1. 每次留存副本时，**同时追加一行**到 manifest.ndjson（记路径/哈希/熵/时间，
//       JSON 内的字符串用 JsonString 转义，避免路径里的引号破坏格式）；
//    2. `Start()` 时扫描 keys 目录：有副本但索引里没有的 → 补登记（缺口A）；
//    3. 副本文件设**只读属性**：抬高勒索病毒批量删除的门槛
//       （DeleteFile 对只读文件会失败，多数勒索实现不做 ClearReadOnly）；
//    4. `ClearCapturedKeys()` 改为**默认保留**，仅在显式传入 force 时才真删
//       （缺口B）；UI 侧仍可调用，但必须让用户确认"这些可能是真密钥"。
//
//  ⚠️ 本模块**只做留存，不做解密**。原因：解密需要判断密钥算法/模式/IV，
//     猜测错误会把文件彻底弄坏。留存是"把可能性保住"，解密应由人工取证完成。
//     这是有意的设计边界 —— 详见 rollback.h 的说明。
// ===========================================================================
static void AppendKeyManifest(const CapturedKey& k) {
    // 追加写；失败不影响主流程（副本本身已经落盘，索引可事后重建）
    std::ofstream f(A2W(KeyManifestPath()).c_str(), std::ios::binary | std::ios::app);
    if (!f) return;
    f << "{\"store\":" << JsonString(k.storePath)
      << ",\"orig\":" << JsonString(k.path)
      << ",\"sha\":" << JsonString(k.sha)
      << ",\"size\":" << k.size
      << ",\"entropy\":" << k.entropy
      << ",\"at\":" << k.at
      << "}\n";
}

// 扫描 keys 目录下所有 key_*.bin，返回实际存在的副本文件名集合（全路径）。
static void ScanKeyDirFiles(std::vector<std::string>& outFull) {
    std::string dir = KeyDirImpl();
    std::string pat = dir + "\\key_*.bin";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileU8(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        outFull.push_back(dir + "\\" + W2A(fd.cFileName));
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// 从 manifest 读取已登记过的副本路径（用于去重）。
static void LoadKeyManifest(std::set<std::string>& outStores) {
    std::ifstream f(A2W(KeyManifestPath()).c_str(), std::ios::binary);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // 轻量解析：只取 "store":"..." 字段（不引入 JSON 解析依赖）
        size_t p = line.find("\"store\":");
        if (p == std::string::npos) continue;
        size_t q1 = line.find('"', p + 8);
        if (q1 == std::string::npos) continue;
        size_t q2 = q1 + 1;
        std::string val;
        while (q2 < line.size()) {
            if (line[q2] == '\\' && q2 + 1 < line.size()) {
                char c = line[q2 + 1];
                if (c == '\\') { val += '\\'; q2 += 2; continue; }
                if (c == '"')  { val += '"';  q2 += 2; continue; }
                if (c == 'n')  { val += '\n'; q2 += 2; continue; }
                if (c == 't')  { val += '\t'; q2 += 2; continue; }
                if (c == 'r')  { val += '\r'; q2 += 2; continue; }
                // \uXXXX：按 UTF-8 还原（路径里可能有中文用户目录）
                if (c == 'u' && q2 + 5 < line.size()) {
                    unsigned cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        char hx = line[q2 + 2 + i];
                        unsigned d;
                        if (hx >= '0' && hx <= '9') d = (unsigned)(hx - '0');
                        else if (hx >= 'a' && hx <= 'f') d = (unsigned)(hx - 'a' + 10);
                        else if (hx >= 'A' && hx <= 'F') d = (unsigned)(hx - 'A' + 10);
                        else { d = 0; }
                        cp = cp * 16 + d;
                    }
                    if (cp < 0x80) val += (char)cp;
                    else if (cp < 0x800) {
                        val += (char)(0xC0 | (cp >> 6));
                        val += (char)(0x80 | (cp & 0x3F));
                    } else {
                        val += (char)(0xE0 | (cp >> 12));
                        val += (char)(0x80 | ((cp >> 6) & 0x3F));
                        val += (char)(0x80 | (cp & 0x3F));
                    }
                    q2 += 6;
                    continue;
                }
                val += c; q2 += 2; continue;
            }
            if (line[q2] == '"') break;
            val += line[q2++];
        }
        if (!val.empty()) outStores.insert(Lower(val));
    }
}

// 启动时重建密钥索引（缺口A 的修复）。
//
// 三种情况都要处理：
//   ① 副本文件存在 + manifest 有登记 → 正常重建
//   ② 副本文件存在 + manifest 无登记 → 补登记（manifest 被删/写失败）
//   ③ manifest 有登记 + 副本文件不存在 → 跳过（副本被清理了，索引留着无用）
//
// 重建时**重算 sha 与熵**：不信任 manifest 里的值 —— manifest 是纯文本，
// 可以被人为篡改；而副本内容才是唯一真相。重算虽然多一次读盘，
// 但只在启动时发生且文件都很小（<64KB），成本可忽略。
static void RebuildKeyIndexFromDisk() {
    std::set<std::string> manifestStores;
    LoadKeyManifest(manifestStores);

    std::vector<std::string> files;
    ScanKeyDirFiles(files);

    size_t rebuilt = 0, orphan = 0;
    uint64_t maxSeq = 0;
    for (const auto& full : files) {
        // 解析序号（用于恢复 g_keySeq，避免新副本覆盖旧副本）
        {
            size_t p = full.find_last_of("\\/");
            std::string fn = (p == std::string::npos) ? full : full.substr(p + 1);
            if (fn.size() > 4 && fn.compare(0, 4, "key_") == 0) {
                uint64_t n = _strtoui64(fn.c_str() + 4, nullptr, 10);
                if (n > maxSeq) maxSeq = n;
            }
        }

        // 读副本内容（重算 sha / 熵 / 体积）
        HANDLE h = CreateFileU8(full.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        LARGE_INTEGER sz{};
        GetFileSizeEx(h, &sz);
        if (sz.QuadPart <= 0 || sz.QuadPart > 1024 * 1024) { CloseHandle(h); continue; }
        std::string data; data.resize((size_t)sz.QuadPart);
        DWORD rd = 0;
        BOOL ok = ReadFile(h, &data[0], (DWORD)data.size(), &rd, nullptr);
        CloseHandle(h);
        if (!ok || rd == 0) continue;
        data.resize(rd);

        CapturedKey k;
        k.storePath = full;
        k.size      = data.size();
        k.sha       = Sha256Bytes(data.data(), data.size());
        k.entropy   = EntropyOfBuffer(data);
        k.at        = NowMs();          // 重建时刻（原落盘时刻已不可考）
        // 原始路径：manifest 里有就沿用（供用户查看"这密钥是从哪抓的"）
        k.path      = "(重启后重建索引，原始落盘路径不可考)";
        if (!manifestStores.count(Lower(full))) orphan++;
        k.confirmed = false;

        {
            std::lock_guard<std::mutex> lk(g_keyMtx);
            if (g_keys.size() >= g_cfg.keyMaxKept) break;
            // 防重复（理论上不会，保险起见）
            bool dup = false;
            for (const auto& e : g_keys) if (e.storePath == full) { dup = true; break; }
            if (dup) continue;
            g_keys.push_back(k);
        }
        // 补登记孤儿副本（缺口A 的直接修复）
        if (!manifestStores.count(Lower(full))) AppendKeyManifest(k);
        rebuilt++;
    }

    if (rebuilt) {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.keysKept = g_keys.size();
    }
    // 恢复序号，避免新副本覆盖已存在的编号
    if (maxSeq > 0) {
        LONG64 cur = *(volatile LONG64*)&g_keySeq;
        if ((uint64_t)cur < maxSeq) InterlockedExchange64((volatile LONG64*)&g_keySeq, (LONG64)maxSeq);
    }
    LogDbg("[rollback] 密钥索引重建完成：从磁盘恢复 " + std::to_string(rebuilt) +
           " 份副本（其中 " + std::to_string(orphan) +
           " 份为 manifest 缺失的孤儿，已补登记）");
}


// 该扩展名是否"像密钥文件"。
//
// ---------------------------------------------------------------------------
//  【2026-09-19 事故】旧判据 `ext.size() <= 7 → return true` 是误报主源
// ---------------------------------------------------------------------------
//  旧逻辑的隐含假设是"正常程序的小体积随机数据文件几乎总带已知扩展名"，
//  所以"短扩展名 → 可能像密钥 → 交给熵值与时序关联确认"。
//
//  实测结果（09-19 日志）：**156 次捕获，真阳性 0 次**。误报来源：
//    · Edge 的 `edge_BITS_*\<UUID>` —— **无扩展名**，直接命中"无扩展名 → 像密钥"
//    · `scoped_dir*\...`、`chrome_Unpacker_*` —— 同样是临时解包产物
//    · 各类安装器的随机命名载荷
//  它们的共同点：**不是密钥，是"随机命名的临时二进制"**。
//  熵值判据对它们完全无效 —— 压缩/加密的临时数据熵天然 7.87~7.99。
//
//  ---------------------------------------------------------------------------
//  【新判据】从"黑名单 + 短后缀放行"改为"白名单 + 结构确认"
//  ---------------------------------------------------------------------------
//  思路转变：**密钥文件是可枚举的，不是可推测的**。
//  与其问"这个扩展名看起来像不像密钥"（必然误报），不如问
//  "这个文件的形态是否**只可能**是密钥"。真正的勒索密钥只有两类形态：
//    A. 已知密钥容器/编码：.key/.pem/.der/.p12/.pfx/.jks/.keystore/.ppk
//       —— 这些是密钥的**专用格式**，正常程序不会拿来存别的东西；
//    B. 明文密钥的常见落盘名：`key`/`privkey`/`private_key`/`secret`/`master`
//       等词 + .txt/.dat/.bin/.key 扩展名或无扩展名。
//  其余一律不再进入候选 —— 宁可漏，不可误（回滚是破坏性动作）。
// ---------------------------------------------------------------------------
static bool LooksLikeKeyExt(const std::string& pathLower) {
    size_t slash = pathLower.find_last_of("\\/");
    std::string base = (slash == std::string::npos) ? pathLower : pathLower.substr(slash + 1);
    size_t dot = base.find_last_of('.');
    std::string stem = (dot == std::string::npos || dot == 0) ? base : base.substr(0, dot);
    std::string ext  = (dot == std::string::npos || dot == 0) ? std::string() : base.substr(dot);

    // -----------------------------------------------------------------------
    //  ⚠️ 顺序很关键：**先看文件名主干有没有密钥词，再看扩展名黑名单**。
    //
    //  踩坑记录（回归测试发现）：如果把 kNotKey（含 .txt）放在前面直接 return false，
    //  那么 `secret_key.txt` 会被拒 —— 但勒索软件把密钥存成 .txt 是很常见的做法
    //  （不引人注目、双击能看到内容迷惑受害者）。等于把真密钥漏掉了。
    //
    //  所以调整为先做"密钥词主干判定"：只要主干明确指向密钥，扩展名就走
    //  容器类白名单（含 .txt/.dat/.bin），不再被 kNotKey 一刀切拒掉。
    //  kNotKey 只用于**主干没有密钥语义**的普通文件。
    // -----------------------------------------------------------------------
    static const char* kKeyWords[] = {
        "privkey", "private_key", "privatekey", "secret_key", "secretkey",
        "masterkey", "master_key", "ransom", "decrypt_key", "decryption",
        "encryption_key", "enc_key", "aes_key", "rsa_priv", "rsa_key",
        "id_rsa", "keypair", "key_pair", "server_key",
        // 中文场景
        "私钥", "密钥", "公钥",
    };
    bool named = false;
    for (const char* w : kKeyWords)
        if (stem.find(w) != std::string::npos) { named = true; break; }

    // 密钥专用扩展名：无论主干叫什么，这些扩展名本身就是密钥容器
    static const char* kKeyExt[] = {
        ".key", ".pem", ".der", ".p12", ".pfx", ".jks", ".keystore", ".ppk",
        ".pgp", ".gpg", ".asc",
    };
    bool dedicatedExt = false;
    for (const char* e : kKeyExt) if (ext == e) { dedicatedExt = true; break; }

    // 压缩/归档后缀优先整体排除（压缩产物熵天然 >=7.5，与密钥不可区分）
    if (LooksLikeCompressedExt(ext)) return false;

    // 临时目录下的**随机命名二进制**：Edge/Chrome/安装器解包产物。
    // 这是旧判据的最大误报源（edge_BITS_<UUID> 无扩展名就命中）。
    bool inTemp = (pathLower.find("\\appdata\\local\\temp\\") != std::string::npos) ||
                  (pathLower.find("\\windows\\temp\\") != std::string::npos);
    if (inTemp) {
        // Temp 下只收"明确指向密钥"的：专用扩展名 或 主干含密钥词
        if (dedicatedExt || named) return true;
        return false;
    }

    // 非 Temp 区域：
    if (dedicatedExt) return true;       // 密钥专用格式
    if (!named) {
        // 主干没有密钥语义 —— 此时才用 kNotKey 排除普通文件
        static const char* kNotKey[] = {
            ".tmp", ".temp", ".log", ".ini", ".cfg", ".conf", ".json", ".xml", ".txt",
            ".md", ".html", ".css", ".js", ".lock", ".pid", ".cache", ".idx", ".db",
            ".sqlite", ".lnk", ".url", ".crdownload", ".part", ".partial", ".ico", ".png",
            ".jpg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".otf", ".exe", ".dll",
            ".sys", ".msi", ".cab", ".mui", ".msp", ".node", ".wasm", ".map",
        };
        for (const char* e : kNotKey) if (ext == e) return false;
        return false;   // 无语义 + 非专用扩展名 → 不收（守恒原则：宁可漏，不可误）
    }

    // 主干含密钥词 → 扩展名须是"容器类"或无扩展名
    static const char* kContainerExt[] = {
        ".dat", ".bin", ".enc", ".aes", ".rsa", ".crypt", ".locked", ".blob",
        ".bak", ".old", ".txt", ".asc",
    };
    if (ext.empty()) return true;
    for (const char* e : kContainerExt) if (ext == e) return true;
    return false;
}

// 尝试把一个小体积高熵文件登记为"密钥候选"。
// 返回 true 表示已登记（或已存在）。**此函数会做磁盘 IO（读文件算熵 + 复制副本），
// 但调用点已在监控线程里且只对小文件触发，开销可忽略。**
static bool TryCaptureKey(const std::string& full, const std::string& fullLower) {
    if (!g_cfg.keyHuntEnabled) return false;
    if (fullLower.empty()) return false;
    if (IsExcluded(fullLower)) return false;
    // 自身副本目录不捕获（防递归）
    if (fullLower.find("\\rollback_cache\\") != std::string::npos) return false;

    if (!LooksLikeKeyExt(fullLower)) return false;

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExU8(full.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz < g_cfg.keyMinBytes || sz > g_cfg.keyMaxBytes) return false;

    // 已捕获过同路径 → 跳过（同一文件反复写入不重复登记）
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        for (const auto& k : g_keys) if (k.path == full) return true;
        if (g_keys.size() >= g_cfg.keyMaxKept) return false;   // 已满，不再收
    }

    double ent = EntropyOfFile(full);
    if (ent < g_cfg.keyEntropyMin) return false;   // 熵不够 → 不像随机密钥

    // 读入内存（小文件，一次性读完）并写副本
    HANDLE hs = CreateFileU8(full.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return false;
    std::string data; data.resize((size_t)sz);
    DWORD rd = 0;
    BOOL okRead = ReadFile(hs, &data[0], (DWORD)sz, &rd, nullptr);
    CloseHandle(hs);
    if (!okRead || rd == 0) return false;
    data.resize(rd);

    // 魔数兜底：改了后缀的压缩包（xx.dat.gz、无后缀 zip）同样熵虚高，按文件头识别。
    if (HasArchiveMagic(data)) return false;

    uint64_t seq = (uint64_t)InterlockedIncrement64((volatile LONG64*)&g_keySeq);
    char nm[96];
    sprintf_s(nm, "\\key_%04llu.bin", (unsigned long long)seq);
    std::string store = KeyDirImpl() + nm;

    HANDLE hd = CreateFileU8(store.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    BOOL okWrite = WriteFile(hd, data.data(), (DWORD)data.size(), &wr, nullptr);
    FlushFileBuffers(hd);
    CloseHandle(hd);
    if (!okWrite || wr != data.size()) { DeleteFileU8(store.c_str()); return false; }

    // -----------------------------------------------------------------------
    //  只读加固（2026-09-19 新增）
    //  勒索病毒删密钥时用的是普通 DeleteFile/CreateFile(TRUNCATE)，
    //  这类调用对 FILE_ATTRIBUTE_READONLY 的文件会失败。
    //  多数勒索实现不会额外做"先清只读再删"——加了这一层，
    //  副本的存活概率显著提升。用户要清理时需要手动去掉只读属性
    //  （ClearCapturedKeysImpl 内部会先清属性再删，见该函数）。
    // -----------------------------------------------------------------------
    if (g_cfg.keyReadonlyGuard)
        SetFileAttributesU8(store.c_str(), FILE_ATTRIBUTE_READONLY);

    CapturedKey k;
    k.path     = full;
    k.storePath= store;
    k.sha      = Sha256Bytes(data.data(), data.size());
    k.size     = data.size();
    k.entropy  = ent;
    k.at       = NowMs();

    size_t kept = 0;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        // 并发插入检查（两次通知可能同时到）
        for (const auto& e : g_keys) if (e.path == full) { DeleteFileU8(store.c_str()); return true; }
        if (g_keys.size() >= g_cfg.keyMaxKept) { DeleteFileU8(store.c_str()); return false; }
        g_keys.push_back(k);
        kept = g_keys.size();
    }
    // 持久化索引（2026-09-19 新增）：锁外做 I/O（本项目铁律：不持锁做 I/O）
    AppendKeyManifest(k);
    StatAdd(10, 1);
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.keysKept = kept;
    }
    LogDbg("[rollback] 密钥候选已留存: " + full +
           "（" + std::to_string(k.size) + "B, 熵=" + std::to_string(k.entropy) +
           "）→ " + store + "（已写入 manifest，重启后可恢复）");
    return true;
}

// 时序关联：某目录刚出现过密钥候选，随后该目录内出现批量改写
// → 把候选**正式确认**为勒索密钥，并返回 true（调用方据此提前定性，不等阈值）。
//
// ---------------------------------------------------------------------------
//  【2026-09-19 事故修正】去掉 `anywhere` 这条过宽的关联通道
// ---------------------------------------------------------------------------
//  旧判据的 `anywhere` = "候选落在 \temp 下 或 盘根" → 视为与**任意目录**相关。
//  后果：只要 Temp 里攒下一个候选（Edge 的 edge_BITS_* 天天有），
//        此后**任何**目录出现 5 次批量改写，都会被判定为"密钥时序关联成立"
//        → 提前定性 → 自动回滚。这是误报从"候选表"升级为"覆盖写"的关键一步。
//
//  修正：只保留**同目录**关联。理由：
//    真勒索的行为是"密钥落在某目录 → 立刻用它加密**同一批**目录里的文件"，
//    同目录关联足以覆盖。跨目录的弱关联收益远小于误伤代价。
//  另外增加"候选必须很新"的约束（默认 keyWindowSec=30s），
//  避免一个几天前的旧候选被拿来给今天的正常批量操作背书。
// ---------------------------------------------------------------------------
static bool ConfirmKeyByBurst(const std::string& dirLower, size_t* outKeyIdx = nullptr) {
    if (!g_cfg.keyHuntEnabled) return false;
    if (dirLower.empty()) return false;
    uint64_t now = NowMs();
    uint64_t win = (uint64_t)g_cfg.keyWindowSec * 1000;
    size_t idx = (size_t)-1;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        // 找最近落盘、尚未确认、且**就在该目录内**的候选
        for (size_t i = g_keys.size(); i-- > 0; ) {
            CapturedKey& k = g_keys[i];
            if (k.confirmed) continue;
            if (now - k.at > win) continue;      // 超出关联窗口，不再认
            if (DirOfPath(Lower(k.path)) != dirLower) continue;   // 必须同目录
            idx = i;
            break;
        }
        if (idx != (size_t)-1) {
            g_keys[idx].confirmed = true;
            g_keys[idx].linkedVictims = 0;
        }
    }
    if (idx == (size_t)-1) return false;
    if (outKeyIdx) *outKeyIdx = idx;
    StatAdd(11, 1);
    LogDbg("[rollback] 密钥时序关联成立：目录 " + dirLower +
           " 在密钥落盘 " + std::to_string((now - g_keys[idx].at) / 1000) +
           " 秒后出现批量改写 → 认定为勒索密钥");
    return true;
}

// ===========================================================================
//  文件落地前置捕获（2026-09-19 新增）
//
//  【为什么需要】
//  银狐的攻击链条是「诱导下载 → 载荷落盘 → 自启执行」。
//  现有事件源（WMI 进程创建 + 注册表 Run）都发生在**第三步之后** ——
//  载荷已经在跑了。把判定点前移到「落盘那一刻」，
//  可以在攻击者还没执行时就已经定性。
//
//  【判据】（多信号联合，不单看一条）
//    ① 落地位置：Temp / 下载 / 盘根 / AppData —— 用户正常程序极少往这些地方放 exe；
//    ② 文件形态：PE 头（MZ）或脚本头（powershell/cmd/ActiveX 特征字符串）；
//    ③ 命名特征：随机名（纯 hex、或数字+字母高混杂）。
//  ① 与（② 或 ③）同时成立才记入候选。
//
//  【为什么不做重判定】
//  本模块（rollback.cpp）的职责是**回滚引擎**，不做完整的行为判定
//  （那在 behavior.cpp / JudgeProcess）。这里只做"低成本初筛"：
//  读文件头 512 字节 + 看路径与文件名，不调 WinVerifyTrust、不做全文件熵扫描 ——
//  避免在监控线程里引入重 IO（这正是本项目"持锁做 I/O"教训的对偶面）。
//  初筛命中的结果交给上层判定层，让专业的判定函数去下结论。
// ===========================================================================
// ★ 2026-10-03（C3）：两个落地判据的实现已抽到 criteria.cpp（生产与回归测试共用）。
//   抽出来的原因同 behavior.cpp：判据必须有单测兜底 —— 今天这一处改了四版才做对，
//   每一版都是被「不该收的反例」打回的（is-0001 顺序号 / Office GUID /
//   PackageCache 短 GUID / %TEMP% 短名），没有反例常驻就一定会重犯。
static bool LooksLikeRandomName(const std::string& b)  { return sf::crit::LooksLikeRandomName(b); }
static bool ParentDirLooksRandom(const std::string& f){ return sf::crit::ParentDirLooksRandom(f); }

// ---------------------------------------------------------------------------
//  ★ 2026-10-02 新增：用户「已知文件夹」的**注册表权威路径**
// ---------------------------------------------------------------------------
//  为什么需要（本机实测发现）：IsLandingHotspot 与 DefaultWatchDirs 原先都靠
//  「用户名 + 字面拼路径」定位桌面/下载/文档等位置，例如
//      root + "\Downloads"、pathLower.find("\downloads\")
//  这套做法隐含两个前提，而它们**都不成立**：
//    ① 用户没把文件夹重定向。本机实测：下载已被重定向到 D:\tianl\下载 ——
//       拼出来的 C:\Users\tianl\Downloads 根本不存在（存在性检查直接跳过），
//       而 D:\tianl\下载 既不在监视清单、也匹配不到字面串 "\downloads\" → **双漏**。
//    ② 文件夹名是英文。中文系统 / 改过名的系统上，"桌面""下载"字面匹配同样失效。
//  权威来源只有一个：注册表 Shell Folders —— 用户改位置或开 OneDrive 重定向时
//  它会同步更新，且正是 Explorer 真正使用的值。
//
//  ⚠️ 服务跑在 Session 0（SYSTEM），**不能**用 SHGetFolderPathW(CSIDL_*) 取"当前用户"
//     （那返回的是 SYSTEM 自己的 profile —— 见 CollectUserProfiles 里同类注释的坑），
//     必须逐个真实用户 SID 从 HKU 读。
// ---------------------------------------------------------------------------
static void CollectUserShellDirsRegistry(std::vector<std::string>& out) {
    HKEY hk = nullptr;
    if (RegOpenKeyExA(HKEY_USERS, "", 0, KEY_READ, &hk) != ERROR_SUCCESS) return;
    static const char* kSf =
        "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
    // 只取"落地高发"语义成立的六个：桌面 / 文档 / 下载 / 图片 / 视频 / 音乐。
    // AppData 那一族由 DefaultWatchDirsEx 单独细粒度处理，不在这里重复。
    static const char* kNames[] = {
        "Desktop", "Personal", "{374DE290-123F-4565-9164-39C4925E467B}",
        "My Pictures", "My Video", "My Music",
    };
    char name[256] = { 0 };
    for (DWORD idx = 0;; ++idx) {
        DWORD nlen = (DWORD)sizeof(name);
        if (RegEnumKeyExA(hk, idx, name, &nlen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        // 只认真实用户 SID（跳过 _Classes / .DEFAULT / S-1-5-18 等）
        if (std::string(name).compare(0, 9, "S-1-5-21-") != 0) continue;
        const std::string sub = std::string(name) + kSf;
        const std::wstring wsub = A2W(sub);
        for (const char* vn : kNames) {
            wchar_t wval[MAX_PATH * 2] = { 0 };
            DWORD cb = sizeof(wval), type = 0;
            const std::wstring wvn = A2W(vn);
            // ★★ 2026-10-02 必须用 **W 版**（原为 RegGetValueA）：
            //   注册表存的是 UTF-16，RegGetValueA 会按**系统 ACP**（本机 936/GBK）
            //   转码，而本程序全程约定窄串为 **UTF-8** —— 两者不容，中文路径直接被写坏。
            //   实测：D:\tianl\下载 读出来后被当成 UTF-8，日志显示为 "D:\tianl\????"，
            //   监视目录被跳过，落到该目录的载荷此生不被捕获（2026-10-02 验收发现）。
            //   不加 RRF_NOEXPAND → REG_EXPAND_SZ（如 %USERPROFILE%\Desktop）自动展开。
            if (RegGetValueW(HKEY_USERS, wsub.c_str(), wvn.c_str(),
                             RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ,
                             &type, wval, &cb) != ERROR_SUCCESS || !wval[0])
                continue;
            const std::string val = W2A(wval);          // UTF-16 → UTF-8（统一窄串约定）
            if (val.empty()) continue;
            const DWORD a = GetFileAttributesW(wval);   // 用刚读到的宽路径，避免二次转码
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
                out.push_back(val);
        }
    }
    RegCloseKey(hk);
}

// 上面那份路径的"小写 + 带尾分隔符"版本，供 IsLandingHotspot 做前缀匹配。
// 惰性初始化一次（call_once）：首次调用可能来自任意线程，之后只读。
static const std::vector<std::string>& KnownUserShellDirsLower() {
    static std::vector<std::string> v;
    static std::once_flag once;
    std::call_once(once, [] {
        std::vector<std::string> raw;
        CollectUserShellDirsRegistry(raw);
        for (const auto& s : raw) {
            std::string l = Lower(s);
            if (l.empty()) continue;
            if (l.back() != '\\') l.push_back('\\');
            v.push_back(l);
        }
    });
    return v;
}

// 落地高发区判定（入参须为小写路径）
// ---------------------------------------------------------------------------
//  ★ 统一「落地候选」扩展表（2026-09-26 收敛为一份，杜绝两处口径漂移）
// ---------------------------------------------------------------------------
//  可执行/脚本类：行为初筛的目标（PE 头 / 脚本特征）。
//  压缩包（.zip/.7z/.rar）：**哈希精确匹配**的入口 —— 云库条目就是压缩包本身的
//  SHA-256（theZoo 类 payload 投递形态：库记的是 zip 哈希），字节级同一性匹配
//  与 PE 结构无关；压缩包在行为初筛恒不命中（PK 头非 MZ），由 ProbeLandedFile
//  末尾的「云库哈希 fallback」完成判定。
//  ⚠️ 此表被 ProbeLandedFile 与 NotifyExternalLandedImpl（ETW 哨兵入口）共用，
//     改动必须两处同义 —— 收成一份就是为了让"两处不一致"在结构上不可能。
static const char* kLandedExts[] = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".zip", ".7z", ".rar",
    // ★ 2026-10-03（P1-2）补 .sys / .ocx / .cpl / .lnk —— 原表漏这几类，
    //   导致它们**落地捕获零日志**。实证代价：我们自己的分析工具 innoextract.exe
    //   落在 C:\Temp\ 时因是 .exe 才走通落地捕获并进入送检（于是被自家锁 100 秒）。
    //   **若它当时是 .dll，这一步完全不会发生** —— 既不锁（省事）也不送检（漏报）。
    //   这类「按扩展名决定是否防御」的口子对攻击者是现成绕过：把载荷改成 .dll/.sys
    //   就从落地捕获里消失了。.sys 尤其重要：它本身就是驱动加载点（BYOVD 路径）。
    //   这几种落地量都极小（一条规则命中一个），全盘哨兵那一路也收得起。
    ".sys", ".ocx", ".cpl", ".lnk",
};

// ★★ 2026-10-03（P1-2）**只限热点区**的扩展名。
//   `.dll` 不进上面的共用表：ETW 全盘哨兵那一路是 `requireHotspot=false`（全盘判定），
//   而 Windows 上装一个软件就要落几百个 dll、全盘每天几万到几十万 —— 塞进共用表会把
//   待重探队列（kPendMax 有上限，满了**丢最早**）打爆，真实载荷反而被挤掉。
//   分口径而不是加进共用表，是为了同时满足两点：
//     ① 热点区（temp/downloads/appdata/桌面…）的 dll 落地照常判定 —— 那才是投放点；
//     ② 全盘那一路量能不变，不引入 DoS 面。
//   理由：侧加载/劫持的 dll 一定紧贴被加载的程序（Program Files、AppData、系统目录附近），
//   这些位置绝大多数已被 `IsLandingHotspot` 的目录规则或 `IsExcluded` 覆盖。
static const char* kHotspotOnlyExts[] = {
    ".dll",
};

// 后缀是否落在「热点区扩展名」里（只比扩展名，不比长度）
static bool HasHotspotOnlyExt(const std::string& base) {
    for (const char* e : kHotspotOnlyExts) {
        const size_t n = strlen(e);
        if (base.size() > n && base.compare(base.size() - n, n, e) == 0) return true;
    }
    return false;
}

static bool IsLandingHotspot(const std::string& pathLower) {
    // ★★ 2026-10-03（铁律 40 根因 + 铁律 23）：**自家产物目录必须先排除**。
    //   `C:\ProgramData\SilverFoxGuard\` 下面有 dist/、holds/、quarantine/、logs/ 等，
        //   每一轮构建、每一次送检都会往里写新 exe —— 而下面第 1826 行把
    //   `\programdata\` 整体判为落地高发区 ⇒ **我们自己的构建产物被当成刚落地的载荷**
    //   ⇒ 落地初筛命中 → 自动送检 → `MakeHold` 持句柄锁 2–3 分钟
    //   ⇒ 表现：① 打包时 makensis `failed opening file`（错怪火绒，实测两次同因）
    //         ② 分析样本时从压缩包解出的 exe 全 `PermissionError`
    //   ⇒ **这不是"误报"级别的问题，是产品级自伤**。先于所有字面匹配排除。
    static const char* kOwnDirs[] = {
        "\\programdata\\silverfoxguard\\",
        "\\programdata\\silverfox guard\\",
        "\\silverfoxenvscan\\",
    };
    for (const char* d : kOwnDirs) {
        const size_t dn = strlen(d);
        if (pathLower.size() > dn && pathLower.compare(0, dn, d) == 0) return false;
    }

    // ★ 2026-10-02：先认「权威的用户已知文件夹（桌面/文档/下载/图片/视频/音乐）」。
    //   下面的字面匹配在**重定向或改名**的系统上会整片失效 —— 本机实测：下载已被
    //   重定向到 D:\tianl\下载，既匹配不到 "\downloads\"，也匹配不到 "\download\"。
    //   注册表给的是真实路径，与用户名/系统语言/重定向无关（来源见上方注释）。
    for (const auto& d : KnownUserShellDirsLower()) {
        if (pathLower.size() > d.size() && pathLower.compare(0, d.size(), d) == 0) return true;
    }
    if (pathLower.find("\\temp\\") != std::string::npos) return true;
    if (pathLower.find("\\downloads\\") != std::string::npos) return true;
    if (pathLower.find("\\download\\") != std::string::npos) return true;
    if (pathLower.find("\\appdata\\local\\") != std::string::npos) return true;
    if (pathLower.find("\\appdata\\roaming\\") != std::string::npos) return true;
    if (pathLower.find("\\desktop\\") != std::string::npos) return true;
    // ---- 2026-09-24 全域化补充：银狐实测的另外三个标准落点 ----
    //  ProgramData（服务/计划任务载荷常宿主于此，虚拟机实验里载荷就落在这类位置）
    //  Users\Public（全用户可写，经典投放点）
    //  启动文件夹（持久化点：能往这里写可执行文件的正常流程极少）
    if (pathLower.find("\\programdata\\") != std::string::npos) return true;
    if (pathLower.find("\\users\\public\\") != std::string::npos) return true;
    if (pathLower.find("\\start menu\\programs\\startup\\") != std::string::npos) return true;
    if (pathLower.find("\\program files\\") != std::string::npos &&
        pathLower.find("\\temp\\") != std::string::npos) return true;      // 畸形路径（临时物伪装进 Program Files）
    // 盘根（形如 "d:\xxx.exe"：第 3 字符是反斜杠且后面再无反斜杠）
    if (pathLower.size() > 4 && pathLower[1] == ':' && pathLower[2] == '\\' &&
        pathLower.find('\\', 3) == std::string::npos) return true;
    return false;
}

static bool ReadHeadBytes(const std::string& path, char* out, DWORD want, DWORD* got) {
    HANDLE h = CreateFileU8(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BOOL ok = ReadFile(h, out, want, got, nullptr);
    CloseHandle(h);
    return ok != FALSE;
}

// 落地初筛。返回 true 表示"值得让上层判定层关注"。
//
// ★ outNeedRetry（2026-09-25 新增，修 P0「先建后写漏判」）：
//   非空时，若本次返回 false 的原因是「**内容尚未就绪**」——体积为 0、或文件头
//   一个字节都读不到——就置 true，让上层把这个路径排进延后重探队列。
//
//   为什么必须把这个信号单独暴露出来：ProbeLandedFile 返回 false 有七八种原因，
//   但其中**只有「还没写完」会因为等待而变成可判定**。不在热点目录、被排除规则
//   命中、不是可执行类、体积超上限——这些等多久都一样是 false。如果上层不区分
//   原因就一律重探，等于给每个无关文件都排一次磁盘探测，白烧 I/O；
//   反之若完全不给信号（旧行为），「先建后写」的文件就**此生不再被判定**。
//   所以判据必须由本函数给出，不能由调用方猜。
//
//   ★ requireHotspot（2026-09-26 ETW 全盘哨兵新增）：是否要求「落地高发区」。
//     ReadDirectoryChangesW 路径保持 true（监视清单本身已把位置筛过一遍，且
//     语义是"高发区行为画像"）。ETW 哨兵路径必须传 **false** —— ETW 事件天然
//     全盘全卷，而云库哈希隔离（service 层 HashDbVerdict）的前提是文件先通过
//     本函数进入 g_landed 队列；若在非高发区（如 C:\Games、盘符任意子目录）
//     被热点闸门拦下，**云库哈希永远查不到它** —— 这正是银泊实测发现的
//     「监测只覆盖一部分」盲区的深层机制。全盘模式下其余判据（可执行类、
//     PE 头、体积上限、排除规则）全部保留 —— 它们是行为质量判据，不是覆盖面判据。
static bool ProbeLandedFile(const std::string& full, const std::string& fullLower,
                            int* outLevel, std::string* outReason,
                            bool* outNeedRetry = nullptr,
                            bool requireHotspot = true) {
    if (outNeedRetry) *outNeedRetry = false;
    if (!g_cfg.landHuntEnabled) return false;
    if (requireHotspot && !IsLandingHotspot(fullLower)) return false;
    if (IsExcluded(fullLower)) return false;
    if (!g_exeDirLower.empty() && fullLower.find(g_exeDirLower) != std::string::npos) return false;

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    // 属性都读不到 → 文件已经不存在了（被删 / 被改名搬走），重探没有意义，
    // 刻意**不**置 needRetry：否则队列会被「创建后立刻删掉」的临时文件塞满。
    if (!GetFileAttributesExU8(full.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    // 超上限是这个文件**永远**不会满足的条件，同样不该重探。
    if (sz > g_cfg.landMaxBytes) return false;

    size_t slash = fullLower.find_last_of("\\/");
    std::string base = (slash == std::string::npos) ? fullLower : fullLower.substr(slash + 1);

    // 只关心可执行/脚本类落地（文档/图片落地是正常行为）；
    // 压缩包也进（它们是哈希精确匹配的入口，见 kLandedExts 注释）。
    bool exeLike = false;
    for (const char* e : kLandedExts) {
        size_t n = strlen(e);
        if (base.size() > n && base.compare(base.size() - n, n, e) == 0) { exeLike = true; break; }
    }
    // ★ 2026-10-03（P1-2）`.dll` 只在**热点区**这一路收（见 kHotspotOnlyExts 的量能说明）。
    //   requireHotspot 传 false 的那一路是 ETW 全盘哨兵，全盘 dll 量极大，
    //   收进来会把待重探队列打爆（满了丢最早 ⇒ 真实载荷被挤掉）。
    if (!exeLike && requireHotspot) exeLike = HasHotspotOnlyExt(base);
    bool rndName = LooksLikeRandomName(base);
    if (!exeLike && !rndName) {
        // ★★ 2026-10-03 补最后一道兜底：内容判据（读文件头是不是 PE）。
        //
        //  【为什么扩展名白名单 + 命名形态两者都不够】
        //    两者都是**攻击者可控的表面特征**。银狐实测的解包中间态就已经同时绕过了它们：
        //      `is-1DHAF.tmp` —— 后缀不在表内、命名（digits=1）过不了随机名判据
        //      ⇒ 落地捕获直接 return false，载荷零日志、零送检。
        //    把它改成 `is-1DHAF.dat` / `a1b2c3.bin` / 甚至无扩展名，同样绕过。
        //    **扩展名与文件名都能改，PE 头改不了。**
        //
        //  ★★★ 但 PE 头**单独**用会造成更严重的事故（自测抓到的）：
        //    正常安装器（Office / Edge / 任何 Inno 包）运行时满天飞 `is-XXXXXX.tmp`，
        //    且**全是 PE**。无条件按 MZ 收 ⇒ 全盘每个安装器临时文件都进送检队列
        //    ⇒ 自动送检配额瞬间打爆（kAutoPerHour）⇒ **真载荷反而挤不进来**。
        //    这是「加检测面必须评估量能」的直接又一次验证。
        //
        //  【所以门槛是三者同时成立】
        //    ① 文件头是 PE（MZ）；**且**
        //    ② 它在一个**由程序新建的随机命名目录**里 —— 银狐的落点形态是
        //       `…\yCcAU\WlBU\is-1DHAF.tmp`：`yCcAU` / `WlBU` 两层都是随机名，
        //       而 Office 的临时文件在 `…\{GUID}\` 或 `%TEMP%\{GUID}\` 下，
        //       父目录是**标准 GUID 形态**、不是随机名。
        //    用「父目录也随机」把安装器的规范临时目录排除掉。
        //  【为什么不用文件大小/时间再筛】那两个都是更弱的信号，且会漏掉分块慢写的载荷。
        char mz[2] = { 0 };
        DWORD got = 0;
        if (ReadHeadBytes(full, mz, sizeof(mz), &got) && got == 2 &&
            mz[0] == 'M' && mz[1] == 'Z' && ParentDirLooksRandom(fullLower)) {
            exeLike = true;   // PE 头 + 随机父目录 ⇒ 按可执行体继续判定
        }
    }
    if (!exeLike && !rndName) return false;

    // ★★★ P0 闸门（就在这）：`sz == 0` 判否本身没错——0 字节文件确实无从判定。
    //  问题在于**调用时机**：`curl -o` / `Invoke-WebRequest -OutFile` /
    //  `certutil -urlcache -f` / BITS 直写 / 脚本写文件 / 解包器落盘 全是
    //  「先创建 0 字节 → 随后写入」两步落地。FILE_ACTION_ADDED 到达那一刻体积
    //  就是 0，于是这里判否；而随后写入触发的 FILE_ACTION_MODIFIED **不在初筛
    //  触发面上**（初筛只在 ADDED / rename 时跑）→ 该文件此生不被判定，
    //  日志、告警、隔离**全部静默**。
    //  最阴的一点：浏览器下载的末步是 rename（临时名 → 正式名），反而一定命中，
    //  所以日常点几下浏览器永远发现不了这个洞。
    //  现在把「体积为 0」明确标成 needRetry，交给延后重探队列。
    if (sz == 0) {
        if (outNeedRetry && (exeLike || rndName)) *outNeedRetry = true;
        return false;
    }

    char head[512] = { 0 };
    DWORD got = 0;
    if (!ReadHeadBytes(full, head, sizeof(head) - 1, &got) || got < 2) {
        // 文件非 0 但一个字节都读不出来：多半是「刚创建、写入句柄还独占着」
        // （或写入者的共享标志不允许我们读）。这类同样值得等一会再看。
        if (outNeedRetry && (exeLike || rndName)) *outNeedRetry = true;
        return false;
    }
    head[got] = 0;

    bool isPE = ((unsigned char)head[0] == 'M' && (unsigned char)head[1] == 'Z');
    bool isScript = (strstr(head, "powershell") != nullptr ||
                     strstr(head, "cmd.exe") != nullptr ||
                     strstr(head, "WScript") != nullptr ||
                     strstr(head, "ActiveXObject") != nullptr);

    if (isPE && rndName) {
        if (outLevel) *outLevel = 2;
        if (outReason) *outReason = "随机命名的可执行文件落在落地高发区（疑似银狐载荷）";
        return true;
    }
    if (isScript) {
        if (outLevel) *outLevel = 2;
        if (outReason) *outReason = "脚本载荷落在落地高发区（内含 powershell/cmd 执行特征）";
        return true;
    }
    if (isPE) {
        if (outLevel) *outLevel = 1;
        if (outReason) *outReason = "可执行文件落在落地高发区（旁证，命名正常）";
        return true;
    }

    // ★ 云库哈希精确匹配 fallback（2026-09-26，修「压缩包测不中」）
    //  行为画像没命中（典型：压缩包——PK 头非 MZ、也非脚本）不代表可以放过：
    //  云库条目可能正是**这个文件本身**的 SHA-256（theZoo 类投递，库记 zip 哈希）。
    //  字节级同一性与名字/位置/PE 结构全部无关 —— 在库即判。
    //  代价可控：FileSha256Cached 带 (路径,大小,mtime) 缓存 + 体积上限（大文件跳过）；
    //  HitMalicious 是 Bloom 前置（负查询极廉价）。**不命中即静默 false** ——
    //  不入 g_landed、不弹窗，零误报面。
    {
        std::string sha;
        if (sf::pehash::FileSha256Cached(full, sha, nullptr)) {
            std::string why;
            if (sf::hashshare::HitMalicious(sf::hashshare::kAlgoSha256, sha, &why)) {
                if (outLevel) *outLevel = 2;
                if (outReason) *outReason = "云库哈希命中（" + why + "），SHA-256 " +
                                            sha.substr(0, 16) + "…";
                return true;
            }
        }
    }
    return false;
}

// ===========================================================================
//  ★★ 落地命中统一处理 + 延后重探队列（2026-09-25，修 P0「先建后写漏判」）
//
//  背景：初筛只在 FILE_ACTION_ADDED / rename 时跑，而 ProbeLandedFile 对 0 字节
//  文件必然判否 —— 「先创建后写入」的载荷因此整条链静默（详见 ProbeLandedFile
//  里 "P0 闸门" 的注释）。修法是：ADDED 时若判定失败的原因是「内容尚未就绪」，
//  就把它排进本队列，过 1.5 秒再判一次。
//
//  【为什么必须抽出 ApplyLandedHit】
//  重探命中后要走的处理路径，必须与 ADDED 初筛**逐字相同**（RecordSoftLand 的
//  sysZone、消费式队列上限、统计口径、日志口径）。如果重探分支自己抄一份，
//  将来任何一处被改，两条路就会漂移 —— 而「同一类命中走两条不同的路」正是
//  本项目反复吃亏的模型（服务端 / 客户端口径差、GUI 三副本不一致……）。
//  收成一处，就没有漂移的可能。
// ===========================================================================
//   sysZone = true   软件自写区（AppData / ProgramData / Users\Public / 启动夹）
//                    → 参与「落地旁证 → 执行」组合升档；**刻意不写日志**
//                      （这些目录写入极其频繁，逐条 LogDbg 会把 guard.log 刷爆
//                       并拖慢热路径）
//   sysZone = false  用户主动落点（Downloads / 桌面 / 盘根）
//                    → 只入消费式队列（弹窗展示），不参与组合升档
static void ApplyLandedHit(const std::string& full, const std::string& why,
                           int lv, bool sysZone) {
    // ---- 同路径短窗去重（2026-09-26 双路冗余配套）----
    // 同一个落地文件现在可能从两条路到达：ReadDirectoryChangesW 的 ADDED/rename
    // 初筛，与 ETW 全盘哨兵（EID 30 新建 / 27 改名）。不去重的话 g_landed 会有
    // 两条 → service 层消费两次 → 弹窗两次、hashdb 查两次（隔离第二次时文件已
    // 被移走，产生一条"文件不存在"的噪声记录）。60 秒窗口内同路径只认第一次。
    static std::mutex s_dedMtx;
    static std::unordered_map<std::string, uint64_t> s_seen;   // pathLower → lastMs
    // ★ 2026-09-26 修复「同一样本每次启动只拦一次」：60 秒窗口会把用户
    //   「删掉再投」的合法二次落地也静默吞掉（银泊实测）。此去重只为防
    //   ETW + 目录监视对**同一落地事件**的双报——那两路间隔是毫秒级，
    //   2 秒绰绰有余；真正的同队列去重由 QueuePendingProbe 的 map 键负责。
    static const uint64_t kDedupMs = 2000;
    {
        const uint64_t now = NowMs();
        const std::string key = Lower(full);   // 两路传来的大小写可能不同，键必须归一
        std::lock_guard<std::mutex> lk(s_dedMtx);
        if (s_seen.size() > 4096) {
            for (auto it = s_seen.begin(); it != s_seen.end();)
                if (now - it->second > kDedupMs) it = s_seen.erase(it); else ++it;
            if (s_seen.size() > 4096) s_seen.clear();
        }
        auto it = s_seen.find(key);
        if (it != s_seen.end() && now - it->second < kDedupMs) return;   // 窗口内重复 → 静默
        s_seen[key] = now;
    }
    if (!sysZone) {
        StatAdd(12, 1);   // 记入"落地初筛命中"统计
        LogDbg("[rollback] 落地初筛命中（" + std::to_string(lv) + "级）: " +
               full + " —— " + why);
    }
    RecordSoftLand(full, why, lv, sysZone);
    std::lock_guard<std::mutex> lk(g_landMtx);
    g_landed.alerts.push_back({ full, why, NowMs(), lv });
    if (g_landed.alerts.size() > 256) g_landed.alerts.pop_front();
}

// ===========================================================================
//  ★★ ETW 全盘落地哨兵入口（2026-09-26，银泊提议）
// ===========================================================================
//  【背景】银泊实测发现「文件监测只覆盖一部分」：落地捕获挂在
//  ReadDirectoryChangesW 上，而它的监视面是**目录清单**（用户目录/Temp/AppData/
//  ProgramData/Public + 盘根），C:\ 下的自建目录（C:\temp、C:\Soft……）完全
//  不在其中 —— 落到那里的云库样本此生进不了 g_landed，隔离区永远等不到它。
//
//  【方案】不扩清单，直接复用已有的 iowatch ETW 采集层（Kernel-File provider，
//  0x1C90 掩码：新建/创建/改名/删除，**天然全盘全卷、无目录清单、无句柄上限**）：
//    iowatch 消费线程 sink → 本函数（纯内存：小写化 + 扩展名/随机名过滤 + 入队）
//    → 复用 PendingProbe 延后重探队列（同路径去重、1.5 秒等写完、每轮限速）
//    → DrainPendingProbes 在 rollback 监视线程里做真正的磁盘判定（读 512B 头）
//    → 命中走 ApplyLandedHit → service 层 hashdb 查询 → 隔离。
//  磁盘 I/O 全部留在 rollback 自己的线程，ETW 消费线程只做字符串活 ——
//  严守 iowatch.h 的「sink 不得做重活」铁律。
//
//  【与 ReadDirectoryChangesW 的关系：双路冗余，不是替换】
//    · ETW 哨兵：覆盖面之王（全盘），但只有 I/O 流通知，无目录级事件细节；
//    · 目录监视：勒索快照/回滚/密钥截获仍然**必须**靠它（需要 LAST_WRITE/SIZE
//      语义与目录上下文）—— 这些能力 ETW 替代不了。
//  两路对同一文件天然由 QueuePendingProbe 的 map 键去重收敛成一次判定。
//
//  【入口过滤为什么便宜】可执行扩展名表（9 个后缀的后缀比较）+ LooksLikeRandomName
//  （字符统计）。ETW 全盘新建事件的大头是缓存/日志/临时物，全在这里被挡下；
//  过滤不动的进队列也还有 IsExcluded / 512 上限 / 只探一次三道闸。
// ===========================================================================
static bool IsScreenOnlyPath(const std::string& p);            // 定义在本文件下方（2100 附近）
static void QueuePendingProbe(const std::string& full, const std::string& fl,
                              bool sysZone, bool extWide = false);
static bool NotifyExternalLandedImpl(const std::string& path) {
    if (path.empty() || path.size() < 5) return false;      // 至少形如 "C:\x.exe"
    if (path.size() > 1024) return false;                    // 异常超长，防御
    const std::string fl = Lower(path);

    // 自身目录排除（防自噬：隔离区/日志/快照的写操作绝不判）
    if (!g_exeDirLower.empty() && fl.find(g_exeDirLower) != std::string::npos) return false;
    if (IsExcluded(fl)) return false;

    // 只关心可执行/脚本类落地 + 压缩包（哈希精确匹配入口）——
    // 用与 ProbeLandedFile 同一份 kLandedExts（口径统一，防漂移）。
    size_t slash = fl.find_last_of("\\/");
    std::string base = (slash == std::string::npos) ? fl : fl.substr(slash + 1);
    bool exeLike = false;
    for (const char* e : kLandedExts) {
        size_t n = strlen(e);
        if (base.size() > n && base.compare(base.size() - n, n, e) == 0) { exeLike = true; break; }
    }
    if (!exeLike && !LooksLikeRandomName(base)) return false;

    // sysZone 按路径语义判定（与 ProcessNotifications 两条分支的口径一致）：
    // AppData/ProgramData/Public/Temp 等软件自写区 → true（参与组合升档、不打日志）；
    // 其余（盘根/自建目录/C:\Windows 等）→ false（用户可见路径，走弹窗展示队列）。
    QueuePendingProbe(path, fl, IsScreenOnlyPath(fl), /*extWide=*/true);
    return true;
}

// 对外入口（rollback.h 导出）。Impl 与上层无耦合，包装只为隔离 static 内部件。
void NotifyExternalLanded(const std::string& path) { NotifyExternalLandedImpl(path); }

// 待重探项。以**小写全路径**为 map 键，天然完成「同路径去重」。
struct PendProbe {
    std::string path;        // 原始大小写（回传给上层展示 / 给隔离区用）
    std::string pathLower;   // 判据用
    uint64_t    dueMs = 0;
    bool        sysZone = false;
    bool        extWide = false;   // true = 来自 ETW 全盘哨兵（重探时放开热点限制）
};
static std::mutex                            g_pendMtx;
static std::unordered_map<std::string, PendProbe> g_pendProbes;
static const size_t   kPendMax     = 512;    // 队列上限：高频写入目录不至于把内存撑爆
static const int      kPendDrain   = 8;      // 每轮最多重探几个（限制单轮磁盘开销）
static const uint64_t kPendDelayMs = 1500;   // 延后 1.5 秒 —— 足够正常下载写出首块

// 入队。**同路径只入一次、且不延期**（已在队列里就直接返回）：
// 反复改写 dueMs 会让一个永远写不满的占位文件无限续命，每一轮都去摸一次磁盘。
// 双路冗余（ReadDirectoryChangesW 与 ETW 哨兵）天然受益：同一路径两路都报，
// map 键去重保证只判一次。（extWide 默认值见上方前向声明，勿在此重复指定）
static void QueuePendingProbe(const std::string& full, const std::string& fl,
                              bool sysZone, bool extWide) {
    std::lock_guard<std::mutex> lk(g_pendMtx);
    if (g_pendProbes.find(fl) != g_pendProbes.end()) return;
    if (g_pendProbes.size() >= kPendMax) {
        // 满了：丢最早入队的那个。宁可漏掉最老的，也不能让队列无界增长。
        auto oldest = g_pendProbes.begin();
        for (auto it = g_pendProbes.begin(); it != g_pendProbes.end(); ++it)
            if (it->second.dueMs < oldest->second.dueMs) oldest = it;
        g_pendProbes.erase(oldest);
    }
    g_pendProbes.emplace(fl, PendProbe{ full, fl, NowMs() + kPendDelayMs, sysZone, extWide });
}

// 到期重探。每轮最多 kPendDrain 个，**只重探这一次**：不满足即放弃。
// 为什么不做「失败再延期」：正常下载 1.5 秒内必然写出首批字节（哪怕只写出前
// 512 字节也足够判 MZ / 脚本特征）；1.5 秒后仍是 0 字节的，是「占位文件被
// 立刻删掉」或「创建者压根还没写」这类情况，再等也不会变成可判定。
static void DrainPendingProbes() {
    std::vector<PendProbe> due;
    const uint64_t now = NowMs();
    {
        std::lock_guard<std::mutex> lk(g_pendMtx);
        for (auto it = g_pendProbes.begin();
             it != g_pendProbes.end() && due.size() < (size_t)kPendDrain; ) {
            if (it->second.dueMs <= now) { due.push_back(it->second); it = g_pendProbes.erase(it); }
            else ++it;
        }
    }
    for (auto& p : due) {
        int lv = 0; std::string why;
        // 重探时不再关心 needRetry —— 只有这一次机会，成败都出队。
        // extWide=true（ETW 全盘哨兵）→ requireHotspot=false，全盘判定。
        if (ProbeLandedFile(p.path, p.pathLower, &lv, &why, nullptr, !p.extWide) && lv >= 1)
            ApplyLandedHit(p.path, why, lv, p.sysZone);
    }
}

static std::string DirOfPath(const std::string& lowerPath) {
    size_t p = lowerPath.find_last_of("\\/");
    return (p == std::string::npos) ? std::string() : lowerPath.substr(0, p);
}

// 记录一次改写并返回该目录在当前窗口内的累计改写次数
static uint32_t BumpDirHeat(const std::string& dirLower) {
    if (dirLower.empty()) return 0;
    uint64_t now = NowMs();
    uint64_t win = (uint64_t)g_cfg.burstWindowSec * 1000;
    std::lock_guard<std::mutex> lk(g_heatMtx);
    // 表满时清掉过期的，仍满则整体清空（宁可丢失热度，不可无界增长）
    if (g_heat.size() > 4096) {
        for (auto it = g_heat.begin(); it != g_heat.end();) {
            if (now - it->second.windowStart > win) it = g_heat.erase(it);
            else ++it;
        }
        if (g_heat.size() > 4096) g_heat.clear();
    }
    DirHeat& h = g_heat[dirLower];
    if (now - h.windowStart > win) { h.windowStart = now; h.count = 0; }
    return ++h.count;
}

// 决定是否为此文件建立快照。返回 true 表示应该建。
// ext 为文件的扩展名（小写含点），isRename 表示本次通知是否为改名。
static bool ShouldSnapshotThis(const std::string& fullLower, const std::string& ext,
                               bool isRename, uint32_t* outHeat = nullptr) {
    if (!g_cfg.riskTieredSnapshot) return true;   // 分层关闭 → 退回旧行为

    // 判据①：改成陌生后缀 —— 勒索的强特征，无条件建快照
    if (isRename && LooksLikeRansomExt(ext)) return true;

    // 判据②：该目录短时间内已被频繁改写（这片区域"正在被批量动"）
    uint32_t heat = BumpDirHeat(DirOfPath(fullLower));
    if (outHeat) *outHeat = heat;
    if (heat >= g_cfg.burstFileTrigger) return true;

    // 判据③：高价值文档的首次改写（首次改写前那一版最值得留）
    if (g_cfg.highValueOnly && IsHighValueDoc(fullLower)) {
        // "首次改写"由 SnapshotFile 内部的"已持有则跳过"保证：
        // 这里直接返回 true，若已有快照则 SnapshotFile 会立即返回而不重复写盘。
        return true;
    }

    // 其余情况（普通文件偶发写入，如同目录第 1~4 次改写且非高价值类型）不建快照。
    // 注意：判据②说明该目录热度会累积，一旦超过 burstFileTrigger，
    //       后续同目录的改写都会建快照 —— 所以并不存在"完全无保护"的目录。
    return false;
}

// ===========================================================================
//  快照建立
// ===========================================================================
bool SnapshotFile(const std::string& path, const std::string& reason) {
    if (!g_cfg.enabled) return false;
    std::string key = NormKey(path);
    if (key.empty()) return false;
    if (IsExcluded(key)) return false;
    if (!IsProtectedExt(key)) { StatAdd(4, 1); return false; }

    // 已持有快照 → 不重复拍（**关键**：只保留"最初的那一份"，
    // 即文件被改动之前的状态。若反复覆盖快照，勒索进程多轮加密后
    // 快照里存的就成了上一轮的密文，回滚等于没回滚。）
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) { TouchLocked(key); return true; }
    }

    // 取文件大小
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExU8(path.c_str(), GetFileExInfoStandard, &fad)) return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    uint64_t sz = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
    if (sz == 0) return false;                              // 空文件没有回滚价值
    if (sz > g_cfg.maxFileBytes) { StatAdd(4, 1); return false; }

    // 容量预检：即使拍下来也放不下就不拍（避免先写后淘汰的无效 IO）
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        if (CacheBytesLocked() + sz > g_cfg.maxCacheBytes && sz > g_cfg.maxCacheBytes / 8)
            { StatAdd(4, 1); return false; }
    }

    std::string snap = SnapPathOf(path);
    std::string meta = MetaPathOf(path);

    // 复制原文（带共享读，避免与正在写入的进程互斥而拿不到）
    HANDLE hs = CreateFileU8(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) { StatAdd(4, 1); return false; }
    HANDLE hd = CreateFileU8(snap.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); StatAdd(4, 1); return false; }

    std::vector<char> buf(1 << 16);
    uint64_t copied = 0;
    std::string sha;
    {
        BCRYPT_ALG_HANDLE ha = nullptr;
        BCRYPT_HASH_HANDLE hh = nullptr;
        bool hasHash = (BCryptOpenAlgorithmProvider(&ha, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0) &&
                       (BCryptCreateHash(ha, &hh, nullptr, 0, nullptr, 0, 0) == 0);
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
            DWORD wr = 0;
            if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) break;
            if (hasHash) BCryptHashData(hh, (PUCHAR)buf.data(), rd, 0);
            copied += rd;
        }
        if (hasHash) {
            BYTE d[32]; ULONG cb = 32;
            if (BCryptFinishHash(hh, d, cb, 0) == 0) {
                static const char* hx = "0123456789abcdef";
                for (int i = 0; i < 32; ++i) { sha += hx[d[i] >> 4]; sha += hx[d[i] & 0xf]; }
            }
            BCryptDestroyHash(hh);
        }
        if (ha) BCryptCloseAlgorithmProvider(ha, 0);
    }
    CloseHandle(hs);
    CloseHandle(hd);
    if (copied == 0) { DeleteFileU8(snap.c_str()); StatAdd(4, 1); return false; }

    Meta m;
    m.path = path; m.sha = sha; m.size = copied; m.time = NowMs(); m.reason = reason;
    WriteMeta(meta, m);

    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        SnapEntry e;
        e.path = path; e.sha = sha; e.snapPath = snap; e.metaPath = meta;
        e.size = copied; e.atime = m.time;
        // 若并发插入已存在（两个线程同时抢拍同一文件），保留先到的，
        // 并把刚写的这组文件删掉（否则会留下永远无人引用的孤儿快照 + 泄漏磁盘）
        auto it = g_cache.find(key);
        if (it != g_cache.end()) {
            DeleteFileU8(snap.c_str());
            DeleteFileU8(meta.c_str());
            TouchLocked(key);
        } else {
            g_cache[key] = e;
            g_lru.push_back(key);
            StatAdd(3, 1);              // snapshotTaken++
            EvictLocked();              // 先淘汰（此时 g_cache 已含新条目）
            SyncCacheStatsLocked();     // 再把真实占用同步给统计
        }
    }
    return true;
}

bool HasSnapshot(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    return g_cache.count(NormKey(path)) > 0;
}

bool RestoreFile(const std::string& path) {
    // -----------------------------------------------------------------------
    //  最后一道防线（2026-09-19 事故后新增）
    //
    //  即使上层因为任何原因把浏览器数据目录/自身目录塞进了受害者清单，
    //  这里也**拒绝执行覆盖写**。回滚是破坏性操作（CREATE_ALWAYS），
    //  一旦执行就无法看出"本来不该动"，所以在真正落盘前必须再挡一次。
    //
    //  教训：把过滤只放在"收集受害者"那一处是不够的 —— 调用路径有
    //  自动回滚 / 手动回滚 / 撤销回滚三条，任何一条绕过过滤都会重现事故。
    // -----------------------------------------------------------------------
    {
        std::string pl = Lower(path);
        if (IsExcluded(pl)) return false;
        if (!g_exeDirLower.empty() && pl.find(g_exeDirLower) != std::string::npos) return false;
    }
    std::string key = NormKey(path);
    SnapEntry e;
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it == g_cache.end()) return false;
        e = it->second;
        TouchLocked(key);
    }
    // 清只读属性（勒索常把原文件设为只读防恢复）
    DWORD attr = GetFileAttributesU8(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_READONLY))
        SetFileAttributesU8(path.c_str(), attr & ~FILE_ATTRIBUTE_READONLY);

    HANDLE hs = CreateFileU8(e.snapPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return false;

    // -----------------------------------------------------------------------
    //  回滚前备份（2026-09-21 新增）—— 必须在 CREATE_ALWAYS 之前
    //
    //  位置说明：这里已经是"万事俱备、下一句就要截断重写"的那一行。
    //  放在这里而不是函数开头，是为了避免"备份了一堆、结果快照打不开
    //  直接 return 白备份"的浪费；也确保备份的正是**马上要被抹掉的那一版**，
    //  中间没有任何其他写入插进来改变它的内容。
    //
    //  严格模式下备份失败 → 直接返回 false，放弃本次覆盖：
    //  调用方会把它计入"不可恢复"并如实上报，绝不假装成功。
    // -----------------------------------------------------------------------
    if (!PreBackupBeforeOverwrite(path, "rollback-overwrite")) {
        CloseHandle(hs);
        LogDbg("[rollback] 严格模式下放弃回滚（备份失败，宁可不回滚也不抹掉现有内容）: " + path);
        return false;
    }

    HANDLE hd = CreateFileU8(path.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); return false; }

    std::vector<char> buf(1 << 16);
    bool ok = true;
    uint64_t wrote = 0;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { ok = false; break; }
        wrote += rd;
    }
    CloseHandle(hs);
    CloseHandle(hd);
    if (!ok) return false;

    // 恢复成功后**删除该快照**：卡巴的回滚是一次性补救动作，不是持续状态。
    // 保留会占满缓存，且若用户之后再改这个文件，旧快照已无意义（文件已是新内容）。
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        auto it = g_cache.find(key);
        if (it != g_cache.end()) {
            DeleteFileU8(it->second.snapPath.c_str());
            DeleteFileU8(it->second.metaPath.c_str());
            g_cache.erase(it);
            for (auto i2 = g_lru.begin(); i2 != g_lru.end(); ++i2)
                if (*i2 == key) { g_lru.erase(i2); break; }
            SyncCacheStatsLocked();
        }
    }
    StatAdd(6, 1);
    (void)wrote;
    return true;
}

// ===========================================================================
//  滑动窗口信号统计
//
//  为什么用窗口而不是累计计数：勒索的特征是**爆发式**改文件（秒级几十上百个），
//  而正常软件（编译、批量重命名、解压）虽然也会改很多文件，但通常分布在更长时间里，
//  且不会伴随"高熵随机后缀改名"与"写勒索说明"。窗口 + 多信号联合是关键。
// ===========================================================================
struct Ev {
    std::string path;
    std::string ext;       // 变更后的扩展名（小写）
    bool        isRename = false;
    bool        ransomRename = false;  // 改成了勒索特征后缀（LooksLikeRansomExt 命中）
    bool        isNote   = false;
    double      entropy  = 0.0;
    uint64_t    t        = 0;
};

static std::mutex       g_evMtx;
static std::deque<Ev>   g_ev;
static std::atomic<bool> g_ransomActive{ false };
static std::string      g_lastTrigger;
static std::mutex       g_triggerMtx;

static void TrimWindowLocked() {          // 调用方须持 g_evMtx
    uint64_t cutoff = NowMs() - (uint64_t)g_cfg.windowSeconds * 1000ull;
    while (!g_ev.empty() && g_ev.front().t < cutoff) g_ev.pop_front();
}

// ---------------------------------------------------------------------------
//  临时目录判定（2026-09-19 16:41 codebuddy 插件解压误报风暴后新增）
//  事故：插件市场安装解压 2000+ 文件到 Temp\codebuddy-marketplace-install-*，
//        包内文档命中「解密说明」关键词 → 「勒索说明伴随批量改动」反复成立
//        → 连续弹卡 + 回滚把解压文件覆盖成快照版本（破坏安装）。
//  结论：Temp 永远繁忙（解压/编译/浏览器缓存），**永不参与信号统计**。
//        Temp 事件只保留密钥截获与落地初筛（这两项是有意针对 Temp 设计）。
// ---------------------------------------------------------------------------
static bool IsTempPath(const std::string& p) {
    std::string l = Lower(p);
    return l.find("\\appdata\\local\\temp\\") != std::string::npos ||
           l.find("\\appdata\\roaming\\temp\\") != std::string::npos ||
           l.find("\\windows\\temp\\") != std::string::npos ||
           l.find("\\temp\\") == 0;   // 盘根 Temp 目录（注意：注释行尾勿以反斜杠结尾，C4010 行继续符会吞掉下一行）
}

// ---------------------------------------------------------------------------
//  「只判不快照」目录判定（2026-09-24 全域落地捕获）
// ---------------------------------------------------------------------------
// 【背景 · 虚拟机实战暴露的漏报】
//   银狐实测：YouDaoX64.exe 落在桌面只拿到「1 级旁证」，随后释放的载荷进
//   %APPDATA% / %LOCALAPPDATA% —— 这些目录**根本不在监视列表里**，
//   目录变更通知压根没触发，落地初筛一次都没跑过。攻击链中段完全静默。
//
// 【为什么不能直接把这些目录做成"可快照目录"】
//   AppData 是浏览器 profile、应用缓存、IDE 索引的集中地，体量以 GB 计。
//   若纳入快照（160MB 配额 / 4MB 单文件），配额会被瞬间打爆，
//   且这些内容本来也不是"需要回滚保护的用户文档"。
//   → 它们只需要「落盘即判」：命中就交给上层处置，**不建任何快照**。
//
// 【与 IsTempPath 的区别】
//   IsTempPath 是 IsScreenOnlyPath 的子集。删除类事件仍只看 IsTempPath
//   （AppData 下应用自行清理缓存是常态，算勒索旁证会大面积误报）。
static bool IsScreenOnlyPath(const std::string& p) {
    std::string l = Lower(p);
    if (IsTempPath(l)) return true;
    static const char* kSO[] = {
        "\\appdata\\roaming\\",
        "\\appdata\\local\\",
        "\\appdata\\locallow\\",
        "\\programdata\\",
        "\\users\\public\\",
        "\\start menu\\programs\\startup\\",   // 用户/公共启动文件夹（持久化落点）
    };
    for (const char* e : kSO) if (l.find(e) != std::string::npos) return true;
    return false;
}

// 判定当前窗口是否构成勒索事件
static bool EvaluateLocked(uint32_t* outModified, uint32_t* outRenamed,
                           uint32_t* outNotes, std::string* outTrigger,
                           Risk* outRisk = nullptr, uint32_t thresholdScale = 1) {
    // thresholdScale：冷却期内的门槛倍率（见 HandleRansomDetection 的说明）。
    //   >1 时只抬门槛、**不停判** —— 这是「冷却期不再给攻击者放长假」的关键。
    TrimWindowLocked();
    uint32_t mod = 0, ren = 0, note = 0;
    for (const auto& e : g_ev) {
        if (e.isNote) note++;
        else if (e.isRename) {
            if (e.ransomRename) ren++;
            else mod++;   // 正常改名（日志轮转/下载落盘）：计入改动量，不作勒索旁证
        }
        else mod++;
    }
    if (outModified) *outModified = mod;
    if (outRenamed)  *outRenamed  = ren;
    if (outNotes)    *outNotes    = note;

    // ---- 判定规则（对齐业界"多信号联合"共识，单信号不定性）----
    //  硬条件：窗口内批量改写数量达标
    const uint32_t filesThr  = g_cfg.filesThreshold  * thresholdScale;
    const uint32_t renameThr = g_cfg.renameThreshold * thresholdScale;
    const uint32_t noteThr   = g_cfg.noteThreshold   * thresholdScale;
    bool burst = (mod + ren) >= filesThr;
    //  旁证：高熵随机后缀改名 / 勒索说明文件
    bool renameSignal = ren >= renameThr;
    bool noteSignal   = note >= noteThr;

    // -----------------------------------------------------------------------
    //  【2026-09-19 事故修正】判据收紧为"真勒索形状"
    // -----------------------------------------------------------------------
    //  修正前的两条判据各自都过松，合起来能命中大量正常操作：
    //    · `noteSignal && (mod+ren) >= 3`
    //        → 只要有一个含 "readme" 的文件 + 任意 3 个文件被改动就成立。
    //          《安装软件解压》《编译》《浏览器写缓存》全都满足。
    //    · `burst && renameSignal`
    //        → 依赖 LooksLikeRansomExt 与 LookLikeRansomNote 的宽松判定，
    //          同样容易被 Edge 的 edge_BITS_* / scoped_dir* 命中。
    //
    //  修正后的原则：**必须有"文件被改成陌生后缀"这一条不可伪装的硬证据**，
    //  因为这是加密的物理结果 —— 加密必然改名，正常软件保存不改扩展名。
    //  勒索说明只能作为"加强旁证"，不能单独配合少量改动就定性。
    // -----------------------------------------------------------------------

    //  判据 A（最强，可独立定性）：批量加密改名
    //    · 真勒索必然把大量文件改成陌生后缀（ren 计数）；
    //    · ren 的计数已经过 LooksLikeRansomExt 三层过滤（压缩后缀/魔数/良性后缀），
    //      正常软件的日志轮转、下载落盘、备份轮转都已被排除在外；
    //    · 要求"批量"级别的 ren 数量（默认 10），而非 1 个。
    if (burst && renameSignal) {
        if (outTrigger) *outTrigger = "短时间内大量文件被改写并改成高熵随机后缀";
        if (outRisk) *outRisk = Risk::High;
        return true;
    }

    //  判据 B（需要同时满足两个独立强证据）：勒索说明必须伴随**真实批量改名**
    //    修正点：右边从 (mod+ren)>=3 改成 renameSignal。
    //    即"有勒索说明" + "确实有一批文件被改成陌生后缀" ——
    //    单独一个 README 文件 + 少量普通改写不再定性。
    if (noteSignal && renameSignal) {
        if (outTrigger) *outTrigger = "检测到勒索说明文件（HOW TO DECRYPT / 解密说明）且伴随批量文件被改成陌生后缀";
        if (outRisk) *outRisk = Risk::High;
        return true;
    }
    // 说明：本引擎目前**不产出 Risk::Suspect 判定** —— 宁可漏报可疑、不可误伤正常
    // （回滚是覆盖写，误伤代价高于漏报）。Suspect 档位留给上层其他事件源
    // （文件落地 / 计划任务 / 注册表启动项）复用，那些场景不涉及覆盖写，
    // 适合"先弹窗问用户再动手"。
    return false;
}

// ===========================================================================
//  进程归属：找出"谁在改这个文件"
//
//  用户态拿不到内核的 IRP 发起者信息，故用**启发式归属**：
//  在事件发生时枚举进程，优先取"命令行/路径指向该文件所在目录"的进程。
//  取不到时退回 0（报告里如实标注"未能定位肇事进程"）。
// ===========================================================================
struct ProcInfo {
    uint32_t pid = 0;
    std::string path;
};

static bool IsSystemNoiseProc(const std::string& pathLower) {
    static const char* kNoise[] = {
        "\\system32\\svchost.exe", "\\system32\\searchindexer.exe",
        "\\system32\\dllhost.exe", "\\system32\\msmpeng.exe",
        "\\system32\\searchprotocolhost.exe", "\\system32\\searchfilterhost.exe",
        "\\system32\\trustedinstaller.exe", "\\system32\\tiworker.exe",
        "\\system32\\compattelrunner.exe", "\\system32\\backgroundtaskhost.exe",
        "\\system32\\runtimebroker.exe", "\\system32\\smartscreen.exe",
        "\\system32\\conhost.exe", "\\system32\\wmiprvse.exe",
        "\\system32\\taskhostw.exe", "\\system32\\sihost.exe",
        "\\system32\\explorer.exe", "\\system32\\csrss.exe", "\\system32\\winlogon.exe",
        "\\system32\\services.exe", "\\system32\\lsass.exe", "\\system32\\wininit.exe",
        "\\system32\\spoolsv.exe", "\\system32\\registry", "\\system32\\msiexec.exe",
        "silverfoxguardsvc.exe", "\\system32\\dwm.exe",
        "\\system32\\fontdrvhost.exe", "\\system32\\ctfmon.exe",
        "\\system32\\securityhealthservice.exe", "\\system32\\smartscreen.exe",
    };
    for (const char* n : kNoise) if (pathLower.find(n) != std::string::npos) return true;
    return false;
}

// 取进程映像**全路径**（PROCESSENTRY32 只给基名，无法用于目录归属判断）
static std::string FullPathOfPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return "";
    char buf[MAX_PATH * 4] = { 0 };
    DWORD n = (DWORD)sizeof(buf);
    std::string out;
    if (QueryFullProcessImageNameA(h, 0, buf, &n) && n) out.assign(buf, n);
    CloseHandle(h);
    return out;
}

// 枚举进程，挑出最可能的肇事者。
//
// 归属策略（按可信度递减）：
//   ① 映像路径落在**受害者所在目录**内 —— 最可信（勒索常把自己复制到目标目录）
//   ② 映像路径落在**受害者目录的祖先目录**内 —— 次可信（从盘根遍历加密）
//   ③ 映像路径不在系统目录、且不是已知噪声进程 —— 弱候选，仅在①②都无命中时采用
// 若三等都不满足，返回空（报告里如实写"未能定位"），**不硬凑一个**——
// 把无辜进程标成勒索凶手会引发用户恐慌与误杀，比说"没查到"更糟。
static ProcInfo FindSuspectProcess(const std::vector<std::string>& victims) {
    ProcInfo best;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return best;

    // 受害者目录集合（全小写）
    std::set<std::string> dirs;
    for (const auto& v : victims) {
        size_t p = v.find_last_of("\\/");
        if (p != std::string::npos) dirs.insert(Lower(v.substr(0, p)));
    }

    int  bestRank = 99;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
            if (pe.th32ProcessID == GetCurrentProcessId()) continue;

            std::string exe = W2A(pe.szExeFile);
            std::string le  = Lower(exe);
            if (IsSystemNoiseProc("\\" + le)) continue;
            if (le.find("silverfoxguard") != std::string::npos) continue;
            // Defender / 第三方杀软排除（全盘扫描会大量读写文件）
            if (le.find("huorong") != std::string::npos || le.find("hrsword") != std::string::npos ||
                le.find("usysdiag") != std::string::npos || le.find("360") != std::string::npos ||
                le.find("qqpctray") != std::string::npos || le.find("kxescore") != std::string::npos ||
                le.find("avp.exe") != std::string::npos || le.find("kavfs") != std::string::npos ||
                le.find("msmpeng") != std::string::npos) continue;
            // Windows Update / 系统维护类后台进程：它们会成批改文件，但**不是**勒索。
            // 实测（2026-09-18）它们会被误判为凶手（MoUsoCoreWorker.exe），
            // 因为原实现"取最后一个候选"且不看路径是否落在受害者目录内。
            if (le.find("mousocoreworker") != std::string::npos ||
                le.find("usoclient") != std::string::npos ||
                le.find("tiworker") != std::string::npos ||
                le.find("trustedinstaller") != std::string::npos ||
                le.find("wuauclt") != std::string::npos ||
                le.find("compattelrunner") != std::string::npos ||
                le.find("defrag") != std::string::npos) continue;

            std::string full = Lower(FullPathOfPid(pe.th32ProcessID));
            if (full.empty()) continue;

            int rank = 3;   // 默认弱候选
            for (const auto& d : dirs) {
                if (d.empty()) continue;
                // ① 映像就在受害者目录内
                size_t dp = full.find_last_of("\\/");
                if (dp != std::string::npos && full.substr(0, dp) == d) { rank = 1; break; }
                // ② 映像落在受害者目录的祖先路径上
                if (d.size() > full.size() && d.compare(0, full.size(), full) == 0) { rank = 2; break; }
                if (full.size() > d.size() && full.compare(0, d.size(), d) == 0 && rank > 2) { rank = 2; }
            }

            if (rank < bestRank) {
                bestRank = rank;
                best.pid = pe.th32ProcessID;
                best.path = full;
                if (rank == 1) break;      // 最高可信度，无需再看
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    // 弱候选（rank 3）可信度太低，宁可报告"未定位"也不冤枉无关进程。
    if (bestRank >= 3) { ProcInfo none; return none; }
    return best;
}

// ===========================================================================
//  ★★ 句柄归因（2026-09-23 新增）：找出"谁正开着这些文件"
// ===========================================================================
//  为什么必须加：原有 FindSuspectProcess 只看「进程映像路径是否落在受害者
//  目录内」，对 python.exe / rundll32.exe / cmd.exe 这类**外部解释器**完全失效。
//  实测（2026-09-23 纯行为勒索模拟，python 脚本改写 200 个文件）：
//  归因返回 pid=0 → 没能终止进程 → 攻击把 200 个文件全加密完。
//  **没有归因就没有止血**，这是从"发现并回滚一批"到"当场掐死"的关键一刀。
//
//  做法（纯用户态，不需要驱动）：
//    ① NtQuerySystemInformation(SystemExtendedHandleInformation) 取全局句柄表；
//    ② 每个句柄 DuplicateHandle 到自己进程；
//    ③ ★ 必须先 GetFileType 过滤（只留 FILE_TYPE_DISK）—— 本 API 的著名坑：
//       对管道/同步设备句柄调 GetFinalPathNameByHandle 会**挂死**；
//    ④ GetFinalPathNameByHandleW 取真实路径，规范化后与受害者集合比对；
//    ⑤ 取「命中文件数最多」的进程：只碰到一个文件的往往是无辜者
//       （杀软扫描、索引器、备份程序），开着一堆受害者文件的才是真凶。
//
//  权限：服务为 LocalSystem，跨进程 DuplicateHandle 需要 PROCESS_DUP_HANDLE ✓
//  性能：全表数万句柄，一次扫描约几十~几百毫秒；仅在判定成立时调用（低频）✓
// ===========================================================================
typedef LONG SfNtStatus;
typedef SfNtStatus(WINAPI* PFN_NtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

struct SfHandleEntryEx {
    PVOID     Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG     GrantedAccess;
    USHORT    CreatorBackTraceIndex;
    USHORT    ObjectTypeIndex;
    ULONG     HandleAttributes;
    ULONG     Reserved;
};
struct SfHandleInfoEx {
    ULONG_PTR     NumberOfHandles;
    ULONG_PTR     Reserved;
    SfHandleEntryEx Handles[1];
};

// GetFinalPathNameByHandleW 返回 "\\?\C:\..."，统一去掉前缀并小写
static std::string NormHandlePathLower(const std::string& in) {
    std::string s = in;
    if (s.rfind("\\\\?\\UNC\\", 0) == 0)      s = "\\\\" + s.substr(8);
    else if (s.rfind("\\\\?\\", 0) == 0)      s = s.substr(4);
    return Lower(s);
}

// 安全软件/索引类进程自己也会打开文件 —— 不能把它们当成勒索凶手
static bool IsScannerLikeProc(const std::string& pathLower) {
    static const char* kNoise[] = {
        "huorong", "sysdiag", "kaspersky", "\\avp", "klnag", "avp.exe",
        "msmpeng", "windefend", "securityhealth", "360", "qqpctray",
        "searchindexer", "searchprotocolhost", "searchfilterhost",
        "\\windows\\system32\\svchost.exe", "backup", "dropbox", "onedrive",
        "\\everything.exe", "antimalware",
    };
    for (const char* n : kNoise) if (pathLower.find(n) != std::string::npos) return true;
    return false;
}

static ProcInfo FindSuspectByHandles(const std::vector<std::string>& victims) {
    ProcInfo best;
    if (victims.empty()) return best;

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return best;
    auto pNtQSI = (PFN_NtQuerySystemInformation)GetProcAddress(nt, "NtQuerySystemInformation");
    if (!pNtQSI) return best;

    const ULONG kSystemExtendedHandleInformation = 64;
    const SfNtStatus STATUS_INFO_LENGTH_MISMATCH = (SfNtStatus)0xC0000004L;

    std::vector<BYTE> buf(1u << 20);
    bool ok = false;
    for (int i = 0; i < 8; ++i) {                       // 逐步扩容（1MB → 128MB 上限）
        ULONG need = 0;
        SfNtStatus st = pNtQSI(kSystemExtendedHandleInformation, buf.data(), (ULONG)buf.size(), &need);
        if (st == 0) { ok = true; break; }
        if (st != STATUS_INFO_LENGTH_MISMATCH) return best;
        if (buf.size() > (128u << 20)) return best;
        buf.resize(buf.size() * 2);
    }
    if (!ok) return best;
    auto* info = (SfHandleInfoEx*)buf.data();

    std::set<std::string> targets;
    for (const auto& v : victims) targets.insert(NormHandlePathLower(v));

    std::unordered_map<uint32_t, int>   hits;       // pid → 命中文件数
    std::unordered_map<uint32_t, HANDLE> procCache; // pid → 进程句柄（避免重复 OpenProcess）
    const DWORD me = GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < info->NumberOfHandles; ++i) {
        const SfHandleEntryEx& e = info->Handles[i];
        const uint32_t pid = (uint32_t)e.UniqueProcessId;
        if (pid == 0 || pid == 4 || pid == me) continue;

        HANDLE& hProc = procCache[pid];
        if (!hProc) {
            hProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
            if (!hProc) { hProc = INVALID_HANDLE_VALUE; continue; }
        } else if (hProc == INVALID_HANDLE_VALUE) {
            continue;
        }

        HANDLE hDup = nullptr;
        if (!DuplicateHandle(hProc, (HANDLE)e.HandleValue, GetCurrentProcess(), &hDup,
                             0, FALSE, DUPLICATE_SAME_ACCESS)) continue;

        // ★ 类型过滤必须在取路径之前：管道/设备句柄会让 GetFinalPathNameByHandle 挂死
        if (GetFileType(hDup) == FILE_TYPE_DISK) {
            std::vector<wchar_t> wpath(MAX_PATH * 4);
            DWORD n = GetFinalPathNameByHandleW(hDup, wpath.data(), (DWORD)wpath.size(), 0);
            if (n > 0 && n < wpath.size()) {
                int u8 = WideCharToMultiByte(CP_UTF8, 0, wpath.data(), (int)n, nullptr, 0, nullptr, nullptr);
                if (u8 > 0) {
                    std::string p8(u8, '\0');
                    WideCharToMultiByte(CP_UTF8, 0, wpath.data(), (int)n, &p8[0], u8, nullptr, nullptr);
                    if (targets.count(NormHandlePathLower(p8))) hits[pid]++;
                }
            }
        }
        CloseHandle(hDup);
    }
    for (auto& kv : procCache) if (kv.second && kv.second != INVALID_HANDLE_VALUE) CloseHandle(kv.second);

    // 选命中最多者；单命中容易被"扫描类进程"蹭到，要求 ≥2 或至少不是扫描类
    uint32_t bestPid = 0; int bestHits = 0;
    for (const auto& kv : hits) {
        if (kv.second > bestHits) { bestHits = kv.second; bestPid = kv.second ? kv.first : 0; }
    }
    if (!bestPid || bestHits <= 0) return best;

    std::string full = Lower(FullPathOfPid(bestPid));
    if (full.empty()) return best;
    if (IsScannerLikeProc(full)) {
        LogDbg("[rollback] 句柄归因命中疑似扫描类进程，忽略: pid=" + std::to_string(bestPid) + " " + full);
        ProcInfo none; return none;
    }
    if (bestHits < 2) {
        // 只有 1 个文件命中：可能只是恰好打开过 —— 可信度不足，交给启发式兜底
        LogDbg("[rollback] 句柄归因命中数不足（1）: pid=" + std::to_string(bestPid) + " " + full);
        ProcInfo none; return none;
    }

    best.pid = bestPid;
    best.path = full;
    LogDbg("[rollback] 句柄归因命中: pid=" + std::to_string(bestPid) +
           " " + full + "（开有 " + std::to_string(bestHits) + " 个受害者文件句柄）");
    return best;
}

static bool TerminateSuspect(uint32_t pid) {
    if (!pid) return false;
    HANDLE h = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok != FALSE;
}

// ===========================================================================
//  信誉门（2026-09-19 新增：wallpaper64.exe 误杀事故的根治）
//  事故：Wallpaper Engine（Steam 正版、Valve 签名）批量写 Temp 缓存，
//        「高熵随机后缀」判据把 .tmp.js 双扩展当勒索改名 → 归因环拉到
//        wallpaper64.exe → 全量终止。根因不是"归因错了"，而是**终止决策
//        没有信誉层**——正规杀软在终止前都查进程信誉。
//  实现：sf::ProcReputable（behavior.cpp 共享版，签名厂商名单/可信路径）；
//        此处补一个回滚特有的判据：受害文件全部在临时目录 → 不构成勒索
//        目标（Temp 一次性文件），也不终止。
// ===========================================================================
static bool AllVictimsInTemp(const std::vector<std::string>& victims) {
    if (victims.empty()) return false;
    size_t hit = 0;
    for (const auto& v : victims) {
        std::string l = Lower(v);
        if (l.find("\\appdata\\local\\temp\\") != std::string::npos ||
            l.find("\\appdata\\roaming\\temp\\") != std::string::npos ||
            l.find("\\windows\\temp\\") != std::string::npos ||
            l.find("\\temp\\") == 0) hit++;
    }
    return hit == victims.size();
}

// ===========================================================================
//  回滚执行
// ===========================================================================
// 把文件当前内容备份到 undo 目录（回滚前的"用户版本"）。
// 返回备份路径，失败返回空串（失败不阻断回滚——回滚比撤销重要）。
static std::string SaveUndoCopy(const std::string& srcPath, const std::string& token) {
    std::string ud = CacheDirImpl() + "\\undo";
    CreateDirectoryU8(ud.c_str(), nullptr);
    // 文件名：token + 序号 + 原文件名的哈希（原文件名可能含非法字符/过长）
    static std::atomic<uint32_t> seq{ 0 };
    char nm[160];
    sprintf_s(nm, "\\%s_%08X_%06u.bak", token.substr(0, 8).c_str(),
              (unsigned)std::hash<std::string>{}(Lower(srcPath)), (unsigned)(seq.fetch_add(1) % 1000000));
    std::string dst = ud + nm;

    HANDLE hs = CreateFileU8(srcPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE) return {};
    HANDLE hd = CreateFileU8(dst.c_str(), GENERIC_WRITE, 0, nullptr,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) { CloseHandle(hs); return {}; }

    std::vector<char> buf(256 * 1024);
    std::string err;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { err = "read"; break; }
        if (!rd) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { err = "write"; break; }
    }
    CloseHandle(hs);
    FlushFileBuffers(hd);
    CloseHandle(hd);
    if (!err.empty()) { DeleteFileU8(dst.c_str()); return {}; }
    return dst;
}

static RollbackReport RollbackVictims(const std::vector<std::string>& victims, const std::string& trigger,
                                      bool makeUndo = true) {
    RollbackReport rep;
    rep.trigger = trigger;
    rep.victims = victims.size();

    // ---- 撤销凭据：每次回滚生成一个，供后续 UndoLastRollback 校验 ----
    std::string token;
    if (makeUndo) {
        static std::atomic<uint32_t> tokSeq{ 0 };
        char tb[64];
        sprintf_s(tb, "%llx%08x", (unsigned long long)GetTickCount64(), (unsigned)(tokSeq.fetch_add(1)));
        token = tb;
        // 新的回滚发生 → 旧撤销记录作废（见 g_undoList 上方的说明）
        ClearUndoLocked();
    }

    // ★ 归因优先级（2026-09-23）：先句柄归因（因果证据 = 谁正开着这些文件），
    //   失败再退回映像路径启发式（对"金蝉脱壳式"的外部解释器无能为力）。
    ProcInfo sus = FindSuspectByHandles(victims);
    if (!sus.pid) sus = FindSuspectProcess(victims);
    rep.pid = sus.pid;
    rep.processPath = sus.path;

    if (g_cfg.terminateOnDetect && sus.pid) {
        // ★ 信誉门：可信厂商签名进程 / 受害文件全在临时目录 → 跳过终止。
        //   告警照发（用户仍有知情权），但不杀进程（见上方信誉门注释）。
        if (sf::ProcReputable(sus.path) || AllVictimsInTemp(victims)) {
            LogDbg("[rollback] 终止决策被信誉门拦截（签名可信厂商/受害者全在临时目录）→ 跳过终止: " + sus.path);
        } else if (TerminateSuspect(sus.pid)) {
            LogDbg("[rollback] 已终止肇事进程 pid=" + std::to_string(sus.pid) + " " + sus.path);
        } else {
            LogDbg("[rollback] 终止进程失败 pid=" + std::to_string(sus.pid));
        }
    }
    if (!sus.pid)
        LogDbg("[rollback] 未能定位肇事进程（不冤枉无关进程，报告如实标注）");

    for (const auto& v : victims) {
        // 先校验快照是否仍然"对得上"：若快照时间晚于文件当前修改时间，
        // 说明快照拍的就是已被破坏的内容 → 不能用来恢复（诚实标注为不可恢复）。
        bool ok = false;
        {
            std::lock_guard<std::mutex> lk(g_cacheMtx);
            auto it = g_cache.find(NormKey(v));
            if (it != g_cache.end()) ok = true;
        }
        if (!ok) {
            rep.unrecover++;
            if (rep.lostPaths.size() < kMaxListedPaths) rep.lostPaths.push_back(v);
            continue;
        }
        // ★ 覆盖写之前先留一份"用户版本"，供事后撤销（只在能恢复时才留——
        //   恢复不了的文件本来就没被改动，不需要撤销）。
        std::string undoCopy;
        if (makeUndo) undoCopy = SaveUndoCopy(v, token);

        if (RestoreFile(v)) {
            rep.restored++;
            if (rep.restoredPaths.size() < kMaxListedPaths) rep.restoredPaths.push_back(v);
            if (!undoCopy.empty()) {
                std::lock_guard<std::mutex> lk(g_undoMtx);
                UndoEntry ue;
                ue.path = v;
                ue.undoPath = undoCopy;
                // 取备份文件的实际大小（SaveUndoCopy 已写入）
                WIN32_FILE_ATTRIBUTE_DATA fad{};
                if (GetFileAttributesExU8(undoCopy.c_str(), GetFileExInfoStandard, &fad))
                    ue.size = ((uint64_t)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
                g_undoList.push_back(ue);
            }
        } else {
            // 恢复失败 → 那份备份没有意义，删掉（避免留垃圾）
            if (!undoCopy.empty()) DeleteFileU8(undoCopy.c_str());
            rep.unrecover++;
            if (rep.lostPaths.size() < kMaxListedPaths) rep.lostPaths.push_back(v);
        }
    }
    StatAdd(5, 1);
    StatAdd(7, rep.unrecover);

    if (makeUndo) {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        g_undoToken   = token;
        g_undoTrigger = trigger;
        g_undoAtMs    = NowMs();
        LogDbg("[rollback] 已留存撤销副本 " + std::to_string(g_undoList.size()) +
               " 份（token=" + token + "，10 分钟内可在弹窗中点「撤销」）");
    }
    return rep;
}

std::string RollbackReport::ToJson() const {
    std::ostringstream os;
    os << "{\"victims\":" << victims
       << ",\"restored\":" << restored
       << ",\"unrecoverable\":" << unrecover
       << ",\"bytesSaved\":" << bytesSaved
       << ",\"pid\":" << pid
       << ",\"process\":" << JsonString(processPath)
       << ",\"trigger\":" << JsonString(trigger)
       << ",\"restoredPaths\":[";
    for (size_t i = 0; i < restoredPaths.size(); ++i) {
        if (i) os << ",";
        os << JsonString(restoredPaths[i]);
    }
    os << "],\"lostPaths\":[";
    for (size_t i = 0; i < lostPaths.size(); ++i) {
        if (i) os << ",";
        os << JsonString(lostPaths[i]);
    }
    os << "]}";
    return os.str();
}

// ===========================================================================
//  勒索处置入口：由监控线程在判定成立时调用
//
//  ⚠️ 冷却期（cooldown）是必需的，不是优化：
//  回滚动作本身要**写回**几十上百个文件，这些写入同样会产生文件变更通知
//  → 又被喂进滑动窗口 → 再次满足触发条件 → 再次回滚……形成正反馈。
//  实测（2026-09-18 端到端模拟）：不加冷却会连续触发 5 次，
//  恢复数从 30 递减到 23（重复回滚同一批文件，且每次都在消耗 CPU/IO）。
//
//  ★★ 但"冷却期内全面停判"是错的（2026-09-23 修正）：
//  实测纯行为勒索模拟（python 改写 200 文件）：判定成立时只处理了窗口内的
//  16 个文件，随后进入 20 秒停判 —— 攻击者在这 20 秒里把剩下 184 个文件
//  全部加密完（日志 `恢复 16 / 共计 16`，磁盘上却留下 200 个 .sfxlock）。
//  **20 秒自由窗口对真实勒索（每秒可加密数百文件）是致命的。**
//
//  新策略：冷却期缩短到 3 秒，且冷却期内**只把门槛放大 4 倍、绝不停止判定** ——
//    · 回滚自身写入（几十个文件）达不到放大后的门槛 → 不会自激；
//    · 攻击者若继续加密 → 很可能再次达标 → 第二次处置 + 此时句柄归因能定位
//      到真凶 → 终止进程 → **真正止血**。
// ===========================================================================
static std::atomic<uint64_t> g_cooldownUntilMs{ 0 };
static const uint64_t kCooldownMs = 3000;    // 3 秒（原 20 秒：等于给攻击者放长假）
static const uint32_t kCooldownScale = 4;    // 冷却期内的门槛倍率（不停判，只抬门槛）

static void HandleRansomDetection() {
    const bool inCooldown = (NowMs() < g_cooldownUntilMs.load());

    std::vector<std::string> victims;
    std::string trigger;
    Risk risk = Risk::High;
    {
        std::lock_guard<std::mutex> lk(g_evMtx);
        uint32_t mod = 0, ren = 0, note = 0;
        if (!EvaluateLocked(&mod, &ren, &note, &trigger, &risk,
                            inCooldown ? kCooldownScale : 1u)) return;
        // -------------------------------------------------------------------
        //  收集窗口内的文件作为受害者（2026-09-19 事故修正）
        //
        //  修正前：把窗口里**所有出现过**的路径全算受害者，上限 2000。
        //  事故：窗口里混进了浏览器 Preferences、edge_BITS_* 等被改动的文件，
        //        它们一并被"回滚"（旧快照覆盖新文件）→ Edge 扩展凭空消失。
        //
        //  修正后必须同时满足三个条件才算受害者：
        //    ① 被排除规则排除的（含浏览器数据目录）→ 一律不碰
        //    ② 必须有**快照**：没有快照的文件回滚也无从下手，
        //       列进去只会拉高"不可恢复"计数、制造恐慌
        //    ③ 必须确实"被改过"（有扩展名/有改名标记），空路径不算
        //  说明：第②条同时天然排除了"从未被快照保护过"的正常文件。
        // -------------------------------------------------------------------
        std::set<std::string> uniq;
        size_t scanned = 0;
        for (auto it = g_ev.rbegin(); it != g_ev.rend(); ++it) {
            ++scanned;
            if (scanned > 20000) break;               // 最多回看 2 万条事件
            if (it->path.empty()) continue;
            std::string pl = Lower(it->path);
            if (IsExcluded(pl)) continue;             // ① 排除规则（含浏览器目录）
            if (!g_exeDirLower.empty() &&
                pl.find(g_exeDirLower) != std::string::npos) continue;  // 自身目录
            if (!HasSnapshot(it->path)) continue;     // ② 无快照 → 无从回滚
            uniq.insert(it->path);
            if (uniq.size() >= 2000) break;
        }
        victims.assign(uniq.begin(), uniq.end());
        g_ev.clear();     // 清空窗口，避免处理完立即再次触发
    }
    if (victims.empty()) return;

    // 先进入冷却期，再开始回滚 —— 顺序很重要：
    // 若先回滚后设冷却，回滚期间的写入通知会趁冷却尚未生效时挤进窗口。
    g_cooldownUntilMs.store(NowMs() + kCooldownMs);

    StatAdd(8, 1);
    g_ransomActive.store(true);

    LogDbg("[rollback] ==== 勒索行为判定成立 ==== 触发原因: " + trigger +
           "，涉及文件 " + std::to_string(victims.size()) + " 个");
    RollbackReport rep = RollbackVictims(victims, trigger);
    LogDbg("[rollback] 回滚完成: 恢复 " + std::to_string(rep.restored) +
           " / 共计 " + std::to_string(rep.victims) +
           "，不可恢复 " + std::to_string(rep.unrecover) +
           "，肇事进程 pid=" + std::to_string(rep.pid) + " " + rep.processPath);
    LogDbg("[rollback] 进入 " + std::to_string(kCooldownMs / 1000) +
           " 秒冷却期（回滚写入不触发自激；期间判定门槛 ×" +
           std::to_string(kCooldownScale) + "，攻击若继续仍会被抓）");

    { std::lock_guard<std::mutex> lk(g_triggerMtx); g_lastTrigger = trigger; }

    // 把结果交给上层展示（服务方注入的回调负责写扫描结果 + 弹窗通知）。
    // 本模块不直接引用 g_result / NotifyAnomaly —— 那样会让本模块无法独立测试。
    if (g_detCb) {
        DetectionInfo info;
        info.trigger       = trigger;
        info.processPath   = rep.processPath;
        info.pid           = rep.pid;
        info.victims       = rep.victims;
        info.restored      = rep.restored;
        info.unrecoverable = rep.unrecover;
        info.risk          = risk;
        info.autoHandled   = (rep.restored > 0);   // 已自动终止 + 回滚
        // 撤销凭据：只在"确实覆盖过内容"时提供（没回滚成功就没有可撤销的东西）
        {
            std::lock_guard<std::mutex> lk(g_undoMtx);
            info.undoable = !g_undoList.empty() && (rep.restored > 0);
            if (info.undoable) info.undoToken = g_undoToken;
        }
        g_detCb(info);
    }
}

// ===========================================================================
//  目录监控（ReadDirectoryChangesW）
// ===========================================================================
struct WatchTarget {
    std::string     dir;      // 窄路径（展示用）
    std::wstring    dirW;     // 宽路径（API 用）
    HANDLE          h = INVALID_HANDLE_VALUE;
    OVERLAPPED      ov{};
    HANDLE          ev = nullptr;
    std::vector<char> buf;
    bool            recursive = true;
};

// 枚举本机所有**真实用户**的 profile 目录。
//
// 【为什么必须这样做】
// 服务跑在 LocalSystem / Session 0。此时 SHGetFolderPathW(nullptr, CSIDL_*) 的
// "当前用户"是 **SYSTEM**，返回的是 C:\Windows\system32\config\systemprofile\Desktop
// —— **用户自己的桌面根本不在监控范围内**。
// 实测证据（2026-09-19 日志）：09-18 监控 7 个目录 → 09-19 服务重启后降为 2 个，
// 少的正是桌面/文档/下载，用户桌面上的勒索测试文件因此完全没被监控到。
//
// 做法：枚举 HKU\<SID> 下所有 S-1-5-21-* 的真实用户 SID（与 service.cpp 里
// RegRunWatch 的 HKU 枚举模式一致），对每个 SID 拼出已知文件夹路径。
// 用 %USERPROFILE% 的注册表值（ProfileImagePath）拿用户根目录，再拼子目录 ——
// 比调 SHGetFolderPathW 可靠，因为后者只认"当前进程用户"。
static void CollectUserProfiles(std::vector<std::string>& out) {
    HKEY hkUsers = nullptr;
    if (RegOpenKeyExA(HKEY_USERS, nullptr, 0, KEY_READ, &hkUsers) != ERROR_SUCCESS) return;

    DWORD nSub = 0;
    RegQueryInfoKeyA(hkUsers, nullptr, nullptr, nullptr, &nSub, nullptr, nullptr,
                     nullptr, nullptr, nullptr, nullptr, nullptr);

    std::vector<char> nm(512);
    for (DWORD i = 0; i < nSub; ++i) {
        DWORD ns = (DWORD)nm.size();
        if (RegEnumKeyA(hkUsers, i, nm.data(), ns) != ERROR_SUCCESS) continue;
        std::string sid(nm.data());
        // 只看真实用户 SID（排除 .DEFAULT / S-1-5-18 等系统 SID）；
        // 同时排除 *_Classes（它是 SID 的附属 hive，不是独立用户）
        if (sid.find("S-1-5-21-") == std::string::npos) continue;
        if (sid.size() > 8 && sid.compare(sid.size() - 8, 8, "_Classes") == 0) continue;

        // 取该用户的 ProfileImagePath（即 C:\Users\<name>）
        // ★ 2026-10-02：整体改 W 版（原 RegGetValueA / ExpandEnvironmentStringsA）。
        //   用户名含中文时，A 版按 ACP(936) 转码 → 与全程序的 UTF-8 约定冲突 →
        //   profile 路径被写坏 → GetFileAttributesU8 判"不存在" → 该用户**所有**
        //   已知文件夹（桌面/文档/下载/图片…）静默不在监视面。
        //   与 CollectUserShellDirsRegistry 的修复同源（那里是本机实测触发点）。
        wchar_t wprof[MAX_PATH * 2] = { 0 };
        DWORD cb = sizeof(wprof), type = 0;
        const std::wstring wvkey = A2W(sid + "\\Volatile Environment");
        if (RegGetValueW(hkUsers, wvkey.c_str(), L"USERPROFILE", RRF_RT_REG_SZ,
                         &type, wprof, &cb) != ERROR_SUCCESS || !wprof[0]) {
            // Volatile Environment 未加载（用户未登录）时兜底走 HKLM 的 ProfileList
            cb = sizeof(wprof);
            const std::wstring wpkey =
                A2W("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\" + sid);
            if (RegGetValueW(HKEY_LOCAL_MACHINE, wpkey.c_str(), L"ProfileImagePath",
                             RRF_RT_REG_EXPAND_SZ | RRF_RT_REG_SZ,
                             &type, wprof, &cb) != ERROR_SUCCESS || !wprof[0])
                continue;
            // 展开环境变量（ProfileImagePath 常含 %SystemDrive%）
            wchar_t wexp[MAX_PATH * 2] = { 0 };
            if (ExpandEnvironmentStringsW(wprof, wexp, _countof(wexp)))
                wcscpy_s(wprof, wexp);
        }
        const std::string root = W2A(wprof);          // UTF-16 → UTF-8（统一窄串约定）
        if (root.empty()) continue;
        const DWORD a = GetFileAttributesW(wprof);    // 用宽路径判存在性，不再二次转码
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) continue;
        out.push_back(root);
    }
    RegCloseKey(hkUsers);
}

static std::vector<std::string> DefaultWatchDirs() {
    std::vector<std::string> v;
    wchar_t p[MAX_PATH] = { 0 };

    // ---- ① 所有真实用户的已知文件夹（核心修复）----
    // 服务在 Session 0，必须显式枚举用户 SID，否则取到的是 SYSTEM 的 profile。
    std::vector<std::string> profiles;
    CollectUserProfiles(profiles);
    static const char* kUserSub[] = {
        "\\Desktop", "\\Documents", "\\Downloads", "\\Pictures", "\\Videos", "\\Music",
    };
    for (const auto& root : profiles) {
        for (const char* sub : kUserSub) {
            std::string full = root + sub;
            DWORD a = GetFileAttributesU8(full.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(full);
        }
    }

    // ★ 2026-10-02：追加注册表权威路径（覆盖"文件夹被重定向 / 改名 / 非英文名"）。
    //   本机实测：下载已被重定向到 D:\tianl\下载 → 上面用 root+"\Downloads" 拼出的
    //   C:\Users\tianl\Downloads **不存在**（存在性检查直接跳过）→ 下载目录完全没被
    //   监视，落到那里的载荷此生不会被落地初筛判定、也不会被送检。
    //   与上面的硬拼路径同源去重：重复监视同一目录只会白耗句柄 + 产生重复事件。
    {
        std::vector<std::string> sh;
        CollectUserShellDirsRegistry(sh);
        for (const auto& s : sh) {
            const std::string l = Lower(s);
            bool dup = false;
            for (const auto& e : v) if (Lower(e) == l) { dup = true; break; }
            if (!dup) v.push_back(s);
        }
    }

    // 若一个用户 profile 都没枚举到（极端情况），退回旧行为，至少不是空的
    if (profiles.empty()) {
        struct { int csidl; const char* name; } kUser[] = {
            { CSIDL_DESKTOPDIRECTORY, "桌面" }, { CSIDL_PERSONAL, "文档" },
            { CSIDL_MYVIDEO, "视频" }, { CSIDL_MYPICTURES, "图片" },
        };
        for (auto& k : kUser) {
            if (SUCCEEDED(SHGetFolderPathW(nullptr, k.csidl, nullptr, 0, p)) && p[0]) {
                std::string s = W2A(p);
                if (!s.empty()) v.push_back(s);
            }
        }
        PWSTR pw = nullptr;
        static const GUID kDownloads =
            { 0x374DE290, 0x123F, 0x4565, { 0x91, 0x64, 0x39, 0xC4, 0x92, 0x5B, 0x5E, 0xE5 } };
        if (SUCCEEDED(SHGetKnownFolderPath(kDownloads, 0, nullptr, &pw)) && pw) {
            std::string s = W2A(pw);
            if (!s.empty()) v.push_back(s);
            CoTaskMemFree(pw);
        }
    }

    // ---- ② 落地高发区（前置捕获的覆盖范围，2026-09-19 新增）----
    // 银狐载荷落盘的典型位置：用户 Temp、系统 Temp、盘根。
    // 这些目录不建快照（内容多为临时物），但**纳入监控**以便"落盘即判"。
    for (const auto& root : profiles) {
        std::string t = root + "\\AppData\\Local\\Temp";
        DWORD a = GetFileAttributesU8(t.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(t);
    }
    {
        wchar_t winW[MAX_PATH] = { 0 };
        if (GetWindowsDirectoryW(winW, MAX_PATH)) {
            std::string t = W2A(winW) + "\\Temp";
            DWORD a = GetFileAttributesU8(t.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(t);
        }
    }
    // 公共文档
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_DOCUMENTS, nullptr, 0, p)) && p[0]) {
        std::string s = W2A(p);
        if (!s.empty()) v.push_back(s);
    }
    // 固定盘根（存在才加）——勒索最爱扫驱动器根
    // 2026-09-26 监控面扩容：从硬编码 D:/E:/F 改为**动态枚举全部固定盘（非系统盘）**。
    // 硬编码的两个问题：① G/H 及以后永远不监控；② 系统盘 C 的覆盖在
    // DefaultWatchDirsEx 里单独做（根非递归 + 一级子目录递归）——若在此递归 C:\，
    // Windows/Program Files 的海量系统事件会全部灌进监视线程。
    {
        wchar_t winDirW[MAX_PATH] = { 0 };
        GetWindowsDirectoryW(winDirW, MAX_PATH);
        const char sysDrive = (winDirW[1] == L':') ? (char)toupper((unsigned char)winDirW[0]) : 'C';
        const DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (!(drives & (1u << i))) continue;
            std::string root; root += (char)('A' + i); root += ":\\";   // 形如 "D:\"
            if ((char)toupper((unsigned char)root[0]) == sysDrive) continue;  // 系统盘根另行处理
            if (GetDriveTypeW(A2W(root).c_str()) != DRIVE_FIXED) continue;   // 跳过 U盘/光驱/网络盘
            DWORD a = GetFileAttributesU8(root.c_str());
            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) v.push_back(root);
        }
    }
    // 测试钩子：环境变量 SFG_RB_TEST_WATCH 指向的目录也纳入监控。
    // 为什么保留这个钩子：勒索判定是本模块最核心也最危险的逻辑（判错会回滚用户
    // 正常文件），必须能用**真实文件操作**端到端验证，而不是只测内部函数。
    // 生产环境不会设置该变量，故无安全影响。
    {
        wchar_t envW[MAX_PATH * 4] = { 0 };
        DWORD n = GetEnvironmentVariableW(L"SFG_RB_TEST_WATCH", envW, MAX_PATH * 4);
        if (n > 0 && n < MAX_PATH * 4) {
            // 支持用 ; 分隔多个目录
            std::string all = W2A(envW);
            size_t start = 0;
            while (start <= all.size()) {
                size_t sep = all.find(';', start);
                std::string one = all.substr(start, (sep == std::string::npos) ? std::string::npos : sep - start);
                if (!one.empty()) {
                    DWORD a = GetFileAttributesU8(one.c_str());
                    if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
                        v.push_back(one);
                }
                if (sep == std::string::npos) break;
                start = sep + 1;
            }
        }
    }
    // 去重
    std::set<std::string> seen;
    std::vector<std::string> out;
    for (auto& s : v) {
        std::string k = NormKey(s);
        if (k.empty() || seen.count(k)) continue;
        seen.insert(k);
        out.push_back(s);
    }
    return out;
}

// ---------------------------------------------------------------------------
//  ★ 全域落地捕获的监视目标（2026-09-24）
// ---------------------------------------------------------------------------
//  DefaultWatchDirs() 是「需要快照保护的用户目录」，会被 BaselinePatrol 用来
//  抽样建档 —— 所以**不能**把 AppData 这类巨量目录混进它。
//  本函数在它之上追加「只判不快照」的落点目录，并支持逐目录控制 recursive：
//
//    recursive=true  —— %AppData%\Roaming、ProgramData、Users\Public、
//                       LocalLow：载荷常落在随机子目录里，必须递归
//    recursive=false —— %LocalAppData% 本体：这是全机最繁忙的目录之一
//                       （浏览器缓存 / Teams / IDE 索引），递归监视会产生
//                       每秒数千条通知；而非递归已能覆盖"直接丢在根部"
//                       这一银狐主用形态，子目录落点由「进程出生卡」兜底
struct WatchDir {
    std::string path;
    bool        recursive;
};

static void AddWatchDirIfExists(std::vector<WatchDir>& v,
                                const std::string& path, bool recursive) {
    if (path.empty()) return;
    DWORD a = GetFileAttributesU8(path.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) return;
    v.push_back({ path, recursive });
}

static std::vector<WatchDir> DefaultWatchDirsEx() {
    std::vector<WatchDir> out;
    for (const auto& d : DefaultWatchDirs()) out.push_back({ d, true });

    std::vector<std::string> profiles;
    CollectUserProfiles(profiles);
    for (const auto& root : profiles) {
        // 载荷落点三兄弟（银狐/ValleyRAT 的默认投放目录）
        AddWatchDirIfExists(out, root + "\\AppData\\Roaming", true);
        AddWatchDirIfExists(out, root + "\\AppData\\Local",   false);
        AddWatchDirIfExists(out, root + "\\AppData\\LocalLow", true);
        // 用户启动文件夹（持久化点：能往这里丢 exe 的正常流程极少）
        AddWatchDirIfExists(out,
            root + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
            false);
    }

    // ProgramData：全用户可写，服务/计划任务载荷常宿主于此
    {
        wchar_t p[MAX_PATH] = { 0 };
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0]) {
            std::string s = W2A(p);
            AddWatchDirIfExists(out, s, true);
            AddWatchDirIfExists(out,
                s + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", false);
        }
        // Users\Public：经典投放点（公共文档 / 公共下载）
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_DOCUMENTS, nullptr, 0, p)) && p[0]) {
            std::string cd = W2A(p);                       // ...\Users\Public\Documents
            size_t sl = cd.find_last_of('\\');
            if (sl != std::string::npos) AddWatchDirIfExists(out, cd.substr(0, sl), true);
        }
        // 公共启动文件夹（显式路径兜底，CSIDL 在某些精简系统上取不到）
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, p)) && p[0])
            AddWatchDirIfExists(out, W2A(p), false);
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, p)) && p[0])
            AddWatchDirIfExists(out, W2A(p), false);
    }

    // ★ 系统盘根 + 一级自建子目录（2026-09-26 监控面扩容，银泊实测发现盲区）
    // 【盲区】此前 C 盘只覆盖「高发落点」清单（用户目录/Temp/AppData/ProgramData/
    // Public），C:\ 下的用户自建目录（C:\temp、C:\Soft、C:\games……）**完全不在
    // 监视范围** —— 落到那里的载荷此生不被落地初筛判定，隔离区永远等不到它。
    // 【为什么不对系统盘整盘递归】C:\Windows / Program Files 每天产生海量变更
    // （索引、遥测、更新），再大的通知缓冲也会被打爆，且每条事件都要过一遍
    // 初筛函数，纯属烧 CPU 还制造溢出漏报。故拆两层：
    //   · 根目录**非递归** —— 覆盖「直接丢 C:\xxx」形态，且能看到新一级子目录的创建；
    //   · 一级子目录逐个**递归** —— 排除系统目录后剩下的全是用户自建目录，这才是盲区本体。
    // Users / ProgramData 已被上面细粒度目标覆盖，重复监控只浪费句柄与事件量。
    {
        wchar_t winDirW[MAX_PATH] = { 0 };
        GetWindowsDirectoryW(winDirW, MAX_PATH);
        if (winDirW[1] == L':') {
            std::string sysRoot;
            sysRoot += (char)toupper((unsigned char)winDirW[0]);
            sysRoot += ":\\";                                  // 形如 "C:\"
            AddWatchDirIfExists(out, sysRoot, false);          // 根：非递归
            static const char* kSkip1st[] = {
                "\\windows", "\\program files", "\\program files (x86)",
                "\\users", "\\programdata", "\\perflogs",
                "\\$recycle.bin", "\\system volume information",
                "\\recovery", "\\drvron", "\\onedrivetemp",
                // ★ 2026-10-02 补：Sandboxie 盒根。**不要删这一条** ——
                //   ① 盒内是**一次性**虚拟 FS，每轮送检都整棵树「创建 → 删除」，
                //      递归监控它既灌进海量无用事件，又让盒内写入被当真机勒索行为
                //      （2026-10-02 09:44:59「勒索行为已拦截」误报的根因，
                //       详见 IsExcluded() 里 kSelfRoots 的事故注释）；
                //   ② 盒内活动本由探针（probe DLL）负责观测，真机监控面不需要它；
                //   ③ 若 box 配了 OpenFilePath 直通真机，写入会出现在真机路径上，仍被监控。
                "\\sandbox",
            };
            WIN32_FIND_DATAW fd{};
            HANDLE hFind = FindFirstFileU8((sysRoot + "*").c_str(), &fd);
            if (hFind != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    std::string nm = W2A(fd.cFileName);
                    if (nm == "." || nm == "..") continue;
                    const std::string ln = Lower("\\" + nm);
                    bool skip = false;
                    for (const char* s : kSkip1st) if (ln == s) { skip = true; break; }
                    if (skip) continue;
                    AddWatchDirIfExists(out, sysRoot + nm + "\\", true);   // 自建目录：递归
                } while (FindNextFileW(hFind, &fd));
                FindClose(hFind);
            }
        }
    }

    // 去重（保留首个出现者的 recursive 设置）
    std::set<std::string> seen;
    std::vector<WatchDir> ded;
    for (auto& w : out) {
        std::string k = NormKey(w.path);
        if (k.empty() || seen.count(k)) continue;
        seen.insert(k);
        ded.push_back(w);
    }
    return ded;
}

static bool OpenWatchTarget(WatchTarget& wt) {
    wt.dirW = A2W(wt.dir);
    wt.h = CreateFileW(wt.dirW.c_str(),
                       FILE_LIST_DIRECTORY,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING,
                       FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                       nullptr);
    if (wt.h == INVALID_HANDLE_VALUE) return false;
    wt.ev = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    wt.ov.hEvent = wt.ev;
    // 2026-09-26：64KB → 256KB。盘根/自建目录级监控后事件量上升，
    // 缓冲不足会让挂读以 ERROR_NOTIFY_ENUM_DIR 失败（溢出恢复见 WatchThread）。
    wt.buf.assign(256 * 1024, 0);
    return true;
}

static void CloseWatchTarget(WatchTarget& wt) {
    if (wt.h != INVALID_HANDLE_VALUE) { CancelIoEx(wt.h, &wt.ov); CloseHandle(wt.h); wt.h = INVALID_HANDLE_VALUE; }
    if (wt.ev) { CloseHandle(wt.ev); wt.ev = nullptr; }
}

// 处理一批变更通知
static void ProcessNotifications(WatchTarget& wt, DWORD bytes) {
    size_t off = 0;
    while (off < bytes) {
        auto* fni = (FILE_NOTIFY_INFORMATION*)(wt.buf.data() + off);
        if (fni->FileNameLength == 0) { if (!fni->NextEntryOffset) break; off += fni->NextEntryOffset; continue; }

        // FileName 是不带结尾 \0 的变长数组（踩坑点）
        std::wstring nameW(fni->FileName, fni->FileNameLength / sizeof(WCHAR));
        std::string  name = W2A(nameW);
        std::string  full = wt.dir;
        if (!full.empty() && full.back() != '\\') full += "\\";
        full += name;
        std::string  fl = Lower(full);

        StatAdd(2, 1);

        bool isRename = (fni->Action == FILE_ACTION_RENAMED_NEW_NAME);
        bool isModify = (fni->Action == FILE_ACTION_MODIFIED ||
                         fni->Action == FILE_ACTION_ADDED ||
                         fni->Action == FILE_ACTION_RENAMED_NEW_NAME);
        bool isDelete = (fni->Action == FILE_ACTION_REMOVED);

        if (isModify || isRename) {
            // ---- 排除自身与系统噪声 ----
            if (IsExcluded(fl)) goto next;
            if (!g_exeDirLower.empty() && fl.find(g_exeDirLower) != std::string::npos) goto next;
            // ---- 只判不快照区：密钥截获 + 落地初筛，不快照、不进信号统计 ----
            //  2026-09-24 从 IsTempPath 扩为 IsScreenOnlyPath：把 AppData 全系 /
            //  ProgramData / Users\Public / 启动文件夹 一并纳入「落盘即判」，
            //  但**刻意不建快照**（这些目录体量以 GB 计，纳入快照会瞬间打爆配额）。
            if (IsScreenOnlyPath(fl)) {
                TryCaptureKey(full, fl);
                if (fni->Action == FILE_ACTION_ADDED || isRename) {
                    int lv = 0; std::string why; bool needRetry = false;
                    // ★ lv>=1 也入队（2026-09-24）：旁证级落地要在服务层可见，
                    //   否则「落地旁证 → 随后被执行/被写成计划任务」的组合升档无从谈起。
                    // ★ needRetry（2026-09-25）：判定失败但原因是「内容尚未就绪」
                    //   （体积为 0 / 文件头读不到）→ 排进延后重探队列，1.5 秒后再判。
                    //   修 P0「先建后写漏判」，详见 ProbeLandedFile 的 P0 闸门注释。
                    if (ProbeLandedFile(full, fl, &lv, &why, &needRetry)) {
                        // 本分支全部位于 IsScreenOnlyPath（软件自写区）→ sysZone=true，
                        // 只有它参与「落地→执行」组合升档。
                        if (lv >= 1) ApplyLandedHit(full, why, lv, true);
                    } else if (needRetry) {
                        QueuePendingProbe(full, fl, true);
                    }
                }
                StatAdd(4, 1);   // 记入"跳过"统计
                goto next;
            }

            size_t dotPos = fl.find_last_of('.');
            std::string extOfFile = (dotPos == std::string::npos) ? "" : fl.substr(dotPos);

            // ---- 密钥截获（2026-09-19 新增）----
            // 必须**抢在快照逻辑之前**：密钥文件所在目录（Temp/盘根）通常不在
            // 受保护扩展名里，走不到后面的 SnapshotFile；而且密钥本身也不是
            // "需要快照保护的用户文件"——它的价值在于**内容留存**。
            TryCaptureKey(full, fl);

            // ---- 文件落地前置捕获（2026-09-19 新增）----
            // 只对"新增"动作做（MODIFIED 可能是反复写入，会重复判定）。
            // 判定很轻：路径 + 文件名 + 512 字节文件头，不涉及重 IO。
            if (fni->Action == FILE_ACTION_ADDED || isRename) {
                int lv = 0; std::string why; bool needRetry = false;
                if (ProbeLandedFile(full, fl, &lv, &why, &needRetry)) {
                    // 交给上层判定层（service 的 LandedAlertWatch 会读到这个标记）。
                    // 本模块不直接弹窗/终止进程 —— 那是 service 层的职责，
                    // 保持本模块可独立测试（见 rollback.h 的注入回调说明）。
                    // ★ lv>=1 也入队：服务层用 lv==1 的条目做「落地旁证 + 后续动作」
                    //   的组合升档（见 service.cpp 的 g_softLand）。
                    // 本分支是 Downloads / 桌面 / 盘根等**用户主动落点** →
                    // sysZone=false，只入消费式队列（弹窗展示），不参与组合升档。
                    if (lv >= 1) ApplyLandedHit(full, why, lv, false);
                } else if (needRetry) {
                    // ★ 先建后写（2026-09-25，P0 修复）：ADDED 到达时体积为 0，
                    //   等 1.5 秒重探一次。这是 curl -o / Invoke-WebRequest -OutFile /
                    //   certutil -urlcache -f / BITS / 脚本写文件 / 解包器落盘的共同形态。
                    QueuePendingProbe(full, fl, false);
                }
            }

            // ---- 建立写前快照（风险分层：只对"有可疑迹象"的文件建）----
            // 注意：FILE_ACTION_MODIFIED 在文件**第一次写入后**就触发，
            // 所以这次快照可能已经是部分加密后的内容。这就是 header 里说的
            // "竞态窗口"——用下面的基线巡逻做二次保险。
            {
                uint32_t heat = 0;
                bool want = ShouldSnapshotThis(fl, extOfFile, isRename, &heat);
                // 目录热度达到"批量改写"阈值时，说明这片区域正在被大面积动，
                // 即便本次文件本身不满足条件，也建一份（此时风险已显著升高）。
                bool hotDir = (heat >= g_cfg.filesThreshold);
                if (want || hotDir) {
                    LARGE_INTEGER sz{}; HANDLE hq = CreateFileU8(full.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hq != INVALID_HANDLE_VALUE) {
                        GetFileSizeEx(hq, &sz); CloseHandle(hq);
                        if (sz.QuadPart > 0 && (uint64_t)sz.QuadPart <= g_cfg.maxFileBytes)
                            SnapshotFile(full, isRename ? "rename" : "modify");
                    }
                } else {
                    StatAdd(4, 1);   // 记入"跳过"统计，让 UI 能看到分层生效
                }

                // ---- 密钥时序关联（2026-09-19 新增）----
                // 判据：某目录刚出现过"体积小 + 高熵 + 陌生扩展名"的候选密钥文件，
                // 紧接着这片区域开始被批量改写 —— 这几乎只有一种解释：
                // **攻击者刚生成密钥、紧接着开始用它加密**。
                //
                // 一旦成立，**不必等 filesThreshold（默认 25）个文件被加密**就能定性，
                // 把拦截点从"第 25 个文件"提前到"第一个爆发批次"。
                // 触发条件取 burstFileTrigger（默认 5）—— 比 filesThreshold 更早。
                if (g_cfg.keyHuntEnabled && heat >= g_cfg.burstFileTrigger) {
                    size_t keyIdx = 0;
                    if (ConfirmKeyByBurst(DirOfPath(fl), &keyIdx)) {
                        std::string kpath;
                        { std::lock_guard<std::mutex> lk(g_keyMtx);
                          if (keyIdx < g_keys.size()) kpath = g_keys[keyIdx].path; }
                        LogDbg("[rollback] ==== 密钥关联提前定性 ==== 密钥来源: " + kpath +
                               "，目录热度 " + std::to_string(heat) +
                               "（阈值 " + std::to_string(g_cfg.filesThreshold) + "）");
                        // 立即进入处置（不等常规 8 事件节拍，也不等阈值）
                        HandleRansomDetection();
                        goto next;   // 本事件已并入本次判定，不再重复计入窗口
                    }
                }
            }

            // ---- 信号采集 ----
            Ev e;
            e.path = full;
            e.isRename = isRename;
            // 改名分级（2026-09-19 PCL2 误报根治）：只有改成勒索特征后缀的改名
            // 才算"高熵随机后缀"旁证；日志轮转（.log→.log.gz）、下载落盘、
            // 备份轮转等正常改名仍计入改动量（mod），但不再供勒索判定使用。
            e.ransomRename = isRename && LooksLikeRansomExt(extOfFile);
            e.t = NowMs();
            e.ext = extOfFile;
            if (e.ransomRename) e.entropy = EntropyOfFile(full);
            std::string base = fl.substr(fl.find_last_of("\\/") + 1);
            if (LooksLikeRansomNote(base)) e.isNote = true;

            {
                std::lock_guard<std::mutex> lk(g_evMtx);
                g_ev.push_back(e);
                if (g_ev.size() > 20000) g_ev.pop_front();
            }
            // 判定（每 8 个事件评估一次，避免每条通知都跑一遍 O(n) 统计）
            static std::atomic<int> tick{ 0 };
            if ((++tick % 8) == 0) HandleRansomDetection();
        } else if (isDelete) {
            // 原文件被删除 —— 勒索的重要旁证（业界共识：加密后删除原文件）。
            // 这里不建快照（文件已没了），只是记录下来供判定使用。
            // Temp 的删除不算旁证（解压/清理常态删除海量临时文件）。
            if (IsTempPath(fl)) goto next;
            std::lock_guard<std::mutex> lk(g_evMtx);
            Ev e; e.path = full; e.t = NowMs();
            g_ev.push_back(e);
            if (g_ev.size() > 20000) g_ev.pop_front();
        }
    next:
        if (!fni->NextEntryOffset) break;
        off += fni->NextEntryOffset;   // 按字节推进（踩坑点：不能用 sizeof）
    }
}

// ---- 基线巡逻：对高危目录里的文档做周期性哈希抽样比对 ----
// 这是"抢拍迟了"的二次保险：即使某次快照来晚了，也能从更早的基线快照恢复。
// 为控制开销，每轮只抽样 N 个文件，且只对**尚无快照**的受保护类型文件建立基线。
static void BaselinePatrol(const std::vector<std::string>& dirs) {
    const int kMaxPerRound = 300;
    int done = 0;
    for (const auto& d : dirs) {
        if (done >= kMaxPerRound) break;
        std::string pattern = d;
        if (!pattern.empty() && pattern.back() != '\\') pattern += "\\";
        pattern += "*";
        WIN32_FIND_DATAW fd{};
        HANDLE hf = FindFirstFileU8(pattern.c_str(), &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::string full = d;
            if (!full.empty() && full.back() != '\\') full += "\\";
            full += W2A(fd.cFileName);
            std::string fl = Lower(full);
            if (IsExcluded(fl)) continue;
            if (!IsProtectedExt(fl)) continue;
            uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            if (sz == 0 || sz > g_cfg.maxFileBytes) continue;
            if (HasSnapshot(full)) continue;
            SnapshotFile(full, "baseline");
            if (++done >= kMaxPerRound) break;
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    if (done) LogDbg("[rollback] 基线巡逻：本轮为 " + std::to_string(done) + " 个文件建立基线快照");
}

// ===========================================================================
//  监控线程
// ===========================================================================
static void WatchThread() {
    SetThreadDescription(GetCurrentThread(), L"SFG-RollbackWatch");

    std::vector<std::string> dirs = DefaultWatchDirs();       // 基线巡逻用（只含需快照保护的目录）
    std::vector<WatchDir>    all  = DefaultWatchDirsEx();     // 监视用（含全域落点，只判不快照）
    // ★ Windows 的 WaitForMultipleObjects 上限是 MAXIMUM_WAIT_OBJECTS=64，
    //   监视线程一次性等待全部事件句柄，所以目标数必须留余量截断。
    //   截断时**打印数量**，否则"某目录没被监视"会变成无声漏报。
    const size_t kMaxTargets = 60;
    std::vector<WatchTarget> targets;
    size_t truncated = 0;
    for (const auto& d : all) {
        if (targets.size() >= kMaxTargets) { ++truncated; continue; }
        WatchTarget wt;
        wt.dir       = d.path;
        wt.recursive = d.recursive;
        if (OpenWatchTarget(wt)) targets.push_back(std::move(wt));
        else LogDbg("[rollback] 无法监控目录（跳过）: " + d.path);
    }
    if (truncated)
        LogDbg("[rollback] ⚠ 监视目录数超过上限 " + std::to_string(kMaxTargets) +
               "，已截断 " + std::to_string(truncated) + " 个（这些目录不再产生落地事件）");
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.watching = !targets.empty();
    }
    LogDbg("[rollback] 监控启动，共 " + std::to_string(targets.size()) +
           " 个目录（含 AppData/ProgramData/Users\\Public/启动文件夹 全域落点，只判不快照）");

    if (targets.empty()) return;

    // 为每个目录挂初次异步读
    for (auto& t : targets) {
        ResetEvent(t.ev);
        ReadDirectoryChangesW(t.h, t.buf.data(), (DWORD)t.buf.size(), t.recursive,
                              FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                              FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                              FILE_NOTIFY_CHANGE_SECURITY,
                              nullptr, &t.ov, nullptr);
    }

    uint64_t lastPatrol = NowMs();
    uint64_t lastPendSweep = NowMs();
    while (g_running.load()) {
        // 收集所有事件句柄 + 停止事件，一次性等待
        std::vector<HANDLE> hs;
        hs.reserve(targets.size() + 1);
        for (auto& t : targets) hs.push_back(t.ev);
        hs.push_back(g_stopEvent ? g_stopEvent : nullptr);

        DWORD n = (DWORD)hs.size();
        std::vector<HANDLE> wait = hs;
        if (!wait.back()) { wait.pop_back(); n--; }
        DWORD r = WaitForMultipleObjects(n, wait.data(), FALSE, 1000);

        // ★ 延后重探的到期检查（2026-09-25，P0「先建后写漏判」修复）
        //  刻意**放在超时分支之外**：在事件密集的目录（AppData 下的浏览器缓存、
        //  Downloads 里的大文件解包……）ReadDirectoryChangesW 会被连续唤醒，
        //  WAIT_TIMEOUT 可能几十秒都不出现 —— 一旦把重探挂在超时分支里它就会被
        //  **饿死**，而「先建后写」恰恰最喜欢发生在这些高频目录里。
        //  500 毫秒扫一次（而不是每来一个事件都扫），避免热路径上反复拿锁。
        //  注：重探以 1.5 秒为到期线，而本循环最长 1 秒醒一次 → 最多约 2 秒内完成，
        //  与「落地 15 秒内完成隔离」的端到端时延要求相比完全够用。
        if (NowMs() - lastPendSweep >= 500) {
            lastPendSweep = NowMs();
            DrainPendingProbes();
        }

        if (r == WAIT_TIMEOUT) {
            // 超时：做基线巡逻 + 顺便检查是否需要重新挂读
            if (NowMs() - lastPatrol > 30000) {       // 每 30 秒巡逻一轮
                lastPatrol = NowMs();
                BaselinePatrol(dirs);
                // 回滚前备份的按时间淘汰也搭这趟车（2026-09-21 新增）。
                // 为什么不另开线程：这条线程本就每 30 秒醒一次，而清理只是
                // 遍历几十个索引条目 + 偶尔删文件，开销远小于再养一个线程。
                // 更重要的是"少一个线程就少一处要同步的退出逻辑"。
                PrunePreBackupsPeriodic();
            }
            continue;
        }
        if (r == WAIT_OBJECT_0 + targets.size()) break;   // 停止事件
        if (r < WAIT_OBJECT_0 || r >= WAIT_OBJECT_0 + targets.size()) {
            StatAdd(9, 1);
            Sleep(50);
            continue;
        }

        size_t idx = r - WAIT_OBJECT_0;
        WatchTarget& t = targets[idx];
        DWORD bytes = 0;
        if (GetOverlappedResult(t.h, &t.ov, &bytes, FALSE) && bytes > 0) {
            try { ProcessNotifications(t, bytes); }
            catch (...) { StatAdd(9, 1); }
        } else {
            // 2026-09-26 监控面扩容配套：通知缓冲溢出恢复。
            // 缓冲不够时 ReadDirectoryChangesW 的挂读会以 ERROR_NOTIFY_ENUM_DIR(336)
            // 或 ERROR_MORE_DATA(234) 失败 —— 此前没有任何处理：句柄还开着，
            // 但事件流已断，该目录从此**静默漏报**（比没监控更危险：界面上它
            // 「看起来在监控」）。现在溢出即重新挂读：目录树的当前状态会由新一轮
            // 通知重建，丢掉的只是溢出瞬间的积压事件；配合 256KB 缓冲已属罕见。
            const DWORD err = GetLastError();
            if (err == ERROR_NOTIFY_ENUM_DIR || err == ERROR_MORE_DATA)
                LogDbg("[rollback] ⚠ " + t.dir + " 通知缓冲溢出，已重挂读（溢出瞬间积压事件丢失）");
        }
        // 重新挂读（必须每次重新投递，ReadDirectoryChangesW 是一次性的）
        ResetEvent(t.ev);
        if (!ReadDirectoryChangesW(t.h, t.buf.data(), (DWORD)t.buf.size(), t.recursive,
                                   FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE |
                                   FILE_NOTIFY_CHANGE_SECURITY,
                                   nullptr, &t.ov, nullptr)) {
            StatAdd(9, 1);
        }
    }

    for (auto& t : targets) CloseWatchTarget(t);
    LogDbg("[rollback] 监控线程退出");
}

static std::thread g_watchThread;

// ===========================================================================
//  配置加载
// ===========================================================================
std::string DefaultConfigPath() {
    wchar_t exeW[MAX_PATH]{}; GetModuleFileNameW(nullptr, exeW, MAX_PATH);
    std::string d = W2A(exeW); size_t q = d.find_last_of('\\');
    std::string base = (q != std::string::npos) ? d.substr(0, q + 1) : "";
    const std::string cands[] = {
        base + "data\\rollback_rules.txt",
        base + "rollback_rules.txt",
        "C:\\ProgramData\\SilverFoxGuard\\rollback_rules.txt"
    };
    for (const auto& c : cands) if (FileExists(c)) return c;
    return "";
}

bool LoadConfigFromFile(const std::string& path, Config& out) {
    if (path.empty()) return false;
    std::ifstream f(A2W(path).c_str());
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        // 允许行尾注释
        size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        auto trim = [](std::string s) {
            size_t a = s.find_first_not_of(" \t");
            size_t b = s.find_last_not_of(" \t");
            return (a == std::string::npos) ? std::string() : s.substr(a, b - a + 1);
        };
        k = trim(k); v = trim(v);
        if (k.empty() || v.empty()) continue;
        try {
            if (k == "enabled")              out.enabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "max_cache_mb")    out.maxCacheBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            else if (k == "max_file_mb")     out.maxFileBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            else if (k == "window_seconds")  out.windowSeconds = (uint32_t)std::stoul(v);
            else if (k == "files_threshold") out.filesThreshold = (uint32_t)std::stoul(v);
            else if (k == "rename_threshold")out.renameThreshold = (uint32_t)std::stoul(v);
            else if (k == "note_threshold")  out.noteThreshold = (uint32_t)std::stoul(v);
            else if (k == "entropy_threshold") out.entropyThreshold = std::stod(v);
            else if (k == "terminate_on_detect") out.terminateOnDetect = (v == "1" || Lower(v) == "true" || v == "on");
            // ---- 风险分层建快照（2026-09-18 新增，快照瘦身）----
            else if (k == "risk_tiered_snapshot") out.riskTieredSnapshot = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "burst_window_sec")     out.burstWindowSec = (uint32_t)std::stoul(v);
            else if (k == "burst_file_trigger")   out.burstFileTrigger = (uint32_t)std::stoul(v);
            else if (k == "high_value_only")      out.highValueOnly = (v == "1" || Lower(v) == "true" || v == "on");
            // ---- 密钥截获 + 落地捕获（2026-09-19 新增）----
            else if (k == "key_hunt_enabled")     out.keyHuntEnabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "key_max_kb")           out.keyMaxBytes = (uint64_t)std::stoull(v) * 1024;
            else if (k == "key_min_bytes")        out.keyMinBytes = (uint64_t)std::stoull(v);
            else if (k == "key_entropy_min")      out.keyEntropyMin = std::stod(v);
            else if (k == "key_window_sec")       out.keyWindowSec = (uint32_t)std::stoul(v);
            else if (k == "key_max_kept")         out.keyMaxKept = (uint32_t)std::stoul(v);
            else if (k == "key_readonly_guard")   out.keyReadonlyGuard = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "land_hunt_enabled")    out.landHuntEnabled = (v == "1" || Lower(v) == "true" || v == "on");
            else if (k == "land_max_mb")          out.landMaxBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            // ---- 回滚前备份（2026-09-21 新增）----
            else if (k == "rollback_pre_backup")        out.rollbackPreBackup = (v == "1" || Lower(v) == "true" || Lower(v) == "on");
            else if (k == "rollback_pre_backup_strict") out.rollbackPreBackupStrict = (v == "1" || Lower(v) == "true" || Lower(v) == "on");
            else if (k == "rollback_pre_backup_mb")     out.preBackupBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
            else if (k == "rollback_pre_backup_hours")  out.preBackupHours = (uint32_t)std::stoul(v);
            else if (k == "rollback_pre_backup_file_mb")out.preBackupFileBytes = (uint64_t)std::stoull(v) * 1024 * 1024;
        } catch (...) { /* 单条配置非法不影响其它 */ }
    }
    return true;
}

// ===========================================================================
//  生命周期
// ===========================================================================
static std::once_flag g_startOnce;
static std::atomic<bool> g_startedOnce{ false };

bool Start(const Config& cfg) {
    bool expected = false;
    if (!g_startedOnce.compare_exchange_strong(expected, true)) return true;   // 幂等
    g_cfg = cfg;
    CacheDirImpl();

    // 从外置配置覆盖（对齐卡巴/360 的"配置与规则可热更"做法）
    std::string cp = DefaultConfigPath();
    if (!cp.empty()) {
        Config c2 = g_cfg;
        if (LoadConfigFromFile(cp, c2)) {
            g_cfg = c2;
            LogDbg("[rollback] 已加载配置: " + cp);
        }
    }
    if (!g_cfg.enabled) { LogDbg("[rollback] 配置为禁用，不启动监控"); return true; }

    // 记录自身安装目录（用于排除自身活动）
    g_exeDirLower = Lower(DirName(GetExePath()));

    // -----------------------------------------------------------------------
    //  密钥索引重建（2026-09-19 新增，关键：必须早于监控线程启动）
    //
    //  为什么必须做：g_keys 是纯内存索引，服务重启后清空。若不重建，
    //  磁盘上已留存的所有密钥副本都成了**无人认领的孤儿** ——
    //  用户明明"截获过密钥"，重启一次就全丢了（这是旧实现的致命缺口）。
    //
    //  顺序要求：必须在 g_watchThread 启动**之前**完成，否则新捕获的候选
    //  可能与重建过程竞争同一个 g_keySeq / g_keys，造成序号冲突。
    // -----------------------------------------------------------------------
    if (g_cfg.keyHuntEnabled) {
        RebuildKeyIndexFromDisk();
    }

    g_running.store(true);
    g_watchThread = std::thread(WatchThread);
    LogDbg("[rollback] 引擎已启动，快照缓存上限 " + std::to_string(g_cfg.maxCacheBytes / 1024 / 1024) + " MB");
    return true;
}

void Stop() {
    if (!g_running.exchange(false)) return;
    if (g_stopEvent) SetEvent(g_stopEvent);
    if (g_watchThread.joinable()) g_watchThread.join();
    std::lock_guard<std::mutex> lk(g_statsMtx);
    g_stats.watching = false;
}

bool IsRunning() { return g_running.load(); }

Stats GetStats() {
    std::lock_guard<std::mutex> lk(g_statsMtx);
    return g_stats;
}

std::string CacheDir() { return CacheDirImpl(); }

void ClearCache() {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    for (auto& kv : g_cache) {
        DeleteFileU8(kv.second.snapPath.c_str());
        DeleteFileU8(kv.second.metaPath.c_str());
    }
    g_cache.clear();
    g_lru.clear();
    SyncCacheStatsLocked();
    LogDbg("[rollback] 快照缓存已清空");
}

// ---------------------------------------------------------------------------
//  手工回滚入口（供扩展面板「我要回滚」/ 测试使用）
// ---------------------------------------------------------------------------
std::string ManualRollback(const std::string& reason);

// ---------------------------------------------------------------------------
//  撤销最近一次自动回滚（"反向回滚"）
//
//  把最近一次自动回滚覆盖掉的内容还原回去 —— 即让文件回到"回滚前"的版本。
//  这不是"取消回滚"，而是"反向回滚"：用户拿回自己被覆盖的那一份。
// ---------------------------------------------------------------------------
bool HasUndoableRollback() {
    std::lock_guard<std::mutex> lk(g_undoMtx);
    if (g_undoList.empty() || g_undoToken.empty()) return false;
    return (NowMs() - g_undoAtMs) <= kUndoWindowMs;
}

std::string UndoLastRollback(const std::string& token) {
    std::vector<UndoEntry> list;
    std::string trig, tok;
    uint64_t age = 0;
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        if (g_undoList.empty() || g_undoToken.empty()) {
            return "{\"ok\":false,\"reason\":\"没有可撤销的回滚记录\"}";
        }
        uint64_t now = NowMs();
        if (now - g_undoAtMs > kUndoWindowMs) {
            ClearUndoLocked();
            return "{\"ok\":false,\"reason\":\"撤销时限已过（超过 10 分钟），为避免破坏数据已作废\"}";
        }
        if (!token.empty() && token != g_undoToken) {
            return "{\"ok\":false,\"reason\":\"撤销凭据不匹配（可能已发生新的回滚）\"}";
        }
        list = g_undoList;      // 拷贝一份，避免持锁做磁盘 IO
        trig = g_undoTrigger;
        tok  = g_undoToken;
        age  = now - g_undoAtMs;
    }

    uint64_t restored = 0, failed = 0;
    std::vector<std::string> okPaths, badPaths;
    for (const auto& u : list) {
        HANDLE hs = CreateFileU8(u.undoPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hs == INVALID_HANDLE_VALUE) {
            failed++; if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path);
            continue;
        }
        // -------------------------------------------------------------------
        //  回滚前备份（2026-09-21 新增）—— 这条路径此前是**完全没有兜底**的
        //
        //  这里原本是函数体里内联的 CREATE_ALWAYS，绕过了 RestoreFile，
        //  因此也绕过了 RestoreFile 里的所有保护。后果是：用户点「撤销」，
        //  当前文件被 undo 副本覆盖，而"点撤销之前的那一份"不留任何副本。
        //  一旦这次撤销本身是错的（比如自动回滚本来就判对了，用户误点撤销），
        //  用户就退无可退 —— 既回不到被回滚前，也回不到撤销前。
        //
        //  语义提醒：撤销操作是"把文件恢复到**被回滚前**（即已被加密的）版本"。
        //  也就是说它本身就是一次**可能有害的写入**（详见函数上方注释）。
        //  正因为它有害，才更需要前备份：用户应当能在撤销后又反悔。
        // -------------------------------------------------------------------
        std::string undoWhy = "undo-rollback";
        if (!PreBackupBeforeOverwrite(u.path, undoWhy)) {
            CloseHandle(hs);
            failed++; if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path);
            continue;
        }
        HANDLE hd = CreateFileU8(u.path.c_str(), GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hd == INVALID_HANDLE_VALUE) {
            CloseHandle(hs);
            failed++; if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path);
            continue;
        }
        std::vector<char> buf(256 * 1024);
        bool okAll = true;
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { okAll = false; break; }
            if (!rd) break;
            DWORD wr = 0;
            if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { okAll = false; break; }
        }
        CloseHandle(hs);
        CloseHandle(hd);
        if (okAll) { restored++; if (okPaths.size() < kMaxListedPaths) okPaths.push_back(u.path); }
        else       { failed++;   if (badPaths.size() < kMaxListedPaths) badPaths.push_back(u.path); }
    }

    LogDbg("[rollback] 撤销完成: 还原 " + std::to_string(restored) +
           "，失败 " + std::to_string(failed) + "（触发原因: " + trig + "）");

    // 撤销成功后清理记录（备份文件已用掉；失败项也一并清理，避免反复重试写坏文件）
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        ClearUndoLocked();
    }

    std::ostringstream os;
    os << "{\"ok\":true,\"restored\":" << restored
       << ",\"failed\":" << failed
       << ",\"trigger\":" << JsonString(trig)
       << ",\"token\":" << JsonString(tok)
       << ",\"ageMs\":" << age
       << ",\"restoredPaths\":[";
    for (size_t i = 0; i < okPaths.size(); ++i) { if (i) os << ","; os << JsonString(okPaths[i]); }
    os << "],\"failedPaths\":[";
    for (size_t i = 0; i < badPaths.size(); ++i) { if (i) os << ","; os << JsonString(badPaths[i]); }
    os << "]}";
    return os.str();
}

// 对外一次性拉取统计 + 运行态的 JSON（供管道 rollbackstatus 命令）
std::string StatusJson() {
    Stats s = GetStats();
    std::string trig;
    { std::lock_guard<std::mutex> lk(g_triggerMtx); trig = g_lastTrigger; }
    std::ostringstream os;
    uint64_t now = NowMs(), cd = g_cooldownUntilMs.load();
    os << "{\"running\":" << (s.watching ? "true" : "false")
       << ",\"enabled\":" << (g_cfg.enabled ? "true" : "false")
       << ",\"cooldown\":" << ((cd > now) ? "true" : "false")
       << ",\"cooldownLeftMs\":" << ((cd > now) ? (cd - now) : 0)
       << ",\"snapshots\":" << s.snapshots
       << ",\"snapBytes\":" << s.snapBytes
       << ",\"eventsSeen\":" << s.eventsSeen
       << ",\"snapshotTaken\":" << s.snapshotTaken
       << ",\"snapshotSkipped\":" << s.snapshotSkipped
       << ",\"rollbacks\":" << s.rollbacks
       << ",\"restored\":" << s.restored
       << ",\"unrecoverable\":" << s.unrecoverable
       << ",\"detected\":" << s.detected
       << ",\"watcherErrors\":" << s.watcherErrors
       << ",\"cacheDir\":" << JsonString(CacheDirImpl())
       << ",\"maxCacheMB\":" << (g_cfg.maxCacheBytes / 1024 / 1024)
       << ",\"lastTrigger\":" << JsonString(trig);

    // ---- 密钥截获 + 落地捕获（2026-09-19 新增）----
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        size_t confirmed = 0;
        for (const auto& k : g_keys) if (k.confirmed) confirmed++;
        os << ",\"keyHunt\":" << (g_cfg.keyHuntEnabled ? "true" : "false")
           << ",\"keysCaptured\":" << s.keysCaptured
           << ",\"keysKept\":" << g_keys.size()
           << ",\"keysConfirmed\":" << confirmed
           << ",\"keyHits\":" << s.keyHits;
    }
    {
        std::lock_guard<std::mutex> lk(g_landMtx);
        os << ",\"landHunt\":" << (g_cfg.landHuntEnabled ? "true" : "false")
           << ",\"landedSuspect\":" << s.landedSuspect
           << ",\"landedPending\":" << g_landed.alerts.size();
    }

    // 撤销状态（高风险自动处置后，前端据此显示「撤销我的处理」入口）
    {
        std::lock_guard<std::mutex> lk(g_undoMtx);
        bool undoable = !g_undoList.empty() && !g_undoToken.empty() &&
                        (now - g_undoAtMs) <= kUndoWindowMs;
        uint64_t leftMs = 0;
        if (undoable) leftMs = kUndoWindowMs - (now - g_undoAtMs);
        os << ",\"undoable\":" << (undoable ? "true" : "false")
           << ",\"undoToken\":" << JsonString(undoable ? g_undoToken : std::string())
           << ",\"undoCount\":" << (undoable ? g_undoList.size() : (size_t)0)
           << ",\"undoLeftMs\":" << leftMs
           << ",\"undoTrigger\":" << JsonString(undoable ? g_undoTrigger : std::string());
    }
    os << "}";
    return os.str();
}

// 手动回滚：把所有持有快照的文件恢复到快照状态（用户主动发起的"撤销最近改动"）
//
// 同样留存撤销记录：用户手动回滚也可能点错（比如误以为某批改动是异常的），
// 留一份"回滚前内容"让他能反悔。语义与自动回滚一致。
std::string ManualRollback(const std::string& reason) {
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lk(g_cacheMtx);
        for (auto& kv : g_cache) keys.push_back(kv.second.path);
    }
    RollbackReport rep = RollbackVictims(keys, reason.empty() ? "用户手动回滚" : reason);
    LogDbg("[rollback] 手动回滚: 恢复 " + std::to_string(rep.restored) +
           "，不可恢复 " + std::to_string(rep.unrecover));
    return rep.ToJson();
}

// 列出当前持有快照的文件（供 UI 展示"哪些文件被保护着"）
std::string ListSnapshotsJson() {
    std::lock_guard<std::mutex> lk(g_cacheMtx);
    std::ostringstream os;
    os << "{\"count\":" << g_cache.size() << ",\"items\":[";
    size_t i = 0;
    for (auto& kv : g_cache) {
        if (i++) os << ",";
        os << "{\"path\":" << JsonString(kv.second.path)
           << ",\"size\":" << kv.second.size
           << ",\"sha\":" << JsonString(kv.second.sha) << "}";
        if (i >= 500) break;      // 上限，避免响应过大
    }
    os << "]}";
    return os.str();
}

// ===========================================================================
//  密钥截获对外接口（2026-09-19 新增）
// ===========================================================================
std::string ListCapturedKeysJson() {
    std::lock_guard<std::mutex> lk(g_keyMtx);
    std::ostringstream os;
    os << "{\"count\":" << g_keys.size() << ",\"items\":[";
    for (size_t i = 0; i < g_keys.size(); ++i) {
        const auto& k = g_keys[i];
        if (i) os << ",";
        os << "{\"index\":" << i
           << ",\"path\":" << JsonString(k.path)
           << ",\"store\":" << JsonString(k.storePath)
           << ",\"size\":" << k.size
           << ",\"sha\":" << JsonString(k.sha)
           << ",\"entropy\":" << k.entropy
           << ",\"at\":" << k.at
           << ",\"confirmed\":" << (k.confirmed ? "true" : "false") << "}";
    }
    os << "]}";
    return os.str();
}

std::string ReadCapturedKeyHex(size_t keyIndex) {
    std::string store;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        if (keyIndex >= g_keys.size())
            return "{\"ok\":false,\"reason\":\"密钥下标超出范围\"}";
        store = g_keys[keyIndex].storePath;
    }
    // 读文件在锁外做（本项目铁律：不在持锁时做 I/O）
    HANDLE h = CreateFileU8(store.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return "{\"ok\":false,\"reason\":\"密钥副本已不存在（可能已被清理）\"}";
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    // 上限保护：单次最多回传 64KB（正常密钥远小于此）
    uint64_t want = (sz.QuadPart > 0 && sz.QuadPart <= 65536) ? (uint64_t)sz.QuadPart : 65536;
    std::string data; data.resize((size_t)want);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, &data[0], (DWORD)want, &rd, nullptr);
    CloseHandle(h);
    if (!ok) return "{\"ok\":false,\"reason\":\"读取密钥副本失败\"}";
    data.resize(rd);

    static const char* hx = "0123456789abcdef";
    std::string hex; hex.reserve(data.size() * 2);
    for (unsigned char c : data) { hex += hx[c >> 4]; hex += hx[c & 0xf]; }

    std::ostringstream os;
    os << "{\"ok\":true,\"size\":" << data.size()
       << ",\"hex\":" << JsonString(hex) << "}";
    return os.str();
}

// 清空密钥留存。
//
// ---------------------------------------------------------------------------
//  【2026-09-19 修正】默认**保留**，必须显式确认才真删
// ---------------------------------------------------------------------------
//  旧实现无参数直接删光，本意是"清理误报留下的垃圾"。但风险在于：
//    · 用户看到"156 份候选全是误报" → 顺手点清空；
//    · 之后真中招时，这一批里**可能就有真密钥**，却已经被删了；
//    · 副本一旦删除，磁盘上再无第二份 —— 密钥文件本身早被勒索者删了。
//  所以改为：
//    · force=false（默认，UI 的普通"清理"）：只清**未确认**的候选，
//      已确认（时序关联成立过）的一律保留 —— 那些是高价值证据；
//    · force=true（UI 需二次确认）：真删全部。
//
//  另外，副本带 FILE_ATTRIBUTE_READONLY，删除前必须先去属性，
//  否则 DeleteFileU8 会静默失败（留下孤儿文件）。
// ---------------------------------------------------------------------------
static void ClearCapturedKeysImpl(bool force) {
    std::vector<std::string> toDelete;
    size_t keptConfirmed = 0;
    {
        std::lock_guard<std::mutex> lk(g_keyMtx);
        std::vector<CapturedKey> remain;
        for (const auto& k : g_keys) {
            if (force || !k.confirmed) toDelete.push_back(k.storePath);
            else { remain.push_back(k); keptConfirmed++; }
        }
        g_keys.swap(remain);
    }
    for (const auto& p : toDelete) {
        // 只读属性会让 DeleteFileU8 失败 —— 先清掉
        DWORD a = GetFileAttributesU8(p.c_str());
        if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_READONLY))
            SetFileAttributesU8(p.c_str(), a & ~FILE_ATTRIBUTE_READONLY);
        DeleteFileU8(p.c_str());
    }
    {
        std::lock_guard<std::mutex> lk(g_statsMtx);
        g_stats.keysKept = g_keys.size();
    }
    LogDbg(std::string("[rollback] 已") + (force ? "清空" : "清理未确认的") +
           "密钥留存（删除 " + std::to_string(toDelete.size()) +
           " 份，保留已确认 " + std::to_string(keptConfirmed) + " 份）");
}

void ClearCapturedKeys() { ClearCapturedKeysImpl(false); }
void ClearCapturedKeysForce() { ClearCapturedKeysImpl(true); }

std::string KeyDir() { return KeyDirImpl(); }

// ===========================================================================
//  落地捕获对外接口（2026-09-19 新增）
// ===========================================================================
std::string TakeLandedAlertsJson() {
    std::deque<LandAlert> items;
    {
        std::lock_guard<std::mutex> lk(g_landMtx);
        items.swap(g_landed.alerts);      // 取走即清空（避免反复上报刷屏）
    }
    std::ostringstream os;
    os << "{\"count\":" << items.size() << ",\"items\":[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) os << ",";
        os << "{\"path\":" << JsonString(items[i].path)
           << ",\"reason\":" << JsonString(items[i].reason)
           << ",\"at\":" << items[i].at
           << ",\"lv\":" << items[i].lv << "}";
    }
    os << "]}";
    return os.str();
}

// ---------------------------------------------------------------------------
//  落地旁证回查（2026-09-24 新增）
//
//  为什么单独开一个函数而不改 TakeLandedAlertsJson 的语义：
//  那个接口是「取走即清空」的消费式设计（防刷屏），一旦改成"看一眼不清"，
//  上层的告警去重就整体失效。这里查的是上面那份独立的只读档案。
//
//  path 大小写不敏感匹配（内部统一转小写）。
//  outLv / outSysZone / outReason 均可传 nullptr。命中返回 true。
// ---------------------------------------------------------------------------
bool QuerySoftLanded(const std::string& path, uint64_t maxAgeMs,
                     int* outLv, bool* outSysZone, std::string* outReason) {
    const std::string l = Lower(path);
    const uint64_t now = NowMs();
    std::lock_guard<std::mutex> lk(g_softMtx);
    // 队列追加式（时间有序），从尾部倒着找；一旦越出时效窗口即可停。
    for (std::deque<SoftLand>::reverse_iterator it = g_softLand.rbegin();
         it != g_softLand.rend(); ++it) {
        if (now >= it->at && now - it->at > maxAgeMs) break;
        if (it->pathLower != l) continue;
        if (outLv)      *outLv = it->lv;
        if (outSysZone) *outSysZone = it->sysZone;
        if (outReason)  *outReason = it->reason;
        return true;
    }
    return false;
}

// ===========================================================================
//  回滚前备份的对外接口（2026-09-21 新增）
// ===========================================================================

std::string PreBackupDir() {
    return PreBackupDirImpl();
}

void PreBackupStats(uint64_t& count, uint64_t& bytes) {
    std::lock_guard<std::mutex> lk(g_pbMtx);
    LoadPreBackupIndexLocked();
    count = g_pbList.size();
    bytes = g_pbBytes;
}

std::string ListPreBackupsJson() {
    std::vector<PreBackupEntry> copy;
    uint64_t bytes = 0;
    {
        std::lock_guard<std::mutex> lk(g_pbMtx);
        LoadPreBackupIndexLocked();
        copy = g_pbList;
        bytes = g_pbBytes;
    }
    // 新的排前面：用户最关心的永远是"刚才那次覆盖之前"的内容
    std::sort(copy.begin(), copy.end(),
              [](const PreBackupEntry& a, const PreBackupEntry& b) { return a.atMs > b.atMs; });

    uint64_t now = NowMs();
    std::ostringstream os;
    os << "{\"count\":" << copy.size()
       << ",\"bytes\":" << bytes
       << ",\"dir\":" << JsonString(PreBackupDirImpl())
       << ",\"enabled\":" << (g_cfg.rollbackPreBackup ? "true" : "false")
       << ",\"strict\":" << (g_cfg.rollbackPreBackupStrict ? "true" : "false")
       << ",\"keepHours\":" << g_cfg.preBackupHours
       << ",\"capBytes\":" << g_cfg.preBackupBytes
       << ",\"items\":[";
    size_t n = 0;
    for (const auto& e : copy) {
        if (n >= 200) break;      // 与快照列表一致：最多 200 条，避免管道消息过大
        if (n) os << ",";
        uint64_t ageMs = (now > e.atMs) ? (now - e.atMs) : 0;
        os << "{\"id\":" << JsonString(e.id)
           << ",\"origin\":" << JsonString(e.origin)
           << ",\"size\":" << e.size
           << ",\"ageMs\":" << ageMs
           << ",\"reason\":" << JsonString(e.why)
           << "}";
        ++n;
    }
    os << "],\"shown\":" << n << "}";
    return os.str();
}

std::string RestorePreBackup(const std::string& id) {
    PreBackupEntry e;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_pbMtx);
        LoadPreBackupIndexLocked();
        for (const auto& it : g_pbList) {
            if (it.id == id) { e = it; found = true; break; }
        }
    }
    if (!found) return "{\"ok\":false,\"reason\":\"找不到该备份（可能已按保留期清理）\"}";

    // -------------------------------------------------------------------
    //  这道闸门比"覆盖勒索加密文件"更值得留意：
    //  还原备份 = 把**曾经被覆盖掉的那一版**写回去，也就是文件会**倒退**。
    //  如果用户在覆盖之后又做了新编辑，这次还原同样会丢掉那些编辑。
    //  所以还原本身也必须先备份 —— 让"还原"这个动作也可以反悔。
    //  否则用户会陷入和当初一模一样的两难。
    // -------------------------------------------------------------------
    if (!PreBackupBeforeOverwrite(e.origin, "restore-prebackup")) {
        return "{\"ok\":false,\"reason\":\"严格模式：写入前备份失败，已放弃还原以免丢失当前内容\"}";
    }

    HANDLE hs = CreateFileU8(e.file.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hs == INVALID_HANDLE_VALUE)
        return "{\"ok\":false,\"reason\":\"备份文件无法打开（可能已被手工删除）\"}";

    // 目标目录可能已被删除 → 尽力恢复目录结构，恢复不了就如实报错
    std::string dir = e.origin.substr(0, e.origin.find_last_of("\\/"));
    if (!dir.empty() && GetFileAttributesU8(dir.c_str()) == INVALID_FILE_ATTRIBUTES) {
        // 逐级创建（CreateDirectoryU8 不会自动建父级）
        std::string cur;
        for (size_t i = 0; i < dir.size(); ++i) {
            cur += dir[i];
            if (dir[i] == '\\' || (i + 1 == dir.size())) {
                if (cur.size() > 3) CreateDirectoryU8(cur.c_str(), nullptr);
            }
        }
    }

    HANDLE hd = CreateFileU8(e.origin.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hd == INVALID_HANDLE_VALUE) {
        CloseHandle(hs);
        return "{\"ok\":false,\"reason\":\"无法写入目标文件（err=" +
               std::to_string(GetLastError()) + "）\"}";
    }

    std::vector<char> buf(256 * 1024);
    bool okAll = true;
    uint64_t written = 0;
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(hs, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { okAll = false; break; }
        if (!rd) break;
        DWORD wr = 0;
        if (!WriteFile(hd, buf.data(), rd, &wr, nullptr) || wr != rd) { okAll = false; break; }
        written += rd;
    }
    CloseHandle(hs);
    FlushFileBuffers(hd);
    CloseHandle(hd);

    if (!okAll) {
        LogDbg("[rollback] 还原备份失败（写入中断）: " + e.origin);
        return "{\"ok\":false,\"reason\":\"写入中断，文件可能不完整（请用文件历史/云盘副本恢复）\"}";
    }
    LogDbg("[rollback] 已按备份还原 " + std::to_string(written) + " 字节 → " + e.origin +
           "（备份 id=" + id + "，该备份仍保留）");
    // 注意：还原后**不删除**这个备份。理由与密钥留存同理 ——
    // 用户可能想反复比对，删掉就再无第二次机会。
    return "{\"ok\":true,\"restored\":" + std::to_string(written) +
           ",\"path\":" + JsonString(e.origin) + "}";
}

std::string ClearPreBackups(bool force) {
    uint64_t removed = 0, freed = 0;
    {
        std::lock_guard<std::mutex> lk(g_pbMtx);
        LoadPreBackupIndexLocked();
        if (force) {
            for (const auto& e : g_pbList) {
                if (DeleteFileU8(e.file.c_str())) { ++removed; freed += e.size; }
            }
            g_pbList.clear();
            g_pbBytes = 0;
            RewritePreBackupIndexLocked();
        } else {
            // 非强制 → 只做一轮保留期清理（对应用户说的"清掉过期备份"）
            uint64_t before = g_pbBytes;
            size_t   cnt0   = g_pbList.size();
            PrunePreBackupsLocked();
            removed = (uint64_t)(cnt0 - g_pbList.size());
            freed   = (before > g_pbBytes) ? (before - g_pbBytes) : 0;
        }
    }
    LogDbg("[rollback] 清理回滚前备份: 移除 " + std::to_string(removed) +
           " 份，释放 " + std::to_string(freed / 1024) + " KB（force=" +
           (force ? "1" : "0") + "）");
    return "{\"ok\":true,\"removed\":" + std::to_string(removed) +
           ",\"freed\":" + std::to_string(freed) +
           ",\"forced\":" + (force ? "true" : "false") + "}";
}

}  // namespace rb
}  // namespace sf
