// sfdb.cpp — 自研 SQL 子集数据库：**存储层**
//
// ===========================================================================
//  本文件负责什么（以及刻意不负责什么）
// ===========================================================================
//  负责：帧编解码、CRC32、文件打开/创建、崩溃恢复（重放 + 截断）、
//        追加写入、原子压缩、内存表/主键索引/二级索引的维护、Database 门面。
//  不负责：词法、语法、求值 —— 那些在 sfdb_sql.cpp。
//
//  分界线是「磁盘格式」：本文件是**唯一**知道帧长什么样的地方。
//  查询层调用的 Store::Insert 等方法内部完成「校验 → 落盘 → 应用内存」，
//  所以查询层永远不可能写出「内存改了但磁盘没改」的状态。
//
// ===========================================================================
//  ★ 三条必须遵守的顺序约定（改这个文件前先读）
// ===========================================================================
//  ① 先校验、后落盘、最后改内存。校验不过时一个字节都不能写。
//  ② 落盘失败 → 内存不变（返回 false）。落盘成功后的内存变更写成了
//     不可失败的形式（push_back / 赋值），所以不存在「磁盘有了内存没有」。
//  ③ 所有 *W 文件 API 的路径必须先过 Utf8ToWide()。中英文路径混用是
//     本项目历史高发故障（GetFileAttributesA 静默失败），不要图省事写 *A。
#include "sfdb_impl.h"

#include <cstring>
#include <mutex>

#include "common.h"   // LogDbg（仅用于开库/恢复/压缩这类需要留痕的节点）

namespace sf {
namespace sfdb {

// ===========================================================================
//  文件级工具（Value 语义层与 impl 存储层共用）
// ===========================================================================
//  ⚠️ 放在 sf::sfdb 层而不是 impl 层：因为下面 Value::ToText / Compare / Like
//     是 **sf::sfdb::Value** 的成员，定义在 impl 命名空间里会被 MSVC 判
//     C2888「不能在命名空间 impl 内定义符号」。而它们又要用这三个小工具，
//     所以工具必须提到 impl 外面来（C++ 名字查找：内层命名空间能找到外层的名字）。
namespace {

// ASCII 小写化（不改动 >=0x80 的字节，避免破坏 UTF-8 序列）
std::string LowerAscii(const std::string& s) {
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i) {
        unsigned char c = (unsigned char)o[i];
        if (c >= 'A' && c <= 'Z') o[i] = (char)(c + 32);
    }
    return o;
}

// 整体解析为十进制整数。带首尾空白容忍；出现任何非数字立即失败（"12a" 不算 12）。
bool ParseIntAll(const std::string& s, long long& out) {
    size_t i = 0, n = s.size();
    while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
    size_t j = n;
    while (j > i && (s[j - 1] == ' ' || s[j - 1] == '\t' || s[j - 1] == '\r' || s[j - 1] == '\n')) --j;
    if (i >= j) return false;

    bool neg = false;
    if (s[i] == '+' || s[i] == '-') { neg = (s[i] == '-'); ++i; }
    if (i >= j) return false;

    unsigned long long v = 0;
    for (; i < j; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned long long d = (unsigned long long)(s[i] - '0');
        if (v > (0x7FFFFFFFFFFFFFFFull - d) / 10ull) return false;  // 溢出
        v = v * 10ull + d;
    }
    out = neg ? -(long long)v : (long long)v;
    return true;
}

int CmpI64(long long a, long long b) { return a < b ? -1 : (a > b ? 1 : 0); }

}  // namespace

// ===========================================================================
//  Value 语义（属于 sf::sfdb 层，不属于 impl）
// ===========================================================================
std::string Value::ToText() const {
    if (type == Text) return s;
    if (type == Int)  return std::to_string(i);
    return std::string();
}

long long Value::ToInt(long long def) const {
    if (type == Int) return i;
    if (type == Text) {
        long long v = 0;
        if (ParseIntAll(s, v)) return v;
    }
    return def;
}

int Value::Compare(const Value& a, const Value& b) {
    // 数值优先：两边都能当整数 → 按整数比
    if (a.type == Int && b.type == Int) return CmpI64(a.i, b.i);
    if (a.type == Int && b.type == Text) {
        long long v = 0;
        if (ParseIntAll(b.s, v)) return CmpI64(a.i, v);
    }
    if (a.type == Text && b.type == Int) {
        long long v = 0;
        if (ParseIntAll(a.s, v)) return CmpI64(v, b.i);
    }
    // 其余情况按文本比（大小写不敏感 —— Windows 路径/状态名语义，见 sfdb.h 文件头）
    int c = _stricmp(a.ToText().c_str(), b.ToText().c_str());
    return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

bool Value::Like(const std::string& text, const std::string& pattern) {
    const std::string t = LowerAscii(text);
    const std::string p = LowerAscii(pattern);

    // 经典「双指针 + 最近一个 % 回溯点」算法：O(n·m) 最坏、O(n) 典型，
    // 不需要递归也不吃栈。不用正则是因为正则引擎要么引 std::regex（慢且吃栈），
    // 要么自己写 NFA（本引擎不需要那个量级的表达力）。
    size_t ti = 0, pi = 0;
    size_t star = std::string::npos, mark = 0;

    while (ti < t.size()) {
        if (pi < p.size() && (p[pi] == '_' || p[pi] == t[ti])) {
            ++ti; ++pi;
        } else if (pi < p.size() && p[pi] == '%') {
            star = pi++;
            mark = ti;
        } else if (star != std::string::npos) {
            pi = star + 1;
            ti = ++mark;
        } else {
            return false;
        }
    }
    while (pi < p.size() && p[pi] == '%') ++pi;
    return pi == p.size();
}

namespace impl {

// ===========================================================================
//  CRC32（IEEE 802.3，反射多项式 0xEDB88320）
// ===========================================================================
//  自己实现而不是引 zlib：这里只需要 30 行，且能让 /MT 单文件目标零额外依赖。
//  表在静态初始化时算好（C++11 起函数内静态局部量的初始化是线程安全的）。
namespace {

struct Crc32Table {
    uint32_t t[256];
    Crc32Table() {
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
    }
};

const Crc32Table g_crcTable;

}  // namespace

uint32_t Crc32(const void* data, size_t len) {
    const unsigned char* p = (const unsigned char*)data;
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) c = g_crcTable.t[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;

}

// ===========================================================================
//  UTF-8 → 宽字符
// ===========================================================================
//  ⚠️ 不要用 MultiByteToWideChar 的返回值直接当长度去 resize：
//     它返回的是**含结尾 NUL** 的字符数，多出来的那个 NUL 会让后续
//     CreateFileW 把路径当成空串结束——路径里出现内嵌 NUL 时行为诡异。
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) {
        // 非法 UTF-8 时退化为 ANSI 尝试一次（总比直接失败好，但会记日志）
        n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (n <= 0) return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], n);
        sf::LogDbg("[sfdb] 警告：路径不是合法 UTF-8，已按 ANSI 兜底解析");
        return w;
    }
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// ===========================================================================
//  负载编解码
// ===========================================================================
//  格式刻意朴素：小端定长整数 + 长度前缀字符串。没有对齐填充、没有变长整数。
//  理由是这几个字节在总量里占比极小（一行约 100~300 字节），
//  换来的是「拿十六进制编辑器就能读懂」——安全产品的可审查性优先。
void Writer::U8(uint8_t v) { buf.push_back((char)v); }

void Writer::U32(uint32_t v) {
    char b[4];
    b[0] = (char)(v & 0xFFu);
    b[1] = (char)((v >> 8) & 0xFFu);
    b[2] = (char)((v >> 16) & 0xFFu);
    b[3] = (char)((v >> 24) & 0xFFu);
    buf.append(b, 4);
}

void Writer::I64(long long v) {
    unsigned long long u = (unsigned long long)v;
    char b[8];
    for (int i = 0; i < 8; ++i) b[i] = (char)((u >> (8 * i)) & 0xFFull);
    buf.append(b, 8);
}

void Writer::Str(const std::string& s) {
    U32((uint32_t)s.size());
    buf.append(s);
}

void Writer::Value_(const Value& v) {
    U8((uint8_t)v.type);
    if (v.type == Value::Int)       I64(v.i);
    else if (v.type == Value::Text) Str(v.s);
}

bool Reader::U8(uint8_t& v) {
    if (bad_ || off_ + 1 > n_) { bad_ = true; return false; }
    v = (uint8_t)p_[off_++];
    return true;
}

bool Reader::U32(uint32_t& v) {
    if (bad_ || off_ + 4 > n_) { bad_ = true; return false; }
    const unsigned char* p = (const unsigned char*)(p_ + off_);
    v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    off_ += 4;
    return true;
}

bool Reader::I64(long long& v) {
    if (bad_ || off_ + 8 > n_) { bad_ = true; return false; }
    const unsigned char* p = (const unsigned char*)(p_ + off_);
    unsigned long long u = 0;
    for (int i = 0; i < 8; ++i) u |= ((unsigned long long)p[i]) << (8 * i);
    v = (long long)u;
    off_ += 8;
    return true;
}

bool Reader::Str(std::string& v) {
    uint32_t len = 0;
    if (!U32(len)) return false;
    // 长度前缀本身可能是被破坏的数据：先做合理性检查再决定是否分配
    if (len > kMaxPayload || off_ + (size_t)len > n_) { bad_ = true; return false; }
    v.assign(p_ + off_, (size_t)len);
    off_ += (size_t)len;
    return true;
}

bool Reader::Value_(Value& v) {
    uint8_t t = 0;
    if (!U8(t)) return false;
    if (t == (uint8_t)Value::Null) { v.type = Value::Null; v.i = 0; v.s.clear(); return true; }
    if (t == (uint8_t)Value::Int)  { v.type = Value::Int; v.s.clear(); return I64(v.i); }
    if (t == (uint8_t)Value::Text) { v.type = Value::Text; v.i = 0; return Str(v.s); }
    bad_ = true;   // 未知类型码 = 数据被污染
    return false;
}

void WriteCells(Writer& w, const std::vector<Value>& cells) {
    w.U32((uint32_t)cells.size());
    for (size_t i = 0; i < cells.size(); ++i) w.Value_(cells[i]);
}

bool ReadCells(Reader& r, std::vector<Value>& cells) {
    uint32_t n = 0;
    if (!r.U32(n)) return false;
    if (n > 256) return false;          // 列数上限，防被破坏数据撑爆内存
    cells.clear();
    cells.resize((size_t)n);
    for (uint32_t i = 0; i < n; ++i) {
        if (!r.Value_(cells[i])) return false;
    }
    return r.Ok();
}

// ===========================================================================
//  Table 小工具
// ===========================================================================
int Table::FindCol(const std::string& n) const {
    for (size_t i = 0; i < cols.size(); ++i) {
        if (_stricmp(cols[i].name.c_str(), n.c_str()) == 0) return (int)i;
    }
    return -1;
}

long long Table::LiveCount() const {
    long long c = 0;
    for (size_t i = 0; i < rows.size(); ++i) if (!rows[i].dead) ++c;
    return c;
}

long long Table::DeadCount() const {
    long long c = 0;
    for (size_t i = 0; i < rows.size(); ++i) if (rows[i].dead) ++c;
    return c;
}

std::string KeyOf(const Value& v) {
    if (v.type == Value::Int) return std::to_string(v.i);
    if (v.type == Value::Text) return LowerAscii(v.s);
    return std::string();   // Null → 空键（调用方应拒绝）
}

// ===========================================================================
//  索引维护
// ===========================================================================
void Store::IndexAdd(Table& t, size_t rowIdx) {
    if (rowIdx >= t.rows.size()) return;
    const Row& r = t.rows[rowIdx];
    for (size_t k = 0; k < t.idx.size(); ++k) {
        Index& ix = t.idx[k];
        if (ix.col < 0 || ix.col >= (int)r.cells.size()) continue;
        ix.map[KeyOf(r.cells[ix.col])].push_back(rowIdx);
    }
}

void Store::IndexRemove(Table& t, size_t rowIdx) {
    if (rowIdx >= t.rows.size()) return;
    const Row& r = t.rows[rowIdx];
    for (size_t k = 0; k < t.idx.size(); ++k) {
        Index& ix = t.idx[k];
        if (ix.col < 0 || ix.col >= (int)r.cells.size()) continue;
        auto it = ix.map.find(KeyOf(r.cells[ix.col]));
        if (it == ix.map.end()) continue;
        std::vector<size_t>& v = it->second;
        for (size_t j = 0; j < v.size(); ++j) {
            if (v[j] == rowIdx) { v.erase(v.begin() + (ptrdiff_t)j); break; }
        }
        if (v.empty()) ix.map.erase(it);
    }
}

void Store::RebuildIndexes(Table& t) {
    for (size_t k = 0; k < t.idx.size(); ++k) t.idx[k].map.clear();
    for (size_t i = 0; i < t.rows.size(); ++i) {
        if (!t.rows[i].dead) IndexAdd(t, i);
    }
}

// ===========================================================================
//  Store：查找
// ===========================================================================
Table* Store::Find(const std::string& name) {
    for (size_t i = 0; i < tables.size(); ++i) {
        if (_stricmp(tables[i].name.c_str(), name.c_str()) == 0) return &tables[i];
    }
    return nullptr;
}

const Table* Store::Find(const std::string& name) const {
    for (size_t i = 0; i < tables.size(); ++i) {
        if (_stricmp(tables[i].name.c_str(), name.c_str()) == 0) return &tables[i];
    }
    return nullptr;
}

// ===========================================================================
//  帧写入
// ===========================================================================
namespace {

// 把一帧写到任意句柄（追加路径用 hFile，压缩路径用临时文件句柄）。
// 不负责 flush —— 由调用方决定（压缩时最后统一 flush 一次就够）。
bool WriteFrameTo(HANDLE h, uint8_t kind, const std::string& payload) {
    if (payload.size() > (size_t)kMaxPayload) return false;

    FrameHead fh;
    fh.magic = kMagic;
    fh.kind  = kind;
    fh.flags = 0;
    fh.pad   = 0;
    fh.len   = (uint32_t)payload.size();
    fh.crc   = payload.empty() ? 0u : Crc32(payload.data(), payload.size());

    DWORD w = 0;
    if (!WriteFile(h, &fh, (DWORD)sizeof(fh), &w, nullptr) || w != sizeof(fh)) return false;
    if (!payload.empty()) {
        if (!WriteFile(h, payload.data(), (DWORD)payload.size(), &w, nullptr) || w != payload.size())
            return false;
    }
    return true;
}

// 递归建目录（CreateDirectoryW 只建一层，而 %ProgramData%\SilverFoxGuard 常常不存在）
bool EnsureDirW(const std::wstring& dir) {
    if (dir.size() <= 3) return true;   // "C:\" 这种根，无需创建
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES) {
        return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    }
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 0) {
        if (!EnsureDirW(dir.substr(0, pos))) return false;
    }
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

}  // namespace

bool Store::AppendFrame(FrameKind kind, const std::string& payload) {
    if (hFile == INVALID_HANDLE_VALUE) {
        SetErr("日志句柄无效（未打开？）");
        return false;
    }
    // 每次都显式定位到末尾：防止外部（或上一次重放的读指针）把写位置搞偏。
    // 顺序写 + FILE_END 定位是追加式存储唯一的写入方式。
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    if (!SetFilePointerEx(hFile, zero, nullptr, FILE_END)) {
        SetErr("定位日志末尾失败，错误码 " + std::to_string(GetLastError()));
        return false;
    }
    if (!WriteFrameTo(hFile, (uint8_t)kind, payload)) {
        SetErr("写入日志失败，错误码 " + std::to_string(GetLastError()));
        return false;
    }
    if (syncOnWrite) FlushFileBuffers(hFile);

    fileBytes += (long long)(sizeof(FrameHead) + payload.size());
    ++frames;
    ++appends;
    return true;
}

bool Store::Sync() {
    if (hFile == INVALID_HANDLE_VALUE) return false;
    return FlushFileBuffers(hFile) != FALSE;
}

// ===========================================================================
//  应用一帧到内存（重放与实时写入共用）
// ===========================================================================
namespace {

// 建表（重放语义：同名则**替换**，因为日志里同名 CREATE 必然跟在一个 DROP 之后）
bool ApplyCreateTable(std::vector<Table>& tables, const std::string& name, const std::vector<Col>& cols) {
    for (size_t i = 0; i < tables.size(); ++i) {
        if (_stricmp(tables[i].name.c_str(), name.c_str()) == 0) {
            tables.erase(tables.begin() + (ptrdiff_t)i);
            break;
        }
    }
    Table t;
    t.name = name;
    t.cols = cols;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (cols[i].isPk) { t.pk = (int)i; break; }
    }
    tables.push_back(t);
    return true;
}

}  // namespace

// 插入一行（含主键复活语义与索引维护）
static void ApplyInsertRow(Store& st, Table& t, const std::vector<Value>& cells) {
    if (t.pk >= 0 && t.pk < (int)cells.size()) {
        auto it = t.pkMap.find(KeyOf(cells[t.pk]));
        if (it != t.pkMap.end() && it->second < t.rows.size()) {
            // 主键已存在：可能是墓碑 → 原地复活并整行替换（这正是「删了再插同主键」）
            size_t ri = it->second;
            st.IndexRemove(t, ri);
            t.rows[ri].cells = cells;
            t.rows[ri].dead  = false;
            st.IndexAdd(t, ri);
            return;
        }
    }
    size_t ri = t.rows.size();
    Row r;
    r.cells = cells;
    r.dead  = false;
    t.rows.push_back(r);
    if (t.pk >= 0 && t.pk < (int)cells.size()) t.pkMap[KeyOf(cells[t.pk])] = ri;
    st.IndexAdd(t, ri);
}

static void ApplyDeleteRow(Store& st, Table& t, const Value& pkValue) {
    auto it = t.pkMap.find(KeyOf(pkValue));
    if (it == t.pkMap.end()) return;
    size_t ri = it->second;
    if (ri >= t.rows.size() || t.rows[ri].dead) return;
    st.IndexRemove(t, ri);
    t.rows[ri].dead = true;
    // 保留 pkMap 条目（指向墓碑）—— 这样「插入同主键」能 O(1) 复活，
    // 同时也让 DELETE 的语义是「保留身份、清除内容」而不是「抹掉存在」。
}

// 建索引：对已有活行做一次全扫建图（日志里 CREATE INDEX 可能出现在 INSERT 之后）
static void ApplyCreateIndex(Table& t, const std::string& idxName, int col, bool unique) {
    for (size_t i = 0; i < t.idx.size(); ++i) {
        if (_stricmp(t.idx[i].name.c_str(), idxName.c_str()) == 0) {
            t.idx.erase(t.idx.begin() + (ptrdiff_t)i);
            break;
        }
    }
    Index ix;
    ix.name   = idxName;
    ix.col    = col;
    ix.unique = unique;
    for (size_t ri = 0; ri < t.rows.size(); ++ri) {
        if (t.rows[ri].dead) continue;
        if (col < 0 || col >= (int)t.rows[ri].cells.size()) continue;
        ix.map[KeyOf(t.rows[ri].cells[col])].push_back(ri);
    }
    t.idx.push_back(ix);
}

// ===========================================================================
//  重放（崩溃恢复）
// ===========================================================================
namespace {

// 带缓冲的顺序读。用手写小缓冲而不是一次 ReadFile 整文件：
//   · 库可能长到几十 MB，整读会白占内存；
//   · 崩溃点定位需要精确的「已消费字节数」，缓冲层能顺带维护它。
struct BufReader {
    HANDLE            h    = INVALID_HANDLE_VALUE;
    std::vector<char> buf;
    size_t            pos  = 0;
    size_t            len  = 0;
    bool              eof  = false;
    unsigned long long consumed = 0;   // 已成功消费（读到且通过校验）的字节数

    explicit BufReader(HANDLE fh) : h(fh) { buf.resize(256 * 1024); }

    bool Fill() {
        if (pos < len) return true;
        if (eof) return false;
        DWORD rd = 0;
        if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr) || rd == 0) {
            eof = true;
            return false;
        }
        len = (size_t)rd;
        pos = 0;
        return true;
    }

    bool HasMore() {
        if (pos < len) return true;
        return Fill();
    }

    bool ReadExact(char* out, size_t n) {
        size_t done = 0;
        while (done < n) {
            if (!Fill()) return false;
            size_t avail = len - pos;
            size_t take  = (avail < (n - done)) ? avail : (n - done);
            memcpy(out + done, buf.data() + pos, take);
            pos  += take;
            done += take;
        }
        return true;
    }
};

}  // namespace

bool Store::Replay(const std::wstring& wpath) {
    tables.clear();
    frames    = 0;
    recovered = 0;

    LARGE_INTEGER sz;
    sz.QuadPart = 0;
    if (!GetFileSizeEx(hFile, &sz)) {
        SetErr("读取文件大小失败，错误码 " + std::to_string(GetLastError()));
        return false;
    }
    fileBytes = sz.QuadPart;

    if (fileBytes == 0) {
        // 全新库：立刻写文件头帧，让「空库」与「坏文件」在磁盘上可区分
        Writer w;
        w.I64(1);
        w.Str("SilverFoxGuard-sfdb");
        return AppendFrame(kFrameHeader, w.buf);
    }

    // 从 0 开始顺序读（每次打开都从文件头重放）
    LARGE_INTEGER zero;
    zero.QuadPart = 0;
    SetFilePointerEx(hFile, zero, nullptr, FILE_BEGIN);

    BufReader fr(hFile);
    unsigned long long cursor  = 0;      // 下一帧应处的偏移
    bool               damaged = false;
    std::string        why;

    while (true) {
        if (!fr.HasMore()) break;        // 干净地停在帧边界 = 正常结束

        char hb[sizeof(FrameHead)];
        if (!fr.ReadExact(hb, sizeof(hb))) { damaged = true; why = "尾部帧头不足 16 字节"; break; }

        FrameHead fh;
        memcpy(&fh, hb, sizeof(fh));

        if (fh.magic != kMagic)  { damaged = true; why = "帧魔数不匹配（文件被其它数据覆盖？）"; break; }
        if (fh.len > kMaxPayload){ damaged = true; why = "帧长度超上限（头被写坏？）"; break; }

        std::string payload;
        if (fh.len) {
            payload.resize(fh.len);
            if (!fr.ReadExact(&payload[0], fh.len)) { damaged = true; why = "帧负载不足（写入中途断电）"; break; }
            if (Crc32(payload.data(), payload.size()) != fh.crc) {
                damaged = true; why = "帧 CRC 校验失败（负载被写坏）"; break;
            }
        }

        // 应用这一帧
        Reader r(payload.data(), payload.size());
        switch (fh.kind) {
            case kFrameHeader: {
                long long ver = 0;
                std::string tag;
                r.I64(ver);
                r.Str(tag);
                if (!r.Ok()) { damaged = true; why = "文件头帧解析失败"; }
                break;
            }
            case kFrameCheckpoint:
                break;   // 纯诊断信息，重放时忽略

            case kFrameCreateTable: {
                std::string name;
                uint32_t n = 0;
                std::vector<Col> cols;
                if (r.Str(name) && r.U32(n) && n <= 64) {
                    cols.resize(n);
                    for (uint32_t i = 0; i < n; ++i) {
                        uint8_t t = 0, pk = 0;
                        if (!r.Str(cols[i].name) || !r.U8(t) || !r.U8(pk)) break;
                        cols[i].type = (t == (uint8_t)Value::Int) ? Value::Int : Value::Text;
                        cols[i].isPk = (pk != 0);
                    }
                }
                if (!r.Ok() || cols.empty()) { damaged = true; why = "建表帧解析失败"; }
                else ApplyCreateTable(tables, name, cols);
                break;
            }

            case kFrameCreateIndex: {
                std::string tname, iname, cname;
                uint8_t uniq = 0;
                if (!(r.Str(tname) && r.Str(iname) && r.Str(cname) && r.U8(uniq))) {
                    damaged = true; why = "建索引帧解析失败";
                    break;
                }
                Table* t = Find(tname);
                if (!t) { damaged = true; why = "建索引帧引用了不存在的表 " + tname; break; }
                int col = t->FindCol(cname);
                if (col < 0) { damaged = true; why = "建索引帧引用了不存在的列 " + cname; break; }
                ApplyCreateIndex(*t, iname, col, uniq != 0);
                break;
            }

            case kFrameDropTable: {
                std::string name;
                if (!r.Str(name)) { damaged = true; why = "删表帧解析失败"; break; }
                for (size_t i = 0; i < tables.size(); ++i) {
                    if (_stricmp(tables[i].name.c_str(), name.c_str()) == 0) {
                        tables.erase(tables.begin() + (ptrdiff_t)i);
                        break;
                    }
                }
                break;
            }

            case kFrameInsert: {
                std::string tname;
                std::vector<Value> cells;
                if (!r.Str(tname) || !ReadCells(r, cells)) { damaged = true; why = "插入帧解析失败"; break; }
                Table* t = Find(tname);
                if (!t) { damaged = true; why = "插入帧引用了不存在的表 " + tname; break; }
                if (cells.size() != t->cols.size()) { damaged = true; why = "插入帧列数与表定义不符"; break; }
                ApplyInsertRow(*this, *t, cells);
                break;
            }

            case kFrameUpdate: {
                std::string tname;
                Value oldKey;
                std::vector<Value> cells;
                if (!r.Str(tname) || !r.Value_(oldKey) || !ReadCells(r, cells)) {
                    damaged = true; why = "更新帧解析失败";
                    break;
                }
                Table* t = Find(tname);
                if (!t || t->pk < 0 || t->pk >= (int)cells.size()) {
                    damaged = true; why = "更新帧指向无主键的表";
                    break;
                }
                if (cells.size() != t->cols.size()) {
                    damaged = true; why = "更新帧列数与表定义不符";
                    break;
                }
                const std::string ok0 = KeyOf(oldKey);
                auto it = t->pkMap.find(ok0);
                if (it == t->pkMap.end() || it->second >= t->rows.size()) {
                    damaged = true; why = "更新帧的旧主键不存在（" + ok0 + "）";
                    break;
                }
                size_t ri = it->second;
                IndexRemove(*t, ri);
                t->rows[ri].cells = cells;
                t->rows[ri].dead  = false;
                const std::string nk = KeyOf(cells[t->pk]);
                if (nk != ok0) {
                    t->pkMap.erase(ok0);
                    t->pkMap[nk] = ri;
                }
                IndexAdd(*t, ri);
                break;
            }

            case kFrameDelete: {
                std::string tname;
                Value pkv;
                if (!r.Str(tname) || !r.Value_(pkv)) { damaged = true; why = "删除帧解析失败"; break; }
                Table* t = Find(tname);
                if (!t) { damaged = true; why = "删除帧引用了不存在的表 " + tname; break; }
                ApplyDeleteRow(*this, *t, pkv);
                break;
            }

            default:
                // 未来版本加的帧类型，旧引擎不认识 → 无法安全跳过（不知道语义）
                damaged = true;
                why = "遇到未知帧类型 " + std::to_string((int)fh.kind) + "（库由更新版本写入？）";
                break;
        }

        if (damaged) break;

        cursor += sizeof(FrameHead) + fh.len;
        ++frames;
    }

    // ---- 崩溃恢复：把损坏点之后的内容**截掉** ----
    // 这里的选择很关键：宁可丢最后一条记录，也不让整个库打不开。
    // 对隔离区索引这类数据，后者是灾难（用户看不到自己的文件去哪了）。
    if (damaged) {
        unsigned long long badAt = cursor;
        if (badAt > (unsigned long long)fileBytes) badAt = (unsigned long long)fileBytes;

        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)badAt;
        if (SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN) && SetEndOfFile(hFile)) {
            recovered = fileBytes - (long long)badAt;
            sf::LogDbg("[sfdb] 日志尾部损坏已截断：" + why +
                       "；丢弃 " + std::to_string(recovered) + " 字节（前 " +
                       std::to_string(frames) + " 帧完好）");
        } else {
            sf::LogDbg("[sfdb] 日志损坏（" + why + "）但截断失败，错误码 " +
                       std::to_string(GetLastError()) + "；本库以只读方式继续");
        }
        fileBytes = (long long)badAt;
    }

    if (frames == 0) {
        // 文件非空却没有任何有效帧（例如被别的程序覆写了开头，或第一帧就残缺）
        // → 当作空库重建头帧，否则之后追加的帧永远处于「无头」状态，下次打开
        //   又会从偏移 0 读到一个残缺头，陷入「每次都截断」的死循环。
        LARGE_INTEGER sz2;
        sz2.QuadPart = 0;
        if (GetFileSizeEx(hFile, &sz2) && sz2.QuadPart > 0) {
            LARGE_INTEGER li;
            li.QuadPart = 0;
            if (SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN) && SetEndOfFile(hFile)) {
                recovered += sz2.QuadPart;
                sf::LogDbg("[sfdb] 库文件无有效帧，已整体截断 " +
                           std::to_string(sz2.QuadPart) + " 字节并重建");
            }
        }
        fileBytes = 0;
        Writer w;
        w.I64(1);
        w.Str("SilverFoxGuard-sfdb");
        if (!AppendFrame(kFrameHeader, w.buf)) return false;
    }

    return true;
}

// ===========================================================================
//  Store：打开 / 关闭
// ===========================================================================
bool Store::OpenFile(const std::string& pathUtf8) {
    path = pathUtf8;
    err.clear();

    if (pathUtf8.empty()) { SetErr("库路径为空"); return false; }

    std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) { SetErr("库路径无法转为宽字符（非法 UTF-8？）：" + pathUtf8); return false; }

    size_t slash = w.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash > 0) {
        std::wstring dir = w.substr(0, slash);
        if (!EnsureDirW(dir)) {
            SetErr("创建库目录失败，错误码 " + std::to_string(GetLastError()));
            return false;
        }
    }

    hFile = CreateFileW(w.c_str(),
                        GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ,          // 允许他方（诊断工具）只读打开
                        nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        SetErr("打开库文件失败，错误码 " + std::to_string(GetLastError()) + "：" + pathUtf8);
        return false;
    }

    if (!Replay(w)) {
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    LARGE_INTEGER li;
    li.QuadPart = 0;
    SetFilePointerEx(hFile, li, nullptr, FILE_END);

    open = true;
    return true;
}

void Store::CloseFile() {
    if (hFile != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(hFile);
        CloseHandle(hFile);
        hFile = INVALID_HANDLE_VALUE;
    }
    tables.clear();
    open = false;
}

// ===========================================================================
//  Store：变更操作
// ===========================================================================
bool Store::CreateTable(const std::string& name, const std::vector<Col>& cols, bool ifNotExists) {
    if (name.empty()) { SetErr("表名不能为空"); return false; }
    if (cols.empty()) { SetErr("表至少要有一列"); return false; }
    if (cols.size() > 64) { SetErr("列数超过上限 64"); return false; }

    int pkCount = 0;
    for (size_t i = 0; i < cols.size(); ++i) {
        if (cols[i].name.empty()) { SetErr("存在空列名"); return false; }
        if (cols[i].isPk && ++pkCount > 1) { SetErr("一个表最多只能有一个主键"); return false; }
    }
    for (size_t i = 0; i < cols.size(); ++i) {
        for (size_t j = i + 1; j < cols.size(); ++j) {
            if (_stricmp(cols[i].name.c_str(), cols[j].name.c_str()) == 0) {
                SetErr("列名重复：" + cols[i].name);
                return false;
            }
        }
    }

    if (Find(name)) {
        if (ifNotExists) return true;
        SetErr("表已存在：" + name + "（可用 DROP TABLE 先删）");
        return false;
    }

    Writer w;
    w.Str(name);
    w.U32((uint32_t)cols.size());
    for (size_t i = 0; i < cols.size(); ++i) {
        w.Str(cols[i].name);
        w.U8((uint8_t)cols[i].type);
        w.U8(cols[i].isPk ? 1 : 0);
    }
    if (!AppendFrame(kFrameCreateTable, w.buf)) return false;

    ApplyCreateTable(tables, name, cols);
    return true;
}

bool Store::CreateIndex(const std::string& table, const std::string& indexName,
                        const std::string& col, bool unique, bool ifNotExists) {
    Table* t = Find(table);
    if (!t) { SetErr("表不存在：" + table); return false; }
    int ci = t->FindCol(col);
    if (ci < 0) { SetErr("列不存在：" + table + "." + col); return false; }
    if (indexName.empty()) { SetErr("索引名不能为空"); return false; }

    for (size_t i = 0; i < t->idx.size(); ++i) {
        if (_stricmp(t->idx[i].name.c_str(), indexName.c_str()) == 0) {
            if (ifNotExists) return true;
            SetErr("索引已存在：" + indexName);
            return false;
        }
    }

    if (unique) {
        for (size_t ri = 0; ri < t->rows.size(); ++ri) {
            if (t->rows[ri].dead) continue;
            for (size_t rj = ri + 1; rj < t->rows.size(); ++rj) {
                if (t->rows[rj].dead) continue;
                if (Value::Compare(t->rows[ri].cells[ci], t->rows[rj].cells[ci]) == 0) {
                    SetErr("无法建唯一索引 " + indexName + "：已有重复值");
                    return false;
                }
            }
        }
    }

    Writer w;
    w.Str(table);
    w.Str(indexName);
    w.Str(col);
    w.U8(unique ? 1 : 0);
    if (!AppendFrame(kFrameCreateIndex, w.buf)) return false;

    ApplyCreateIndex(*t, indexName, ci, unique);
    return true;
}

bool Store::DropTable(const std::string& name, bool ifExists) {
    Table* t = Find(name);
    if (!t) {
        if (ifExists) return true;
        SetErr("表不存在：" + name);
        return false;
    }
    Writer w;
    w.Str(name);
    if (!AppendFrame(kFrameDropTable, w.buf)) return false;

    for (size_t i = 0; i < tables.size(); ++i) {
        if (_stricmp(tables[i].name.c_str(), name.c_str()) == 0) {
            tables.erase(tables.begin() + (ptrdiff_t)i);
            break;
        }
    }
    return true;
}

bool Store::Insert(const std::string& tableName, const std::vector<Value>& cells) {
    Table* t = Find(tableName);
    if (!t) { SetErr("表不存在：" + tableName); return false; }
    if (cells.size() != t->cols.size()) {
        SetErr("列数不匹配：表 " + tableName + " 有 " + std::to_string(t->cols.size()) +
               " 列，给了 " + std::to_string(cells.size()) + " 个值");
        return false;
    }

    if (t->pk >= 0) {
        const Value& pkv = cells[t->pk];
        if (pkv.IsNull()) { SetErr("主键列 " + t->cols[t->pk].name + " 不能为空"); return false; }
        auto it = t->pkMap.find(KeyOf(pkv));
        if (it != t->pkMap.end() && it->second < t->rows.size() && !t->rows[it->second].dead) {
            SetErr("主键重复：" + KeyOf(pkv));
            return false;
        }
    }

    for (size_t k = 0; k < t->idx.size(); ++k) {
        Index& ix = t->idx[k];
        if (!ix.unique || ix.col < 0 || ix.col >= (int)cells.size()) continue;
        auto it = ix.map.find(KeyOf(cells[ix.col]));
        if (it == ix.map.end()) continue;
        for (size_t j = 0; j < it->second.size(); ++j) {
            size_t ri = it->second[j];
            if (ri < t->rows.size() && !t->rows[ri].dead) {
                SetErr("唯一索引 " + ix.name + " 冲突：" + cells[ix.col].ToText());
                return false;
            }
        }
    }

    Writer w;
    w.Str(tableName);
    WriteCells(w, cells);
    if (!AppendFrame(kFrameInsert, w.buf)) return false;

    ApplyInsertRow(*this, *t, cells);
    return true;
}

bool Store::UpdateByPk(const std::string& tableName, const Value& key,
                       const std::vector<Value>& newCells) {
    Table* t = Find(tableName);
    if (!t) { SetErr("表不存在：" + tableName); return false; }
    if (t->pk < 0) { SetErr("表 " + tableName + " 没有主键，无法按主键更新"); return false; }
    if (newCells.size() != t->cols.size()) { SetErr("列数不匹配"); return false; }

    const std::string oldKey = KeyOf(key);
    auto it = t->pkMap.find(oldKey);
    if (it == t->pkMap.end() || it->second >= t->rows.size() || t->rows[it->second].dead) {
        SetErr("要更新的行不存在（主键 " + oldKey + "）");
        return false;
    }
    size_t ri = it->second;

    const Value& pkv = newCells[t->pk];
    if (pkv.IsNull()) { SetErr("主键不能为空"); return false; }
    const std::string newKey = KeyOf(pkv);

    // 主键搬家：新主键不能撞到别的活行（撞到自己不算 —— 值没变的情况下面 oldKey==newKey 已短路）
    if (newKey != oldKey) {
        auto jt = t->pkMap.find(newKey);
        if (jt != t->pkMap.end() && jt->second < t->rows.size() && !t->rows[jt->second].dead) {
            SetErr("更新后主键重复：" + newKey);
            return false;
        }
    }

    for (size_t k = 0; k < t->idx.size(); ++k) {
        Index& ix = t->idx[k];
        if (!ix.unique || ix.col < 0) continue;
        auto jt = ix.map.find(KeyOf(newCells[ix.col]));
        if (jt == ix.map.end()) continue;
        for (size_t j = 0; j < jt->second.size(); ++j) {
            size_t other = jt->second[j];
            if (other == ri || other >= t->rows.size() || t->rows[other].dead) continue;
            SetErr("唯一索引 " + ix.name + " 冲突：" + newCells[ix.col].ToText());
            return false;
        }
    }

    Writer w;
    w.Str(tableName);
    w.Value_(key);          // ★ 旧主键：重放时靠它定位（主键可能被改）
    WriteCells(w, newCells);
    if (!AppendFrame(kFrameUpdate, w.buf)) return false;

    // ---- 应用内存 ----
    IndexRemove(*t, ri);
    t->rows[ri].cells = newCells;
    t->rows[ri].dead  = false;
    if (newKey != oldKey) {
        t->pkMap.erase(oldKey);      // 旧主键不再指向任何活行
        t->pkMap[newKey] = ri;
    }
    IndexAdd(*t, ri);
    return true;
}

bool Store::DeleteByPk(const std::string& tableName, const Value& pkValue) {
    Table* t = Find(tableName);
    if (!t) { SetErr("表不存在：" + tableName); return false; }
    if (t->pk < 0) { SetErr("表 " + tableName + " 没有主键，无法按主键删除"); return false; }

    auto it = t->pkMap.find(KeyOf(pkValue));
    if (it == t->pkMap.end() || it->second >= t->rows.size() || t->rows[it->second].dead) {
        SetErr("要删除的行不存在（主键 " + KeyOf(pkValue) + "）");
        return false;
    }

    Writer w;
    w.Str(tableName);
    w.Value_(pkValue);
    if (!AppendFrame(kFrameDelete, w.buf)) return false;

    size_t ri = it->second;
    IndexRemove(*t, ri);
    t->rows[ri].dead = true;
    return true;
}

// ===========================================================================
//  压缩
// ===========================================================================
bool Store::Compact() {
    if (!open) { SetErr("库未打开"); return false; }

    std::wstring wsrc = Utf8ToWide(path);
    if (wsrc.empty()) { SetErr("路径转宽失败"); return false; }
    std::wstring wtmp = wsrc + L".tmp";

    HANDLE hNew = CreateFileW(wtmp.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hNew == INVALID_HANDLE_VALUE) {
        SetErr("创建压缩临时文件失败，错误码 " + std::to_string(GetLastError()));
        return false;
    }

    // ---- 阶段 1：把「活数据」写进临时文件 ----
    bool ok = true;
    {
        Writer w;
        w.I64(1);
        w.Str("SilverFoxGuard-sfdb");
        ok = WriteFrameTo(hNew, kFrameHeader, w.buf);
    }

    for (size_t ti = 0; ok && ti < tables.size(); ++ti) {
        Table& t = tables[ti];

        Writer w;
        w.Str(t.name);
        w.U32((uint32_t)t.cols.size());
        for (size_t ci = 0; ci < t.cols.size(); ++ci) {
            w.Str(t.cols[ci].name);
            w.U8((uint8_t)t.cols[ci].type);
            w.U8(t.cols[ci].isPk ? 1 : 0);
        }
        ok = WriteFrameTo(hNew, kFrameCreateTable, w.buf);

        for (size_t ii = 0; ok && ii < t.idx.size(); ++ii) {
            Index& ix = t.idx[ii];
            if (ix.col < 0 || ix.col >= (int)t.cols.size()) continue;
            Writer iw;
            iw.Str(t.name);
            iw.Str(ix.name);
            iw.Str(t.cols[ix.col].name);
            iw.U8(ix.unique ? 1 : 0);
            ok = WriteFrameTo(hNew, kFrameCreateIndex, iw.buf);
        }

        for (size_t ri = 0; ok && ri < t.rows.size(); ++ri) {
            if (t.rows[ri].dead) continue;
            Writer rw;
            rw.Str(t.name);
            WriteCells(rw, t.rows[ri].cells);
            ok = WriteFrameTo(hNew, kFrameInsert, rw.buf);
        }
    }

    if (ok) {
        Writer w;
        w.I64((long long)frames);
        ok = WriteFrameTo(hNew, kFrameCheckpoint, w.buf);
    }

    if (ok) FlushFileBuffers(hNew);
    CloseHandle(hNew);

    if (!ok) {
        DeleteFileW(wtmp.c_str());
        SetErr("压缩写入临时文件失败（原库未受影响）");
        return false;
    }

    // ---- 阶段 2：原子替换 ----
    // 关掉旧句柄再替换：Windows 不允许替换一个自己持有写句柄的文件。
    // 这一步之前原库始终完好 —— 所以压缩是「崩溃安全」的。
    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    if (!MoveFileExW(wtmp.c_str(), wsrc.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD e = GetLastError();
        DeleteFileW(wtmp.c_str());
        // 尽力把原库重新打开，避免压缩失败把库搞成「不可用」
        hFile = CreateFileW(wsrc.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        SetErr("压缩替换失败，错误码 " + std::to_string(e) + "（原库已重新打开）");
        if (hFile == INVALID_HANDLE_VALUE) {
            open = false;
            tables.clear();
        } else {
            tables.clear();
            Replay(wsrc);
        }
        return false;
    }

    // ---- 阶段 3：重开 + 重放，保证内存与磁盘严格一致 ----
    tables.clear();
    hFile = CreateFileW(wsrc.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        open = false;
        SetErr("压缩后重新打开失败，错误码 " + std::to_string(GetLastError()));
        return false;
    }
    if (!Replay(wsrc)) {
        open = false;
        return false;
    }
    LARGE_INTEGER li;
    li.QuadPart = 0;
    SetFilePointerEx(hFile, li, nullptr, FILE_END);

    ++compacts;
    sf::LogDbg("[sfdb] 压缩完成：" + path + " → " + std::to_string(fileBytes) + " 字节，" +
               std::to_string(tables.size()) + " 张表");
    return true;
}

}  // namespace impl

// ===========================================================================
//  Database 门面
// ===========================================================================
//  这一层只做三件事：持锁、转发、把 Stats 汇总成好读的形状。
//  它刻意不持有任何业务判断 —— 与「主干不做业务判断」是同一条原则。
struct Database::Impl {
    sf::sfdb::impl::Store store;
    mutable std::mutex    mu;
};

Database::Database() : p_(new Impl()) {}

Database::~Database() { delete p_; }

bool Database::Open(const std::string& pathUtf8) {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.OpenFile(pathUtf8);
}

void Database::Close() {
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->store.CloseFile();
}

bool Database::IsOpen() const {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.open;
}

std::string Database::LastError() const {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.err;
}

bool Database::Exec(const std::string& sql, std::vector<ResultSet>& outs) {
    std::lock_guard<std::mutex> lk(p_->mu);
    if (!p_->store.open) {
        p_->store.SetErr("库未打开");
        return false;
    }
    outs.clear();
    return impl::SqlRunAll(p_->store, sql, outs);
}

bool Database::ExecOne(const std::string& sql, ResultSet& out) {
    std::vector<ResultSet> outs;
    if (!Exec(sql, outs)) return false;
    if (outs.empty()) {
        out = ResultSet();
        return true;
    }
    out = outs[0];
    return true;
}

bool Database::Compact() {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.Compact();
}

void Database::SetSyncOnWrite(bool on) {
    std::lock_guard<std::mutex> lk(p_->mu);
    p_->store.syncOnWrite = on;
}

bool Database::Sync() {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.Sync();
}

Stats Database::GetStats() const {
    std::lock_guard<std::mutex> lk(p_->mu);

    Stats s;
    s.path      = p_->store.path;
    s.open      = p_->store.open;
    s.fileBytes = p_->store.fileBytes;
    s.frames    = p_->store.frames;
    s.appends   = p_->store.appends;
    s.compacts  = p_->store.compacts;
    s.recovered = p_->store.recovered;

    long long totalDead = 0, totalLive = 0;
    for (size_t i = 0; i < p_->store.tables.size(); ++i) {
        const impl::Table& t = p_->store.tables[i];
        TableStat ts;
        ts.name    = t.name;
        ts.rows    = (long long)t.rows.size();
        ts.live    = t.LiveCount();
        ts.dead    = t.DeadCount();
        ts.columns = (int)t.cols.size();
        ts.indexes = (int)t.idx.size();
        ts.hasPk   = (t.pk >= 0);
        totalDead += ts.dead;
        totalLive += ts.live;
        s.tables.push_back(ts);
    }
    // 「脏」的判据：墓碑占比超过活行的 1/4，或者文件里平均每行开销 > 4 倍
    // （说明 UPDATE 帧堆得太多）。两者都指向「该 Compact 了」。
    s.dirty = (totalDead > 0 && totalDead * 4 > totalLive);
    return s;
}

bool Database::QueryText(const std::string& sql, std::string& out) {
    out.clear();
    ResultSet rs;
    if (!ExecOne(sql, rs)) return false;
    if (rs.rows.empty() || rs.rows[0].empty()) return false;
    out = rs.rows[0][0].ToText();
    return true;
}

bool Database::QueryInt(const std::string& sql, long long& out) {
    out = 0;
    ResultSet rs;
    if (!ExecOne(sql, rs)) return false;
    if (rs.rows.empty() || rs.rows[0].empty()) return false;
    out = rs.rows[0][0].ToInt();
    return true;
}

bool Database::TableExists(const std::string& table) const {
    std::lock_guard<std::mutex> lk(p_->mu);
    return p_->store.Find(table) != nullptr;
}

long long Database::CountRows(const std::string& table) const {
    std::lock_guard<std::mutex> lk(p_->mu);
    if (table.empty()) {
        long long n = 0;
        for (size_t i = 0; i < p_->store.tables.size(); ++i) n += p_->store.tables[i].LiveCount();
        return n;
    }
    const impl::Table* t = p_->store.Find(table);
    return t ? t->LiveCount() : 0;
}

std::string Database::Quote(const std::string& raw) {
    std::string o;
    o.reserve(raw.size() + 2);
    o.push_back('\'');
    for (size_t i = 0; i < raw.size(); ++i) {
        char c = raw[i];
        if (c == '\'') o += "''";          // SQL 标准的单引号转义
        else           o.push_back(c);
    }
    o.push_back('\'');
    return o;
}

}  // namespace sfdb
}  // namespace sf
