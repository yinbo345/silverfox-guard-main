// pehash.cpp — pehash.h 的实现。设计理由与算法出处见 pehash.h 文件头，这里只写
//              "为什么这么写"的工程约束。
//
// ===========================================================================
//  三条工程约束（都对应本项目吃过亏的形态）
// ===========================================================================
//
//  ① **一律 *W 文件 API**（铁律 §4）。本文件里没有一处 `std::ifstream`。
//     这不是风格问题：中文用户名下一次静默失败，日志里一行痕迹都没有。
//
//  ② **全部解析都在有边界检查的内存缓冲上做**。恶意 PE 的头部字段是攻击者
//     完全可控的（节表 RVA、thunk 链长度、名字串长度），任何一处没查边界就是
//     一个越界读。参考依据：LIEF 源码里那两条专门的防护注释
//     （"Bounds the import thunk loop to prevent hangs on malformed IATs"、
//     "Bounds peek_string_at to prevent multi-megabyte reads on invalid RVAs"）
//     说的就是这件事 —— 解析器本身是攻击面。
//
//  ③ **★ 一处解析失误必须只影响"那个字段"，不能蔓延到整张表。**
//     这条最容易写错：如果把"越界/串未终止"记成一个**粘性**的失败标志，
//     那么导入表里第一个坏名字就会让后面所有本可解析的条目全部丢弃 →
//     我们算出的 imphash **与参考实现不同** → 库里存的和查的对不上 →
//     库看着建好了却永远查不中、**且不报任何错**。
//     所以：结构性字段（头部/节表）用粘性标志（错了就没必要继续），
//     字符串读取用 `TryCStr`（**不**污染标志，只跳过这一条）。
#include "pehash.h"

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace sf {
namespace pehash {

// 上限常量（kShaMaxBytes / kImphashMaxBytes / kCacheCap）定义在 pehash.h。
//   · kShaMaxBytes 只由 FileSha256Cached 施加（限制**热路径耗时**）
//   · kImphashMaxBytes 由 Imphash 施加（PE 解析要整文件进内存，是硬需要）
// ⚠️ 不要在本文件里再写一遍 —— 那是同一编译单元内的重定义。

// ===========================================================================
//  基础工具
// ===========================================================================
namespace {

// UTF-8 → UTF-16。失败返回空（调用方判空 = 路径非法，不是"文件不存在"）。
std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// 以只读方式打开（共享模式放到最宽：样本可能正被另一个进程读）。
HANDLE OpenReadW(const std::string& pathUtf8) {
    std::wstring w = Widen(pathUtf8);
    if (w.empty()) return INVALID_HANDLE_VALUE;
    return CreateFileW(w.c_str(), GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                       nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

enum ReadRes {
    kReadOk = 0,
    kReadFail,      // 打不开 / 读失败 —— **瞬时**，不应缓存
    kReadTooBig,    // 超过上限 —— **稳定**，可以缓存为"不处理"
};

// 整个文件读进内存（PE 解析需要随机访问）。
// ★ 上限检查在分配之前做 —— 不能让一个 4GB 的文件把常驻服务撑爆。
ReadRes ReadWholeW(const std::string& pathUtf8, uint64_t cap, uint64_t& outSize,
                   std::vector<uint8_t>& out) {
    out.clear();
    outSize = 0;
    HANDLE h = OpenReadW(pathUtf8);
    if (h == INVALID_HANDLE_VALUE) return kReadFail;

    LARGE_INTEGER sz;
    sz.QuadPart = 0;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return kReadFail; }
    const uint64_t n64 = (uint64_t)sz.QuadPart;
    outSize = n64;
    if (n64 > cap) { CloseHandle(h); return kReadTooBig; }
    if (n64 == 0)  { CloseHandle(h); return kReadOk; }

    out.resize((size_t)n64);
    size_t got = 0;
    while (got < out.size()) {
        size_t left = out.size() - got;
        DWORD want = (DWORD)(left > (1u << 20) ? (1u << 20) : left);
        DWORD rd = 0;
        if (!ReadFile(h, out.data() + got, want, &rd, nullptr) || rd == 0) {
            CloseHandle(h);
            out.clear();
            return kReadFail;
        }
        got += rd;
    }
    CloseHandle(h);
    return kReadOk;
}

// 有边界检查的缓冲读取器。
//
// ★ 两套 API 的分工（见文件头约束③）：
//    · U16/U32/U64/Dir   —— 结构性字段，粘性 ok（错了整份解析作废）
//    · TryCStr           —— 字符串字段，**不动 ok**，只返回本次成败
struct Rd {
    const uint8_t* p = nullptr;
    size_t n = 0;
    bool ok = true;

    bool Has(size_t off, size_t len) const { return off <= n && len <= n - off; }
    uint16_t U16(size_t o) {
        if (!Has(o, 2)) { ok = false; return 0; }
        uint16_t v; std::memcpy(&v, p + o, 2); return v;
    }
    uint32_t U32(size_t o) {
        if (!Has(o, 4)) { ok = false; return 0; }
        uint32_t v; std::memcpy(&v, p + o, 4); return v;
    }
    uint64_t U64(size_t o) {
        if (!Has(o, 8)) { ok = false; return 0; }
        uint64_t v; std::memcpy(&v, p + o, 8); return v;
    }
    // 以 NUL 结尾的串，最多读 maxLen 字节，不含 NUL。
    // 越界 / 限长内没有终止符 → 返回 false，**且不改 ok**。
    bool TryCStr(size_t o, size_t maxLen, std::string& out) const {
        out.clear();
        if (o >= n) return false;
        const size_t avail = n - o;
        const size_t lim = (avail < maxLen) ? avail : maxLen;
        size_t i = 0;
        while (i < lim && p[o + i] != 0) ++i;
        if (i >= lim) return false;          // 限长内没结束 → 不采信
        out.assign((const char*)p + o, i);
        return true;
    }
};

// ---- BCrypt ----
// 走 CNG 而不是自带实现：算法库已在链路里（build.sh 有 bcrypt.lib），
// 自带一份 SHA-256/MD5 只会多一处可能写错的地方。
std::string FinishHex(BCRYPT_HASH_HANDLE hh, size_t digestBytes) {
    static const char* hx = "0123456789abcdef";
    BYTE buf[64];
    if (digestBytes > sizeof(buf)) return std::string();
    if (BCryptFinishHash(hh, buf, (ULONG)digestBytes, 0) != 0) return std::string();
    std::string o;
    o.reserve(digestBytes * 2);
    for (size_t i = 0; i < digestBytes; ++i) {
        o += hx[buf[i] >> 4];
        o += hx[buf[i] & 0xf];
    }
    return o;
}

bool HashBytes(LPCWSTR algo, const void* data, size_t len, size_t digestBytes,
               std::string& outHex) {
    outHex.clear();
    BCRYPT_ALG_HANDLE h = nullptr;
    if (BCryptOpenAlgorithmProvider(&h, algo, nullptr, 0) != 0) return false;
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(h, &hh, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(h, 0);
        return false;
    }
    bool ok = true;
    if (len) ok = (BCryptHashData(hh, (PUCHAR)data, (ULONG)len, 0) == 0);
    if (ok) outHex = FinishHex(hh, digestBytes);
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(h, 0);
    return ok && !outHex.empty();
}

bool Sha256Hex(const void* data, size_t len, std::string& outHex) {
    return HashBytes(BCRYPT_SHA256_ALGORITHM, data, len, 32, outHex);
}
bool Md5Hex(const void* data, size_t len, std::string& outHex) {
    return HashBytes(BCRYPT_MD5_ALGORITHM, data, len, 16, outHex);
}

std::string Lower(const std::string& s) {
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i)
        if (o[i] >= 'A' && o[i] <= 'Z') o[i] = (char)(o[i] - 'A' + 'a');
    return o;
}

// ===========================================================================
//  观测计数
// ===========================================================================
//  「一个数字如果没人能反驳它，它就不是校验，只是日志。」
//  所以每类成因分开计，且都能被 hashchain 命令读出来。
std::atomic<long long> g_shaCompute{0}, g_shaCacheHit{0}, g_shaTooBig{0}, g_shaFail{0};
std::atomic<long long> g_impCompute{0}, g_impCacheHit{0}, g_impNotPe{0}, g_impFail{0};
std::atomic<long long> g_md5Compute{0}, g_md5CacheHit{0}, g_md5TooBig{0}, g_md5Fail{0};
std::atomic<long long> g_sha1Compute{0}, g_sha1CacheHit{0}, g_sha1TooBig{0}, g_sha1Fail{0};
std::atomic<long long> g_cacheEvicted{0};

inline void Bump(std::atomic<long long>& c) { c.fetch_add(1, std::memory_order_relaxed); }

// ===========================================================================
//  热路径缓存
// ===========================================================================
//  ★ 三段式（**与 scanner.cpp 的缓存同一个纪律**）：
//      锁内查 → **锁外 I/O** → 锁内写
//    绝不能持锁做 I/O。在锁里读 40MB 文件 = 把查询它的线程全部串行化，
//    且表现为"偶发卡顿"，极难归因。
//
//  ★ 键含 (文件大小, 最后写时间)：文件被改写就自动失效，不需要 TTL。
//    只按路径缓存是最容易写出的错版本 —— 样本被替换后一直命中旧哈希，
//    现象是"明明换了样本却还是旧结论"。
struct Ent {
    uint64_t    size  = 0;
    uint64_t    mtime = 0;
    std::string hex;              // 哈希值（空 = 没算过）
    bool        notPe = false;    // 仅 imphash 用：已确认"没有可用结论且稳定"
};

std::mutex g_shaMtx;
std::unordered_map<std::string, Ent> g_shaCache;
std::mutex g_impMtx;
std::unordered_map<std::string, Ent> g_impCache;
std::mutex g_digMtx;
std::unordered_map<std::string, Ent> g_digCache;   // MD5 / SHA-1 共用；键前置 1 字符算法前缀

// 取文件身份（大小 + 最后写时间）。走 *W；失败返回 false。
bool FileIdentity(const std::string& pathUtf8, uint64_t& size, uint64_t& mtime) {
    std::wstring w = Widen(pathUtf8);
    if (w.empty()) return false;
    HANDLE h = CreateFileW(w.c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    BY_HANDLE_FILE_INFORMATION fi{};
    const bool ok = GetFileInformationByHandle(h, &fi) != 0;
    CloseHandle(h);
    if (!ok) return false;
    size = ((uint64_t)fi.nFileSizeHigh << 32) | (uint64_t)fi.nFileSizeLow;
    mtime = ((uint64_t)fi.ftLastWriteTime.dwHighDateTime << 32) |
            (uint64_t)fi.ftLastWriteTime.dwLowDateTime;
    return true;
}

// ★ 容量满则整体清空，而不是做 LRU：实现简单，重算代价可控。
//   但**淘汰必须记账** —— 否则"缓存一直不命中的真正原因是容量太小"
//   会被误读成"没配缓存"。
void PutLocked(std::unordered_map<std::string, Ent>& m,
               const std::string& k, const Ent& e) {
    if (m.size() >= kCacheCap && m.find(k) == m.end()) {
        g_cacheEvicted.fetch_add((long long)m.size(), std::memory_order_relaxed);
        m.clear();
    }
    m[k] = e;
}

// 通用整文件摘要：algId = BCRYPT_*_ALGORITHM；outLen = 输出字节数（32/16/20）。
// 不设大小上限（"算法"语义；上限由 CachedDigest 施加）。SHA-256 / MD5 / SHA-1 共用。
bool FileDigestW(const std::string& pathUtf8, LPCWSTR algId, DWORD outLen,
                std::string& outHex,
                std::atomic<long long>& failCtr, std::atomic<long long>& okCtr) {
    outHex.clear();
    HANDLE h = OpenReadW(pathUtf8);
    if (h == INVALID_HANDLE_VALUE) { Bump(failCtr); return false; }
    LARGE_INTEGER sz; sz.QuadPart = 0;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); Bump(failCtr); return false; }
    BCRYPT_ALG_HANDLE ah = nullptr;
    if (BCryptOpenAlgorithmProvider(&ah, algId, nullptr, 0) != 0) {
        CloseHandle(h); Bump(failCtr); return false;
    }
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(ah, &hh, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(ah, 0); CloseHandle(h); Bump(failCtr); return false;
    }
    bool ok = true;
    std::vector<uint8_t> buf(1 << 16);
    for (;;) {
        DWORD rd = 0;
        if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &rd, nullptr)) { ok = false; break; }
        if (rd == 0) break;
        if (BCryptHashData(hh, buf.data(), rd, 0) != 0) { ok = false; break; }
    }
    if (ok) outHex = FinishHex(hh, outLen);
    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(ah, 0);
    CloseHandle(h);
    if (!ok || outHex.empty()) { outHex.clear(); Bump(failCtr); return false; }
    Bump(okCtr);
    return true;
}

// 通用缓存封装（MD5 / SHA-1 共用一张表，键前置 1 字符算法前缀与 SHA-256 缓存隔离）。
bool CachedDigest(char algoChar, const std::string& pathUtf8, LPCWSTR algId, DWORD outLen,
                  std::string& outHex, uint64_t* outSize,
                  std::atomic<long long>& failCtr, std::atomic<long long>& okCtr,
                  std::atomic<long long>& hitCtr, std::atomic<long long>& tooBigCtr) {
    outHex.clear();
    if (outSize) *outSize = 0;
    uint64_t size = 0, mtime = 0;
    if (!FileIdentity(pathUtf8, size, mtime)) { Bump(failCtr); return false; }
    if (outSize) *outSize = size;
    if (size > kShaMaxBytes) { Bump(tooBigCtr); return false; }
    const std::string key = std::string(1, (char)algoChar) + pathUtf8;
    {
        std::lock_guard<std::mutex> lk(g_digMtx);
        auto it = g_digCache.find(key);
        if (it != g_digCache.end() && it->second.size == size &&
            it->second.mtime == mtime && !it->second.hex.empty()) {
            outHex = it->second.hex;
            Bump(hitCtr);
            return true;
        }
    }
    std::string hex;
    if (!FileDigestW(pathUtf8, algId, outLen, hex, failCtr, okCtr)) return false;
    {
        std::lock_guard<std::mutex> lk(g_digMtx);
        Ent e; e.size = size; e.mtime = mtime; e.hex = hex;
        PutLocked(g_digCache, key, e);
    }
    outHex = hex;
    return true;
}

}  // namespace

// ===========================================================================
//  SHA-256（整文件）
// ===========================================================================
bool FileSha256(const std::string& pathUtf8, std::string& outHex) {
    return FileDigestW(pathUtf8, BCRYPT_SHA256_ALGORITHM, 32, outHex,
                       g_shaFail, g_shaCompute);
}
bool FileMd5(const std::string& pathUtf8, std::string& outHex) {
    return FileDigestW(pathUtf8, BCRYPT_MD5_ALGORITHM, 16, outHex,
                       g_md5Fail, g_md5Compute);
}
bool FileSha1(const std::string& pathUtf8, std::string& outHex) {
    return FileDigestW(pathUtf8, BCRYPT_SHA1_ALGORITHM, 20, outHex,
                       g_sha1Fail, g_sha1Compute);
}

bool FileSha256Cached(const std::string& pathUtf8, std::string& outHex, uint64_t* outSize) {
    outHex.clear();
    if (outSize) *outSize = 0;

    uint64_t size = 0, mtime = 0;
    if (!FileIdentity(pathUtf8, size, mtime)) { Bump(g_shaFail); return false; }
    if (outSize) *outSize = size;

    // ★ 热路径专有的大小上限：超了就不算。
    //   目的不是省内存（FileSha256 本来就是流式），而是**限制消费线程被
    //   一次哈希拖住的时长** —— 一个 200MB 的安装包要算 1 秒以上，
    //   在 ETW 事件消费线程里做这件事会让队列积压、表现成"实时防护变慢"。
    if (size > kShaMaxBytes) { Bump(g_shaTooBig); return false; }

    {   // ---- 锁内查 ----
        std::lock_guard<std::mutex> lk(g_shaMtx);
        auto it = g_shaCache.find(pathUtf8);
        if (it != g_shaCache.end() && it->second.size == size &&
            it->second.mtime == mtime && !it->second.hex.empty()) {
            outHex = it->second.hex;
            Bump(g_shaCacheHit);
            return true;
        }
    }

    std::string hex;                                   // ---- 锁外 I/O ----
    if (!FileSha256(pathUtf8, hex)) return false;      // 内部已计数

    {   // ---- 锁内写 ----
        std::lock_guard<std::mutex> lk(g_shaMtx);
        Ent e;
        e.size = size;
        e.mtime = mtime;
        e.hex = hex;
        PutLocked(g_shaCache, pathUtf8, e);
    }
    outHex = hex;
    return true;
}

bool FileMd5Cached(const std::string& pathUtf8, std::string& outHex, uint64_t* outSize) {
    return CachedDigest('M', pathUtf8, BCRYPT_MD5_ALGORITHM, 16, outHex, outSize,
                        g_md5Fail, g_md5Compute, g_md5CacheHit, g_md5TooBig);
}
bool FileSha1Cached(const std::string& pathUtf8, std::string& outHex, uint64_t* outSize) {
    return CachedDigest('1', pathUtf8, BCRYPT_SHA1_ALGORITHM, 20, outHex, outSize,
                        g_sha1Fail, g_sha1Compute, g_sha1CacheHit, g_sha1TooBig);
}

// ===========================================================================
//  imphash
// ===========================================================================
namespace {

// 全部是"恶意样本可控字段"的护栏，不是性能调优。
const size_t kMaxDescs    = 512;    // 导入描述符表条目上限
const size_t kMaxThunks   = 4096;   // 单个 DLL 的 thunk 链上限
const size_t kMaxNameLen  = 512;    // DLL / 函数名字串上限
const size_t kMaxSections = 96;     // 节表条目上限

struct Sec { uint32_t va = 0, vsz = 0, rsz = 0, raw = 0; };

// RVA → 文件内偏移。边界语义与 probe.cpp 的 RvaToRaw **保持一致**
// （那边是全盘扫描用的权威版本）。刻意重写而不是 include：解析器的
// 边界规则改动时必须两处同时改并各跑各的回归 —— 这条写在文档里，
// 不靠"希望没人只改一处"。
bool RvaToOff(const std::vector<Sec>& secs, uint32_t rva, size_t& out) {
    for (size_t i = 0; i < secs.size(); ++i) {
        const Sec& s = secs[i];
        if (s.vsz > 0 && rva >= s.va && rva < s.va + s.vsz) {
            if (rva - s.va >= s.rsz) return false;      // 落在未初始化尾部
            out = (size_t)s.raw + (rva - s.va);
            return true;
        }
        if (s.vsz == 0 && s.rsz > 0 && rva >= s.va && rva < s.va + s.rsz) {
            out = (size_t)s.raw + (rva - s.va);
            return true;
        }
    }
    return false;
}

enum ImpRes { kImpOk, kImpNotPe, kImpReadFail };

// 解析导入表 → 规范化后的 `lib.func` 列表（**保持导入表顺序，不排序**）。
//
// ⚠️ 不排序是算法的一部分：Mandiant 定义就是按导入表顺序拼接。改成排序
//    会让所有外部造的库对不上 —— 且不报错。
ImpRes ParseImportPairs(const std::string& pathUtf8, std::vector<std::string>& out) {
    out.clear();

    uint64_t fileSize = 0;
    std::vector<uint8_t> buf;
    ReadRes rr = ReadWholeW(pathUtf8, kImphashMaxBytes, fileSize, buf);
    if (rr == kReadTooBig) return kImpReadFail;
    if (rr == kReadFail)   return kImpReadFail;
    if (buf.size() < 0x40) return kImpNotPe;

    Rd rd{buf.data(), buf.size(), true};
    if (rd.U16(0) != 0x5A4D) return kImpNotPe;                    // 'MZ'
    const uint32_t lfanew = rd.U32(0x3C);
    if (!rd.ok || (size_t)lfanew + 24 > buf.size()) return kImpNotPe;
    if (rd.U32(lfanew) != 0x00004550) return kImpNotPe;           // 'PE\0\0'

    const size_t fh = (size_t)lfanew + 4;
    const uint16_t nsec    = rd.U16(fh + 2);
    const uint16_t optSize = rd.U16(fh + 16);
    if (!rd.ok || nsec == 0 || nsec > kMaxSections) return kImpNotPe;

    const size_t opt = fh + 20;
    const uint16_t magic = rd.U16(opt);
    if (!rd.ok) return kImpNotPe;
    bool   pe64 = false;
    size_t dirOff = 0;                       // 第一个数据目录项的位置
    if      (magic == 0x20B) { pe64 = true;  dirOff = opt + 112; }   // PE32+
    else if (magic == 0x10B) { pe64 = false; dirOff = opt + 96;  }   // PE32
    else return kImpNotPe;

    const uint32_t impRva = rd.U32(dirOff + 1 * 8);      // DataDirectory[1] = IMPORT
    if (!rd.ok || impRva == 0) return kImpNotPe;

    // ★ 为什么"无导入表"返回 NotPe 而不是给出 MD5("")：
    //   加壳样本的导入表往往被抹掉。若给它一个 MD5("") 的 imphash，
    //   **所有加壳样本会得到同一个值** → 库里一旦收录一条，全部加壳样本
    //   都会被命中。那是把一个空值变成一台误报机器。宁可不给结论。

    std::vector<Sec> secs;
    secs.reserve(nsec);
    const size_t secOff = opt + optSize;
    for (uint16_t i = 0; i < nsec; ++i) {
        const size_t o = secOff + (size_t)i * 40;
        if (!rd.Has(o, 40)) break;
        Sec s;
        s.vsz = rd.U32(o + 8);
        s.va  = rd.U32(o + 12);
        s.rsz = rd.U32(o + 16);
        s.raw = rd.U32(o + 20);
        if (!rd.ok) break;
        secs.push_back(s);
    }
    if (secs.empty()) return kImpNotPe;

    size_t descOff = 0;
    if (!RvaToOff(secs, impRva, descOff)) return kImpNotPe;
    if (descOff + 20 > buf.size()) return kImpNotPe;

    for (size_t di = 0; di < kMaxDescs; ++di) {
        const size_t o = descOff + di * 20;
        if (!rd.Has(o, 20)) break;
        const uint32_t oft     = rd.U32(o + 0);
        const uint32_t nameRva = rd.U32(o + 12);
        const uint32_t ft      = rd.U32(o + 16);
        if (!rd.ok) break;
        if (oft == 0 && nameRva == 0 && ft == 0) break;    // 终止项
        if (nameRva == 0) continue;

        size_t nameOff = 0;
        if (!RvaToOff(secs, nameRva, nameOff)) continue;
        std::string dll;
        if (!rd.TryCStr(nameOff, kMaxNameLen, dll)) continue;   // ★ 只跳这一条
        dll = Lower(dll);
        if (dll.empty()) continue;

        // ★ 规范化：小写后**在第一个 '.' 处截断**。
        //   与 Mandiant / pefile 的 `libname.split('.')[0]` 等价：
        //     kernel32.dll            → kernel32
        //     api-ms-win-crt-l1-1-0.dll → api-ms-win-crt-l1-1-0（本身无多余点）
        const size_t dot = dll.find('.');
        if (dot != std::string::npos) dll = dll.substr(0, dot);
        if (dll.empty()) continue;

        const uint32_t thunkRva = oft ? oft : ft;
        if (thunkRva == 0) continue;
        size_t thunkOff = 0;
        if (!RvaToOff(secs, thunkRva, thunkOff)) continue;

        const size_t    step    = pe64 ? 8 : 4;
        const uint64_t  kOrdFlg = pe64 ? 0x8000000000000000ull : 0x80000000ull;
        const uint64_t  kMask   = pe64 ? 0x7FFFFFFFFFFFFFFFull : 0x7FFFFFFFull;

        for (size_t ti = 0; ti < kMaxThunks; ++ti) {
            const size_t to = thunkOff + ti * step;
            if (!rd.Has(to, step)) break;
            const uint64_t val = pe64 ? rd.U64(to) : (uint64_t)rd.U32(to);
            if (!rd.ok) break;
            if (val == 0) break;

            std::string fn;
            if (val & kOrdFlg) {
                // 按序号导入：`ord<十进制，无前导零>`
                char tmp[24];
                std::snprintf(tmp, sizeof(tmp), "ord%u", (unsigned)(val & 0xFFFFull));
                fn = tmp;
            } else {
                size_t hintOff = 0;
                if (!RvaToOff(secs, (uint32_t)(val & kMask), hintOff)) continue;
                if (hintOff + 2 >= buf.size()) continue;
                std::string raw;
                if (!rd.TryCStr(hintOff + 2, kMaxNameLen, raw)) continue;  // 跳过 2 字节 hint
                fn = Lower(raw);
                const size_t d2 = fn.find('.');
                if (d2 != std::string::npos) fn = fn.substr(0, d2);
                if (fn.empty()) continue;
            }
            out.push_back(dll + "." + fn);
        }
    }

    return out.empty() ? kImpNotPe : kImpOk;
}

// 内部版：把"失败是否稳定"一并告诉调用方（决定缓存策略）。
bool ComputeImphash(const std::string& pathUtf8, std::string& outHex, bool& stableFail) {
    stableFail = false;
    outHex.clear();
    std::vector<std::string> pairs;
    const ImpRes r = ParseImportPairs(pathUtf8, pairs);
    if (r == kImpReadFail)  { Bump(g_impFail);  stableFail = false; return false; }
    if (r == kImpNotPe || pairs.empty()) { Bump(g_impNotPe); stableFail = true; return false; }

    std::string joined;
    joined.reserve(pairs.size() * 16);
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i) joined += ',';
        joined += pairs[i];
    }
    if (!Md5Hex(joined.data(), joined.size(), outHex) || outHex.empty()) {
        outHex.clear();
        Bump(g_impFail);
        stableFail = false;
        return false;
    }
    Bump(g_impCompute);
    return true;
}

}  // namespace

bool Imphash(const std::string& pathUtf8, std::string& outHex) {
    bool stable = false;
    return ComputeImphash(pathUtf8, outHex, stable);
}

namespace {
// 通用派生键：校验 hex 长度与合法性，前缀 + 小写化后取 SHA-256。
// 前缀是格式的一部分（见 pehash.h），改任何一处都让所有旧库作废。
std::string DeriveKey(const char* prefix, size_t expectHexLen, const std::string& hex) {
    if (hex.size() != expectHexLen) return std::string();
    const std::string low = Lower(hex);
    for (size_t i = 0; i < low.size(); ++i) {
        const char c = low[i];
        const bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!isHex) return std::string();
    }
    const std::string seed = std::string(prefix) + low;
    std::string key;
    if (!Sha256Hex(seed.data(), seed.size(), key)) return std::string();
    return key;
}
}  // namespace

std::string ImphashKey(const std::string& imphashHex) { return DeriveKey("imphash:", 32, imphashHex); }
std::string Md5Key(const std::string& md5Hex32)       { return DeriveKey("md5:", 32, md5Hex32); }
std::string Sha1Key(const std::string& sha1Hex40)     { return DeriveKey("sha1:", 40, sha1Hex40); }

bool ImphashCached(const std::string& pathUtf8, std::string& outHex) {
    outHex.clear();

    uint64_t size = 0, mtime = 0;
    if (!FileIdentity(pathUtf8, size, mtime)) { Bump(g_impFail); return false; }

    {   // ---- 锁内查 ----
        std::lock_guard<std::mutex> lk(g_impMtx);
        auto it = g_impCache.find(pathUtf8);
        if (it != g_impCache.end() && it->second.size == size && it->second.mtime == mtime) {
            if (!it->second.hex.empty()) {
                outHex = it->second.hex;
                Bump(g_impCacheHit);
                return true;
            }
            if (it->second.notPe) { Bump(g_impNotPe); return false; }
        }
    }

    std::string hex;                                   // ---- 锁外 I/O ----
    bool stableFail = false;
    const bool ok = ComputeImphash(pathUtf8, hex, stableFail);   // 内部已计数

    {   // ---- 锁内写 ----
        // ★ **只缓存稳定的失败**（确认不是 PE / 无导入表 / 超上限）。
        //   "读取失败"（文件正被写、被独占）是瞬时的 —— 把瞬时故障记成
        //   "这个文件不是 PE"，会在缓存存活期内一直生效，
        //   而这正是"偶发失效、重开服务就好"的来源。
        std::lock_guard<std::mutex> lk(g_impMtx);
        Ent e;
        e.size  = size;
        e.mtime = mtime;
        e.hex   = ok ? hex : std::string();
        e.notPe = stableFail;
        PutLocked(g_impCache, pathUtf8, e);
    }
    if (ok) { outHex = hex; return true; }
    return false;
}

// ===========================================================================
//  观测
// ===========================================================================
Stats GetStats() {
    Stats s;
    s.shaCompute   = g_shaCompute.load(std::memory_order_relaxed);
    s.shaCacheHit  = g_shaCacheHit.load(std::memory_order_relaxed);
    s.shaTooBig    = g_shaTooBig.load(std::memory_order_relaxed);
    s.shaFail      = g_shaFail.load(std::memory_order_relaxed);
    s.impCompute   = g_impCompute.load(std::memory_order_relaxed);
    s.impCacheHit  = g_impCacheHit.load(std::memory_order_relaxed);
    s.impNotPe     = g_impNotPe.load(std::memory_order_relaxed);
    s.impFail      = g_impFail.load(std::memory_order_relaxed);
    s.md5Compute   = g_md5Compute.load(std::memory_order_relaxed);
    s.md5CacheHit  = g_md5CacheHit.load(std::memory_order_relaxed);
    s.md5TooBig    = g_md5TooBig.load(std::memory_order_relaxed);
    s.md5Fail      = g_md5Fail.load(std::memory_order_relaxed);
    s.sha1Compute  = g_sha1Compute.load(std::memory_order_relaxed);
    s.sha1CacheHit = g_sha1CacheHit.load(std::memory_order_relaxed);
    s.sha1TooBig   = g_sha1TooBig.load(std::memory_order_relaxed);
    s.sha1Fail     = g_sha1Fail.load(std::memory_order_relaxed);
    s.cacheEvicted = g_cacheEvicted.load(std::memory_order_relaxed);
    return s;
}

void ResetStats() {
    g_shaCompute.store(0, std::memory_order_relaxed);
    g_shaCacheHit.store(0, std::memory_order_relaxed);
    g_shaTooBig.store(0, std::memory_order_relaxed);
    g_shaFail.store(0, std::memory_order_relaxed);
    g_impCompute.store(0, std::memory_order_relaxed);
    g_impCacheHit.store(0, std::memory_order_relaxed);
    g_impNotPe.store(0, std::memory_order_relaxed);
    g_impFail.store(0, std::memory_order_relaxed);
    g_md5Compute.store(0, std::memory_order_relaxed);
    g_md5CacheHit.store(0, std::memory_order_relaxed);
    g_md5TooBig.store(0, std::memory_order_relaxed);
    g_md5Fail.store(0, std::memory_order_relaxed);
    g_sha1Compute.store(0, std::memory_order_relaxed);
    g_sha1CacheHit.store(0, std::memory_order_relaxed);
    g_sha1TooBig.store(0, std::memory_order_relaxed);
    g_sha1Fail.store(0, std::memory_order_relaxed);
    g_cacheEvicted.store(0, std::memory_order_relaxed);
}

}  // namespace pehash
}  // namespace sf
