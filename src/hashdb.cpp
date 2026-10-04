// hashdb.cpp — 云端哈希库的本地载体实现
//
// ===========================================================================
//  本文件的两半
// ===========================================================================
//  · 上半：HashDb —— 只读查询（mmap，零启动加载，Bloom 前置）
//  · 下半：Builder —— 一次性构造（排序去重 → 建 Bloom → 原子替换）
//
//  分界线是「谁写文件」：只有 Builder 写，HashDb 只读。这样运行期查询路径上
//  没有任何写操作，也就不需要锁 —— 这在扫描线程里很关键（每个文件都要查一次）。
//
// ===========================================================================
//  ★ 两处容易写错、且写错代价很大的地方
// ===========================================================================
//  ① Bloom 只能证明「肯定不在」，不能证明「在」。
//     所有查询必须走 Bloom → 二分确认 两步。把 Bloom 命中当结论 = 假阳性 =
//     把用户正常文件判成病毒。ContainsRaw 的顺序就是这条铁律的形状。
//  ② 文件读取必须走 *W API。本项目铁律：中文用户名（C:\Users\银泊\…）下
//     任何 *A / std::ifstream(std::string) 路径都会静默失败。
//     注意 common.cpp 的 Sha256File 正是用 std::ifstream —— 所以本文件
//     **不复用它**，自己写 Sha256OfFile（走 CreateFileW + BCrypt 流式）。
#include "hashdb.h"

#include <windows.h>

#include <bcrypt.h>

#include <algorithm>
#include <atomic>     // 统计计数用（查询路径无锁，计数不能跟着裸奔）
#include <cstring>
#include <ctime>

namespace sf {
namespace hashdb {

// ===========================================================================
//  文件格式
// ===========================================================================
namespace {

const uint32_t kMagic   = 0x31484653u;   // 'SFH1'
const uint32_t kVersion = 1;

#pragma pack(push, 1)
struct Header {
    uint32_t magic;
    uint32_t version;      // ★ **格式**版本号（恒 = kVersion=1）；改动会让全体老客户端拒载
    uint32_t kind;
    uint32_t hashBytes;    // 固定 32（SHA-256）
    uint32_t bloomBits;    // 位图总位数（恒为 64 的倍数）
    uint32_t bloomK;       // 哈希函数个数
    uint32_t contentVersion;  // ★ **内容**版本号 (major<<16)|minor；0 = 未标注（原 reserved0）
    uint32_t reserved1;    // 仍未使用（实测全流程只读进结构体、不参与任何判断）
    uint64_t count;        // 条目数
    uint64_t builtAtUnix;
    uint64_t sourceBytes;  // 构造输入的总字节数（诊断用）
    char     tag[8];       // 库标识，如 "av-blk"
};
#pragma pack(pop)

static_assert(sizeof(Header) == 64, "文件头必须是 64 字节");

// ---- 内容版本号编解码 ----
// 为什么用 (major<<16)|minor 而不是 "1.2" 字符串：
//   四字节、无对齐问题、可 mmap 直接读；且**整数比大小天然单调**
//   （0x1000A > 0x10002 ⟺ 1.10 > 1.2），将来做"库是不是比我的新"只需比一个整数。
// 段上限 65535 —— 对病毒库版本号绰绰有余，且保证了四字节装得下。
const uint32_t kContentVerUnset = 0;

std::string ContentVersionToText(uint32_t v) {
    if (v == kContentVerUnset) return std::string("未标注");
    return std::to_string(v >> 16) + "." + std::to_string(v & 0xFFFFu);
}

// "1.2" → (1<<16)|2；空串 / "0" / "0.0" → 0（未标注）；其它一律 **false**。
// ★ 返回 false 时调用方必须报错，绝不能当成 0 继续 —— 见 hashdb.h 的说明。
bool ParseContentVersionText(const std::string& s, uint32_t& out) {
    out = kContentVerUnset;
    if (s.empty()) return true;                       // 未指定 = 未标注
    const size_t dot = s.find('.');
    const std::string a = (dot == std::string::npos) ? s : s.substr(0, dot);
    const std::string b = (dot == std::string::npos) ? std::string("0") : s.substr(dot + 1);
    if (a.empty() || b.empty()) return false;
    for (size_t i = 0; i < a.size(); ++i) if (a[i] < '0' || a[i] > '9') return false;
    for (size_t i = 0; i < b.size(); ++i) if (b[i] < '0' || b[i] > '9') return false;
    // 先卡长度再转数字：std::stoul 对超长输入会抛 out_of_range
    if (a.size() > 5 || b.size() > 5) return false;
    const unsigned long ma = std::stoul(a);
    const unsigned long mi = std::stoul(b);
    if (ma > 65535ul || mi > 65535ul) return false;
    out = ((uint32_t)ma << 16) | (uint32_t)mi;
    return true;
}

// ---- 小端读写（不依赖宿主字节序，也不依赖对齐）----
void PutU32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFFu);
    p[1] = (unsigned char)((v >> 8) & 0xFFu);
    p[2] = (unsigned char)((v >> 16) & 0xFFu);
    p[3] = (unsigned char)((v >> 24) & 0xFFu);
}

void PutU64(unsigned char* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = (unsigned char)((v >> (8 * i)) & 0xFFull);
}

uint32_t GetU32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

uint64_t GetU64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

// ---- UTF-8 → 宽字符（本项目铁律：进 *W API 之前必须转）----
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) {
        n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), nullptr, 0);
        if (n <= 0) return std::wstring();
        std::wstring w((size_t)n, L'\0');
        MultiByteToWideChar(CP_ACP, 0, s.c_str(), (int)s.size(), &w[0], n);
        return w;
    }
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// 递归建目录（与 sfdb.cpp 同名同语义；两处都不依赖对方，避免为一个 10 行函数建公共头）
bool EnsureDirW(const std::wstring& dir) {
    if (dir.size() <= 3) return true;
    DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES) return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos && pos > 0) {
        if (!EnsureDirW(dir.substr(0, pos))) return false;
    }
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

// ---- SHA-256（原始 32 字节）----
// 直接吃 BCrypt。不用 sf::Sha256Bytes 是因为那返回十六进制串，
// 而库内部到处要的是原始字节；来回转一次 hex 白费一倍时间与内存。
//
// ⚠️ 参数名不要叫 `small`：<rpcndr.h>（随 windows.h 一起进来）里有
//    `#define small char`，写了会被预处理成 `const void* char` 直接语法错，
//    而报错信息指向参数表、完全看不出根因。（2026-09-25 真实踩坑）
bool Sha256Stream(HANDLE hRead, const void* oneShotBuf, size_t oneShotLen, unsigned char out32[32]) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) return false;

    BCRYPT_HASH_HANDLE hh = nullptr;
    bool ok = (BCryptCreateHash(alg, &hh, nullptr, 0, nullptr, 0, 0) == 0);
    if (!ok) { BCryptCloseAlgorithmProvider(alg, 0); return false; }

    if (oneShotBuf) {
        ok = (BCryptHashData(hh, (PUCHAR)oneShotBuf, (ULONG)oneShotLen, 0) == 0);
    } else {
        // ★ 必须区分「正常 EOF（rd==0）」与「ReadFile 失败」：
        //   写成 while(ReadFile(...) && rd>0) 会把打开失败的设备/断链当成空文件，
        //   于是"任何文件都算出同一个空哈希"—— 对哈希库是灾难性的静默错误。
        char buf[1 << 16];
        for (;;) {
            DWORD rd = 0;
            if (!ReadFile(hRead, buf, (DWORD)sizeof(buf), &rd, nullptr)) { ok = false; break; }
            if (rd == 0) break;   // 正常读到文件尾
            if (BCryptHashData(hh, (PUCHAR)buf, rd, 0) != 0) { ok = false; break; }
        }
    }

    if (ok) ok = (BCryptFinishHash(hh, out32, 32, 0) == 0);

    BCryptDestroyHash(hh);
    BCryptCloseAlgorithmProvider(alg, 0);
    return ok;
}

// ---- Bloom ----
// 双哈希构造法：把 SHA-256 前 16 字节当两个 64 位种子 h1/h2，
// 第 i 位 = (h1 + i·h2) mod m。这样只需一次哈希就得到 k 个独立位置，
// 比"k 次独立哈希"快 k 倍，且误判率与理论值几乎一致。
void BloomTaps(const unsigned char h[32], uint64_t m, uint32_t k, uint64_t* taps) {
    uint64_t h1 = 0, h2 = 0;
    memcpy(&h1, h, 8);
    memcpy(&h2, h + 8, 8);
    if (h2 == 0) h2 = 0x9E3779B97F4A7C15ull;   // 全零种子 → 退化成单哈希，强制给个奇数常量
    if ((h2 & 1ull) == 0) h2 |= 1ull;          // 偶数种子会让 m 为偶数时覆盖不全，固定成奇数
    for (uint32_t i = 0; i < k; ++i) {
        taps[i] = (h1 + (uint64_t)i * h2) % m;
    }
}

void BloomSet(unsigned char* bits, const uint64_t* taps, uint32_t k) {
    for (uint32_t i = 0; i < k; ++i) {
        uint64_t x = taps[i];
        bits[(size_t)(x >> 3)] |= (unsigned char)(1u << (x & 7u));
    }
}

bool BloomTest(const unsigned char* bits, const uint64_t* taps, uint32_t k) {
    for (uint32_t i = 0; i < k; ++i) {
        uint64_t x = taps[i];
        if ((bits[(size_t)(x >> 3)] & (unsigned char)(1u << (x & 7u))) == 0) return false;
    }
    return true;
}

int Cmp32(const unsigned char* a, const unsigned char* b) {
    return memcmp(a, b, 32);
}

}  // namespace

// ===========================================================================
//  HashDb::Impl
// ===========================================================================
struct HashDb::Impl {
    HANDLE               hFile = INVALID_HANDLE_VALUE;
    HANDLE               hMap  = INVALID_HANDLE_VALUE;
    const unsigned char* base  = nullptr;
    unsigned long long   fileBytes = 0;

    Header               hdr{};
    const unsigned char* bloom = nullptr;
    const unsigned char* arr   = nullptr;

    bool        open = false;
    mutable std::string err;
    // ★ 查询路径**不加锁**（这是本库最大性能卖点：2000 线程同时查也不互相阻塞）。
    //   但统计计数仍然会被并发自增 —— 普通 long long 的自增是「读-改-写」三步，
    //   两个线程交错就会丢计数，而且按 C++ 标准这是数据竞争（UB）。
    //   统计数字虽然没有功能后果，但那种「明明查了 100 万次，统计只有 87 万」的
    //   偏差会让人怀疑引擎有问题，反而更难查 —— 所以用原子量把这条路彻底堵死。
    mutable std::atomic<long long> statQueries{0};
    mutable std::atomic<long long> statBloomMiss{0};
    mutable std::atomic<long long> statHits{0};

    void Unmap() {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (hMap != INVALID_HANDLE_VALUE) { CloseHandle(hMap); hMap = INVALID_HANDLE_VALUE; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
        bloom = nullptr;
        arr   = nullptr;
        fileBytes = 0;
        open = false;
    }

    bool ContainsRaw(const unsigned char h[32]) const {
        if (!open) return false;
        ++statQueries;

        // ① Bloom 前置：不命中 → **肯定不在**，直接返回，省掉二分
        const uint32_t m = hdr.bloomBits;
        const uint32_t k = hdr.bloomK;
        if (bloom && m > 0 && k > 0) {
            uint64_t taps[16];
            uint32_t kk = (k > 16) ? 16 : k;
            BloomTaps(h, (uint64_t)m, kk, taps);
            if (!BloomTest(bloom, taps, kk)) {
                ++statBloomMiss;
                return false;
            }
        }

        // ② 二分确认：Bloom 命中**不等于**存在（存在假阳性），必须真查
        long long lo = 0, hi = (long long)hdr.count - 1;
        while (lo <= hi) {
            long long mid = lo + (hi - lo) / 2;
            const unsigned char* p = arr + (size_t)mid * 32;
            int c = Cmp32(p, h);
            if (c == 0) { ++statHits; return true; }
            if (c < 0) lo = mid + 1;
            else       hi = mid - 1;
        }
        return false;
    }
};

// ===========================================================================
//  HashDb
// ===========================================================================
HashDb::HashDb() : p_(new Impl()) {}

HashDb::~HashDb() {
    p_->Unmap();
    delete p_;
}

bool HashDb::Open(const std::string& pathUtf8) {
    p_->Unmap();
    p_->err.clear();

    if (pathUtf8.empty()) { p_->err = "库路径为空"; return false; }

    std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) { p_->err = "库路径无法转为宽字符（非法 UTF-8？）"; return false; }

    // 共享模式允许读写删：这样云端下发新库时可以在旧库仍被映射的情况下替换
    // （Windows 会把旧文件延后到最后一个视图关闭才真正移除）。
    p_->hFile = CreateFileW(w.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (p_->hFile == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        p_->err = (e == ERROR_FILE_NOT_FOUND)
                      ? ("哈希库不存在：" + pathUtf8)
                      : ("打开哈希库失败，错误码 " + std::to_string(e));
        return false;
    }

    LARGE_INTEGER sz;
    sz.QuadPart = 0;
    if (!GetFileSizeEx(p_->hFile, &sz) || sz.QuadPart < (LONGLONG)sizeof(Header)) {
        p_->err = "哈希库文件过小（不是合法的 .hdb）";
        p_->Unmap();
        return false;
    }
    p_->fileBytes = (unsigned long long)sz.QuadPart;

    p_->hMap = CreateFileMappingW(p_->hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (p_->hMap == INVALID_HANDLE_VALUE || p_->hMap == nullptr) {
        p_->err = "创建文件映射失败，错误码 " + std::to_string(GetLastError());
        p_->Unmap();
        return false;
    }

    void* view = MapViewOfFile(p_->hMap, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        p_->err = "映射视图失败，错误码 " + std::to_string(GetLastError());
        p_->Unmap();
        return false;
    }
    p_->base = (const unsigned char*)view;

    // ---- 校验头（任何一项不符都不进入查询，避免拿错文件当库使）----
    const unsigned char* h = p_->base;
    Header& H = p_->hdr;
    H.magic      = GetU32(h + 0);
    H.version    = GetU32(h + 4);
    H.kind       = GetU32(h + 8);
    H.hashBytes  = GetU32(h + 12);
    H.bloomBits  = GetU32(h + 16);
    H.bloomK     = GetU32(h + 20);
    H.contentVersion = GetU32(h + 24);
    H.reserved1  = GetU32(h + 28);
    H.count      = GetU64(h + 32);
    H.builtAtUnix = GetU64(h + 40);
    H.sourceBytes = GetU64(h + 48);
    memcpy(H.tag, h + 56, 8);
    H.tag[7] = '\0';

    if (H.magic != kMagic) {
        p_->err = "哈希库魔数不匹配（不是 .hdb 文件，或文件被破坏）";
        p_->Unmap();
        return false;
    }
    if (H.version != kVersion) {
        p_->err = "哈希库版本不支持：" + std::to_string(H.version) +
                  "（本程序只认 " + std::to_string(kVersion) + "）";
        p_->Unmap();
        return false;
    }
    // ★ contentVersion **刻意不校验**（这里是唯一该讲清的地方）：
    //   `version` 是格式契约，不符就说明"我不知道怎么读这个文件"，必须拒载；
    //   而 contentVersion 是内容新旧 —— 一个 2024 年的客户端拿到 2030 年的库，
    //   格式没变就**照样能查**，只是不知道库里有更新的东西。拒载它毫无道理，
    //   而且会造成「一次数据更新让全体老客户端失去病毒库」这种灾难性后果。
    //   所以这里任何取值都接受，只如实上报给 hashstat / GUI。
    if (H.hashBytes != 32) {
        p_->err = "哈希库摘要长度不是 32 字节";
        p_->Unmap();
        return false;
    }
    if (H.bloomK < 1 || H.bloomK > 16 || H.bloomBits < 64 || (H.bloomBits % 8) != 0) {
        p_->err = "哈希库 Bloom 参数非法（bits=" + std::to_string(H.bloomBits) +
                  " k=" + std::to_string(H.bloomK) + "）";
        p_->Unmap();
        return false;
    }

    unsigned long long need = (unsigned long long)sizeof(Header) +
                             (unsigned long long)(H.bloomBits / 8) +
                             (unsigned long long)H.count * 32ull;
    if (p_->fileBytes < need) {
        p_->err = "哈希库长度不足（需要 " + std::to_string(need) + " 字节，实际 " +
                  std::to_string(p_->fileBytes) + "），文件可能被截断";
        p_->Unmap();
        return false;
    }
    if (H.count > 200000000ull) {
        p_->err = "哈希库条目数异常（" + std::to_string(H.count) + "），拒绝加载";
        p_->Unmap();
        return false;
    }

    p_->bloom = p_->base + sizeof(Header);
    p_->arr   = p_->bloom + (H.bloomBits / 8);
    p_->open  = true;
    return true;
}

void HashDb::Close() {
    p_->Unmap();
}

bool HashDb::IsOpen() const { return p_->open; }

std::string HashDb::LastError() const { return p_->err; }

long long HashDb::Count() const { return p_->open ? (long long)p_->hdr.count : 0; }

bool HashDb::ContainsHash(const std::string& sha256Hex) const {
    unsigned char h[32];
    if (!HexToHash(sha256Hex, h)) {
        p_->err = "非法的 SHA-256 十六进制串（需 64 个 hex 字符）";
        return false;
    }
    return p_->ContainsRaw(h);
}

bool HashDb::ContainsBytes(const void* data, size_t len, std::string* outHex) const {
    unsigned char h[32];
    if (!Sha256Stream(INVALID_HANDLE_VALUE, data, len, h)) {
        p_->err = "计算 SHA-256 失败";
        return false;
    }
    if (outHex) *outHex = HashToHex(h);
    return p_->ContainsRaw(h);
}

bool HashDb::ContainsFile(const std::string& filePathUtf8, std::string* outHex) const {
    std::string hex;
    if (!Sha256OfFile(filePathUtf8, hex)) {
        p_->err = "读取文件失败（可能是路径含非 UTF-8 字节，或权限不足）：" + filePathUtf8;
        return false;
    }
    if (outHex) *outHex = hex;
    unsigned char h[32];
    if (!HexToHash(hex, h)) {
        p_->err = "内部错误：自算摘要格式异常";
        return false;
    }
    return p_->ContainsRaw(h);
}

Stats HashDb::GetStats() const {
    Stats s;
    s.path        = std::string();   // Impl 不记路径，调用方自己知道；留空避免误导
    s.open        = p_->open;
    s.kind        = p_->open ? (int)p_->hdr.kind : kKindUnknown;
    s.tag         = p_->open ? std::string(p_->hdr.tag) : std::string();
    s.count       = p_->open ? (long long)p_->hdr.count : 0;
    s.fileBytes   = (long long)p_->fileBytes;
    s.bloomBits   = p_->open ? (long long)p_->hdr.bloomBits : 0;
    s.bloomK      = p_->open ? (int)p_->hdr.bloomK : 0;
    s.builtAtUnix = p_->open ? (long long)p_->hdr.builtAtUnix : 0;
    s.contentVersion     = p_->open ? (long long)p_->hdr.contentVersion : 0;
    // 库没打开时给**空串**而不是"未标注" —— 两者语义不同：
    //   "未标注" = 有库但没写版本；空串 = 根本没有可读的库。
    s.contentVersionText = p_->open ? ContentVersionToText(p_->hdr.contentVersion)
                                    : std::string();
    s.queries     = p_->statQueries.load(std::memory_order_relaxed);
    s.bloomMiss   = p_->statBloomMiss.load(std::memory_order_relaxed);
    s.hits        = p_->statHits.load(std::memory_order_relaxed);
    return s;
}

bool HashDb::HexToHash(const std::string& hex, unsigned char out[32]) {
    if (hex.size() != 64) return false;
    for (int i = 0; i < 32; ++i) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nib(hex[i * 2]);
        int lo = nib(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return true;
}

std::string HashDb::HashToHex(const unsigned char h[32]) {
    static const char* hx = "0123456789abcdef";
    std::string o;
    o.reserve(64);
    for (int i = 0; i < 32; ++i) {
        o += hx[h[i] >> 4];
        o += hx[h[i] & 0x0f];
    }
    return o;
}

bool HashDb::ParseContentVersion(const std::string& text, uint32_t& outCode) {
    return ParseContentVersionText(text, outCode);
}

std::string HashDb::ContentVersionText(uint32_t code) {
    return ContentVersionToText(code);
}

bool HashDb::Sha256OfFile(const std::string& filePathUtf8, std::string& outHex) {
    outHex.clear();
    std::wstring w = Utf8ToWide(filePathUtf8);
    if (w.empty()) return false;

    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    unsigned char d[32];
    bool ok = Sha256Stream(h, nullptr, 0, d);
    CloseHandle(h);
    if (!ok) return false;

    outHex = HashToHex(d);
    return true;
}

// ===========================================================================
//  Builder
// ===========================================================================
struct Builder::Impl {
    int         kind = kKindUnknown;
    std::string tag;
    std::vector<std::string> items;   // 每项恰好 32 字节
    long long   skipped = 0;
    long long   sourceBytes = 0;
    uint32_t    contentVersion = kContentVerUnset;   // 0 = 未标注
    uint64_t    builtAtUnix    = 0;                  // 0 = 用 Build 当时的当前时间
    bool        cvBad = false;          // SetContentVersionText 收到非法值 → Build 直接失败
    std::string cvBadText;              // 原始输入，用于报错文案
    std::string err;
};

Builder::Builder() : p_(new Impl()) {}

Builder::~Builder() { delete p_; }

void Builder::SetKind(int kind) { p_->kind = kind; }

void Builder::SetTag(const std::string& tag) {
    p_->tag = tag.size() > 7 ? tag.substr(0, 7) : tag;
}

bool Builder::SetContentVersionText(const std::string& text) {
    uint32_t v = kContentVerUnset;
    if (!ParseContentVersionText(text, v)) {
        // 返回值让调用方**立刻**知道非法；同时记下 cvBad 让 Build() 也失败。
        // 双保险的理由：调用方可能忽略返回值（将来新增的调用点），
        // 而"非法版本号被静默写成未标注"是零症状的假象。
        p_->cvBad = true;
        p_->cvBadText = text;
        return false;
    }
    p_->cvBad = false;
    p_->cvBadText.clear();
    p_->contentVersion = v;
    return true;
}

void Builder::SetBuiltAtUnix(long long unixSec) {
    p_->builtAtUnix = (unixSec > 0) ? (uint64_t)unixSec : 0ull;
}

bool Builder::AddHex(const std::string& sha256Hex) {
    unsigned char h[32];
    if (!HashDb::HexToHash(sha256Hex, h)) { ++p_->skipped; return false; }
    p_->items.push_back(std::string((const char*)h, 32));
    return true;
}

bool Builder::AddBytes(const void* data, size_t len) {
    unsigned char h[32];
    if (!Sha256Stream(INVALID_HANDLE_VALUE, data, len, h)) {
        p_->err = "计算 SHA-256 失败";
        return false;
    }
    p_->items.push_back(std::string((const char*)h, 32));
    p_->sourceBytes += (long long)len;
    return true;
}

bool Builder::AddFile(const std::string& filePathUtf8) {
    std::string hex;
    if (!HashDb::Sha256OfFile(filePathUtf8, hex)) {
        ++p_->skipped;
        return false;
    }
    return AddHex(hex);
}

long long Builder::Count() const { return (long long)p_->items.size(); }

long long Builder::Skipped() const { return p_->skipped; }

std::string Builder::LastError() const { return p_->err; }

bool Builder::SuggestBloom(long long count, uint32_t& outBits, uint32_t& outK) {
    if (count <= 0) return false;
    // 每条 ~10 bit（≈1.25 字节 / 条）→ 理论误判率约 1%，k=7 接近最优
    //   （最优 k = (m/n)·ln2 = 10 × 0.693 ≈ 6.93 → 取 7）
    // 位图长度取 64 的倍数，便于对齐与将来换 64 位访问。
    unsigned long long m = (unsigned long long)count * 10ull;
    if (m < 64) m = 64;
    m = ((m + 63) / 64) * 64;
    if (m > 0xFFFFFFC0ull) m = 0xFFFFFFC0ull;   // 上限约 512MB 位图，防误传超大 count
    outBits = (uint32_t)m;
    outK    = 7;
    return true;
}

bool Builder::Build(const std::string& pathUtf8) {
    p_->err.clear();

    // ★ 非法内容版本号 → 直接失败，**绝不静默降级成"未标注"**。
    //   静默降级会让「我明明传了 2.0、库里却是未标注」变成没有任何症状的假象，
    //   而这种假象只有在用户看 GUI 时才发现 —— 那时库已经发出去了。
    if (p_->cvBad) {
        p_->err = "内容版本号非法：\"" + p_->cvBadText +
                  "\"（应形如 1.2，两段各为 0~65535 的十进制数；留空表示未标注）";
        return false;
    }

    if (p_->items.empty()) { p_->err = "没有可写入的条目"; return false; }
    if (pathUtf8.empty())  { p_->err = "目标路径为空"; return false; }

    // ---- 排序 + 去重 ----
    // 二分查询要求严格升序且无重复（有重复不影响正确性，但白占空间、
    // 且会让 count 与实际条目数不符，给统计带来误导）。
    std::sort(p_->items.begin(), p_->items.end(),
              [](const std::string& a, const std::string& b) {
                  return memcmp(a.data(), b.data(), 32) < 0;
              });
    p_->items.erase(std::unique(p_->items.begin(), p_->items.end()), p_->items.end());

    uint64_t n = (uint64_t)p_->items.size();
    uint32_t bits = 0, k = 0;
    if (!SuggestBloom((long long)n, bits, k)) {
        p_->err = "Bloom 参数计算失败";
        return false;
    }

    // ---- 建 Bloom ----
    std::vector<unsigned char> bloom((size_t)(bits / 8), 0);
    for (uint64_t i = 0; i < n; ++i) {
        uint64_t taps[16];
        BloomTaps((const unsigned char*)p_->items[(size_t)i].data(), (uint64_t)bits, k, taps);
        BloomSet(bloom.data(), taps, k);
    }

    // ---- 写文件头 ----
    unsigned char hb[sizeof(Header)];
    memset(hb, 0, sizeof(hb));
    PutU32(hb + 0,  kMagic);
    PutU32(hb + 4,  kVersion);
    PutU32(hb + 8,  (uint32_t)p_->kind);
    PutU32(hb + 12, 32);
    PutU32(hb + 16, bits);
    PutU32(hb + 20, k);
    PutU32(hb + 24, p_->contentVersion);   // 内容版本号（**不是**格式版本号，见文件头说明）
    PutU32(hb + 28, 0);                    // reserved1 仍未使用
    PutU64(hb + 32, n);
    // 构造时间 = 库的"发布日期"（UTC Unix 秒）。显式指定则用它，否则取当前时间。
    PutU64(hb + 40, p_->builtAtUnix ? p_->builtAtUnix : (uint64_t)::time(nullptr));
    PutU64(hb + 48, (uint64_t)p_->sourceBytes);
    char tag[8] = {0};
    memcpy(tag, p_->tag.c_str(), p_->tag.size() > 7 ? 7 : p_->tag.size());
    memcpy(hb + 56, tag, 8);

    // ---- 写到 .tmp 再做原子替换 ----
    std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) { p_->err = "目标路径无法转为宽字符"; return false; }

    size_t slash = w.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash > 0) {
        if (!EnsureDirW(w.substr(0, slash))) {
            p_->err = "创建目录失败，错误码 " + std::to_string(GetLastError());
            return false;
        }
    }

    std::wstring wtmp = w + L".tmp";
    HANDLE h = CreateFileW(wtmp.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        p_->err = "创建临时库文件失败，错误码 " + std::to_string(GetLastError());
        return false;
    }

    bool ok = true;
    DWORD wr = 0;
    if (ok) ok = WriteFile(h, hb, (DWORD)sizeof(hb), &wr, nullptr) && wr == sizeof(hb);
    if (ok && !bloom.empty())
        ok = WriteFile(h, bloom.data(), (DWORD)bloom.size(), &wr, nullptr) && wr == bloom.size();
    if (ok) {
        // 32 字节 × n 一次性写出：n 到 1e7 时是 320MB，而 WriteFile 的
        // nNumberOfBytesToWrite 参数是 DWORD，必须分块。
        // items 是等长 32 字节的独立 string（各自分配），无法直接当连续内存写，
        // 所以逐块摊进缓冲 —— 每块 32768 条 = 1MB，与写放大取得平衡。
        const size_t total     = p_->items.size();
        const size_t perChunk  = 32768;
        std::vector<char> buf;
        buf.reserve(perChunk * 32);
        size_t i = 0;
        while (ok && i < total) {
            size_t cnt = total - i;
            if (cnt > perChunk) cnt = perChunk;
            buf.clear();
            for (size_t j = 0; j < cnt; ++j) {
                const std::string& it = p_->items[i + j];
                buf.insert(buf.end(), it.data(), it.data() + 32);
            }
            ok = WriteFile(h, buf.data(), (DWORD)buf.size(), &wr, nullptr) && wr == buf.size();
            i += cnt;
        }
    }
    if (ok) FlushFileBuffers(h);
    CloseHandle(h);

    if (!ok) {
        DeleteFileW(wtmp.c_str());
        p_->err = "写入库文件失败（目标上的旧库未受影响）";
        return false;
    }

    if (!MoveFileExW(wtmp.c_str(), w.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DWORD e = GetLastError();
        DeleteFileW(wtmp.c_str());
        p_->err = "替换库文件失败，错误码 " + std::to_string(e);
        return false;
    }

    return true;
}

}  // namespace hashdb
}  // namespace sf
