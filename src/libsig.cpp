// libsig.cpp — libsig.h 的实现。
//
// ===========================================================================
//  四条工程约束（都对应本项目吃过亏的形态）
// ===========================================================================
//
//  ① **零项目依赖**：本文件只 include <windows.h> + <bcrypt.h> + 标准库。
//     刻意**不**引 common.h / pehash.h。理由：它要同时被服务端（政策层）和
//     工具端（libsigkey.exe）链接，"核心验签逻辑被两处各写一份然后慢慢漂移"
//     是本项目最忌的形态之一。不引别的模块，链接它就没有任何附带成本 ——
//     于是"两边共用同一份实现"成了最省事的做法，而不是需要自觉遵守的纪律。
//     代价：本文件自己带一套 Widen / 读文件小工具（约 40 行），值。
//
//  ② **一律 *W 文件 API**（铁律 §4）。本文件没有一处 `std::ifstream`。
//     中文用户名（`C:\Users\银泊\...`）下，窄字符路径会按 ANSI(936) 解释而
//     **静默打开失败**，日志里一行痕迹都没有。签名文件读不到的表现恰好是
//     "没有签名" → 库拒装 → 用户看到"防护没生效"，而根因是编码。
//
//  ③ **密码学失败与 I/O 失败分开**。BCrypt 返回的是 NTSTATUS，
//     `STATUS_INVALID_SIGNATURE`(0xC000A000) 是"签名不对"，
//     而 `STATUS_INVALID_PARAMETER` 是"我参数传错了"。把两者都记成
//     "验签失败"，会让"代码写错了"看起来像"有人攻击"。
//     所以：能识别的错误码给专门文案，其余一律把 NTSTATUS 原值打出来。
//
//  ④ **不猜、不兜底**。找不到 keyId 就是找不到（不退回第一把钥匙）；
//     私有 blob 布局不符就报错（不按偏移硬取 X||Y）；签名长度不对就拒绝
//     （不截断、不补零）。每一条"宽容"都会把明确的错误改写成含糊的错误。
#include "libsig.h"
#include "sfh_pubkey.h"

#include <windows.h>
#include <bcrypt.h>

#include <atomic>
#include <cstdio>
#include <cstring>

namespace sf {
namespace libsig {

// ===========================================================================
//  观测计数
// ===========================================================================
namespace {
std::atomic<long long> g_ok{0}, g_noKey{0}, g_sigMissing{0}, g_sigMalformed{0};
std::atomic<long long> g_unknownKey{0}, g_hashMismatch{0}, g_badSig{0}, g_ioFail{0};
std::atomic<long long> g_signed{0};

inline void Bump(std::atomic<long long>& c) {
    c.fetch_add(1, std::memory_order_relaxed);
}
}  // namespace

void BumpSigned() { Bump(g_signed); }

Stats GetStats() {
    Stats s;
    s.ok           = g_ok.load(std::memory_order_relaxed);
    s.noKey        = g_noKey.load(std::memory_order_relaxed);
    s.sigMissing   = g_sigMissing.load(std::memory_order_relaxed);
    s.sigMalformed = g_sigMalformed.load(std::memory_order_relaxed);
    s.unknownKey   = g_unknownKey.load(std::memory_order_relaxed);
    s.hashMismatch = g_hashMismatch.load(std::memory_order_relaxed);
    s.badSig       = g_badSig.load(std::memory_order_relaxed);
    s.ioFail       = g_ioFail.load(std::memory_order_relaxed);
    s.signedCount  = g_signed.load(std::memory_order_relaxed);
    return s;
}

void ResetStats() {
    g_ok.store(0, std::memory_order_relaxed);
    g_noKey.store(0, std::memory_order_relaxed);
    g_sigMissing.store(0, std::memory_order_relaxed);
    g_sigMalformed.store(0, std::memory_order_relaxed);
    g_unknownKey.store(0, std::memory_order_relaxed);
    g_hashMismatch.store(0, std::memory_order_relaxed);
    g_badSig.store(0, std::memory_order_relaxed);
    g_ioFail.store(0, std::memory_order_relaxed);
    g_signed.store(0, std::memory_order_relaxed);
}

// ===========================================================================
//  基础工具
// ===========================================================================
namespace {

// 签名文件的读取上限。签名文件是一行 128 位 hex + 几行字段，正常 < 1KB。
// 设上限不是为了省内存，而是**不让一个畸形的大文件（或指向别处的路径）
// 把调用方拖住** —— 这个函数会被库装载路径调用，那条路径上卡一下就是
// "开机后防护半天没生效"。
constexpr uint64_t kSigFileMaxBytes = 64 * 1024;

std::wstring Widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

// 读整个文件（上限见上）。返回 false 时通过 outMissing 区分
// "文件不存在"（正常情况：这个库就没有签名）与"读失败"（异常，要记账）。
bool ReadWholeText(const std::string& pathUtf8, std::string& out, bool& outMissing) {
    out.clear();
    outMissing = false;

    const std::wstring w = Widen(pathUtf8);
    if (w.empty()) { outMissing = true; return false; }   // 路径非法 = 等同于没有

    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        outMissing = (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND);
        return false;
    }

    LARGE_INTEGER sz;
    sz.QuadPart = 0;
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    const uint64_t n64 = (uint64_t)sz.QuadPart;
    if (n64 > kSigFileMaxBytes) { CloseHandle(h); return false; }
    if (n64 == 0) { CloseHandle(h); outMissing = false; return true; }   // 空文件 = 存在但内容为空

    out.resize((size_t)n64);
    size_t got = 0;
    while (got < out.size()) {
        DWORD rd = 0;
        const DWORD want = (DWORD)(out.size() - got);
        if (!ReadFile(h, &out[got], want, &rd, nullptr) || rd == 0) {
            CloseHandle(h);
            out.clear();
            return false;
        }
        got += rd;
    }
    CloseHandle(h);
    return true;
}

char LowerCh(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

std::string LowerHex(const std::string& s) {
    std::string o = s;
    for (size_t i = 0; i < o.size(); ++i) o[i] = LowerCh(o[i]);
    return o;
}

bool IsHex64(const std::string& s) {
    if (s.size() != 64) return false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = LowerCh(s[i]);
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    const char l = LowerCh(c);
    if (l >= 'a' && l <= 'f') return l - 'a' + 10;
    return -1;
}

// 去掉尾部空白（含 \r）。签名文件可能被 Windows 编辑器处理过 → CRLF。
// ★ 这里**接受 CRLF** 是有意的：签名文件是人与工具都会碰的文本，
//   因为行尾符而拒装库属于"白白制造一类故障"。而字段**值**仍然严格。
void TrimRight(std::string& s) {
    while (!s.empty()) {
        const char c = s[s.size() - 1];
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') s.erase(s.size() - 1);
        else break;
    }
}

// ---- CNG 小工具 ----
// 每次调用都开关 provider：这条路径一天走不了几次（开机/手动检查更新），
// 而"缓存一个句柄"会引入生命周期与线程安全问题 —— 不值得。
class AlgGuard {
public:
    explicit AlgGuard(LPCWSTR algo) {
        if (BCryptOpenAlgorithmProvider(&h_, algo, nullptr, 0) != 0) h_ = nullptr;
    }
    ~AlgGuard() { if (h_) BCryptCloseAlgorithmProvider(h_, 0); }
    AlgGuard(const AlgGuard&) = delete;
    AlgGuard& operator=(const AlgGuard&) = delete;
    bool ok() const { return h_ != nullptr; }
    BCRYPT_ALG_HANDLE get() const { return h_; }
private:
    BCRYPT_ALG_HANDLE h_ = nullptr;
};

class KeyGuard {
public:
    explicit KeyGuard(BCRYPT_KEY_HANDLE k) : k_(k) {}
    ~KeyGuard() { if (k_) BCryptDestroyKey(k_); }
    KeyGuard(const KeyGuard&) = delete;
    KeyGuard& operator=(const KeyGuard&) = delete;
    BCRYPT_KEY_HANDLE get() const { return k_; }
private:
    BCRYPT_KEY_HANDLE k_ = nullptr;
};

// SHA-256（一次性，输入已在内存里）
bool Sha256Bytes(const void* data, size_t len, std::vector<uint8_t>& out32) {
    out32.assign(32, 0);
    AlgGuard a(BCRYPT_SHA256_ALGORITHM);
    if (!a.ok()) return false;
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(a.get(), &hh, nullptr, 0, nullptr, 0, 0) != 0) return false;
    bool ok = true;
    if (len) ok = (BCryptHashData(hh, (PUCHAR)data, (ULONG)len, 0) == 0);
    if (ok) ok = (BCryptFinishHash(hh, out32.data(), 32, 0) == 0);
    BCryptDestroyHash(hh);
    return ok;
}

// 把 NTSTATUS 变成人能读的一句话。★ 见约束③：不把"参数错"说成"签名不对"。
std::string NtText(const char* what, long nt) {
    char buf[160];
    if ((unsigned long)nt == 0xC000A000ul) {
        std::snprintf(buf, sizeof(buf), "%s：STATUS_INVALID_SIGNATURE（0xC000A000，签名不成立）", what);
    } else if ((unsigned long)nt == 0xC000000Dul) {
        std::snprintf(buf, sizeof(buf), "%s：STATUS_INVALID_PARAMETER（0xC000000D，入参非法——很可能是代码/格式问题，不是攻击）", what);
    } else if ((unsigned long)nt == 0xC0000008ul) {
        std::snprintf(buf, sizeof(buf), "%s：STATUS_INVALID_HANDLE（0xC0000008）", what);
    } else {
        std::snprintf(buf, sizeof(buf), "%s：NTSTATUS=0x%08lX", what, (unsigned long)nt);
    }
    return buf;
}

// 从 BCRYPT_ECCPRIVATE_BLOB 里取 X||Y。
// ★ 先校验布局再取偏移 —— 见约束④。直接 memcpy(blob+8, ...) 在布局
//   与预期不符时会**静默**取出垃圾当公钥，然后所有签名都验不过，
//   而现象是"签名被人改了"。宁可在这里报错。
bool ExtractPubXYFromPrivBlob(const std::vector<uint8_t>& privBlob,
                              uint8_t outXY[kPubXYBytes], std::string& outErr) {
    if (privBlob.size() != kPrivBlobBytes) {
        outErr = "私钥 blob 长度不是 104 字节（BCRYPT_ECCPRIVATE_BLOB for P-256）";
        return false;
    }
    BCRYPT_ECCKEY_BLOB hdr;
    std::memcpy(&hdr, privBlob.data(), sizeof(hdr));
    if (hdr.dwMagic != BCRYPT_ECDSA_PRIVATE_P256_MAGIC) {
        char buf[128];
        std::snprintf(buf, sizeof(buf),
                      "私钥 blob 魔数不是 ECDSA_PRIVATE_P256（实测 0x%08lX）",
                      (unsigned long)hdr.dwMagic);
        outErr = buf;
        return false;
    }
    if (hdr.cbKey != 32) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "私钥 blob cbKey 不是 32（实测 %lu）",
                      (unsigned long)hdr.cbKey);
        outErr = buf;
        return false;
    }
    std::memcpy(outXY, privBlob.data() + sizeof(hdr), kPubXYBytes);
    return true;
}

// ---- 内置公钥表 ----
struct RawKey { const char* id; const char* xyHex; };

// ★ 生成器（libsigkey genkey）会重写 sfh_pubkey.h；本表从宏展开而来，
//   所以"服务端认识哪把钥匙"完全由那个数据文件决定，源码这边一个字不用改。
const RawKey kRawKeys[] = {
    { SFH_KEY_ID, SFH_PUBKEY_HEX },
    SFH_RETIRED_KEYS
};

struct KeySlot {
    bool     valid = false;
    PubKey   key;
};

// 惰性解析一次（公钥表是常量，解析结果也是常量）。
// 用函数内 static 而不是全局对象：避免静态初始化顺序问题，
// C++11 起函数内 static 的初始化是线程安全的。
const std::vector<KeySlot>& Slots() {
    static const std::vector<KeySlot> slots = [] {
        std::vector<KeySlot> v;
        for (size_t i = 0; i < sizeof(kRawKeys) / sizeof(kRawKeys[0]); ++i) {
            KeySlot s;
            const std::string id  = kRawKeys[i].id  ? kRawKeys[i].id  : "";
            const std::string hex = kRawKeys[i].xyHex ? kRawKeys[i].xyHex : "";
            const size_t need = kPubXYBytes * 2;
            if (id.empty() || hex.size() != need) {
                // 空串 = 未配置（合法初始状态）；长度不对 = 配错了（也要能看出来）。
                // 两种都不加入表 —— 于是 BuiltinKeyCount() 会如实反映"能用的钥匙有几把"。
                continue;
            }
            std::vector<uint8_t> raw;
            if (!HexToBytes(hex, raw) || raw.size() != kPubXYBytes) continue;
            s.valid = true;
            s.key.keyId = id;
            std::memcpy(s.key.xy, raw.data(), kPubXYBytes);
            v.push_back(s);
        }
        return v;
    }();
    return slots;
}

}  // namespace

// ===========================================================================
//  十六进制
// ===========================================================================
bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out) {
    out.clear();
    if (hex.empty() || (hex.size() % 2) != 0) return false;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        const int hi = HexVal(hex[i]);
        const int lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) { out.clear(); return false; }
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}

std::string BytesToHex(const void* data, size_t len) {
    static const char* hx = "0123456789abcdef";
    const uint8_t* p = (const uint8_t*)data;
    std::string o;
    o.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        o += hx[p[i] >> 4];
        o += hx[p[i] & 0x0f];
    }
    return o;
}

// ===========================================================================
//  公钥表
// ===========================================================================
size_t BuiltinKeyCount() { return Slots().size(); }

const PubKey* BuiltinKeyAt(size_t index) {
    const std::vector<KeySlot>& s = Slots();
    if (index >= s.size()) return nullptr;
    return &s[index].key;
}

const PubKey* FindBuiltinKey(const std::string& keyId) {
    if (keyId.empty()) return nullptr;
    const std::vector<KeySlot>& s = Slots();
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i].key.keyId == keyId) return &s[i].key;
    }
    return nullptr;
}

std::string BuiltinKeyIdsText() {
    const std::vector<KeySlot>& s = Slots();
    if (s.empty()) return "无";
    std::string o;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i) o += ",";
        o += s[i].key.keyId;
    }
    return o;
}

// ===========================================================================
//  签名消息
// ===========================================================================
std::string BuildMessage(const std::string& keyId, const std::string& libSha256Hex) {
    if (keyId.empty()) return std::string();
    if (!IsHex64(libSha256Hex)) return std::string();
    // ★ 三个字段的分隔符是 '\n'（不是 '\0'、不是 ':'）。
    //   选 '\n' 的理由：keyId 是 ASCII、哈希是定长 hex，两者都不含 '\n'，
    //   所以"拼接结果"与"(prefix,keyId,hash) 三元组"是一一对应的 ——
    //   不存在 `keyId="a\n1"` 与 `(keyId="a", hash="1...")` 撞成同一串的可能。
    //   换成可出现在字段里的分隔符（如 ':'）就会引入这个歧义，
    //   而歧义的表现是"某个特制 keyId 能复用别的库的签名"。
    std::string m;
    m.reserve(64);
    m += kDomainPrefix;
    m += '\n';
    m += keyId;
    m += '\n';
    m += LowerHex(libSha256Hex);
    return m;
}

// ===========================================================================
//  签 / 验
// ===========================================================================
bool SignMessage(const std::vector<uint8_t>& privBlob, const PubKey& expectSelf,
                 const std::string& msg, std::string& outSigHex, std::string& outErr) {
    outSigHex.clear();
    outErr.clear();
    if (msg.empty()) { outErr = "待签消息为空（keyId 或库哈希非法）—— 拒绝签一个空对象"; return false; }

    std::vector<uint8_t> digest;
    if (!Sha256Bytes(msg.data(), msg.size(), digest)) { outErr = "SHA-256 计算失败"; return false; }

    // ---- 先按 blob 里的公钥做一次自校验：确保"这把私钥对应的确实是要公布的那把公钥" ----
    // ★ 这一步看着多余（blob 里本来就带 X||Y），但它挡住的是最坏的一种错：
    //   生成密钥时把 A 的私钥和 B 的公钥配到了一起。那种情况下**签名生成成功、
    //   公钥也发布成功**，只有在用户机器上验签时才失败 —— 而那时问题已经在天上飞了。
    uint8_t xy[kPubXYBytes];
    if (!ExtractPubXYFromPrivBlob(privBlob, xy, outErr)) return false;
    if (std::memcmp(xy, expectSelf.xy, kPubXYBytes) != 0) {
        outErr = "私钥与传入的公钥不匹配（密钥对配错了）—— 拒绝产出会验不过的签名";
        return false;
    }

    AlgGuard a(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!a.ok()) { outErr = "无法打开 CNG 算法提供程序 ECDSA_P256"; return false; }

    BCRYPT_KEY_HANDLE k = nullptr;
    const long st = (long)BCryptImportKeyPair(a.get(), nullptr, BCRYPT_ECCPRIVATE_BLOB, &k,
                                             (PUCHAR)privBlob.data(),
                                             (ULONG)privBlob.size(), 0);
    if (st != 0) { outErr = NtText("导入 ECC 私钥失败", st); return false; }
    KeyGuard kg(k);

    ULONG need = 0;
    long s2 = (long)BCryptSignHash(k, nullptr, digest.data(), (ULONG)digest.size(),
                                   nullptr, 0, &need, 0);
    if (s2 != 0 || need == 0) { outErr = NtText("探测签名长度失败", s2); return false; }
    // ★ 拒绝非常规长度：P-256 的裸 r||s 恒为 64 字节。长度不寻常说明
    //   链接到的 CNG 行为与预期不同（例如被中间层换成 DER 输出），
    //   而那种情况下"照单接收"会让 .sig 文件里躺着一串我们自己也解释不了的字节。
    if (need != kSigBytes) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "CNG 给出的签名长度是 %lu 字节，期望 %zu（裸 r||s）",
                      (unsigned long)need, kSigBytes);
        outErr = buf;
        return false;
    }

    std::vector<uint8_t> sig((size_t)need);
    ULONG got = 0;
    s2 = (long)BCryptSignHash(k, nullptr, digest.data(), (ULONG)digest.size(),
                              sig.data(), (ULONG)sig.size(), &got, 0);
    if (s2 != 0 || got != kSigBytes) { outErr = NtText("签名失败", s2); return false; }

    // ---- 自验一次：多花 1 毫秒，换"这把钥匙的签与验确实能走通" ----
    std::string vErr;
    if (!VerifyMessage(expectSelf, msg, BytesToHex(sig.data(), sig.size()), vErr)) {
        outErr = "自验失败（刚生成的签名验不过）：" + vErr;
        return false;
    }

    outSigHex = BytesToHex(sig.data(), sig.size());
    Bump(g_signed);
    return true;
}

bool VerifyMessage(const PubKey& key, const std::string& msg,
                   const std::string& sigHex, std::string& outErr) {
    outErr.clear();
    if (msg.empty()) { outErr = "消息为空"; return false; }
    if (key.keyId.empty()) { outErr = "公钥 keyId 为空"; return false; }

    std::vector<uint8_t> sig;
    if (!HexToBytes(sigHex, sig)) { outErr = "签名不是合法十六进制"; return false; }
    if (sig.size() != kSigBytes) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "签名长度 %zu 字节，期望 %zu（裸 r||s）",
                      sig.size(), kSigBytes);
        outErr = buf;
        return false;
    }

    std::vector<uint8_t> digest;
    if (!Sha256Bytes(msg.data(), msg.size(), digest)) { outErr = "SHA-256 计算失败"; return false; }

    AlgGuard a(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!a.ok()) { outErr = "无法打开 CNG 算法提供程序 ECDSA_P256"; return false; }

    // 现拼 BCRYPT_ECCPUBLIC_BLOB：头(8) + X(32) + Y(32)。
    // 只存裸坐标（见 sfh_pubkey.h）的理由是"与密码库无关"，
    // 代价就是这里要拼一次 —— 8 行代码换格式独立，值。
    BCRYPT_ECCKEY_BLOB hdr;
    hdr.dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    hdr.cbKey   = 32;
    std::vector<uint8_t> blob(sizeof(hdr) + kPubXYBytes);
    std::memcpy(blob.data(), &hdr, sizeof(hdr));
    std::memcpy(blob.data() + sizeof(hdr), key.xy, kPubXYBytes);

    BCRYPT_KEY_HANDLE k = nullptr;
    const long st = (long)BCryptImportKeyPair(a.get(), nullptr, BCRYPT_ECCPUBLIC_BLOB, &k,
                                             blob.data(), (ULONG)blob.size(), 0);
    if (st != 0) { outErr = NtText("导入 ECC 公钥失败", st); return false; }
    KeyGuard kg(k);

    const long v = (long)BCryptVerifySignature(k, nullptr, digest.data(), (ULONG)digest.size(),
                                              sig.data(), (ULONG)sig.size(), 0);
    if (v != 0) { outErr = NtText("验签失败", v); return false; }
    return true;
}

// ===========================================================================
//  密钥对生成 / 私钥文件
// ===========================================================================
bool GenerateKeyPair(const std::string& keyId, KeyFile& out, std::string& outErr) {
    outErr.clear();
    out = KeyFile();
    out.keyId = keyId.empty() ? std::string("sfh1-1") : keyId;

    AlgGuard a(BCRYPT_ECDSA_P256_ALGORITHM);
    if (!a.ok()) { outErr = "无法打开 CNG 算法提供程序 ECDSA_P256"; return false; }

    BCRYPT_KEY_HANDLE k = nullptr;
    long st = (long)BCryptGenerateKeyPair(a.get(), &k, 256, 0);
    if (st != 0) { outErr = NtText("生成 P-256 密钥对失败", st); return false; }
    KeyGuard kg(k);
    st = (long)BCryptFinalizeKeyPair(k, 0);
    if (st != 0) { outErr = NtText("BCryptFinalizeKeyPair 失败", st); return false; }

    ULONG n = 0;
    st = (long)BCryptExportKey(k, nullptr, BCRYPT_ECCPRIVATE_BLOB, nullptr, 0, &n, 0);
    if (st != 0 || n == 0) { outErr = NtText("探测私钥 blob 长度失败", st); return false; }
    out.privBlob.assign((size_t)n, 0);
    ULONG n2 = n;
    st = (long)BCryptExportKey(k, nullptr, BCRYPT_ECCPRIVATE_BLOB, out.privBlob.data(), n, &n2, 0);
    if (st != 0) { outErr = NtText("导出私钥 blob 失败", st); return false; }

    ULONG m = 0;
    st = (long)BCryptExportKey(k, nullptr, BCRYPT_ECCPUBLIC_BLOB, nullptr, 0, &m, 0);
    if (st != 0 || m == 0) { outErr = NtText("探测公钥 blob 长度失败", st); return false; }
    std::vector<uint8_t> pub((size_t)m, 0);
    ULONG m2 = m;
    st = (long)BCryptExportKey(k, nullptr, BCRYPT_ECCPUBLIC_BLOB, pub.data(), m, &m2, 0);
    if (st != 0) { outErr = NtText("导出公钥 blob 失败", st); return false; }

    // ★ 交叉核对两种导出路径。若 BCRYPT_ECCPRIVATE_BLOB 的布局与预期不同，
    //   "从私钥 blob 里取 X||Y" 会安静地取出垃圾，而公钥文件里躺着正确的坐标 ——
    //   两者不一致会让签名验不过，且现象指向"签名坏了"而不是"布局变了"。
    //   不相等就停在这里：这是生成器，停下来重来一次的代价是零。
    if (out.privBlob.size() != kPrivBlobBytes) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "私钥 blob 长度 %zu，期望 %zu",
                      out.privBlob.size(), kPrivBlobBytes);
        outErr = buf;
        return false;
    }
    if (pub.size() != sizeof(BCRYPT_ECCKEY_BLOB) + kPubXYBytes) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "公钥 blob 长度 %zu，期望 %zu",
                      pub.size(), sizeof(BCRYPT_ECCKEY_BLOB) + kPubXYBytes);
        outErr = buf;
        return false;
    }
    uint8_t xyFromPriv[kPubXYBytes];
    if (!ExtractPubXYFromPrivBlob(out.privBlob, xyFromPriv, outErr)) return false;
    if (std::memcmp(xyFromPriv, pub.data() + sizeof(BCRYPT_ECCKEY_BLOB), kPubXYBytes) != 0) {
        outErr = "两条导出路径给出的公钥不一致（BCrypt blob 布局与预期不符）—— 已中止，不产出可疑密钥";
        return false;
    }

    std::memcpy(out.pubXY, xyFromPriv, kPubXYBytes);
    out.hasPub = true;
    return true;
}

std::string FormatKeyFile(const KeyFile& kf) {
    std::string o;
    o += kKeyFileTag;
    o += "\nkeyid=";
    o += kf.keyId;
    o += "\nalgo=ECDSA_P256";
    o += "\npriv=";
    o += BytesToHex(kf.privBlob.data(), kf.privBlob.size());
    o += "\npub=";
    o += BytesToHex(kf.pubXY, kPubXYBytes);
    if (!kf.note.empty()) {
        o += "\n# ";
        o += kf.note;
    }
    o += "\n";
    return o;
}

bool ParseKeyFile(const std::string& text, KeyFile& out, std::string& outErr) {
    outErr.clear();
    out = KeyFile();
    out.hasPub = false;

    bool sawTag = false;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        TrimRight(line);
        if (line.empty()) continue;
        if (line[0] == '#') {
            if (out.note.empty()) out.note = line.substr(1);
            continue;
        }
        if (!sawTag) {
            if (line != kKeyFileTag) {
                outErr = "不是本程序的私钥文件（首行应为 " + std::string(kKeyFileTag) + "）";
                return false;
            }
            sawTag = true;
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos) { outErr = "私钥文件里有不是 k=v 的行：" + line; return false; }
        const std::string k = line.substr(0, eq);
        const std::string v = line.substr(eq + 1);

        if (k == "keyid") {
            out.keyId = v;
        } else if (k == "algo") {
            if (v != "ECDSA_P256") { outErr = "私钥算法不是 ECDSA_P256（实测 " + v + "）"; return false; }
        } else if (k == "priv") {
            if (!HexToBytes(v, out.privBlob) || out.privBlob.size() != kPrivBlobBytes) {
                outErr = "priv 字段不是 104 字节的十六进制 blob";
                return false;
            }
        } else if (k == "pub") {
            std::vector<uint8_t> raw;
            if (!HexToBytes(v, raw) || raw.size() != kPubXYBytes) {
                outErr = "pub 字段不是 64 字节的十六进制坐标";
                return false;
            }
            std::memcpy(out.pubXY, raw.data(), kPubXYBytes);
            out.hasPub = true;
        } else {
            // ★ 与 .sfh.sig 同一个纪律：未知字段直接拒（见 libsig.h）。
            outErr = "私钥文件里有未知字段：" + k;
            return false;
        }
    }

    if (!sawTag) { outErr = "私钥文件缺少首行标签"; return false; }
    if (out.keyId.empty()) { outErr = "私钥文件缺少 keyid"; return false; }
    if (out.privBlob.size() != kPrivBlobBytes) { outErr = "私钥文件缺少 priv 字段"; return false; }

    // 有 pub 就核对它与 priv 是否同源 —— 挡住"手抄 pub 抄错一位"这类事故。
    if (out.hasPub) {
        uint8_t xy[kPubXYBytes];
        if (!ExtractPubXYFromPrivBlob(out.privBlob, xy, outErr)) return false;
        if (std::memcmp(xy, out.pubXY, kPubXYBytes) != 0) {
            outErr = "私钥文件里的 pub 与 priv 不同源（公钥被改过或抄错）";
            return false;
        }
    } else {
        if (!ExtractPubXYFromPrivBlob(out.privBlob, out.pubXY, outErr)) return false;
        out.hasPub = true;
    }
    return true;
}

bool SignWithKeyFile(const KeyFile& kf, const std::string& libSha256Hex,
                     std::string& outSigHex, std::string& outErr) {
    outSigHex.clear();
    outErr.clear();
    if (!IsHex64(libSha256Hex)) { outErr = "库 SHA-256 不是 64 位十六进制"; return false; }

    const std::string msg = BuildMessage(kf.keyId, libSha256Hex);
    if (msg.empty()) { outErr = "构造签名消息失败"; return false; }

    PubKey self;
    self.keyId = kf.keyId;
    std::memcpy(self.xy, kf.pubXY, kPubXYBytes);

    return SignMessage(kf.privBlob, self, msg, outSigHex, outErr);
}

// ===========================================================================
//  签名文件
// ===========================================================================
bool ParseSigFile(const std::string& text, SigFile& out, std::string& outErr) {
    outErr.clear();
    out = SigFile();

    bool sawTag = false;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        TrimRight(line);
        if (line.empty()) continue;
        if (line[0] == '#') {
            if (out.note.empty()) out.note = line.substr(1);
            continue;
        }
        if (!sawTag) {
            if (line != kSigFileTag) {
                // ★ 专门识别"版本更新的签名文件"，给一句能直接行动的话。
                //   泛泛的"格式不对"会让人去翻文件内容，而真相是"程序该升级了"
                //   或"这个库不该给这个版本用"。
                if (line.compare(0, 10, "SFH1-SIG-V") == 0) {
                    outErr = "签名文件格式版本为 " + line + "，本程序只认 " +
                             std::string(kSigFileTag) + "（需更新程序或改取对应版本的库）";
                } else {
                    outErr = "签名文件首行不是 " + std::string(kSigFileTag);
                }
                return false;
            }
            sawTag = true;
            continue;
        }
        const size_t eq = line.find('=');
        if (eq == std::string::npos) { outErr = "签名文件里有不是 k=v 的行：" + line; return false; }
        const std::string k = line.substr(0, eq);
        const std::string v = line.substr(eq + 1);

        if (k == "keyid") {
            out.keyId = v;
        } else if (k == "sha256") {
            out.libSha256 = LowerHex(v);
        } else if (k == "sig") {
            out.sigHex = LowerHex(v);
        } else {
            // 见 libsig.h：首行标签钉死字段集合，未知字段 = 拒绝（不忽略）。
            outErr = "签名文件里有未知字段：" + k;
            return false;
        }
    }

    if (!sawTag) { outErr = "签名文件缺少首行标签"; return false; }
    if (out.keyId.empty()) { outErr = "签名文件缺少 keyid"; return false; }
    if (out.libSha256.empty()) { outErr = "签名文件缺少 sha256"; return false; }
    if (out.sigHex.empty()) { outErr = "签名文件缺少 sig"; return false; }
    if (!IsHex64(out.libSha256)) { outErr = "sha256 不是 64 位十六进制"; return false; }
    if (out.sigHex.size() != kSigBytes * 2) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "sig 长度 %zu 位十六进制，期望 %zu（64 字节裸 r||s）",
                      out.sigHex.size(), kSigBytes * 2);
        outErr = buf;
        return false;
    }
    return true;
}

std::string FormatSigFile(const SigFile& sf) {
    std::string o;
    o += kSigFileTag;
    o += "\nkeyid=";
    o += sf.keyId;
    o += "\nsha256=";
    o += LowerHex(sf.libSha256);
    o += "\nsig=";
    o += LowerHex(sf.sigHex);
    if (!sf.note.empty()) {
        o += "\n# ";
        o += sf.note;
    }
    o += "\n";
    return o;
}

// ===========================================================================
//  顶层入口
// ===========================================================================
std::string SigPathFor(const std::string& libPathUtf8) {
    if (libPathUtf8.empty()) return std::string();
    return libPathUtf8 + kSigSuffix;
}

const char* ResultText(Result r) {
    switch (r) {
        case kOk:              return "签名有效";
        case kNoKeyConfigured: return "本程序未配置验签公钥";
        case kSigMissing:      return "找不到签名文件";
        case kSigMalformed:    return "签名文件格式不对";
        case kUnknownKey:      return "签名用的钥匙本程序不认识";
        case kHashMismatch:    return "库内容与签名不符";
        case kBadSignature:    return "签名不成立";
    }
    return "未知结果";
}

const char* ResultHint(Result r) {
    switch (r) {
        case kOk:
            return "可以装载。";
        case kNoKeyConfigured:
            return "构建期未注入公钥（src/sfh_pubkey.h 为空）——库将被拒绝装载。"
                   "重跑 dist\\libsigkey.exe genkey 后重新构建即可。";
        case kSigMissing:
            return "库旁边缺少 <库名>.sig。签名与库必须成对下发；"
                   "只补库不补签名 = 库装不上（这是有意的 fail-closed）。";
        case kSigMalformed:
            return "签名文件被改动或截断（换行符不影响，字段名与长度必须严格）。"
                   "重新从发布渠道取一份成对的库与签名。";
        case kUnknownKey:
            return "签名是另一把钥匙签的（常见于钥匙轮换期）。"
                   "把对应公钥加进 src/sfh_pubkey.h 的 SFH_RETIRED_KEYS 并重新构建。";
        case kHashMismatch:
            return "签名自称的内容与磁盘上的库不是同一份 —— 库被替换过，"
                   "或签名文件与库配错了。**拒绝装载并保留旧库**。";
        case kBadSignature:
            return "内容对得上但签名不成立 —— 私钥泄露后的伪造，或签名文件被单改。"
                   "**拒绝装载并保留旧库**。";
    }
    return "";
}

Result VerifyLibFile(const std::string& libPathUtf8, const std::string& sigPathUtf8,
                     const std::string& libSha256Hex, std::string& outDetail) {
    outDetail.clear();

    char buf[512];

    // ---- ① 构建期有没有配公钥：**先查这条** ----
    // ★ 顺序理由：没有公钥时，后面所有检查的结论都没有意义（无论签名好坏都不能
    //   装载）。先报它，操作者才知道"该去重新构建"，而不是去追一个不存在的攻击。
    if (BuiltinKeyCount() == 0) {
        Bump(g_noKey);
        outDetail = ResultHint(kNoKeyConfigured);
        return kNoKeyConfigured;
    }

    // ---- ② 调用方给的库哈希必须合法（内部契约） ----
    const std::string actual = LowerHex(libSha256Hex);
    if (!IsHex64(actual)) {
        Bump(g_hashMismatch);
        outDetail = "内部错误：调用方传入的库 SHA-256 非法，无法比对内容";
        return kHashMismatch;
    }

    // ---- ③ 读签名文件 ----
    std::string text;
    bool missing = false;
    if (!ReadWholeText(sigPathUtf8, text, missing)) {
        if (missing) {
            Bump(g_sigMissing);
            std::snprintf(buf, sizeof(buf), "%s（%s）", ResultText(kSigMissing), sigPathUtf8.c_str());
            outDetail = buf;
        } else {
            Bump(g_sigMissing);
            Bump(g_ioFail);
            // ★ 与"完全没有签名"分开说：前者是配置问题，后者可能只是权限/占用，
            //   两者该做的事完全不同（一个去补文件，一个去查杀软锁/句柄）。
            std::snprintf(buf, sizeof(buf),
                          "签名文件存在但读取失败（%s）—— 注意这与「完全没有签名」不同，"
                          "请查权限/是否被占用",
                          sigPathUtf8.c_str());
            outDetail = buf;
        }
        return kSigMissing;
    }

    // ---- ④ 解析 ----
    SigFile sf;
    std::string perr;
    if (!ParseSigFile(text, sf, perr)) {
        Bump(g_sigMalformed);
        outDetail = ResultText(kSigMalformed);
        outDetail += "：";
        outDetail += perr;
        return kSigMalformed;
    }

    // ---- ⑤ 内容是否就是签的那一份 ----
    if (sf.libSha256 != actual) {
        Bump(g_hashMismatch);
        std::snprintf(buf, sizeof(buf),
                      "%s：签名自称 %s…，磁盘上是 %s…",
                      ResultText(kHashMismatch),
                      sf.libSha256.substr(0, 16).c_str(),
                      actual.substr(0, 16).c_str());
        outDetail = buf;
        return kHashMismatch;
    }

    // ---- ⑥ 认不认识这把钥匙 ----
    const PubKey* key = FindBuiltinKey(sf.keyId);
    if (!key) {
        Bump(g_unknownKey);
        std::snprintf(buf, sizeof(buf), "%s：签名 keyId=%s，本程序内置钥匙为 %s",
                      ResultText(kUnknownKey), sf.keyId.c_str(), BuiltinKeyIdsText().c_str());
        outDetail = buf;
        return kUnknownKey;
    }

    // ---- ⑦ 密码学验证 ----
    // 消息里的哈希用 actual（== sf.libSha256，第 ⑤ 步已证明相等），
    // 所以"签的是什么"与"验的是什么"是同一条串，不存在歧义。
    const std::string msg = BuildMessage(sf.keyId, actual);
    if (msg.empty()) {
        Bump(g_sigMalformed);
        outDetail = "内部错误：无法构造签名消息（keyId 或哈希非法）";
        return kSigMalformed;
    }

    std::string verr;
    if (!VerifyMessage(*key, msg, sf.sigHex, verr)) {
        Bump(g_badSig);
        outDetail = ResultText(kBadSignature);
        outDetail += "（钥匙 ";
        outDetail += sf.keyId;
        outDetail += "）：";
        outDetail += verr;
        return kBadSignature;
    }

    Bump(g_ok);
    std::snprintf(buf, sizeof(buf), "%s：keyId=%s", ResultText(kOk), sf.keyId.c_str());
    outDetail = buf;
    return kOk;
}

}  // namespace libsig
}  // namespace sf
