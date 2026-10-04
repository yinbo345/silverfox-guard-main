// aimodel.cpp — 模型格式与前向推理的实现（格式说明见 aimodel.h）
#include "aimodel.h"

#include <windows.h>

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <mutex>
#include <vector>

namespace sf {
namespace ai {

// ===========================================================================
//  常量与头结构
// ===========================================================================
namespace {

const uint32_t kMagic   = 0x314D4653u;   // 'SFM1'（小端写盘后即 S F M 1）
const uint32_t kVersion = 1;
// ★ 注意：kKindMlp / kKindMulti 定义在 aimodel.h 的 enum Kind 里，不在这里重复定义 ——
//   两处同名常量会形成"匿名命名空间 vs 命名空间成员"的查找歧义，
//   而 kind 是**写进文件头的格式契约**，只允许有一个定义。

const uint32_t kHeaderBytes      = 64;
const uint32_t kLayerDescBytes   = 16;
const uint32_t kMaxLayers        = 64;
const uint32_t kMaxDim           = 4096;   // 单维上限：挡住"头被写坏成巨大值"→ 万亿级乘法

#pragma pack(push, 1)
struct Header {
    uint32_t magic;
    uint32_t version;
    uint32_t kind;
    uint32_t layers;
    uint32_t inDim;
    uint32_t outDim;
    uint32_t reserved0;
    uint32_t reserved1;
    int64_t  createdAtUnix;
    char     tag[8];
    uint64_t reserved2;      // 保留位：把头部补满 64 字节（见下方 static_assert）
    uint64_t checksum;
};
struct LayerDesc {
    uint32_t inDim;
    uint32_t outDim;
    uint32_t act;
    uint32_t reserved;
};
#pragma pack(pop)

// 头部一经发布就不能再改长度 —— 旧模型文件必须能被新版本读出来。
// 布局：0..32 七个 u32 / 32..40 createdAtUnix / 40..48 tag / 48..56 保留 / 56..64 checksum
static_assert(sizeof(Header) == 64, "模型头必须是 64 字节（格式契约）");
static_assert(sizeof(LayerDesc) == 16, "层描述符必须是 16 字节（格式契约）");
static_assert(offsetof(Header, createdAtUnix) == 32, "头部偏移是格式契约，不可变");
static_assert(offsetof(Header, tag) == 40, "头部偏移是格式契约，不可变");
static_assert(offsetof(Header, checksum) == 56, "头部偏移是格式契约，不可变");

uint32_t GetU32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}
void PutU32(unsigned char* p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xFF);
    p[1] = (unsigned char)((v >> 8) & 0xFF);
    p[2] = (unsigned char)((v >> 16) & 0xFF);
    p[3] = (unsigned char)((v >> 24) & 0xFF);
}
uint64_t GetU64(const unsigned char* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | (uint64_t)p[i];
    return v;
}
void PutU64(unsigned char* p, uint64_t v) {
    for (int i = 0; i < 8; ++i) { p[i] = (unsigned char)(v & 0xFF); v >>= 8; }
}

// FNV-1a 64：权重区损坏检测。
// 选它而不是 CRC32 的理由：64 位宽度下"随机坏块碰巧校验通过"的概率约 2^-64，
// 而实现只有 6 行；CRC32 需要一张表或位运算循环，收益不明显。
//
// ★ offset basis 必须是标准 FNV-1a 64 的 14695981039346656037（= 0xCBF29CE484222325）。
//   这里曾经写成 1469598103934665603 —— **少了末位一个 7**（19 位 vs 20 位）。
//   危害不在"校验不灵"（自洽的错常量照样能检出损坏），而在于：
//   它把一个**非标准常量固化成了格式契约**，逼训练器（Python 侧）永久复制这个错误值，
//   一旦哪边有人"顺手改成标准值"，两边就再也对不上，且报错是"权重区校验失败"，
//   看起来像文件坏了 —— 会把人带到完全错误的方向上查。
//   发现时机：多头改造复核格式时逐字段比对标准常量，此刻修零兼容代价
//   （proxy_v1.sfm 尚未产出，preview6 未发布，没有任何已发布模型带这个错校验）。
uint64_t Fnv1a64(const unsigned char* d, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= (uint64_t)d[i];
        h *= 1099511628211ull;
    }
    return h;
}

// 把模型输出夹进 [0,1]，并把 NaN 一路挡掉。
// ⚠️ 模型文件是**外部来源**（将来的云库下发），不能假定末层真的按契约写了 Sigmoid。
//    没有这一步的话，一个 Linear 末层的模型会直接吐出 500 这样的"分数"，
//    喂进评分层就是一记凭空的巨额加权。
float Clamp01(float v) {
    if (!(v == v)) return 0.f;
    if (v < 0.f) return 0.f;
    if (v > 1.f) return 1.f;
    return v;
}

float ApplyAct(uint32_t act, float x) {
    switch (act) {
        case kActRelu:    return x > 0.f ? x : 0.f;
        case kActSigmoid: return 1.f / (1.f + std::exp(-x));
        case kActTanh:    return std::tanh(x);
        default:          return x;   // kActLinear
    }
}

// UTF-8 → 宽。本项目铁律：所有文件 API 走 *W，
// 因为 *A 版本按 ANSI 解释 UTF-8，在中文用户名下会静默失败。
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

bool EnsureParentDirW(const std::wstring& filePath) {
    size_t pos = filePath.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos == 0) return true;
    std::wstring dir = filePath.substr(0, pos);
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    if (GetLastError() == ERROR_ALREADY_EXISTS) return true;
    // ★ 逐级向上：**把 dir 本身当路径再问一次它的父目录**。
    //   曾经的写法是递归传 `dir + L"\\x"` —— 那个参数的父目录仍然等于 dir，
    //   于是每一层都拿同一个目录去建、失败、再递归，无限递归直到爆栈。
    //   正确的递推是"先保证祖先链存在，再建自己"。
    if (!EnsureParentDirW(dir)) return false;
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS ||
           GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 按层描述符算出权重区应有的字节数。任何一处 dim=0 / 超上限都直接判非法 ——
// 否则"头被写坏成 inDim=0x40000000"会变成一次 4GB 的乘法循环。
bool WeightsBytes(const std::vector<LayerDesc>& ls, uint64_t& outBytes, std::string& err) {
    outBytes = 0;
    for (size_t i = 0; i < ls.size(); ++i) {
        const LayerDesc& d = ls[i];
        if (d.inDim == 0 || d.outDim == 0) {
            err = "第 " + std::to_string(i) + " 层维度为 0";
            return false;
        }
        if (d.inDim > kMaxDim || d.outDim > kMaxDim) {
            err = "第 " + std::to_string(i) + " 层维度超上限（" +
                  std::to_string(d.inDim) + "×" + std::to_string(d.outDim) + "）";
            return false;
        }
        // 相邻层必须接得上：这一层的输入 = 上一层的输出
        if (i > 0 && ls[i - 1].outDim != d.inDim) {
            err = "第 " + std::to_string(i - 1) + " 层输出 " +
                  std::to_string(ls[i - 1].outDim) + " 与第 " + std::to_string(i) +
                  " 层输入 " + std::to_string(d.inDim) + " 不匹配";
            return false;
        }
        outBytes += (uint64_t)d.outDim * (uint64_t)d.inDim * 4ull;  // W
        outBytes += (uint64_t)d.outDim * 4ull;                     // b
    }
    return true;
}

}  // namespace

// ===========================================================================
//  Model::Impl
// ===========================================================================
struct Model::Impl {
    HANDLE               hFile = INVALID_HANDLE_VALUE;
    HANDLE               hMap  = INVALID_HANDLE_VALUE;
    const unsigned char* base  = nullptr;
    uint64_t             fileBytes = 0;
    bool                 open  = false;

    // ★ 错误文本与调用计数器都必须在**并发下也安全**：
    //   Forward 被文档承诺为可多线程并发调用（实时防护里多个事件源同时问同一个模型），
    //   于是 const 方法里对 mutable 成员的直接赋值就是真实的数据竞争（按标准是 UB）。
    //   错误路径是冷路径 → 加锁代价可忽略；计数器是热路径 → 用原子。
    mutable std::mutex   errMx;
    std::string          err;
    void Err(const std::string& s) { std::lock_guard<std::mutex> lk(errMx); err = s; }
    void ClearErr()                { std::lock_guard<std::mutex> lk(errMx); err.clear(); }
    std::string ErrText() const    { std::lock_guard<std::mutex> lk(errMx); return err; }

    Header                    hdr{};
    std::vector<LayerDesc>    layers;
    const unsigned char*      weights = nullptr;   // 指向权重区首字节

    mutable std::atomic<long long> forwards{0};

    void Unmap() {
        if (base) { UnmapViewOfFile(base); base = nullptr; }
        if (hMap != INVALID_HANDLE_VALUE) { CloseHandle(hMap); hMap = INVALID_HANDLE_VALUE; }
        if (hFile != INVALID_HANDLE_VALUE) { CloseHandle(hFile); hFile = INVALID_HANDLE_VALUE; }
        layers.clear();
        weights = nullptr;
        fileBytes = 0;
        open = false;
    }

    // 计算每层权重在缓冲区里的偏移（按顺序累加）
    uint64_t WOffset(size_t li) const {
        uint64_t off = 0;
        for (size_t i = 0; i < li; ++i) {
            off += (uint64_t)layers[i].outDim * (uint64_t)layers[i].inDim * 4ull;
            off += (uint64_t)layers[i].outDim * 4ull;
        }
        return off;
    }

    const float* WOf(size_t li) const {
        return (const float*)(weights + WOffset(li));
    }
    const float* BOf(size_t li) const {
        return (const float*)(weights + WOffset(li) +
                              (uint64_t)layers[li].outDim * (uint64_t)layers[li].inDim * 4ull);
    }
};

Model::Model() : p_(new Impl()) {}
Model::~Model() { p_->Unmap(); delete p_; }

bool Model::IsLoaded() const  { return p_->open; }
std::string Model::LastError() const { return p_->ErrText(); }
int Model::InDim() const   { return p_->open ? (int)p_->hdr.inDim  : 0; }
int Model::OutDim() const  { return p_->open ? (int)p_->hdr.outDim : 0; }
int Model::Layers() const  { return p_->open ? (int)p_->hdr.layers : 0; }
int Model::KindId() const  { return p_->open ? (int)p_->hdr.kind   : 0; }
int Model::LabelCount() const {
    if (!p_->open) return 0;
    if (p_->hdr.kind != (uint32_t)kKindMulti) return 0;
    return p_->hdr.outDim >= 2 ? (int)p_->hdr.outDim - 1 : 0;
}
long long Model::CreatedAtUnix() const { return p_->open ? (long long)p_->hdr.createdAtUnix : 0; }
std::string Model::Tag() const {
    if (!p_->open) return std::string();
    // tag 是定长 8 字节且**不保证有结尾 0**（截断过的标记不会补零），
    // 所以按"最多 8 个可打印字符"截断，而不是当 C 字符串用。
    char buf[9] = {0};
    for (int i = 0; i < 8; ++i) {
        char c = p_->hdr.tag[i];
        if (c == '\0') break;
        buf[i] = c;
    }
    return std::string(buf);
}

bool Model::Load(const std::string& pathUtf8) {
    p_->Unmap();
    p_->ClearErr();

    std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) { p_->Err("路径为空或不是合法 UTF-8"); return false; }

    // FILE_SHARE_DELETE：模型换新时可以"先放新文件、再换指针"，
    // 旧视图仍被映射也能替换（Windows 延后到最后一个视图关闭时真正删除）。
    HANDLE hf = CreateFileW(w.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        p_->Err("无法打开模型文件（错误码 " + std::to_string(GetLastError()) + "）");
        return false;
    }

    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(hf, &sz) || sz.QuadPart < (LONGLONG)kHeaderBytes) {
        CloseHandle(hf);
        p_->Err("文件太小，不可能是模型");
        return false;
    }
    p_->fileBytes = (uint64_t)sz.QuadPart;

    HANDLE hm = CreateFileMappingW(hf, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hm) {
        CloseHandle(hf);
        p_->Err("CreateFileMapping 失败（错误码 " + std::to_string(GetLastError()) + "）");
        return false;
    }
    const unsigned char* b = (const unsigned char*)MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (!b) {
        CloseHandle(hm); CloseHandle(hf);
        p_->Err("MapViewOfFile 失败（错误码 " + std::to_string(GetLastError()) + "）");
        return false;
    }

    // 先接管句柄/视图，之后任何失败路径统一走 Unmap（不漏句柄）
    p_->hFile = hf;
    p_->hMap  = hm;
    p_->base  = b;

    auto bail = [&](const std::string& why) {
        p_->Unmap();
        p_->Err(why);
        return false;
    };

    // 逐字段从字节流读，不直接当结构体用 —— 结构体读到的是**本机字节序**，
    // 现在的机器都是小端所以等价，但显式解包让"格式是小端"这件事写在代码里。
    Header h{};
    h.magic         = GetU32(b + 0);
    h.version       = GetU32(b + 4);
    h.kind          = GetU32(b + 8);
    h.layers        = GetU32(b + 12);
    h.inDim         = GetU32(b + 16);
    h.outDim        = GetU32(b + 20);
    h.createdAtUnix = (int64_t)GetU64(b + 32);
    memcpy(h.tag, b + 40, 8);
    h.checksum      = GetU64(b + 56);

    if (h.magic != kMagic)   return bail("魔数不匹配（不是本引擎的模型文件）");
    if (h.version != kVersion) return bail("版本不符：" + std::to_string(h.version) +
                                          "（本程序支持 " + std::to_string(kVersion) + "）");
    if (h.kind != (uint32_t)kKindMlp && h.kind != (uint32_t)kKindMulti)
        return bail("未知模型类型：" + std::to_string(h.kind) +
                    "（本程序支持 1=纯 MLP、2=多头 MLP）");
    if (h.layers == 0 || h.layers > kMaxLayers)
        return bail("层数非法：" + std::to_string(h.layers));
    if (h.inDim == 0 || h.outDim == 0 || h.inDim > kMaxDim || h.outDim > kMaxDim)
        return bail("输入/输出维度非法");

    // 多头模型的输出至少要有 2 维：out[0] 是恶意分，其余才是标签头（见 aimodel.h）。
    // "kind=2 但 outDim=1" 是自相矛盾的声明 —— 与其猜作者本来想干什么，不如拒掉：
    // 放行的话 Score 会从一个"多头模型"里取出第 0 维当分数，而那一维在训练时
    // 可能压根不是按分数训的，这种分数来源不明，正是本项目最忌的一类失败。
    if (h.kind == (uint32_t)kKindMulti && h.outDim < 2)
        return bail("多头模型的输出维度必须 >= 2（out[0] 是恶意分），实际 " +
                    std::to_string(h.outDim));

    const uint64_t descBytes = (uint64_t)h.layers * kLayerDescBytes;
    if (p_->fileBytes < (uint64_t)kHeaderBytes + descBytes)
        return bail("文件长度不足以容纳层描述符");

    std::vector<LayerDesc> ls((size_t)h.layers);
    for (uint32_t i = 0; i < h.layers; ++i) {
        const unsigned char* d = b + kHeaderBytes + (uint64_t)i * kLayerDescBytes;
        ls[i].inDim    = GetU32(d + 0);
        ls[i].outDim   = GetU32(d + 4);
        ls[i].act      = GetU32(d + 8);
        ls[i].reserved = GetU32(d + 12);
        if (ls[i].act > kActTanh)
            return bail("第 " + std::to_string(i) + " 层激活函数编号未知：" +
                        std::to_string(ls[i].act));
    }

    std::string werr;
    uint64_t wbytes = 0;
    if (!WeightsBytes(ls, wbytes, werr)) return bail(werr);

    // 首层输入维度与末层输出维度必须与头一致 —— 这是"头和层描述符对不上"
    // 这一类损坏的最后一道检查。对不上的话前向计算会读错偏移，算出的分数
    // 完全正常（只是没有意义），属于最难发现的失败形态。
    if (ls.front().inDim != h.inDim)
        return bail("首层输入维度 " + std::to_string(ls.front().inDim) +
                    " 与头声明 " + std::to_string(h.inDim) + " 不一致");
    if (ls.back().outDim != h.outDim)
        return bail("末层输出维度 " + std::to_string(ls.back().outDim) +
                    " 与头声明 " + std::to_string(h.outDim) + " 不一致");

    // ★ 多头模型的末层必须是 Sigmoid。这条契约原先只在 Builder（生成端）里检查，
    //   但服务端只做 Load + 推理、从不调用 Builder —— 于是它在本程序里是**死代码**
    //   （/O2 下连字符串都被链接器丢掉，实测在产物里 grep 不到这条错误串）。
    //   而模型的真实来源恰恰是外部（云库下发），只靠生成端自律等于没查。
    //   危害形态：Linear 末层会吐出 5.3 这样的"分数"，Clamp01 把它硬夹成 1.0，
    //   表现为"这个模型对任何输入都给满分"—— 比直接拒载难查得多。
    //   与 Builder 里那条检查**故意重复**：两道墙各自独立成立（一个管"写得出"，
    //   一个管"读得进"），谁少了哪一边都不影响另一边拦人。
    if (h.kind == (uint32_t)kKindMulti && ls.back().act != (uint32_t)kActSigmoid)
        return bail("多头模型的末层激活函数必须是 Sigmoid，当前是 " +
                    std::to_string(ls.back().act));

    const uint64_t needBytes = (uint64_t)kHeaderBytes + descBytes + wbytes;
    if (p_->fileBytes < needBytes)
        return bail("文件被截断：需要 " + std::to_string(needBytes) +
                    " 字节，实际 " + std::to_string(p_->fileBytes));

    const unsigned char* wptr = b + kHeaderBytes + descBytes;
    const uint64_t got = Fnv1a64(wptr, (size_t)wbytes);
    if (got != h.checksum)
        return bail("权重区校验失败（文件损坏；期望 " + std::to_string(h.checksum) +
                    " 实际 " + std::to_string(got) + "）");

    p_->hdr    = h;
    p_->layers = ls;
    p_->weights = wptr;
    p_->open   = true;
    return true;
}

void Model::Unload() {
    p_->Unmap();
    p_->ClearErr();
}

bool Model::Forward(const float* in, int inLen, std::vector<float>& out) const {
    out.clear();
    if (!p_->open) { p_->Err("模型未装载"); return false; }
    const int expect = (int)p_->hdr.inDim;
    if (!in || inLen != expect) {
        p_->Err("输入长度 " + std::to_string(inLen) + " 与模型要求 " +
                std::to_string(expect) + " 不一致");
        return false;
    }
    // NaN/Inf 输入必须在入口挡掉：ReLU 之后 NaN 会一路传播到输出，
    // 而 NaN 与任何阈值比较都是 false → 判定永远落在"不拦截"那一侧。
    // 也就是说坏输入会**静默地把防护关掉**，这是最不能接受的失败形态。
    for (int i = 0; i < expect; ++i) {
        if (!(in[i] == in[i])) { p_->Err("输入第 " + std::to_string(i) + " 维是 NaN"); return false; }
        if (in[i] > 1e30f || in[i] < -1e30f) {
            p_->Err("输入第 " + std::to_string(i) + " 维超出合理范围");
            return false;
        }
    }

    // 用局部缓冲区而不是成员 scratch：这样同一个 Model 可以被多线程并发调用
    // （实时防护里就是多个事件源同时问同一个模型）。
    // 每次分配在两个几十维的小向量之间 —— 相对于调用方的文件 I/O 可忽略。
    std::vector<float> cur(in, in + expect);
    std::vector<float> nxt;

    for (size_t li = 0; li < p_->layers.size(); ++li) {
        const LayerDesc& d = p_->layers[li];
        const float* W = p_->WOf(li);
        const float* B = p_->BOf(li);
        nxt.assign((size_t)d.outDim, 0.f);
        for (uint32_t j = 0; j < d.outDim; ++j) {
            const float* row = W + (size_t)j * d.inDim;
            float acc = B[j];
            for (uint32_t i = 0; i < d.inDim; ++i) acc += row[i] * cur[i];
            nxt[j] = ApplyAct(d.act, acc);
        }
        cur.swap(nxt);
    }

    out.swap(cur);
    p_->forwards.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool Model::Predict(const FeatureVector& fv, std::vector<float>& out) const {
    if (!p_->open || p_->hdr.inDim != (uint32_t)kFeatureDim) {
        out.clear();
        return false;
    }
    return Forward(fv.v, kFeatureDim, out);
}

float Model::Score(const FeatureVector& fv, bool* ok) const {
    if (ok) *ok = false;
    if (!p_->open || p_->hdr.inDim != (uint32_t)kFeatureDim) return 0.f;

    // 只有两种"分数来源"是被契约承认的：
    //   ① kind=1 且 outDim==1 —— v1 老模型，唯一的那一维就是分数；
    //   ② kind=2             —— 契约规定 out[0] 就是恶意分（见 aimodel.h）。
    // kind=1 且 outDim>1 一律拒绝：那种模型的第 0 维**没有任何语义约定**，
    // 取它等于凭空指定一个分数出来 —— 分数要喂进评分层，来源不明就是隐患。
    const bool single = (p_->hdr.kind == (uint32_t)kKindMlp   && p_->hdr.outDim == 1);
    const bool multi  = (p_->hdr.kind == (uint32_t)kKindMulti && p_->hdr.outDim >= 2);
    if (!single && !multi) return 0.f;

    std::vector<float> outv;
    if (!Forward(fv.v, kFeatureDim, outv) || outv.empty()) return 0.f;
    const float s = outv[0];
    if (!(s == s)) return 0.f;      // 万一模型本身算出 NaN，宁可报 0（不可疑）

    // ★ 顺序：ok 必须在 NaN 判定**之后**才置 true。
    //   原实现的 ok=true 落在 NaN 检查之前，于是"前向成功但输出是 NaN"会报成
    //   ok=true 且分数 0 —— 把"算不出来"说成了"算出来是 0 分"（不可疑）。
    //   分数是零等于告诉评分层"这事没问题"，恰恰是最不该发生的一种谎报。
    if (ok) *ok = true;
    return Clamp01(s);
}

bool Model::ScoreLabels(const FeatureVector& fv, float& score,
                        std::vector<float>& labels) const {
    score = 0.f;
    labels.clear();
    if (!p_->open) return false;
    if (p_->hdr.kind != (uint32_t)kKindMulti || p_->hdr.outDim < 2) return false;
    if (p_->hdr.inDim != (uint32_t)kFeatureDim) return false;

    std::vector<float> outv;
    if (!Forward(fv.v, kFeatureDim, outv)) return false;
    if (outv.size() != (size_t)p_->hdr.outDim) {
        labels.clear();
        return false;
    }

    // 分数与标签是一个整体：分数那一维出 NaN 时**整次调用失败**，
    // 而不是"分数归 0、标签照给"。半份结果比没有结果更容易被误用 ——
    // 调用方一旦见过一次"既能给分又能给标签"的返回值，就会默认两个都对。
    if (!(outv[0] == outv[0])) {
        labels.clear();
        return false;
    }
    score = Clamp01(outv[0]);
    labels.assign(outv.size() - 1, 0.f);
    for (size_t i = 1; i < outv.size(); ++i) labels[i - 1] = Clamp01(outv[i]);
    return true;
}

ModelStats Model::GetStats() const {
    ModelStats s;
    s.open = p_->open;
    s.fileBytes = (long long)p_->fileBytes;
    s.forwards  = p_->forwards.load(std::memory_order_relaxed);
    if (!p_->open) return s;
    s.kind = (int)p_->hdr.kind;
    s.layers = (int)p_->hdr.layers;
    s.inDim  = (int)p_->hdr.inDim;
    s.outDim = (int)p_->hdr.outDim;
    s.tag    = Tag();
    s.createdAtUnix = (long long)p_->hdr.createdAtUnix;
    long long params = 0;
    for (size_t i = 0; i < p_->layers.size(); ++i)
        params += (long long)p_->layers[i].outDim * (long long)p_->layers[i].inDim +
                  (long long)p_->layers[i].outDim;
    s.paramCount = params;
    return s;
}

// ===========================================================================
//  Builder
// ===========================================================================
struct Builder::Impl {
    uint32_t inDim = 0;
    uint32_t outDim = 0;
    uint32_t kind = (uint32_t)kKindMlp;
    std::string tag;
    std::vector<LayerDesc> layers;
    std::vector<float>     weights;   // W0,b0,W1,b1,…
    std::string err;
};

Builder::Builder(int inDim, int outDim, const std::string& tag, int kind) : p_(new Impl()) {
    if (inDim <= 0 || outDim <= 0 || inDim > (int)kMaxDim || outDim > (int)kMaxDim) {
        p_->err = "维度非法";
        return;
    }
    if (kind != kKindMlp && kind != kKindMulti) {
        p_->err = "kind 非法（只支持 1=纯 MLP、2=多头 MLP）";
        return;
    }
    // 多头的第 0 维是恶意分、其余才是标签头 → 至少要有 2 维，否则"多头"没有头。
    // ★ 这条与 Model::Load 里的同类检查**故意重复**：这里挡的是"造出一个自己都读不出来
    //   的模型文件"，那里挡的是"读到一个来路不明的模型文件"。两道墙各自独立成立，
    //   少任何一道都会让另一半成为唯一防线（而唯一的防线一旦被绕过就没人知道）。
    if (kind == kKindMulti && outDim < 2) {
        p_->err = "多头模型的 outDim 必须 >= 2（out[0] 是恶意分）";
        return;
    }
    p_->inDim  = (uint32_t)inDim;
    p_->outDim = (uint32_t)outDim;
    p_->kind   = (uint32_t)kind;
    p_->tag    = tag;
}
Builder::~Builder() { delete p_; }

bool Builder::AddLayer(int act, const float* W, int outDim, const float* b) {
    if (act < 0 || act > kActTanh) { p_->err = "激活函数编号非法"; return false; }
    if (outDim <= 0 || outDim > (int)kMaxDim) { p_->err = "层输出维度非法"; return false; }
    if (!W || !b) { p_->err = "权重或偏置指针为空"; return false; }

    const uint32_t inDim = p_->layers.empty() ? p_->inDim : p_->layers.back().outDim;
    LayerDesc d;
    d.inDim = inDim;
    d.outDim = (uint32_t)outDim;
    d.act = (uint32_t)act;
    d.reserved = 0;

    const size_t wn = (size_t)outDim * inDim;
    for (size_t i = 0; i < wn; ++i) {
        if (!(W[i] == W[i])) { p_->err = "权重含 NaN"; return false; }
        p_->weights.push_back(W[i]);
    }
    for (int i = 0; i < outDim; ++i) {
        if (!(b[i] == b[i])) { p_->err = "偏置含 NaN"; return false; }
        p_->weights.push_back(b[i]);
    }
    p_->layers.push_back(d);
    return true;
}

int Builder::LayerCount() const { return (int)p_->layers.size(); }

long long Builder::ParamCount() const { return (long long)p_->weights.size(); }

int Builder::KindId() const { return (int)p_->kind; }

bool Builder::Build(const std::string& pathUtf8) {
    p_->err.clear();
    if (p_->layers.empty()) { p_->err = "没有任何层"; return false; }
    if (p_->layers.back().outDim != p_->outDim) {
        p_->err = "最后一层输出维度 " + std::to_string(p_->layers.back().outDim) +
                  " 与构造时声明的 " + std::to_string(p_->outDim) + " 不一致";
        return false;
    }
    std::string werr;
    uint64_t expectBytes = 0;
    if (!WeightsBytes(p_->layers, expectBytes, werr)) { p_->err = werr; return false; }
    if (expectBytes != (uint64_t)p_->weights.size() * 4ull) {
        p_->err = "权重缓冲区长度与层结构不符（内部错误）";
        return false;
    }

    // 多头模型的末层**必须**是 Sigmoid：out[0] 要被当成 [0,1] 的分数用，
    // 每个标签头也要各自一个 [0,1] 置信度（标签之间互不排斥，不能用 Softmax）。
    // 写别的激活函数也能生成文件、也能跑，但推理侧会被 Clamp01 硬夹到 0 或 1 上，
    // 于是"分数全挤在边界"—— 这类结果比直接报错难查得多，所以在写盘前拦住。
    if (p_->kind == (uint32_t)kKindMulti &&
        p_->layers.back().act != (uint32_t)kActSigmoid) {
        p_->err = "多头模型的末层激活函数必须是 Sigmoid，当前是 " +
                  std::to_string(p_->layers.back().act);
        return false;
    }

    const std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) { p_->err = "路径为空或不是合法 UTF-8"; return false; }
    EnsureParentDirW(w);
    const std::wstring wtmp = w + L".tmp";

    HANDLE h = CreateFileW(wtmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        p_->err = "无法创建临时模型文件（错误码 " + std::to_string(GetLastError()) + "）";
        return false;
    }

    auto closeFail = [&](const std::string& why) {
        CloseHandle(h);
        DeleteFileW(wtmp.c_str());
        p_->err = why;
        return false;
    };

    // ---- 头（64 字节，逐字段写以便格式一目了然）----
    unsigned char hb[kHeaderBytes];
    memset(hb, 0, sizeof(hb));
    PutU32(hb + 0,  kMagic);
    PutU32(hb + 4,  kVersion);
    PutU32(hb + 8,  p_->kind);
    PutU32(hb + 12, (uint32_t)p_->layers.size());
    PutU32(hb + 16, p_->inDim);
    PutU32(hb + 20, p_->outDim);
    // 24..31 reserved
    PutU64(hb + 32, (uint64_t)time(nullptr));
    {
        const size_t tn = p_->tag.size() < 8 ? p_->tag.size() : 8;
        memcpy(hb + 40, p_->tag.data(), tn);   // 不足 8 字节时剩下的保持 0
    }
    // 48..55 reserved（补满 64 字节；这一段的字节数变动会破坏格式契约）
    PutU64(hb + 56, Fnv1a64((const unsigned char*)p_->weights.data(),
                            p_->weights.size() * sizeof(float)));

    DWORD wr = 0;
    if (!WriteFile(h, hb, kHeaderBytes, &wr, nullptr) || wr != kHeaderBytes)
        return closeFail("写模型头失败");

    // ---- 层描述符 ----
    for (size_t i = 0; i < p_->layers.size(); ++i) {
        unsigned char db[kLayerDescBytes];
        PutU32(db + 0,  p_->layers[i].inDim);
        PutU32(db + 4,  p_->layers[i].outDim);
        PutU32(db + 8,  p_->layers[i].act);
        PutU32(db + 12, 0);
        if (!WriteFile(h, db, kLayerDescBytes, &wr, nullptr) || wr != kLayerDescBytes)
            return closeFail("写层描述符失败（第 " + std::to_string(i) + " 层）");
    }

    // ---- 权重区。分块写：一次 WriteFile 塞几百 MB 会在某些磁盘上长时间不可中断 ----
    {
        const size_t total = p_->weights.size();
        const size_t perChunk = 262144;   // 条浮点 = 1MB
        std::vector<float> buf;
        buf.reserve(perChunk);
        size_t i = 0;
        while (i < total) {
            size_t cnt = total - i;
            if (cnt > perChunk) cnt = perChunk;
            buf.assign(p_->weights.begin() + i, p_->weights.begin() + i + cnt);
            const DWORD bytes = (DWORD)(cnt * sizeof(float));
            if (!WriteFile(h, buf.data(), bytes, &wr, nullptr) || wr != bytes)
                return closeFail("写权重失败");
            i += cnt;
        }
    }

    if (!FlushFileBuffers(h)) return closeFail("FlushFileBuffers 失败");
    CloseHandle(h);

    // 原子替换：中途掉电时目标路径上要么是旧模型、要么是新模型，不存在半个
    if (!MoveFileExW(wtmp.c_str(), w.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        p_->err = "替换模型文件失败（错误码 " + std::to_string(GetLastError()) + "）";
        DeleteFileW(wtmp.c_str());
        return false;
    }
    return true;
}

std::string Builder::LastError() const { return p_->err; }

}  // namespace ai
}  // namespace sf
