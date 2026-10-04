// hashdb.h — 云端哈希库的本地载体：**mmap 有序二进制 + Bloom 前置**
//
// ===========================================================================
//  为什么这个不走 sfdb（自研 SQL 数据库）
// ===========================================================================
//  两类数据的访问画像完全不同，硬塞进一个引擎会两头不讨好：
//
//    · 云库哈希（本文件）：**只读、点查、几十万到上千万条、进程启动即用**。
//      查询是「给我一个 SHA-256，在不在库里」。没有事务、没有更新、
//      没有范围扫描、没有多列。用数据库等于给一把锤子配一个机房。
//    · 隔离区/快照元数据（sfdb）：可写、多列、要按条件筛、要按时间排序。
//
//  所以：**A 类只读点查走本文件，B 类可变事务走 sfdb**。
//  （这条分区原则在 docs/storage-architecture.md 里有完整论证。）
//
// ===========================================================================
//  为什么是 Bloom + 有序数组，而不是哈希表 / 前缀树 / 数据库索引
// ===========================================================================
//  · 有序数组 + 二分：N 条只需 32N 字节，无指针、无空洞、可 mmap 直接查，
//    缓存局部性好（二分的前几次访问就把范围缩到一个 cache line 附近）。
//    缺点是插入 O(N) —— 而我们**永远不插入**，云库是整体替换的。
//  · 前置 Bloom：绝大多数查询是「不在库里」（正常文件远多于恶意文件）。
//    Bloom 用 ~1.2 字节/条的代价把「肯定不在」的查询挡在二分之前，
//    实测能把负查询的耗时压到 1/10 以下，且**零启动加载**（mmap 即可）。
//  · 为什么不用 std::unordered_set 全量加载：1000 万条 × (32B + 节点开销 ~56B)
//    约 900MB 内存，还要在服务启动时读 320MB 文件 —— 对一个常驻杀软服务
//    完全不可接受。mmap 方案的内存占用由操作系统按访问页决定，通常只有几 MB。
//
//  ⚠️ Bloom 只能给出「肯定不在」或「可能在」。**必须在 Bloom 命中后再二分确认**，
//     绝不能把 Bloom 命中当结论 —— 否则会有假阳性（把正常文件判成病毒）。
//     这是用 Bloom 最容易犯的错，代码里 ContainsHash 的顺序就体现了这一点。
//
// ===========================================================================
//  文件格式（全部小端）
// ===========================================================================
//      ┌────────────── 64 字节头 ──────────────┐
//      │ magic(4) version(4) kind(4) hashBytes(4)
//      │ bloomBits(4) bloomK(4) contentVer(4) reserved(4)
//      │ count(8) builtAtUnix(8) sourceBytes(8) tag(8)
//      ├────────── Bloom 位图（bloomBits/8 字节）
//      ├────────── 有序 SHA-256 数组（count × 32 字节，按字节序升序，无重复）
//
//  · magic 'SFH1'（0x31484653）—— 防止把别的东西当库 mmap 进来。
//  · hashBytes 固定 32（SHA-256）。留字段是为了将来换算法不破格式号。
//
//  ★★ version 与 contentVer 是**两个完全不同**的概念，绝不能混用：
//     · `version`（+4）= **格式版本号**，恒为 1，由 kVersion 常量控制。
//       Open() 会**硬校验** version != kVersion → 拒绝装载整个库。
//       所以它只在你改了头布局/数组语义时才 +1 —— 一旦改，全体老客户端
//       立刻拒绝装载新库。**内容的更新绝不能碰这个字段。**
//     · `contentVer`（+24，原 reserved0）= **内容的版本号**（"病毒库 v1.2 的 1.2"），
//       编码 `(major << 16) | minor`；**0 表示未标注**（老库天然为 0）。
//       Open() **只读出、不校验** —— 内容新旧是业务问题，不是格式问题。
//       用真内容版本只增不改，且 `(1<<16)|10 > (1<<16)|2`，比较新旧可直接比整数。
//     ⚠️ 历史教训：曾经设想把内容版本写进 `version` —— 那样库每更新一次，
//        全体老客户端都会因 `version != kVersion` **拒绝装载病毒库**，
//        等于**一次数据更新打没全体用户防护**。故一律写 contentVer。
//  · builtAtUnix(+40) = 库的构造时间（Unix 秒，UTC），GUI 上显示为"发布日期"。
//  · 整个文件**写入时一次性构造**，写完 MoveFileEx 原子替换（同 sfdb::Compact）。
//    所以「半更新的库」在磁盘上不可能存在 —— 要么旧库、要么新库。
//
// ===========================================================================
//  线程安全
// ===========================================================================
//  打开后**只读**，mmap 视图对所有线程天然安全（无共享可变状态）。
//  唯一的竞争点是 Open/Close 与查询之间 —— 调用方保证「先 Open 再查询」，
//  进程退出时 Close。本类自身不对 Open/Close 加锁（与 sfdb 的取舍不同：
//  sfdb 有写路径必须锁，本类查询路径无锁才能快）。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sf {
namespace hashdb {

// 库用途（写进文件头，便于诊断「装错库」这类事故）
enum Kind {
    kKindUnknown   = 0,
    kKindMalicious = 1,   // 恶意哈希（命中即判危险）
    kKindTrusted   = 2,   // 可信哈希（命中即豁免，对应"信任区"的正确语义）
};

struct Stats {
    std::string path;
    bool        open       = false;
    int         kind       = kKindUnknown;
    std::string tag;
    long long   count      = 0;   // 条目数
    long long   fileBytes  = 0;
    long long   bloomBits  = 0;
    int         bloomK     = 0;
    long long   builtAtUnix = 0;   // 库构造时间（Unix 秒，UTC）；0 = 未标注
    // 内容版本号（不是格式版本号！见文件头 version vs contentVer 说明）
    long long   contentVersion = 0;      // 原始编码 (major<<16)|minor；0 = 未标注
    std::string contentVersionText;      // 显示用："1.2"；未标注时为"未标注"（**不是** "0.0"）
    long long   queries    = 0;   // 本进程查询次数
    long long   bloomMiss  = 0;   // Bloom 直接判否的次数（省下的二分）
    long long   hits       = 0;   // 确认命中的次数
};

// ===========================================================================
//  只读查询
// ===========================================================================
class HashDb {
public:
    HashDb();
    ~HashDb();

    HashDb(const HashDb&)            = delete;
    HashDb& operator=(const HashDb&) = delete;

    bool Open(const std::string& pathUtf8);   // UTF-8 路径；只读 mmap
    void Close();
    bool IsOpen() const;
    std::string LastError() const;

    // 核心查询。sha256Hex 必须是 64 个十六进制字符（大小写均可）。
    // 非法输入返回 false（同时记 LastError），不会崩。
    bool ContainsHash(const std::string& sha256Hex) const;

    // 便利：直接算哈希再查
    bool ContainsBytes(const void* data, size_t len, std::string* outHex = nullptr) const;
    bool ContainsFile(const std::string& filePathUtf8, std::string* outHex = nullptr) const;

    Stats GetStats() const;

    // 已打开库的条目数（0 = 未打开或空库）
    long long Count() const;

    // ---- 静态工具 ----
    // 64 位十六进制 → 32 字节。失败返回 false。
    static bool HexToHash(const std::string& hex, unsigned char out[32]);
    // 32 字节 → 64 位小写十六进制
    static std::string HashToHex(const unsigned char h[32]);
    // SHA-256（走 *W 文件 API，规避 std::ifstream 的 ANSI 路径陷阱）
    static bool Sha256OfFile(const std::string& filePathUtf8, std::string& outHex);

    // ---- 内容版本号的 文本 ↔ 编码（`(major<<16)|minor`，0 = 未标注）----
    // 公开为静态工具的理由：造库器、验证工具、GUI 都要用**同一份**规则。
    // 各自抄一份必然漂移，而漂移的表现是"版本号被静默写错 / 显示错"——
    // 查得到、也没有任何报错，属于最难发现的一类。
    static bool        ParseContentVersion(const std::string& text, uint32_t& outCode);
    static std::string ContentVersionText(uint32_t code);

private:
    struct Impl;
    Impl* p_;
};

// ===========================================================================
//  构造（离线/云端下发时用）
// ===========================================================================
//  用法：
//      Builder b;
//      b.SetKind(kKindMalicious);
//      b.SetTag("av-blk");
//      b.AddHex("e3b0c442...");
//      b.AddFile("D:\\samples\\x.exe");
//      b.Build("C:\\ProgramData\\SilverFoxGuard\\hash\\malicious.hdb");
//
//  Build 内部：排序 → 去重 → 建 Bloom → 写 .tmp → FlushFileBuffers →
//  MoveFileEx 原子替换。中途失败/断电 → 目标路径上的旧库完好无损。
class Builder {
public:
    Builder();
    ~Builder();

    Builder(const Builder&)            = delete;
    Builder& operator=(const Builder&) = delete;

    void SetKind(int kind);
    void SetTag(const std::string& tag);

    // 内容版本号，形如 "1.2"（major.minor，各段 ≤ 65535）。
    //   · 传空串或 "0.0" → 视为**未标注**（写 0），与老库二进制等价。
    //   · 返回 false = 文本非法。此时 **Build() 也一定会失败**（双保险）：
    //     即使调用方忽略了返回值，也不会把"未标注"偷偷写进库里。
    //     静默降级会让「我明明写了 2.0、库里却是未标注」变成**没有症状**的假象。
    bool SetContentVersionText(const std::string& text);

    // 库构造时间（Unix 秒，UTC）。不调用或传 <=0 → 用 Build() 当时的当前时间。
    void SetBuiltAtUnix(long long unixSec);

    bool AddHex(const std::string& sha256Hex);
    bool AddBytes(const void* data, size_t len);
    bool AddFile(const std::string& filePathUtf8);

    long long Count() const;
    long long Skipped() const;     // 非法输入被跳过的条数

    bool Build(const std::string& pathUtf8);

    std::string LastError() const;

    // 建议的 Bloom 参数（按条目数）。返回 false 表示 count 为 0，无需建库。
    static bool SuggestBloom(long long count, uint32_t& outBits, uint32_t& outK);

private:
    struct Impl;
    Impl* p_;
};

}  // namespace hashdb
}  // namespace sf
