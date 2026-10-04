// hashshare.h — 云端哈希库的「跨模块只读查询」契约
//
// ===========================================================================
//  【要解决的问题】
// ===========================================================================
//  哈希库实例（`g_mal` / `g_tru` / `g_malMd5` / `g_malSha1`）是 mod_sfdb.cpp
//  **匿名命名空间**里的私有对象。
//  命令（hashq / hashstat / hashreload）能用它们，只因为和它们在同一个编译单元。
//  而**真正需要它们的不是命令，是实时处置链** —— `service.cpp` 的
//  「进程出生」与「落地捕获」两条路径。没有这层契约，`service.cpp` 只能：
//    · 走管道自己给自己发一条 hashq（荒谬，且是异步的，判定等不了）；
//    · 或者自己 new 一个 HashDb 打开同一个文件（**错误**：两处各持一份
//      配置/缓存，将来换库、失效、统计全部对不上）。
//
//  ⚠️ 这**正是**本项目最该警惕的形态：**库建好了、接口齐了、命令能查，
//     但判定链从不调用它** —— 病毒库变成一件摆设，而所有日志看起来都正常。
//     （同型教训见 MEMORY.md「半通故障」与「能力缺失 vs 触发缺失」。）
//
// ===========================================================================
//  【★ 为什么这里是一组函数，而不是像 sfdbshare.h 那样暴露实例指针】
// ===========================================================================
//  `sfdbshare.h` 暴露的是 `Database*`，因为它给的语义是「**写**库」——
//  写方需要长生命周期的实例句柄，而且 sfdb 的实例在服务生命周期内不换。
//
//  哈希库不一样：**`hashreload` 命令会替换实例**。mod_sfdb 用
//  `unique_ptr` 承载正是为了"先建好新的再换指针"（避免"先关旧的再开新的"
//  造成一段完全无库可查的窗口）。如果这里暴露 `HashDb*`：
//      service.cpp 拿到指针 → 另一线程执行 hashreload → unique_ptr 被 reset
//      → **旧实例已析构，判定链手里的指针悬垂** → 随机崩溃或读到错数据。
//  这类 bug 的复现条件是"恰好有人 reload 库的同时有个进程落地"，
//  概率低、现象随机、日志干净 —— 属于最难查的一类。
//
//  所以：**只暴露函数。** 每次查询在 mod_sfdb 内部取一次 `shared_lock`
//  再做二分，调用方**永远拿不到一个可能悬垂的指针**。
//  代价是每次查询一次读锁 —— 读锁之间不互斥，而 reload 是极低频操作，
//  这个代价可以忽略；换来的是"悬垂在结构上不可能发生"。
//
// ===========================================================================
//  【★ 为什么契约里没有「查可信库然后放行」这条给判定链的路】
// ===========================================================================
//  项目已定的语义（见 MEMORY.md「信任区语义」）：
//
//      信任 ≠ 放行。信任只豁免**身份类**判据（随机名 / 签名 / 路径），
//      行为类判据照常跑。
//
//  而一个"可信哈希"是**文件级身份豁免** —— 一旦用它放行，等于说
//  「这个文件的字节是一个好文件的字节，所以它做什么都对」。这与既有语义
//  正好相反，会把信任区改造成一个"一次误收录即永久后门"的机制。
//
//  因此：`HitTrusted()` **存在，但只给展示/诊断用**（GUI 里显示"这个文件
//  在可信库里"是合理的），**判定链不得调用它来做降权或放行**。
//  这条纪律靠"不提供更好用的入口"来落实：没有 `ShouldAllow(path)` 这种函数。
#pragma once

#include <string>
#include <vector>   // InstallCloudLibs 的入参（步3 云库下载更新链）

namespace sf {
namespace hashshare {

// ===========================================================================
//  键空间（**与 hashdb::Kind 不是一回事**）
// ===========================================================================
//  Kind 说的是"这本库是什么语义"（恶意/可信）；Algo 说的是"键怎么来的"。
//  两者正交：可以有 (恶意, SHA-256)、(恶意, imphash) 两组。
enum Algo {
    kAlgoSha256  = 0,   // 键 = 文件整文件 SHA-256，64 位十六进制
    kAlgoImphash = 1,   // 键 = ImphashKey(imphash)，64 位十六进制（见 pehash.h）
    kAlgoMd5     = 2,   // 键 = Md5Key(MD5)，64 位十六进制（SHA256("md5:"+hex)，见 pehash.h）
    kAlgoSha1    = 3,   // 键 = Sha1Key(SHA-1)，64 位十六进制（SHA256("sha1:"+hex)，见 pehash.h）
};

// ===========================================================================
//  查询
// ===========================================================================
// key64Hex：64 位十六进制（大小写均可）。非法输入返回 false 且不计数为命中。
//
// ★ 命中 = true。**没有"未知/出错"这一档** —— 查不到就是查不到，
//   与"库没装载"在返回值上不可区分。所以：
//   **绝不要把 false 读成"这个文件是干净的"**，它只意味着"这条判据没意见"。
bool HitMalicious(int algo, const std::string& key64Hex, std::string* outWhy = nullptr);

// ⚠️ 仅供展示 / 诊断。**判定链不得据此降权或放行**（理由见文件头）。
bool HitTrusted(int algo, const std::string& key64Hex);

// ★★ 本地恶意库（独立于云库，高危隔离自动入库；云库更新不触达，不会被冲掉）
//  ------------------------------------------------------------------
//  设计动机：云库 `malicious.sfh` 是**整文件原子替换 + ECDSA 签名**，任何写进
//  它的本地数据，下次云库一更新立刻被覆盖，且本机无私钥重签。所以本机学习到的
//  恶意哈希必须落在**另一个目录（local\）的另一个文件（txt）**，libupdate /
//  hashreload 永远不碰它 → 云库更新不会冲掉本机积累。
//  键空间固定 SHA-256。用途：高危文件被隔离后，把其哈希记到本机本地库，
//  下次同一样本再出现直接秒杀、无需再进沙箱。
bool AddLocalMaliciousSha256(const std::string& sha256Hex);  // 登记成功返回 true（已存在也 true）
bool HitLocalMaliciousSha256(const std::string& sha256Hex);   // 命中即视为恶意
long long LocalMaliciousCount();                              // 当前条目数（hashstat 展示）

// 至少有一本**恶意**库装载成功。
// 用途：启动日志、诊断统计（"库到底下发了没有"）。
// ★ **不要**用它去 gate 判定逻辑 —— 那样"云库没下发"就会静默退化成
//   "这条判据消失"，而日志里看起来一切正常。
bool AnyMaliciousLoaded();

// ===========================================================================
//  观测
// ===========================================================================
//  ★ 三种成因必须分开计：
//    · skippedNoDb —— 库没装载（**正常状态**：新装机还没下发过库）
//    · queries     —— 真正做了二分查询
//    · hits        —— 命中
//  混在一起就没法回答"实时防护为什么没报毒"这个最关键的问题。
struct LookupStats {
    long long queries     = 0;
    long long hits        = 0;
    long long skippedNoDb = 0;
};
LookupStats GetLookupStats();
void ResetLookupStats();

// ===========================================================================
//  登记（**仅 mod_sfdb 调用**）
// ===========================================================================
// 启停时告知契约"库子系统现在可不可用"。不在此登记具体实例 ——
// 实例始终由 mod_sfdb 持有，本契约只借用它的查询能力。
void SetHashSubsystemReady(bool ready);

// 子系统是否已 Init 完成。
// ★ 与 `AnyMaliciousLoaded()` 是**两个不同的问题**，诊断时必须分开问：
//     IsHashSubsystemReady() == false  → mod_sfdb 的 Init 压根没跑到
//     ready == true 但 AnyMaliciousLoaded() == false
//                                      → Init 跑了，但库文件不存在（尚未下发）
//   两种情况的现象都是"实时链查不到东西"，但一个是代码/启动顺序问题，
//   一个是正常的空库状态。混成一个布尔值就永远分不清。
bool IsHashSubsystemReady();

// ===========================================================================
//  ★★ 库信息与安装 —— 步3 云库下载更新链（2026-09-25）
// ===========================================================================
//  上面那一节是**只读查询**（给判定链用），本节是**写入 / 装载**（给
//  `mod_lib` 用）。两者纪律相同：**只暴露函数，绝不暴露实例指针**，
//  理由是本节的风险更高 ——
//    · `InstallCloudLibs` 内部必须 reset 三个 unique_ptr 才换得动文件
//      （被 mmap 着的文件 `MoveFileEx(REPLACE_EXISTING)` 一定失败）；
//    · 那一刻正是"库全空"的窗口，也正是外部持有的 `HashDb*` 变悬垂的时刻。
//  所以调用方（mod_lib）只递**暂存文件的路径**进来，永远不碰实例。

// ---------------------------------------------------------------------------
//  本机某一本库的现状 —— 回答 `mod_lib` 唯一关心的问题："要不要下？"
// ---------------------------------------------------------------------------
//  ★ 为什么给结构体、而不是让 mod_lib 去解析 hashstat 的 JSON：
//    JSON 是**给人的**（字段名/嵌套可以随界面需要改），结构体是**给代码的**。
//    让"要不要下载"这个决策去依赖自家 JSON 的字段名，等于引入一整类
//    "改个字段名 → 更新判据静默失效"的故障 —— 而它不会报任何错。
struct LibInfo {
    bool        loaded    = false;   // 是否已成功装载（= 真的可用）
    long long   count     = 0;       // 条目数
    long long   contentVersion = 0;  // 内容版本号原始编码 (major<<16)|minor；0 = 未标注
    std::string contentVersionText;  // "1.2" / "未标注"
    long long   builtAtUnix = 0;     // 发布日期（UTC 秒）
    std::string sha256;              // 实际算出的库文件 SHA-256（取自验签状态）
    std::string path;                // cloud\<name>
    bool        sigChecked  = false;
    bool        sigOk       = false;
    bool        sigBypassed = false;
    std::string sigResult;           // libsig::ResultText 的结论
    std::string sigDetail;
};

// 索引 → 目标文件名（g_malPath / g_truPath / g_malImpPath / g_malMd5Path /
// g_malSha1Path）的**唯一**对应关系。
// ★ 用常量而不是让调用方传文件名：文件名写错了不会报错，只会"更新成功了但
//   库没变"（往一个没人读的文件里写）。
constexpr int kLibIdxMalSha = 0;   // 恶意(SHA-256)    → malicious.sfh
constexpr int kLibIdxTruSha = 1;   // 可信(SHA-256)    → trusted.sfh
constexpr int kLibIdxMalImp = 2;   // 恶意(imphash)    → malicious_imp.sfh
constexpr int kLibIdxMalMd5 = 3;   // 恶意(MD5)        → malicious_md5.sfh
constexpr int kLibIdxMalSha1= 4;   // 恶意(SHA-1)      → malicious_sha1.sfh

// 取某一本库的现状。idx 越界返回 false（不猜、不兜底）。
bool GetLibInfo(int idx, LibInfo& out);

// cloud\ 目录的 UTF-8 绝对路径 —— 三本库与 `.tmp` 暂存文件都放这里。
// ★ 为什么由 mod_sfdb 提供、而不是 mod_lib 自己推一遍：
//   `%ProgramData%\SilverFoxGuard\cloud` 推错**不会报任何错**，只会表现为
//   「下载成功了，但库没变」—— 因为写到了另一个目录里。一个来源，不可能不一致。
// ⚠️ mod_sfdb 未 Init 前返回空串（调用方必须判空，不要拼出 "\malicious.sfh"）。
std::string CloudDirUtf8();

// 五本库状态的 JSON 快照（数组），与 `hashstat.libs` **同构**。
// ★ 存在的理由：`libstat` / `libcheck` / `libupdate` 都要把"三本库现状"内联进
//   自己的回包。若各自拼一份，字段集合必然随时间漂移 —— 而缺字段的表现是
//   前端某块空白，看起来不像 bug。所以序列化只留一个入口。
std::string LibsJsonSnapshot();

// ---------------------------------------------------------------------------
//  安装 —— **唯一能替换 cloud\<name> 正式文件的入口**
// ---------------------------------------------------------------------------
struct LibInstallItem {
    int         idx = 0;         // 决定目标文件名与 sigIdx（见上方常量）
    std::string stagedLibPath;   // <cloud>\<name>.sfh.tmp（UTF-8）
    // ★ 签名文件路径**不单独传**：由 libsig::SigPathFor(stagedLibPath) 唯一推导。
    //   装载正式库时用的是同一个函数 —— 两端不可能不一致。
};

struct LibInstallResult {
    bool        ok         = false;
    int         installed  = 0;       // 成功替换并装载的库数
    int         failed     = 0;
    bool        rolledBack = false;   // ★ 失败后是否已回滚到旧库
    std::string detail;               // 一句话结论（成功 / 失败 / 回滚原因）
    std::string libsJson;             // 装完的五本库状态，与 hashstat.libs **同构**
                                      //   （直接内联给调用方，避免 libstat 自己再拼一份）
};

// 原子地"卸 → 换 → 装 → 判定 →（失败则）回滚"，全程持一把写锁。
//
// ★ 为什么必须是**一个**函数而不是"先 Unload 再 Install"两个：
//   分两次加锁的话，中间那一小段**库是全空的**。此刻若实时链正好在查哈希，
//   `HitMalicious` 会记为 `skippedNoDb` —— 而它与"这个文件干净"在返回值上
//   **不可区分**（见本文件开头的警告）。把窗口关在锁内，这种歧义在结构上不存在。
//
// ★ 失败语义：**ok=false 且 rolledBack=true** 表示"新库没能用上，但旧库已复原"
//   （防护没有降级）；`rolledBack=true` 但 `libsJson` 里 `loaded` 全为 false
//   才是真正严重的情况（旧库也装不回来），日志里会明确写出来。
LibInstallResult InstallCloudLibs(const std::vector<LibInstallItem>& items);

// 仅重载（不换文件）：重读 cloud\ 下的五本库并重新验签 + mmap。
// 返回"重载后至少有一本**恶意**库可用" —— 注意这与"重载动作成功执行"不是
// 一回事（库不存在时重载照样成功，只是没有库可装，那是正常状态）。
bool ReloadCloudLibs();

}  // namespace hashshare
}  // namespace sf
