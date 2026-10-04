// libsig.h — 病毒库文件（*.sfh）ECDSA P-256 签名/验签的**唯一实现入口**
//
// ===========================================================================
//  【解决了什么问题】
// ===========================================================================
//  病毒库（malicious.sfh / trusted.sfh / malicious_imp.sfh）此前是一批**裸文件**：
//  谁能往 C:\ProgramData\SilverFoxGuard\cloud\ 里写，谁就能决定本机的判定结果。
//  两道现实威胁，都**不会有任何运行时症状**：
//
//    · **放权**：攻击者把一个哈希从恶意库里删掉 / 换成 trusted.sfh 里的白名单，
//      本机立刻对那个样本"视而不见"，而界面上写着"病毒库正常，N 条"。
//    · **栽赃**：往 trusted 库塞假条目无所谓（只会更严），但往恶意库里塞一堆
//      良性哈希 = 把杀软变成误报机器 —— 用户会自己把防护关掉。
//
//  签名把"库文件内容"与"我们签发的私钥"绑死：没有私钥就改不动库，
//  哪怕能完全控制那个目录。
//
// ===========================================================================
//  【★ 三条不可动摇的约定（改任何一条都等于让已发布的库全部失效）】
// ===========================================================================
//  ① **签名对象 = 域分离字符串，不是库文件字节**
//
//         msg = "SFH1-SIG-V1" "\n" <keyId> "\n" <libSha256(64 位小写 hex)>
//
//     为什么签"哈希的文本"而不是"文件字节"：文件可能几十 MB，签字节要求
//     验签方也先把整个文件读进内存；签 64 字节文本则只需要边读边算 SHA-256
//     （哈希本身是流式的，内存恒定）。**安全性没有损失** —— SHA-256 的碰撞
//     抗性就是这个方案的全部前提，换个说法就是"我们信任 SHA-256"。
//
//     为什么要有前缀 `SFH1-SIG-V1` 和 keyId：这是**域分离**。没有它，
//     同一条签名在"签的是一个 .sfh"和"签的是别的东西"之间可以互相搬运
//     （只要那个东西的 SHA-256 恰好也写在同一段文本里）。前缀把用途钉死，
//     keyId 把"用哪把钥匙"钉死 —— 后者还让密钥轮换成为可能（见 ③）。
//     先例：pehash.h 的 `ImphashKey` 用 `"imphash:"` 前缀，注释里写着
//     "前缀是格式的一部分"。这里是同一件事。
//
//  ② **签名编码 = 裸 r||s（各 32 字节大端），不是 DER/ASN.1**
//
//     CNG 的 `BCryptSignHash` 对 ECDSA 输出的就是 64 字节裸串，而
//     `BCryptVerifySignature` 要的也是同一形态。用裸串意味着验签路径上
//     **一行 ASN.1 解析代码都不需要**。
//
//     ★ 这不是图省事 —— 解析器本身就是攻击面。pehash.cpp 文件头引了 LIEF
//       的两条专门防护注释（"Bounds the import thunk loop to prevent hangs
//       on malformed IATs"），说的就是"恶意输入喂给解析器"这件事。DER 的
//      长度字段是攻击者完全可控的，一个手写 ASN.1 解析器是典型的越界读温床。
//       而我们**根本不需要*DER：签名双方都是我们自己，没有互操作需求。
//
//     ⚠️ 副作用（必须记住）：**OpenSSL / Python cryptography 不能直接验这个
//        签名**，它们的 `verify()` 收的是 DER。要把签名交给外部工具核对，
//        得先做 `r||s` → DER 的转换（SEQUENCE{ INTEGER r, INTEGER s }，
//        每项若最高位为 1 需前置 0x00）。本项目自己的工具链两边都是 CNG，
//        不涉及转换；这条只影响"用 openssl 手验"的临时排查场景。
//
//  ③ **keyId 是签名的一部分，且公钥表支持多把钥匙**
//
//     密钥轮换（私钥疑似泄露、或换机器）时，老库是**已经发出去**的。
//     若只支持单把公钥，换钥匙那一刻全体老用户的库全部验签失败 → 全部拒绝
//     装载 → 防护直接归零。所以公钥表是**有序多把**：新钥匙签新库，
//     老钥匙留在表里继续认老库，等老库都过期下线后再从表里摘掉。
//
//     表的内容由 `src/sfh_pubkey.h` 提供（**构建期可配置**，见下）。
//
// ===========================================================================
//  【公钥为什么放在独立头文件、而不是写死在 libsig.cpp 里】
// ===========================================================================
//  写死常量的后果是"换钥匙要改源码"—— 那意味着换钥匙得动一个已经跑通、
//  有回归测试的 .cpp。而我们要的是**换钥匙只换一个数据文件**：
//
//    · `src/sfh_pubkey.h` 由工具 `src/tools/libsigkey.cpp genkey` 生成（勿手改）；
//    · `build.sh` 允许用环境变量 `SFH_KEY_ID` / `SFH_PUBKEY_HEX` 在构建期覆盖
//      （传给 cl 的 `-D`）。用途：临时用一个测试钥匙构建一版做端到端演练，
//      **不需要动仓库里的正式公钥**。
//
//  ⚠️ 公钥是公开信息，进 git 没问题；私钥绝不进 git（.gitignore 已覆盖
//     `signing/`、`*.pfx`，本文件对应的私钥另有显式条目）。
//
// ===========================================================================
//  【★ 默认姿态：fail-closed（拒装），且这个默认必须能被看见】
// ===========================================================================
//  没有配置公钥（`SFH_PUBKEY_HEX` 为空）时，`BuiltinKeyCount() == 0`，
//  任何验签都返回 `kNoKeyConfigured`。**政策层（mod_sfdb.cpp）据此拒绝装载库**。
//
//  这是刻意的：一个"没有公钥就放行"的实现，会让"忘了配公钥的构建"
//  在运行时与"一切正常"长得一模一样 —— 属于本项目最贵的一类故障
//  （静默降级 = 零症状假象）。而 fail-closed 的代价是**立刻可见**的：
//  库装载不上、hashstat 显示拒绝原因、日志里有明确一行。
//
//  调试开关（跳过验签）在政策层实现，且**必须"显式打开 + 默认关闭 + 每次
//  跳过都记日志"**，不允许做成"没有签名就自动跳过"。
// ===========================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sf {
namespace libsig {

// ===========================================================================
//  常量（改它们 = 改格式 = 所有已发布库失效）
// ===========================================================================
inline constexpr const char* kDomainPrefix = "SFH1-SIG-V1";  // 域分离前缀，见 ①
inline constexpr const char* kSigFileTag   = "SFH1-SIG-V1";  // .sfh.sig 首行标签
inline constexpr const char* kKeyFileTag   = "SFH1-KEY-V1";  // 私钥文件首行标签
inline constexpr size_t kPubXYBytes = 64;   // P-256 公钥点 X(32)||Y(32)，大端
inline constexpr size_t kPrivBlobBytes = 104;  // BCRYPT_ECCPRIVATE_BLOB: 头(8)+X+Y+d
inline constexpr size_t kSigBytes = 64;     // 裸 r(32)||s(32)，见 ②

// 签名文件后缀：库 `malicious.sfh` 对应 `malicious.sfh.sig`。
// ★ 用"追加"而不是"替换扩展名"（不是 `malicious.sig`）：
//   后者在只知道库名（不知道它是 .sfh 还是别的）的时代码里会算错路径，
//   而"算错路径"的表现是**找不到签名 → 拒装**，症状看起来像"签名文件丢了"。
inline constexpr const char* kSigSuffix = ".sig";

// ===========================================================================
//  十六进制（公开：调用方与工具都要用；两端必须完全一致，所以只此一份）
// ===========================================================================
// 长度必须偶数、字符必须在 [0-9a-fA-F]；任一不满足返回 false 并清空 out。
// **不做"宽松接受"**（不接受 `0x` 前缀、不接受空格分隔、不接受奇数长度补零）：
// 宽松解析是"两个实现看出两个值"的经典来源。
bool HexToBytes(const std::string& hex, std::vector<uint8_t>& out);
std::string BytesToHex(const void* data, size_t len);   // 输出**小写**

// ===========================================================================
//  公钥表（内容来自 src/sfh_pubkey.h，构建期可配置）
// ===========================================================================
struct PubKey {
    std::string keyId;      // 形如 "sfh1-1"
    uint8_t     xy[kPubXYBytes];   // X(32)||Y(32)，大端
};

// 内置公钥数量。**0 = 构建期未配置公钥**，此时一切验签返回 kNoKeyConfigured。
// 这个数字应当被 hashstat / 启动日志打印出来 —— "知不知道自己在用哪把钥匙"
// 是个必须能一眼看到的事实。
size_t BuiltinKeyCount();
const PubKey* BuiltinKeyAt(size_t index);
// 找不到返回 nullptr。**不要**用"返回第一把钥匙"当兜底：那把钥匙可能不是
// 签这个库的那把，兜底只会把一个明确的"不认识的钥匙"变成"签名不对"，
// 让排查方向跑偏。
const PubKey* FindBuiltinKey(const std::string& keyId);
// 供日志显示用：逗号分隔的全部 keyId（无公钥时为 "无"）。
std::string BuiltinKeyIdsText();

// ===========================================================================
//  签名消息（见 ①，格式固定，两端必须完全一致）
// ===========================================================================
// libSha256Hex 必须是 64 位十六进制（大小写都接受，内部小写化）。
// 入参非法返回空串 —— 调用方判空，**不要**拿空串去签（那会签出一个
// "所有非法输入都相同"的签名，正是本文件头警告过的形态）。
std::string BuildMessage(const std::string& keyId, const std::string& libSha256Hex);

// ===========================================================================
//  核心：签 / 验（纯密码学，无文件 I/O，无项目依赖）
// ===========================================================================
// 这两个函数的入参都是"消息的 SHA-256 摘要"或"消息本身"？——**是消息本身**。
// 内部先对 msg 做 SHA-256 再走 ECDSA。这样调用方不可能"忘了先哈希"，
// 也不可能"哈希的算法与验证方不一致"。
bool SignMessage(const std::vector<uint8_t>& privBlob, const PubKey& expectSelf,
                 const std::string& msg, std::string& outSigHex, std::string& outErr);

bool VerifyMessage(const PubKey& key, const std::string& msg,
                   const std::string& sigHex, std::string& outErr);

// ===========================================================================
//  私钥文件（SFH1-KEY-V1，**仅工具端使用**；服务端不解析私钥）
// ===========================================================================
struct KeyFile {
    std::string           keyId;
    std::vector<uint8_t>  privBlob;   // BCRYPT_ECCPRIVATE_BLOB（104 字节）
    uint8_t               pubXY[kPubXYBytes];   // 与 privBlob 同源的公钥点
    bool                  hasPub = false;
    std::string           note;       // 可选，原样保留（生成日期/机器等）
};

// 生成新密钥对。keyId 为空则用 "sfh1-1"。
bool GenerateKeyPair(const std::string& keyId, KeyFile& out, std::string& outErr);

bool ParseKeyFile(const std::string& text, KeyFile& out, std::string& outErr);
std::string FormatKeyFile(const KeyFile& kf);

// 用私钥文件签。内部会**先自验一次**（用同一把钥匙的公钥验刚生成的签名）——
// 一次生成即证明"这把钥匙的签与验都能走通"，而不是等到部署到用户机器上
// 才发现签名根本验不过。多花 1 毫秒，省掉一整轮"发出去才发现"。
bool SignWithKeyFile(const KeyFile& kf, const std::string& libSha256Hex,
                     std::string& outSigHex, std::string& outErr);

// ===========================================================================
//  签名文件（*.sfh.sig，纯文本、可 grep、diff 友好）
// ===========================================================================
// 形如（字段顺序固定）：
//
//     SFH1-SIG-V1
//     keyid=sfh1-1
//     sha256=<64 位小写 hex，被签库文件的整文件 SHA-256>
//     sig=<128 位小写 hex，裸 r||s>
//
// ★ **首行标签钉死了字段集合**：遇到未知字段名一律**拒绝**（不是忽略）。
//   理由：未知字段最可能的来源是"文件被改过"或"某处写了错字"，而一个被
//   静默忽略的字段正是"两端理解不一致却都不报错"的温床。将来真要加字段，
//   就把标签升成 SFH1-SIG-V2 —— V1 的解析器会因为首行不匹配而干净地拒绝，
//   不需要为前向兼容做任何妥协。
//
// ★ `sha256` 在密码学上是**冗余**的（签名已经盖住了它），但保留它有三个用：
//   ① 快速前置检查，不必先建公钥做一次 EC 运算；
//   ② 出错时能说清"签名自称是 X，而磁盘上是 Y"—— 这是"库被换过"与
//      "签名文件张冠李戴"两类完全不同故障的分水岭；
//   ③ 它是**人和工具都能读**的一行，`libcheck` 直接打印它。
struct SigFile {
    std::string keyId;
    std::string libSha256;   // 64 位小写 hex
    std::string sigHex;      // 128 位小写 hex
    std::string note;        // 可选附加注释行（`#` 开头），原样保留
};

bool ParseSigFile(const std::string& text, SigFile& out, std::string& outErr);
std::string FormatSigFile(const SigFile& sf);

// ===========================================================================
//  ★ 顶层入口：验一份库
// ===========================================================================
enum Result {
    kOk = 0,           // 签名有效
    kNoKeyConfigured,  // 构建期未配公钥（= 本文件的 fail-closed 默认姿态）
    kSigMissing,       // 未找到 .sfh.sig（或打不开）
    kSigMalformed,     // 签名文件格式不对
    kUnknownKey,       // keyId 不在内置公钥表里
    kHashMismatch,     // 签名文件里的 sha256 ≠ 库文件实际 sha256
    kBadSignature,     // 密码学验证失败 —— **这条才是"被篡改"**
};

const char* ResultText(Result r);
// 给日志/界面用的一句话（含"该怎么办"），不含路径。
const char* ResultHint(Result r);

// 入参：库的 UTF-8 路径、签名文件 UTF-8 路径、**调用方已算好的**库整文件
// SHA-256（64 位 hex，可用 pehash::FileSha256）。
//
// ★ 为什么 sha256 由调用方传进来，而不是本函数自己算：
//   政策层（mod_sfdb.cpp LoadCloudLocked）**无论如何都要算这个哈希**——
//   它得先知道库的身份才能决定装不装。让它算完再传进来，避免同一份
//   几十 MB 的文件被读两遍；也让本模块保持**零项目依赖**（只用
//   windows.h + bcrypt.h），从而能被工具端直接链接而不牵出一堆 .obj。
//
// ★ 注意 kBadSignature 与 kHashMismatch 是两个不同的结论，日志里不要合并：
//   · kHashMismatch = 签名是**别的内容**的（文件被替换 / 签名文件错配）
//   · kBadSignature = 内容对得上，但签名不成立（私钥被盗用以外的伪造尝试）
Result VerifyLibFile(const std::string& libPathUtf8, const std::string& sigPathUtf8,
                     const std::string& libSha256Hex, std::string& outDetail);

// 由库路径推出签名文件路径（追加 ".sig"，见 kSigSuffix 的说明）。
std::string SigPathFor(const std::string& libPathUtf8);

// ===========================================================================
//  观测
// ===========================================================================
//  「一个数字如果没人能反驳它，它就不是校验，只是日志。」（同 pehash.h）
//  每类结局分开计 —— 把它们混成一个 failed 数字，
//  "用户在用什么钥匙"和"有东西在改库"就分不出来了。
struct Stats {
    long long ok           = 0;   // 验签通过
    long long noKey        = 0;   // 未配公钥（构建期问题，不是攻击）
    long long sigMissing   = 0;   // 没有 .sig
    long long sigMalformed = 0;   // 格式不对
    long long unknownKey   = 0;   // 不认识的 keyId（钥匙轮换过？）
    long long hashMismatch = 0;   // ★ 库内容与签名不符
    long long badSig       = 0;   // ★ 密码学验证失败
    long long ioFail       = 0;   // 读签名文件失败（瞬时，与"没有"不同）
    long long signedCount  = 0;   // 工具端：本进程签过几次
};
Stats GetStats();
void  ResetStats();
void  BumpSigned();   // 工具端每签一份调一次（工具与会话外用法无法自动统计）

}  // namespace libsig
}  // namespace sf
