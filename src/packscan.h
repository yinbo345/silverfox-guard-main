// packscan.h — 压缩包落地深度检测（2026-09-22）
//
// ===========================================================================
//  这个模块补的是什么缺口（定位务必看准，否则会做错方向）
// ===========================================================================
//  **不是**补解包能力 —— probe.cpp 早已具备完整的递归解包 + 逐层内容判定：
//      · IsArchiveExt      : 21 种归档格式（zip/rar/7z/iso/cab/msix …）
//      · IsDubiousPayloadExt: 23 种载荷格式（exe/dll/sys/hta/wsf/lnk …）
//      · 解包后对「载荷 或 归档」递归扫描 → 嵌套 zip 会被继续解开并做内容判定
//      · 深度上限 5 层、累计解压 2GB 预算（防解压炸弹）
//
//  缺的是**触发**：这套能力过去只在用户右键「单文件查杀」时被调用。
//  压缩包**落到磁盘**那一刻，落地捕获（LandedAlertWatch）不认归档扩展名
//  —— 它只判 PE 头与脚本，`.zip` 直接被忽略。于是「下载了一个恶意压缩包」
//  这件事在实时防护里是完全静默的，要等用户自己想起来去右键查杀。
//
//  本模块把这条断链接上：落地捕获发现归档 → 入队 → 本模块的消费者线程
//  异步调 ScanTargetFile → 命中则经回调交回服务层处置（隔离归档本体）。
//
// ===========================================================================
//  为什么必须异步（不能就地同步扫）
// ===========================================================================
//  解包要几秒（大包更久）并产生大量磁盘 I/O。落地捕获是 5 秒轮询的实时路径，
//  在它内部同步扫包会**阻塞后续所有落地事件**的处理 —— 攻击者只要往监视目录
//  连续丢几个大压缩包，就能把实时防护拖死（这是可被利用的 DoS 面）。
//  所以：入队即返回，扫描在独立线程串行进行。
//
//  ⚠️ 队列满时**丢弃最旧**（保新不保全）：新落地的包更可能是当前攻击链的一环，
//     而旧包早已过期。丢弃会计入 dropped 计数并记日志，不静默。
#pragma once

#include <string>

namespace sf {
namespace packscan {

// 命中回调：在 packscan 的**消费者线程**上调用。
// ⚠️ 实现方可以做隔离等重活（它不在实时路径上），但**不要在这里再入队**
//    （会造成队列自锁）。
//   level >= 2 才回调（level 1 只记日志，不打扰用户 —— 压缩包里有个可疑文件
//   就弹卡会非常吵，而压缩包本身常是正常的安装包）。
using HitSink = void (*)(const std::string& archivePath, int level,
                         const std::string& title, const std::string& detail);

// 该扩展名是否为受支持的归档格式（供落地捕获预筛，避免把无关文件入队）。
bool IsArchiveExt(const std::string& path);

// 入队一个落地的归档路径。**不阻塞、不扫描**，立即返回。
// 重复入队同一路径会被去重（同一文件多次落地事件只扫一次）。
void Enqueue(const std::string& archivePath);

// 设置命中回调（在 Start 之前调用）。
void SetSink(HitSink sink);

// 启动消费者线程。返回 false = 已在运行（幂等）。
bool Start();
void Stop();
bool IsRunning();

// 状态（供 GUI「落地检测」面板与自检命令）
struct Stats {
    unsigned long long queued    = 0;   // 累计入队
    unsigned long long scanned   = 0;   // 累计完成扫描
    unsigned long long hits      = 0;   // 累计命中（level>=2）
    unsigned long long dropped   = 0;   // 队列满丢弃数
    unsigned long long lastMs    = 0;   // 最近一次扫描完成时间（单调毫秒）
    unsigned long long scannedBytes = 0;// 累计扫描的归档体积
};
Stats GetStats();

// 待处理队列快照（JSON 数组，供 GUI 显示"正在检查哪些包"）
std::string PendingJson();
// 最近命中记录（JSON，供 GUI 列表与行为图）
std::string RecentHitsJson();

}  // namespace packscan
}  // namespace sf
