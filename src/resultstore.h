// resultstore.h — 扫描结果（g_result）的唯一写入契约
//
// 【为什么要有这个文件】
// scan_result 的写入样板在 service.cpp 里逐字重复了 4 遍（行 1118 / 1206 / 1661 / 1758），
// 每遍都是同一套四步：
//     持 g_resultMutex → 遍历 findings 按 path 去重 → push_back → 提状态/提分/打时间戳
// 重复的代价不是啰嗦，是**每处都可能漏掉其中一步**：
//   · 漏掉去重      → 同一文件在扩展面板里出现多条
//   · 漏掉 if(score<200) 保护 → 把已有的 200 分**改小**，告警降级
//   · 漏掉 timestamp → 面板显示的时间停在上一轮
// 这三类 bug 历史上都真实发生过。本文件把它们收敛成三个函数，让"漏"在结构上不可能。
//
// 【「只升不降」是本模块的核心不变式】
// 风险状态与分数只会被抬高，绝不会被降低。降级只允许发生在
// 明确的"上一轮全盘扫描结束、用新一轮完整结果整体替换"路径上（scanner.cpp 内部），
// 不经由本模块。因此 EscalateInfected / AddFinding 都不接受"降低"这一语义。
//
// ⚠️ g_result / g_resultMutex 的定义仍然留在 scanner.h/scanner.cpp
//    （它们是 ScanResult 类型的自然归属），本模块只提供受控的写入口。
#pragma once
#include <string>
#include "scanner.h"   // Finding / ScanResult

namespace sf {

// 追加一条发现。
//   · path 非空 → 按 path 大小写不敏感去重（同一文件只留一条）
//   · path 为空 → 按 title 去重（非文件类发现，如"注册表自启动"）
// 返回 true = 实际新增；false = 判重跳过（调用方可据此避免重复弹窗）。
//
// ⚠️ 本函数**不**修改 status / score。风险抬升必须显式调用 EscalateInfected ——
//    把"记一条发现"和"整体判为感染"这两件事分开，是为了避免
//    「加了一条中危旁证，结果整个环境被标成 infected」这类过度告警。
bool AddFinding(const Finding& f);

// 便捷重载：最常用形态。weight 为风险权重（参见 WeightOf 的取值口径）。
bool AddFinding(const std::string& category, const std::string& severity,
                const std::string& title,    const std::string& detail,
                const std::string& path = std::string(),
                const std::string& ioc  = std::string(),
                int weight = 0);

// 把整体状态抬到至少 infected，分数抬到至少 minScore。
// 内部保证「只升不降」：当前分数已高于 minScore 时保持原值。
void EscalateInfected(int minScore = 200);

// 取一份快照（持锁深拷贝）。
// 供弹窗进程 / HTTP 响应 / 管道回复使用 —— 让调用方**不必**直接碰 g_resultMutex，
// 从而杜绝"调用方持锁去做 I/O"这类会让扫描卡死的写法。
ScanResult Snapshot();

}  // namespace sf
