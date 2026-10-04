// resultstore.cpp — 扫描结果写入契约的实现（契约见 resultstore.h）
//
// 本文件把 service.cpp 里重复了 4 遍的写样板收敛成三个函数，
// 并把「风险只升不降」这一不变式固化在实现里（而非依赖调用方自觉）。
#include "resultstore.h"
#include "sfutils.h"    // NowStr

namespace sf {

// 大小写不敏感的 path 判等：统一走 sfutils，避免各写一份导致判等失败。
static bool SameKeyCi(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y) return false;
    }
    return true;
}

bool AddFinding(const Finding& f) {
    std::lock_guard<std::mutex> lk(g_resultMutex);

    // 去重键：优先 path（同一文件只留一条），path 为空时退化为 title。
    // ⚠️ 这条退化规则很重要：非文件类发现（注册表项、计划任务、Defender 状态）
    //    path 恒为空，若不做 title 去重，每次巡检都会追加一条重复记录，
    //    几小时后扩展面板里就会堆出上百条同样的「注册表自启动」。
    bool dup = false;
    for (const auto& e : g_result.findings) {
        if (!f.path.empty()) {
            if (!e.path.empty() && SameKeyCi(e.path, f.path)) { dup = true; break; }
        } else {
            if (e.path.empty() && SameKeyCi(e.title, f.title)) { dup = true; break; }
        }
    }
    if (dup) return false;

    g_result.findings.push_back(f);
    g_result.timestamp = NowStr();
    return true;
}

bool AddFinding(const std::string& category, const std::string& severity,
                const std::string& title,    const std::string& detail,
                const std::string& path,     const std::string& ioc,
                int weight) {
    Finding f;
    f.category = category;
    f.severity = severity;
    f.title    = title;
    f.detail   = detail;
    f.path     = path;
    f.ioc      = ioc;
    f.weight   = weight;
    return AddFinding(f);
}

void EscalateInfected(int minScore) {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    g_result.status = "infected";
    // 「只升不降」：当前分已高于 minScore 时**保持原值**。
    // 历史 bug：某处写成 g_result.score = 200，把上一轮累计的 260 分改小，
    // 导致扩展面板的风险分莫名其妙回落 —— 这里从结构上杜绝。
    if (g_result.score < minScore) g_result.score = minScore;
    g_result.timestamp = NowStr();
}

ScanResult Snapshot() {
    std::lock_guard<std::mutex> lk(g_resultMutex);
    return g_result;   // 持锁深拷贝后立刻释放，调用方拿到的副本可自由使用
}

}  // namespace sf
