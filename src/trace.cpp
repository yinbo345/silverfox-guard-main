// ===========================================================================
//  trace.cpp — 行为链记录与行为图生成（实现）
//  设计说明见 trace.h。本文件不含任何文件 I/O，纯内存 + JSON 字符串。
// ===========================================================================
// ★ include 顺序有讲究：common.h 的 WriteFramed/ReadFramed 用到 HANDLE，
//   它自己不带 windows.h（其他调用方都是先包含 windows.h 的）。
//   这里必须把 windows.h 放前面，否则报 "HANDLE 未声明的标识符"。
#include <windows.h>

#include "trace.h"
#include "common.h"          // sf::JsonString

#include <mutex>
#include <vector>
#include <deque>
#include <algorithm>

namespace trace {

// ---------------------------------------------------------------------------
//  环形缓冲
// ---------------------------------------------------------------------------
namespace {

struct Node {
    Kind        kind;
    std::string subject;
    std::string detail;
    std::string path;
    std::string token;
    std::string extra;
    int         score;
    bool        handled;
    long long   ts;          // GetTickCount64()（毫秒，单调；不受系统时间回拨影响）
};

std::mutex          g_mtx;
std::deque<Node>    g_buf;      // 定长：超过 kCapacity 从头丢弃（丢弃比拒绝好 —— 旧事件价值低）

// 时间戳格式：行为图横轴用「时:分:秒」即可，日期放 generatedAt 里统一说明。
// 用本地时间（用户视角），不用 UTC。
void FormatHms(long long tickMs, char* out, size_t cap) {
    // GetTickCount64 是开机以来的毫秒数，不是绝对时间。转成绝对时间要用
    // GetSystemTimeAsFileTime 换算：先取"现在"的绝对时间与 tick 的差。
    static long long  baseTick = 0;
    static ULONGLONG  baseFile = 0;
    static bool       inited = false;
    static std::mutex baseMtx;
    if (!inited) {
        std::lock_guard<std::mutex> lk(baseMtx);
        if (!inited) {
            FILETIME ft; GetSystemTimeAsFileTime(&ft);
            baseFile = ((ULONGLONG)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
            baseTick = (long long)GetTickCount64();
            inited = true;
        }
    }
    // 100ns 单位 → 毫秒；FILETIME 起点是 1601，这里只取"当天时分秒"：
    // 先算绝对 FILE TIME，再减到 1970 起点，最后取 秒 % 86400 加时区偏移。
    long long delta = tickMs - baseTick;
    ULONGLONG absFile = (ULONGLONG)((long long)baseFile + delta * 10000LL);
    // 转 UNIX 秒：1601→1970 = 11644473600 秒
    long long unixSec = (long long)(absFile / 10000000ULL) - 11644473600LL;

    // 时区偏移（含夏令时）：用 GetTimeZoneInformation 取当前偏移
    TIME_ZONE_INFORMATION tzi;
    DWORD r = GetTimeZoneInformation(&tzi);
    long long biasMin = tzi.Bias;
    if (r == TIME_ZONE_ID_DAYLIGHT)      biasMin += tzi.DaylightBias;
    else if (r == TIME_ZONE_ID_STANDARD) biasMin += tzi.StandardBias;
    // Bias 的方向是"UTC = 本地 + Bias"，故本地 = UTC - Bias
    unixSec -= biasMin * 60LL;

    long long sod = ((unixSec % 86400LL) + 86400LL) % 86400LL;
    int hh = (int)(sod / 3600), mm = (int)((sod % 3600) / 60), ss = (int)(sod % 60);
    snprintf(out, cap, "%02d:%02d:%02d", hh, mm, ss);
}

std::string NowAbsolute() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char b[32];
    snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(b);
}

// 取快照（持锁时间极短：只做拷贝，不做任何 I/O 与格式化）
std::vector<Node> Snapshot() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return std::vector<Node>(g_buf.begin(), g_buf.end());
}

// Subject 为空时的兜底显示名
std::string SubjectOr(const Node& n, const char* fallback) {
    if (!n.subject.empty()) return n.subject;
    if (!n.path.empty()) {
        std::string bn = sf::BaseName(n.path);
        if (!bn.empty()) return bn;
    }
    return std::string(fallback);
}

}  // namespace

// ---------------------------------------------------------------------------
//  Kind 名称
// ---------------------------------------------------------------------------
const char* KindName(Kind k) {
    switch (k) {
        case Kind::Process:  return "process";
        case Kind::Landed:   return "landed";
        case Kind::RegRun:   return "regrun";
        case Kind::Boot:     return "boot";
        case Kind::Key:      return "key";
        case Kind::Rollback: return "rollback";
        default:             return "unknown";
    }
}

// ---------------------------------------------------------------------------
//  记录
// ---------------------------------------------------------------------------
void Record(const Event& e) {
    if (e.kind == Kind::Unknown) return;
    Node n;
    n.kind    = e.kind;
    n.subject = e.subject;
    n.detail  = e.detail;
    n.path    = e.path;
    n.token   = e.token;
    n.extra   = e.extra;
    n.score   = e.score;
    n.handled = e.handled;
    n.ts      = (long long)GetTickCount64();

    std::lock_guard<std::mutex> lk(g_mtx);
    // 去重：同一路径 + 同一类型在 2 秒内重复命中只记一条。
    // 为什么需要：实时防护对同一进程/同一文件会在极短时间内多次回调
    // （WMI 事件风暴、落地监控的初筛+完整判定两阶段），不去重的话
    // 行为图上会出现一串一模一样的节点，用户以为是多个动作。
    if (!g_buf.empty() && !n.path.empty()) {
        const Node& last = g_buf.back();
        if (last.kind == n.kind && last.path == n.path && (n.ts - last.ts) < 2000) {
            // 保留信息量更大的那条（detail 更长者胜）
            if (n.detail.size() > last.detail.size()) g_buf.back() = n;
            return;
        }
    }
    g_buf.push_back(n);
    while ((int)g_buf.size() > kCapacity) g_buf.pop_front();
}

void Record(Kind kind, const std::string& subject, const std::string& detail,
            const std::string& path, const std::string& token, bool handled, int score) {
    Event e;
    e.kind    = kind;
    e.subject = subject;
    e.detail  = detail;
    e.path    = path;
    e.token   = token;
    e.handled = handled;
    e.score   = score;
    Record(e);
}

void Reset() {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_buf.clear();
}

int Count() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return (int)g_buf.size();
}

// ---------------------------------------------------------------------------
//  推断规则
// ---------------------------------------------------------------------------
//  ★ 设计原则（见 trace.h 铁律二）：只在"证据充分"时生成，最多 2 条。
//  每条规则都是"链条走到第 N 环 → 提示第 N+1 环可能是什么"，不做危害定性。
//
//  参考的银狐行为链（公开分析材料里反复出现的固定形态）：
//    下载(IM/钓鱼页) → 落盘 Temp/下载区 → 建注册表自启 → 拉起
//    →（敲诈分支）批量改写文件 + 落密钥 → 删除密钥索赎金
//    →（持久化分支）改写 MBR 建立开机自举
//  ---------------------------------------------------------------------------
namespace {

struct InferNode {
    std::string kind;        // 推断类型标识（前端据此选图标）
    std::string subject;     // 一句话结论（"载荷可能被执行"）
    std::string detail;      // 为什么这么推断（中文）
    std::vector<int> basis;  // 依据的事实节点下标
    std::string confidence;  // "low" / "mid"
};

void AddInfer(std::vector<InferNode>& out, const char* kind, const char* subject,
              const char* detail, std::vector<int> basis, const char* conf) {
    // 上限：最多 2 条推断。画满推断会让"事实"失去分量。
    if (out.size() >= 2) return;
    // basis 去重 + 升序：多条规则会往同一个下标连边，重复的话前端会画双线。
    std::sort(basis.begin(), basis.end());
    basis.erase(std::unique(basis.begin(), basis.end()), basis.end());
    if (basis.empty()) basis.push_back(0);   // 兜底：至少要有一条依据，否则图上孤立
    InferNode n;
    n.kind = kind; n.subject = subject; n.detail = detail;
    n.basis = basis; n.confidence = conf;
    out.push_back(n);
}

}  // namespace

// ---------------------------------------------------------------------------
//  行为图 JSON
// ---------------------------------------------------------------------------
std::string GraphJson(const std::string& token, long long windowMs) {
    if (windowMs <= 0) windowMs = 10 * 60 * 1000;   // 默认 10 分钟

    std::vector<Node> all = Snapshot();
    long long nowTick = (long long)GetTickCount64();

    // ---- 1. 选取窗口内的节点 ----
    //  基准：有 token 时，以"token 匹配的节点"为焦点，取它前后 windowMs 内的事件；
    //  无 token 时取最近 windowMs 内的事件。
    int focusIdx = -1;   // all 里的下标
    if (!token.empty()) {
        for (int i = (int)all.size() - 1; i >= 0; --i) {
            if (all[i].token == token) { focusIdx = i; break; }
        }
    }
    long long refTick = (focusIdx >= 0) ? all[focusIdx].ts : nowTick;

    std::vector<int> picked;   // all 里的下标
    for (int i = 0; i < (int)all.size(); ++i) {
        long long d = refTick - all[i].ts;
        // 焦点事件之前：允许 windowMs 的回溯；之后：只取 2 秒内（同一批次的后续事件）
        if (d >= 0 && d <= windowMs) picked.push_back(i);
        else if (d < 0 && -d <= 2000) picked.push_back(i);
    }
    // 空窗口兜底：取最后 20 条（用户点开按钮时总得有东西看）
    if (picked.empty()) {
        int from = (int)all.size() > 20 ? (int)all.size() - 20 : 0;
        for (int i = from; i < (int)all.size(); ++i) picked.push_back(i);
    }

    // ---- 2. 按时间排序 + 计算焦点在新数组里的位置 ----
    std::sort(picked.begin(), picked.end(),
              [&](int a, int b) { return all[a].ts < all[b].ts; });

    int focusNew = -1;
    for (int i = 0; i < (int)picked.size(); ++i)
        if (picked[i] == focusIdx) { focusNew = i; break; }

    // ---- 3. 事实节点 ----
    //  同一进程/文件反复命中会合并成一条链上的连续节点，前端按 kind 上色。
    struct Fact { const Node* n; std::string at; };
    std::vector<Fact> facts;
    facts.reserve(picked.size());
    for (int idx : picked) {
        char hms[16] = {0};
        FormatHms(all[idx].ts, hms, sizeof(hms));
        Fact f; f.n = &all[idx]; f.at = hms;
        facts.push_back(f);
    }

    // ---- 4. 推断分支 ----
    //  统计窗口内出现过哪些类型（"证据充分"的判据）
    bool hasLanded = false, hasRegRun = false, hasProc = false, hasBoot = false,
         hasKey = false, hasRollback = false;
    int  lastLanded = -1, lastRegRun = -1, lastProc = -1;
    int  landedCount = 0, regrunCount = 0, keyCount = 0;
    for (int i = 0; i < (int)facts.size(); ++i) {
        switch (facts[i].n->kind) {
            case Kind::Landed:   hasLanded = true;   ++landedCount; lastLanded = i; break;
            case Kind::RegRun:   hasRegRun = true;   ++regrunCount; lastRegRun = i; break;
            case Kind::Process:  hasProc = true;     lastProc = i; break;
            case Kind::Boot:     hasBoot = true;     break;
            case Kind::Key:      hasKey = true;      ++keyCount; break;
            case Kind::Rollback: hasRollback = true; break;
            default: break;
        }
    }

    std::vector<InferNode> infers;

    // 规则 A：落地载荷 + 自启动 都出现 → 推断"下一步会被拉起执行"
    //   依据：银狐链条里"落盘"与"自启"是两个独立事实时，几乎必然跟着执行。
    //   但如果已经有 Process 事实，说明已经执行过了（下一步不是"可能"而是"已发生"），
    //   此时不再推断 —— 这是"不给用户看没有的东西"的具体落地。
    if (landedCount >= 1 && regrunCount >= 1 && !hasProc) {
        std::vector<int> basis;
        if (lastLanded >= 0) basis.push_back(lastLanded);
        if (lastRegRun >= 0) basis.push_back(lastRegRun);
        AddInfer(infers, "exec",
                 "载荷可能被执行",
                 "已捕获落地文件并发现它被登记进自启动项 —— 这是银狐链条里"
                 "「先落盘、再持久化」的固定两步，下一步通常是拉起该载荷。"
                 "若你并未主动运行过它，建议先不要重启、等待主防处置。",
                 basis, "mid");
    }

    // 规则 B：已有落地/进程事实 + 出现批量改写（Key）→ 推断"加密未完成，可能继续"
    //   依据：密钥截获是"加密已发生"的直接证据。此时告知用户"可能仍在进行"，
    //   促使其配合回滚，而不是看到一张卡就以为完事了。
    if (hasKey && (hasLanded || hasProc)) {
        std::vector<int> basis;
        for (int i = (int)facts.size() - 1; i >= 0; --i) {
            if (facts[i].n->kind == Kind::Key) { basis.push_back(i); break; }
        }
        if (lastProc >= 0) basis.push_back(lastProc);
        basis.push_back(0);   // 链条起点：最早的落地/进程事实
        AddInfer(infers, "encrypt",                 "加密可能仍在继续",
                 "已捕获疑似勒索密钥，说明批量改写动作确实发生过。"
                 "回滚只还原了有快照的文件；无快照的文件不可恢复（诚实上报）。"
                 "若本机仍有可疑进程在跑，建议立即断开网络并联系取证。",
                 basis, "mid");
    }

    // 规则 C：自启动项 + 无进程事实 → 推断"下次开机可能复活"
    //   仅在既没有落地也没有进程事实时才画（否则 A 规则已经覆盖了这个意思）。
    if (regrunCount >= 1 && !hasProc && !hasLanded && !hasBoot) {
        std::vector<int> basis;
        basis.push_back(lastRegRun >= 0 ? lastRegRun : 0);
        AddInfer(infers, "persist",
                 "开机后可能自动复活",
                 "该自启动项已被移除，但指向的载荷本体若仍在磁盘上，"
                 "攻击者可能再次登记。建议在重建系统前保留隔离区样本用于取证。",
                 basis, "low");
    }

    // ---- 5. 组装 JSON ----
    std::string js = "{";
    js += "\"ok\":true";
    js += ",\"generatedAt\":" + sf::JsonString(NowAbsolute());
    js += ",\"windowMs\":" + std::to_string((long long)windowMs);
    js += ",\"focus\":" + std::to_string(focusNew);

    int nFact  = (int)facts.size();
    int nInfer = (int)infers.size();
    js += ",\"summary\":{\"total\":" + std::to_string(nFact + nInfer)
        + ",\"fact\":" + std::to_string(nFact)
        + ",\"infer\":" + std::to_string(nInfer) + ",\"sources\":[";
    {
        // sources：窗口内出现过的类型去重列表（按固定顺序，便于前端稳定渲染）
        const Kind order[] = { Kind::Process, Kind::Landed, Kind::RegRun,
                               Kind::Boot, Kind::Key, Kind::Rollback };
        bool first = true;
        for (Kind k : order) {
            bool has = false;
            for (const auto& f : facts) if (f.n->kind == k) { has = true; break; }
            if (!has) continue;
            if (!first) js += ",";
            first = false;
            js += sf::JsonString(KindName(k));
        }
    }
    js += "]}";

    // ---- nodes ----
    js += ",\"nodes\":[";
    for (int i = 0; i < nFact; ++i) {
        const Node* n = facts[i].n;
        if (i) js += ",";
        js += "{\"i\":" + std::to_string(i);
        js += ",\"type\":\"fact\"";
        js += ",\"kind\":" + sf::JsonString(KindName(n->kind));
        js += ",\"subject\":" + sf::JsonString(SubjectOr(*n, "未知对象"));
        js += ",\"detail\":" + sf::JsonString(n->detail);
        js += ",\"path\":" + sf::JsonString(n->path);
        js += ",\"at\":" + sf::JsonString(facts[i].at);
        js += ",\"ts\":" + std::to_string(n->ts);
        js += ",\"handled\":" + std::string(n->handled ? "true" : "false");
        js += ",\"token\":" + sf::JsonString(n->token);
        js += ",\"score\":" + std::to_string(n->score);
        js += ",\"extra\":" + sf::JsonString(n->extra);
        js += "}";
    }
    for (int k = 0; k < nInfer; ++k) {
        int i = nFact + k;
        const InferNode& inf = infers[k];
        // ★ 逗号必须由"是否已有元素"决定，不能交给循环下标 i 判断 ——
        //   事实节点为空时 nFact=0，第一条推断节点 i 也等于 0，
        //   于是漏掉分隔逗号，输出 `…}{"i":…` 这种非法 JSON（曾真实发生）。
        if (nFact + k > 0) js += ",";
        js += "{\"i\":" + std::to_string(i);
        js += ",\"type\":\"infer\"";
        js += ",\"kind\":" + sf::JsonString(inf.kind);
        js += ",\"subject\":" + sf::JsonString(inf.subject);
        js += ",\"detail\":" + sf::JsonString(inf.detail);
        js += ",\"path\":\"\"";
        js += ",\"at\":\"\"";
        js += ",\"ts\":0";
        js += ",\"handled\":false";
        js += ",\"token\":\"\"";
        js += ",\"score\":0";
        js += ",\"extra\":\"\"";
        js += ",\"confidence\":" + sf::JsonString(inf.confidence);
        js += ",\"basis\":[";
        for (size_t b = 0; b < inf.basis.size(); ++b) {
            if (b) js += ",";
            js += std::to_string(inf.basis[b]);
        }
        js += "]}";
    }
    js += "]";

    // ---- edges ----
    //  事实之间用 "fact" 边串成时间链（0→1→2…）；推断用 "infer" 边连到依据节点。
    js += ",\"edges\":[";
    bool firstEdge = true;
    for (int i = 1; i < nFact; ++i) {
        if (!firstEdge) js += ",";
        firstEdge = false;
        js += "{\"from\":" + std::to_string(i - 1) + ",\"to\":" + std::to_string(i) +
              ",\"type\":\"fact\"}";
    }
    for (int k = 0; k < nInfer; ++k) {
        const InferNode& inf = infers[k];
        for (int b : inf.basis) {
            // basis 是"新增数组内的下标"，可能因 facts 数量少于预期而越界，做一次保护
            if (b < 0 || b >= nFact) b = 0;
            if (!firstEdge) js += ",";
            firstEdge = false;
            js += "{\"from\":" + std::to_string(b) + ",\"to\":" +
                  std::to_string(nFact + k) + ",\"type\":\"infer\"}";
        }
    }
    js += "]";

    js += "}";
    return js;
}

// ---------------------------------------------------------------------------
//  最近事实紧凑列表（GUI 用）
// ---------------------------------------------------------------------------
std::string RecentJson(int maxItems) {
    if (maxItems <= 0) maxItems = 50;
    std::vector<Node> all = Snapshot();

    std::string js = "{\"count\":" + std::to_string((int)all.size()) + ",\"items\":[";
    int start = (int)all.size() > maxItems ? (int)all.size() - maxItems : 0;
    bool first = true;
    for (int i = start; i < (int)all.size(); ++i) {
        const Node& n = all[i];
        // 倒序输出（最新在前）—— 用户打开面板时最想看刚发生的事
        if (!first) js += ",";
        first = false;
        char hms[16] = {0};
        FormatHms(n.ts, hms, sizeof(hms));
        js += "{\"kind\":" + sf::JsonString(KindName(n.kind));
        js += ",\"subject\":" + sf::JsonString(SubjectOr(n, "未知对象"));
        js += ",\"detail\":" + sf::JsonString(n.detail);
        js += ",\"at\":" + sf::JsonString(hms);
        js += ",\"handled\":" + std::string(n.handled ? "true" : "false");
        js += "}";
    }
    js += "]}";
    return js;
}

}  // namespace trace
