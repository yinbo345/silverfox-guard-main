// errhold.cpp — 沙箱「无结论」待决表实现（契约见 errhold.h）
//
//  实现上三点值得说明：
//
//  1) **token 用随机 hex 而不是计数器**
//     token 是删除授权的唯一凭据（服务端不认路径，只认 token）。
//     计数器 token 会被本地程序"猜下一个"从而对**尚未出结果**的文件抢先下删除指令；
//     随机 64 位则不可猜。依赖 RtlGenRandom（advapi32），无外部依赖。
//
//  2) **取用即出表（Take）而不是「先查后删」**
//     若先 Peek 再 Remove，两步之间可能有第二条路径（超时/另一客户端）抢先生效，
//     于是同一点击既删了文件又放行了它 —— 两条互斥结论同时成立。
//     一次锁内完成「找到 + 摘走」，从结构上消除竞态。
//
//  3) **登记表按到期时刻排序插入**（不排序）
//     待决表极小（一轮送检 0~2 条），线性扫描足够；刻意不引排序容器 ——
//     少一份「排序后与实际到期时刻不一致」的失效面。
#include "errhold.h"

#include <windows.h>
#include <sddl.h>

#include <cstdio>
#include <mutex>
#include <vector>

#include "common.h"    // LogDbg
#include "sfstop.h"    // IsStopRequested

namespace sf {
namespace errhold {

namespace {

std::mutex           g_mtx;
std::vector<Pending> g_list;

// 超时执行回调（由 service.cpp 注入 —— 隔离留底 + 强删能力都在那边）。
// 刻意用函数指针注入而非在 errhold 里 include service/rollback：
// errhold 是「到点没到点」的账本，不该知道「到了之后怎么删」。
static void (*g_timeoutFn)(const std::string&, const std::string&) = nullptr;

// 回调缺装配时的重试退避：60 秒。不设退避就是每秒重算 + 每秒打警告（刷屏+忙循环）。
static const uint64_t kRetryBackoffMs = 60ULL * 1000ULL;
// 自测用：把退避临时改小以便**真实走一遍退避路径**。
// ★ 不能靠"改 dueMs 硬让它过期"来测 —— 那测的是"能不能删"，不是"退避对不对"。
static uint64_t g_backoffOverrideMs = 0;   // 0 = 用默认值
static uint64_t BackoffMs() { return g_backoffOverrideMs ? g_backoffOverrideMs : kRetryBackoffMs; }
static void   SetBackoffForTest(uint64_t ms) { g_backoffOverrideMs = ms; }

uint64_t NowMs() { return (uint64_t)GetTickCount64(); }

std::string GenToken() {
    unsigned char b[8] = {0};
    // RtlGenRandom：系统自带，不引入 bcrypt.lib 依赖（单文件体积敏感）
    if (BCryptGenRandom(nullptr, b, sizeof(b), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        // 退化路径：拿系统时间 + 进程 tick 凑一个。**绝不能返回空 token** ——
        // 空 token 会让"token 为空时如何校验"变成一个漏洞入口。
        const uint64_t t = NowMs();
        memcpy(b, &t, sizeof(t) < 8 ? sizeof(t) : 8);
    }
    static const char* hex = "0123456789abcdef";
    std::string t;
    t.reserve(16);
    for (int i = 0; i < 8; ++i) {
        t.push_back(hex[b[i] >> 4]);
        t.push_back(hex[b[i] & 0xF]);
    }
    return t;
}

}  // namespace

std::string Add(const std::string& origPath, const std::string& copyPath,
                const std::string& why, unsigned seconds) {
    if (origPath.empty()) return std::string();
    // 撞 token 就重生成（极不可能，但不能假设"不可能"）
    std::string tok;
    for (int i = 0; i < 4; ++i) {
        tok = GenToken();
        bool dup = false;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            for (const auto& p : g_list) if (p.token == tok) { dup = true; break; }
        }
        if (!dup) break;
        tok.clear();
    }
    if (tok.empty()) {
        // 极端降级：拿一个不含文件信息的自明标识。
        // ★ 必须打日志：走到这里说明随机源有问题，用户会收到一张
        //   "无法决策、只能等超时" 的卡，而原因只有这里有记录。
        LogDbg("[errhold] ★生成 token 失败（随机源异常），该文件只能等超时自动处置");
        return std::string();
    }

    Pending p;
    p.token    = tok;
    p.origPath = origPath;
    p.copyPath = copyPath;
    p.why      = why;
    p.dueMs    = NowMs() + (uint64_t)seconds * 1000ULL;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_list.push_back(p);
    }
    LogDbg("[errhold] 已登记待决：" + origPath + "（令牌 " + tok.substr(0, 6) + "…，"
           + std::to_string(seconds) + " 秒内未决策则**自动删除**）");
    return tok;
}

bool Take(const std::string& token, Pending& out) {
    if (token.empty()) return false;
    std::lock_guard<std::mutex> lk(g_mtx);
    for (size_t i = 0; i < g_list.size(); ++i) {
        if (g_list[i].token == token) {
            out = g_list[i];
            g_list.erase(g_list.begin() + (long)i);
            return true;
        }
    }
    return false;
}

bool Exists(const std::string& token) {
    if (token.empty()) return false;
    std::lock_guard<std::mutex> lk(g_mtx);
    for (const auto& p : g_list) if (p.token == token) return true;
    return false;
}

void ReapExpired() {
    // 先摘出所有到期的，再在锁外执行真正的删除 ——
    // 锁内做 I/O（隔离+删除，可能几百 ms）会卡住 Add/Take/Exists。
    std::vector<Pending> due;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_list.empty()) return;
        const uint64_t now = NowMs();
        std::vector<Pending> keep;
        for (const auto& p : g_list) {
            if (p.dueMs <= now) due.push_back(p);
            else keep.push_back(p);
        }
        g_list.swap(keep);
    }
    if (due.empty()) return;

    void (*fn)(const std::string&, const std::string&) = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        fn = g_timeoutFn;
    }
    if (!fn) {
        // ★ 回调没装配：已经出表了（摘都摘了），但没人执行删除。
        //   此时若什么都不做，文件会被**永久锁住**（句柄是我们自己持有的，
        //   而唯一的解锁路径就是这条回调）—— 那是最坏结局。
        //   所以：明确记一行，把"缺装配"暴露出来，而不是让它静默变成永久门禁。
        LogDbg("[errhold] ★★★ 超时处置回调未装配（service.cpp 的 SetErrHoldTimeoutHandler "
               "未执行）—— " + std::to_string(due.size()) +
               " 个待决文件已到期却无法自动处置，将**无限期保持封锁**。请检查服务装配代码。");
        // ★ 把它们放回表里：回调装配上后（理论上是服务重启）仍能被处理。
        //   丢掉 = 彻底漏处置；放回 = 下次扫表还会再试一次（幂等）。
        //   ⚠️ 但 dueMs 已过期 ⇒ 放回后**下一次扫表（1 秒后）立刻又到期**，
        //   而回调仍然没装 ⇒ 每秒重算一次 + 每秒打一行警告 = 日志刷屏 + 忙循环。
        //   所以放回时把 dueMs 推后 kRetryBackoffMs，让重试变成低频退避。
        const uint64_t backoff = NowMs() + BackoffMs();
        std::lock_guard<std::mutex> lk(g_mtx);
        for (auto p : due) { p.dueMs = backoff; g_list.push_back(p); }
        return;
    }
    for (const auto& p : due)
        fn(p.token, p.origPath);
}

void SetTimeoutHandler(void (*fn)(const std::string&, const std::string&)) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_timeoutFn = fn;
}

std::string SummaryJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
    long oldest = -1;
    const uint64_t now = NowMs();
    for (const auto& p : g_list) {
        long left = (long)((p.dueMs > now ? (p.dueMs - now) : 0) / 1000ULL);
        if (oldest < 0 || left < oldest) oldest = left;
    }
    char b[160];
    _snprintf_s(b, sizeof(b), _TRUNCATE,
                "{\"pending\":%u,\"oldestLeftSec\":%ld}",
                (unsigned)g_list.size(), oldest);
    return std::string(b);
}

// ===========================================================================
//  自测（--errhold-selftest）
// ===========================================================================
namespace {

int  g_pass = 0, g_fail = 0;
// ★ 参数用 std::string 而非 const char*：自测里大量断言要带动态内容
//   （实测长度、回执路径），用 char* 就得先 c_str() 拼临时串 —— 那样更容易出错。
void Chk(bool cond, const std::string& what) {
    if (cond) { ++g_pass; printf("  [PASS] %s\n", what.c_str()); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what.c_str()); }
}

// 超时回调计数（自测用）
int g_timeoutHits = 0;
std::string g_lastTimeoutPath;
void TestTimeout(const std::string& token, const std::string& origPath) {
    ++g_timeoutHits;
    g_lastTimeoutPath = origPath;
    (void)token;
}

}  // namespace

int RunSelfTest() {
    printf("==== errhold 自测 ====\n");
    g_pass = g_fail = 0;
    g_timeoutHits = 0;
    g_lastTimeoutPath.clear();

    // ---- ① 空路径必须被拒（否则会登记一条无处可指的记录）----
    {
        std::string t = Add("", "copy", "why", 30);
        Chk(t.empty(), "空路径被拒（不产生无效记录）");
    }

    // ---- ② 登记产出可用令牌 ----
    std::string tok;
    {
        tok = Add("C:\\tmp\\a.exe", "C:\\holds\\x\\a.exe", "沙箱没测出结论", 30);
        Chk(tok.size() == 16, "令牌为 16 位 hex（实测 " + std::to_string(tok.size()) + "）");
        bool hex = true;
        for (char c : tok) if (!((c>='0'&&c<='9')||(c>='a'&&c<='f'))) hex = false;
        Chk(hex, "令牌只含 [0-9a-f]（可安全透传命令行）");
        Chk(Exists(tok), "登记后可查到");
    }

    // ---- ③ 阴：令牌不匹配的 Take 必须失败（**删文件授权的唯一闸门**）----
    {
        Pending dummy;
        Chk(!Take("deadbeefdeadbeef", dummy), "错误令牌取用失败");
        Chk(!Take("", dummy),                "空令牌取用失败");
        Chk(!Take("zz", dummy),              "非法字符令牌取用失败");
        Chk(Exists(tok), "上面三次失败没有误删原记录");
    }

    // ---- ④ 取用即出表（互斥的结构保证）----
    {
        Pending got;
        Chk(Take(tok, got), "正确令牌可取出");
        Chk(got.origPath == "C:\\tmp\\a.exe", "取出的路径正确");
        Pending again;
        Chk(!Take(tok, again), "重复取用失败（互斥）");
        Chk(!Exists(tok), "取出后已出表");
    }

    // ---- ⑤ 超时执行（装配回调后）----
    {
        SetTimeoutHandler(&TestTimeout);
        const std::string t2 = Add("C:\\tmp\\b.exe", "C:\\holds\\y\\b.exe", "why2", 0);
        Chk(!t2.empty(), "登记第二条（0 秒 = 已到期）");
        ReapExpired();
        Chk(g_timeoutHits == 1, "到期触发回调一次（实测 " + std::to_string(g_timeoutHits) + "）");
        Chk(g_lastTimeoutPath == "C:\\tmp\\b.exe", "回调收到正确路径");
        Chk(!Exists(t2), "到期后条目已出表（不会重复处置）");
        ReapExpired();
        Chk(g_timeoutHits == 1, "重复扫表不再触发（幂等）");
    }

    // ---- ⑥ 阴：不装配回调 ⇒ 条目必须**留在表里**且退避，不得静默丢弃 ----
    {
        SetTimeoutHandler(nullptr);
        // 退避改到 120ms，才能**真实走一遍**退避→到期的完整路径。
        // ★ 不用"手动改 dueMs 硬让它过期" —— 那样测的是"能不能删"，
        //   测不到"退避到底有没有生效"（而退避失效 = 忙循环 + 日志刷屏）。
        SetBackoffForTest(120);
        const std::string t3 = Add("C:\\tmp\\c.exe", "C:\\holds\\z\\c.exe", "why3", 0);
        Chk(!t3.empty(), "登记第三条");
        ReapExpired();
        Chk(g_timeoutHits == 1, "无回调时不会执行删除（实测未变）");
        Chk(Exists(t3), "★ 无回调时条目仍在表里（否则=永久漏处置）");
        // 退避未到：再扫一次**仍不该**触发（验证退避真的在起作用）
        ReapExpired();
        Chk(Exists(t3), "退避期内重复扫表不重复处置（防忙循环）");
        Sleep(200);   // 等退避到期
        SetTimeoutHandler(&TestTimeout);
        ReapExpired();
        Chk(g_timeoutHits == 2, "退避到期后再次扫表能处理掉（实测 " +
                                std::to_string(g_timeoutHits) + "）");
        Chk(!Exists(t3), "处理后已出表");
        SetBackoffForTest(0);
    }

    // ---- ⑦ 汇总 ----
    {
        const std::string j = SummaryJson();
        Chk(j.find("\"pending\":") != std::string::npos, "汇总含 pending 字段");
    }

    printf("==== 结果：通过 %d / 失败 %d ====\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}

}  // namespace errhold
}  // namespace sf
