// mod_sandbox.cpp — 沙箱分体（主干式架构）
//
// 管道命令：
//   sandboxstat  —— 沙箱环境是否就绪 + 累计统计 + 队列状态 + 最近一次报告（含落地物明细）
//   sandboxscan  —— 送检一个文件（{path, dryrun?, wait?}），**异步**：
//                   立刻回 accepted，结果稍后由 sandboxstat 取，或直接看界面卡片。
//
// ★ 为什么必须异步：一次分析要跑几十秒（等样本在沙箱里跑完 + 观察窗口）。
//   管道是 100ms 级交互通道，同步做会把整个界面卡住，还会让扩展侧的
//   请求超时误判成"服务掉线"。所以命令只入队，实际分析交给本分体的 Run 线程。
//
// ★ 为什么 dryrun 不是"测试专用玩具"：沙箱服务（SbieSvc）未就绪时送检会失败，
//   但"快照 → diff → 评分"这条链本身可以独立验证——它才是本模块的判定核心。
//   dryrun 让这条链可以在没有沙箱的机器上跑通并验收。
//
// ===========================================================================
//  ★★ 2026-09-27 重构：队列搬进 sandbox.cpp，本文件回归"薄管道层"
// ===========================================================================
//  【为什么搬】
//    原来队列（g_queue / g_cv / g_lastWait）与消费循环都锁在本文件的匿名
//    namespace 里，外部（service.cpp 的判定链）**一个字都碰不到**。后果是
//    设计意图断了：
//        sandbox.h 写的「静态初筛判拿不准的样本 → 送进沙箱跑一遍」
//    只能靠**人手**通过 sandboxscan 触发，判定链无法把样本丢进来，
//    也无法把结果拿回去做处置（隔离 / 记 finding / 记行为链）。
//
//  【搬成什么样】
//    队列 + 消费循环体 + 结果回调 → sandbox.cpp（对外契约在 sandbox.h），
//    与 packscan 完全同型：packscan 也是"自己的队列 + 自己的 sink"，
//    由 service.cpp 在装配期 SetSink 接上处置能力。
//
//  【线程归属为什么不一起搬】
//    框架的 RunThreadGuarded 给分体线程提供 SEH + 异常双层兜底。把线程挪到
//    sandbox.cpp 里裸起 std::thread 会**丢掉这层兜底**（消费循环里一次未捕获
//    的访问违例就能把整个服务带走）。所以：
//        线程归分体框架（本文件 Run = ConsumePendingLoop）
//        队列与循环体归 sandbox.cpp
//    两边各拿自己该拿的：框架拿兜底，模块拿能力。
//
//  【顺带修掉的隐患】
//    g_lastWait 原本是**全局单值**：队列里排多个 job 时，每个 job 取的都是
//    "最后一次请求的 wait" → 串味（A 请求 300 秒、B 请求 10 秒、B 先跑，
//    结果是 B 用 300 秒、A 用 10 秒）。现在 waitSec 随 job 一起入队，
//    每个任务只用自己的那份。
#include "module.h"
#include "common.h"    // WriteFramed / JsonGetString / JsonGetInt / LogDbg
#include "sandbox.h"
#include "sfstop.h"

#include <string>

namespace {

// ---------------------------------------------------------------------------
//  sandboxstat
// ---------------------------------------------------------------------------
bool CmdSandboxStat(HANDLE h, const std::string& req) {
    std::string j = "{\"cmd\":\"sandboxstat\",\"ok\":true,\"data\":{";
    j += "\"cfg\":"    + sf::sandbox::ConfigJson();
    j += ",\"stats\":" + sf::sandbox::StatsJson();
    j += ",\"last\":"  + sf::sandbox::LastReportJson();
    // ★ 队列状态（2026-09-27）：顶层 queued 保留（旧调用方可能在读），
    //   另给一个 queue 对象承载完整字段（含 dropped —— 丢弃必须可见，
    //   "队列满了所以没扫"绝不能被静默吞掉）。
    j += ",\"queued\":" + std::to_string(sf::sandbox::QueueDepth());
    j += ",\"queue\":"  + sf::sandbox::QueueStatsJson();
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------------------
//  sandboxscan（入队后立刻返回）
// ---------------------------------------------------------------------------
bool CmdSandboxScan(HANDLE h, const std::string& req) {
    const std::string path = sf::JsonGetString(req, "path");
    const bool dryrun = (sf::JsonGetInt(req, "dryrun") != 0);
    const int  wait   = sf::JsonGetInt(req, "wait");

    if (path.empty()) {
        sf::WriteFramed(h, "{\"cmd\":\"sandboxscan\",\"ok\":false,\"msg\":\"path required\"}");
        return true;
    }
    // 路径存在性在这里先查一次：让"文件不存在"这种低级错误**立刻**反馈，
    // 而不是让用户等几十秒后才从结果卡里看到。
    {
        DWORD a = GetFileAttributesA(path.c_str());
        if (a == INVALID_FILE_ATTRIBUTES) {
            sf::WriteFramed(h, std::string("{\"cmd\":\"sandboxscan\",\"ok\":false,\"msg\":\"file not found\"}") );
            return true;
        }
    }

    // ★ 人工送检刻意 **不去重**（dedup=false）：这是用户/命令行显式要求
    //   "再看一次"，不能被上一次的结论挡住 —— 否则界面会变成
    //   "点了没反应"（半通故障：请求被受理了，但队列静默丢弃）。
    //   自动送检走的是另一条路（service.cpp），那边必须去重。
    sf::sandbox::EnqueueScan(path, dryrun, wait, /*dedup=*/false);
    const size_t qsize = (size_t)sf::sandbox::QueueDepth();

    std::string j = "{\"cmd\":\"sandboxscan\",\"ok\":true,\"accepted\":true,\"dryrun\":";
    j += (dryrun ? "true" : "false");
    j += ",\"queued\":" + std::to_string(qsize);
    j += ",\"path\":" + sf::JsonString(path) + "}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------------------
//  Run —— 消费队列
// ---------------------------------------------------------------------------
// 队列本身与消费循环体都在 sandbox.cpp（见 sandbox.h 的「异步送检队列」段）。
// 本函数只把两者接起来 —— 目的是让线程继续由分体框架托管（双层兜底 + 停止时 join）。
void RunWorker() {
    sf::sandbox::ConsumePendingLoop();
}

const sf::mod::CmdEntry kCmds[] = {
    { "sandboxstat", CmdSandboxStat },
    { "sandboxscan", CmdSandboxScan },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_sandbox = {
    "sandbox",      // 分体名（日志用）
    nullptr,        // Init（环境探测放在首次使用时做，避免启动期拖慢）
    RunWorker,      // Run（消费送检队列，循环体在 sandbox.cpp）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
