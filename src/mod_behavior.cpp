// mod_behavior.cpp — 分体：病毒行为图数据
//
// 迁移自 service.cpp 的管道 if-else 链（behaviorgraph / behaviorrecent）。
// 实现逻辑逐字保留，仅去掉 continue 与缩进。
//
// 本分体**无独立线程** —— 行为链数据由各处置路径（进程/落地/自启/引导）在
// 发生时写入 trace:: 缓冲；这里只负责把缓冲读出来给 UI。
#include "module.h"

#include "common.h"   // WriteFramed / JsonGetString / JsonGetInt
#include "trace.h"    // trace::GraphJson / RecentJson

#include <string>

namespace {

bool CmdBehaviorGraph(HANDLE h, const std::string& req) {
    //  弹窗卡上「查看行为图」按钮 → 主进程经管道取图数据 → 独立窗口渲染。
    //  token 可选：卡片把自己那张卡的撤销凭据带上来，服务端据此把图的
    //  焦点定在"这次事件"上（而不是笼统地画最近 10 分钟的所有事）。
    //  token 走 [0-9a-f] 白名单（与 NotifyAnomaly 同一口径）——
    //  管道虽然是本机，但扩展/其他进程也能连，不假设入参可信。
    std::string tok = sf::JsonGetString(req, "token");
    std::string safeTok;
    for (char c : tok) {
        bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (hex && safeTok.size() < 32) safeTok.push_back(c);
    }
    long long winMs = 0;
    int winMin = sf::JsonGetInt(req, "minutes");   // 可选：调用方指定时间窗（分钟）
    if (winMin > 0 && winMin <= 1440) winMs = (long long)winMin * 60 * 1000;
    sf::WriteFramed(h, "{\"cmd\":\"behaviorgraph\",\"ok\":true,\"data\":" +
                trace::GraphJson(safeTok, winMs) + "}");
    return true;
}

bool CmdBehaviorRecent(HANDLE h, const std::string& req) {
    // 行为链最近事实（轻量，供主界面小面板）
    int n = sf::JsonGetInt(req, "n");
    if (n <= 0 || n > 200) n = 50;
    sf::WriteFramed(h, "{\"cmd\":\"behaviorrecent\",\"ok\":true,\"data\":" +
                trace::RecentJson(n) + "}");
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "behaviorgraph",  CmdBehaviorGraph  },
    { "behaviorrecent", CmdBehaviorRecent },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_behavior = {
    "behavior",
    nullptr,        // Init
    nullptr,        // Run（无线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
