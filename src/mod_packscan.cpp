// mod_packscan.cpp — 分体：压缩包落地检测的状态查询
//
// ===========================================================================
//  这个文件是「主干式架构」的一个示范：加一条命令只改一个文件 + 清单一行
// ===========================================================================
//  它只提供**只读查询**，不持有线程 —— 压缩包检测的实际扫描线程由
//  packscan.cpp 在 service 层启动（原因见 service.cpp 里 OnPackHit 的注释：
//  它依赖服务层的隔离/清除内部能力，不满足"可独立 Init/Run/Stop"的分体判据）。
//
//  所以这里的定位是：**把服务层的一个状态暴露成命令**。
//  这仍然值得做成独立文件 —— 而不是塞回 service.cpp 的 360 行 if-else 链里。
#include "module.h"

#include "common.h"     // WriteFramed
#include "packscan.h"   // GetStats / PendingJson / RecentHitsJson / IsRunning

#include <string>

namespace {

bool CmdPackStat(HANDLE h, const std::string& /*req*/) {
    // 一次返回全部状态：运行态 + 计数 + 待检队列 + 最近命中。
    // 计数全部来自 atomic，读它们不会与扫描线程争锁。
    sf::packscan::Stats s = sf::packscan::GetStats();
    std::string j = "{\"cmd\":\"packstat\",\"ok\":true,\"data\":{";
    j += "\"running\":" + std::string(sf::packscan::IsRunning() ? "true" : "false");
    j += ",\"queued\":"   + std::to_string(s.queued);
    j += ",\"scanned\":"  + std::to_string(s.scanned);
    j += ",\"hits\":"     + std::to_string(s.hits);
    j += ",\"dropped\":"  + std::to_string(s.dropped);
    j += ",\"lastMs\":"   + std::to_string(s.lastMs);
    j += ",\"pending\":"  + sf::packscan::PendingJson();
    j += ",\"recent\":"   + sf::packscan::RecentHitsJson();
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "packstat", CmdPackStat },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_packscan = {
    "packscan",
    nullptr,        // Init（扫描线程由 service 层装配）
    nullptr,        // Run（见文件头说明：不持有线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
