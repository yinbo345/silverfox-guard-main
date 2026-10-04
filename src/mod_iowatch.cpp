// mod_iowatch.cpp — 分体：文件/注册表事件采集的状态与最近事件查询
//
// ===========================================================================
//  定位（与 mod_packscan 完全同理）
// ===========================================================================
//  采集线程由 service.cpp 装配（与 netwatch / etwproc 一致 —— 采集层归
//  service 层持有，分体只暴露管道命令）。所以本文件**不持有线程**，
//  只把 iowatch 的状态与最近事件暴露成命令。
//
//  为什么需要它：iowatch 是本产品唯一一路「量可能很大」的事件源，
//  上线后银泊需要能**不翻日志**就回答两个问题：
//    ① 到底订上了没有、采到了多少、丢了多少？（iowatchstat）
//    ② 具体采到的是些什么事件？（iowatchq）
//  没有这两条命令，"订阅补全成功没有"就只能靠猜 —— 而这正是本次要消灭的问题。
#include "module.h"

#include "common.h"    // WriteFramed / JsonString / JsonGetInt
#include "iowatch.h"   // GetStats / Recent / IsRunning / SessionName

#include <string>
#include <vector>

namespace {

const char* KindName(sf::iowatch::Kind k) {
    switch (k) {
        case sf::iowatch::Kind::Created: return "created";
        case sf::iowatch::Kind::Renamed: return "renamed";
        case sf::iowatch::Kind::Deleted: return "deleted";
        // EID 12「打开/创建」：只做遥测，不是落地事件（2026-10-02 误报事故修复）
        case sf::iowatch::Kind::Opened:  return "opened";
        default:                         return "unknown";
    }
}

// kind 的判定依据：让上层知道这条结论有多硬
//   eid     → 由事件 ID 直接判定（硬依据）
//   keyword → 由 keyword 位判定（硬依据）
//   name    → EID 10/11 的"名字建立/移除"通知（软依据：改名需配对才能确认）
const char* KindSrcName(sf::iowatch::KindSrc s) {
    switch (s) {
        case sf::iowatch::KindSrc::ByEid:        return "eid";
        case sf::iowatch::KindSrc::ByKeyword:    return "keyword";
        case sf::iowatch::KindSrc::ByNameNotify: return "name";
        default:                                 return "none";
    }
}

bool CmdIoWatchStat(HANDLE h, const std::string& /*req*/) {
    sf::iowatch::Stats s = sf::iowatch::GetStats();
    std::string j = "{\"cmd\":\"iowatchstat\",\"ok\":true,\"data\":{";
    j += "\"running\":"      + std::string(sf::iowatch::IsRunning() ? "true" : "false");
    j += ",\"session\":"     + sf::JsonString(sf::iowatch::SessionName());
    j += ",\"receivedFile\":"+ std::to_string(s.receivedFile);
    j += ",\"receivedReg\":" + std::to_string(s.receivedReg);
    j += ",\"delivered\":"   + std::to_string(s.delivered);
    j += ",\"dropped\":"     + std::to_string(s.dropped);
    j += ",\"parseFail\":"   + std::to_string(s.parseFail);
    j += ",\"noPathField\":" + std::to_string(s.noPathField);
    j += ",\"filteredSelf\":"+ std::to_string(s.filteredSelf);
    j += ",\"filteredNoise\":"+std::to_string(s.filteredNoise);
    j += ",\"deduped\":"     + std::to_string(s.deduped);
    j += ",\"lastEventMs\":" + std::to_string(s.lastEventMs);
    j += ",\"healthy\":"     + std::string(sf::iowatch::IsHealthy() ? "true" : "false");
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

bool CmdIoWatchQ(HANDLE h, const std::string& req) {
    int n = sf::JsonGetInt(req, "n");
    if (n <= 0 || n > 200) n = 50;

    std::vector<sf::iowatch::IoEvent> evs = sf::iowatch::Recent((size_t)n);
    std::string j = "{\"cmd\":\"iowatchq\",\"ok\":true,\"data\":{\"count\":";
    j += std::to_string(evs.size());
    j += ",\"events\":[";
    for (size_t i = 0; i < evs.size(); ++i) {
        const sf::iowatch::IoEvent& e = evs[i];
        if (i) j += ',';
        j += "{\"kind\":\"";
        j += KindName(e.kind);
        j += "\",\"kindSrc\":\"";
        j += KindSrcName(e.kindSrc);
        j += "\",\"registry\":";
        j += (e.registry ? "true" : "false");
        j += ",\"pid\":"   + std::to_string(e.pid);
        j += ",\"tid\":"   + std::to_string(e.tid);
        j += ",\"eid\":"   + std::to_string((unsigned)e.eid);
        j += ",\"atMs\":"  + std::to_string(e.atMs);
        j += ",\"proc\":"  + sf::JsonString(e.procName);
        j += ",\"path\":"  + sf::JsonString(e.path);
        if (!e.valueName.empty()) j += ",\"value\":" + sf::JsonString(e.valueName);
        if (e.createOptions)      j += ",\"createOptions\":" + std::to_string(e.createOptions);
        if (e.infoClass)          j += ",\"infoClass\":"     + std::to_string(e.infoClass);
        j += '}';
    }
    j += "]}}";
    sf::WriteFramed(h, j);
    return true;
}

// 清空最近事件缓冲（方便"开始观察之前先归零"）
bool CmdIoWatchClear(HANDLE h, const std::string& /*req*/) {
    sf::iowatch::ClearRecent();
    sf::WriteFramed(h, "{\"cmd\":\"iowatchclear\",\"ok\":true}");
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "iowatchstat",  CmdIoWatchStat  },
    { "iowatchq",     CmdIoWatchQ     },
    { "iowatchclear", CmdIoWatchClear },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_iowatch = {
    "iowatch",
    nullptr,        // Init（采集线程由 service 层装配，见文件头说明）
    nullptr,        // Run（不持有线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
