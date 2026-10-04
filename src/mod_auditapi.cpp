// mod_auditapi.cpp — 分体：跨进程注入/内存加载事件的统计与最近事件查询
//
// 与 mod_iowatch.cpp 完全同理：采集线程由 service.cpp 装配（auditapi 归 service 层
// 持有），本文件只把状态与最近事件暴露成管道命令，供银泊"不翻日志"即可回答：
//   ① auditapistat  —— 订上了没有、采到多少、丢了多少、是否健康
//   ② auditapiq     —— 具体采到的是些什么事件（source→target→access）
//   ③ auditapiclear —— 观察前先归零环形缓冲
#include "module.h"

#include "common.h"    // WriteFramed / JsonString / JsonGetInt
#include "auditapi.h"  // GetStats / Recent / IsRunning / SessionName / PushRecent / ApiOp
#include "behavior.h"  // ImagePathOfPid（查询时按需补全映像名，见下方注释）

#include <cstdio>
#include <string>
#include <vector>

namespace {

const char* OpName(sf::auditapi::ApiOp op) {
    switch (op) {
        case sf::auditapi::ApiOp::SetContextThread:  return "SetContextThread";
        case sf::auditapi::ApiOp::OpenProcess:       return "OpenProcess";
        case sf::auditapi::ApiOp::OpenThread:        return "OpenThread";
        case sf::auditapi::ApiOp::TerminateProcess:  return "TerminateProcess";
        case sf::auditapi::ApiOp::LoadImageCallback: return "LoadImageCb";
        case sf::auditapi::ApiOp::CreateSymlink:     return "CreateSymlink";
        default:                                    return "unknown";
    }
}

bool CmdAuditApiStat(HANDLE h, const std::string& /*req*/) {
    sf::auditapi::Stats s = sf::auditapi::GetStats();
    std::string j = "{\"cmd\":\"auditapistat\",\"ok\":true,\"data\":{";
    j += "\"running\":"      + std::string(sf::auditapi::IsRunning() ? "true" : "false");
    j += ",\"session\":"     + sf::JsonString(sf::auditapi::SessionName());
    j += ",\"received\":"    + std::to_string(s.received);
    j += ",\"delivered\":"   + std::to_string(s.delivered);
    j += ",\"dropped\":"     + std::to_string(s.dropped);
    j += ",\"parseFail\":"   + std::to_string(s.parseFail);
    j += ",\"lastEventMs\":" + std::to_string(s.lastEventMs);
    j += ",\"healthy\":"     + std::string(sf::auditapi::IsHealthy() ? "true" : "false");
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

bool CmdAuditApiQ(HANDLE h, const std::string& req) {
    int n = sf::JsonGetInt(req, "n");
    if (n <= 0 || n > 200) n = 50;

    std::vector<sf::auditapi::ApiEvent> evs = sf::auditapi::Recent((size_t)n);
    std::string j = "{\"cmd\":\"auditapiq\",\"ok\":true,\"data\":{\"count\":";
    j += std::to_string(evs.size());
    j += ",\"events\":[";
    for (size_t i = 0; i < evs.size(); ++i) {
        const sf::auditapi::ApiEvent& e = evs[i];
        if (i) j += ',';
        j += "{\"op\":\""; j += OpName(e.op); j += "\"";
        // ★ 2026-10-02 补：eid 是原始事件号（op 由它映射而来）；
        //   hasAccess/hasRet 用于区分「掩码真的是 0」与「压根没解析到」——
        //   只看数字会把两者混为一谈，而判定分支全靠掩码位。
        //   accessHex 直接给十六进制：位运算看十进制太容易出错。
        j += ",\"eid\":"   + std::to_string(e.eid);
        j += ",\"srcPid\":" + std::to_string(e.srcPid);
        j += ",\"tgtPid\":" + std::to_string(e.tgtPid);
        j += ",\"tgtTid\":" + std::to_string(e.tgtTid);
        j += ",\"access\":" + std::to_string(e.desiredAccess);
        j += ",\"accessHex\":\"";
        {
            char hb[16];
            snprintf(hb, sizeof(hb), "0x%08X", (unsigned)e.desiredAccess);
            j += hb;
        }
        j += "\"";
        j += ",\"hasAccess\":" + std::string(e.hasAccess ? "true" : "false");
        j += ",\"ret\":"    + std::to_string(e.returnCode);
        j += ",\"hasRet\":"  + std::string(e.hasRet ? "true" : "false");
        j += ",\"atMs\":"   + std::to_string(e.atMs);
        // ★ 2026-10-02：采集侧（auditapi.cpp ConsumerLoop）已**停止对全部事件**查映像名
        //   ——那会让"每消费一条 OpenProcess 事件就自己再开两次进程"形成自我放大
        //   （实测 5min OpenProcess=171 万条）。这里改成**查询时按需补全**：
        //   一次 auditapiq 最多 200 条 → 最多 200 次 OpenProcess(0x1000)，
        //   由人工触发、不在热路径上，不构成反馈环。
        //   掩码 0x1000 不含任何注入位，故这些补全调用本身永远不会触发注入告警。
        std::string srcImg = e.srcImage;
        if (srcImg.empty() && e.srcPid) srcImg = sf::ImagePathOfPid((unsigned long)e.srcPid);
        std::string tgtImg = e.tgtImage;
        if (tgtImg.empty() && e.tgtPid) tgtImg = sf::ImagePathOfPid((unsigned long)e.tgtPid);
        j += ",\"src\":"    + sf::JsonString(sf::BaseName(srcImg));
        j += ",\"tgt\":"    + sf::JsonString(sf::BaseName(tgtImg));
        j += '}';
    }
    j += "]}}";
    sf::WriteFramed(h, j);
    return true;
}

bool CmdAuditApiClear(HANDLE h, const std::string& /*req*/) {
    sf::auditapi::ClearRecent();
    sf::WriteFramed(h, "{\"cmd\":\"auditapiclear\",\"ok\":true}");
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "auditapistat",  CmdAuditApiStat  },
    { "auditapiq",     CmdAuditApiQ     },
    { "auditapiclear", CmdAuditApiClear },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_auditapi = {
    "auditapi",
    nullptr,        // Init（采集线程由 service 层装配）
    nullptr,        // Run（不持有线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
