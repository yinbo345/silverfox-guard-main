// mod_boot.cpp — 分体：MBR 引导扇区防护的状态查询与处置
//
// 迁移自 service.cpp 的管道 if-else 链（bootstatus / bootrestore / bootaccept）。
//
// ⚠️ bootrestore / bootaccept 成功后会清除服务层的"引导告警活跃"标志
//    （g_bootActive）。该标志属于服务层状态（决定弹窗卡是否需要询问用户），
//    分体不直接触碰，改经 sf::ClearBootAlertActive() 显式调用 —— 这样
//    "谁能改这个状态"在代码里是可检索的，而不是靠一个全局变量名到处出现。
#include "module.h"

#include "common.h"     // WriteFramed
#include "bootguard.h"  // boot::StatusJson / Restore / Accept
#include "service.h"    // sf::ClearBootAlertActive

#include <string>

namespace {

bool CmdBootStatus(HANDLE h, const std::string& /*req*/) {
    // 状态查询：弹窗卡的「某某程序」归因回填 + GUI 引导防护面板共用。
    sf::WriteFramed(h, "{\"cmd\":\"bootstatus\",\"ok\":true,\"data\":" + boot::StatusJson() + "}");
    return true;
}

bool CmdBootRestore(HANDLE h, const std::string& /*req*/) {
    // 被动告警卡「恢复引导」：基线写回扇区 0
    bool ok = boot::Restore();
    if (ok) sf::ClearBootAlertActive();
    sf::WriteFramed(h, std::string("{\"cmd\":\"bootrestore\",\"ok\":true,\"report\":{\"ok\":") +
                (ok ? "true" : "false") + ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                (ok ? "引导记录已从基线恢复，磁盘引导代码已还原。"
                    : "恢复失败：写入扇区 0 被拒（可能有磁盘工具占用）。") + "\"}}");
    return true;
}

bool CmdBootAccept(HANDLE h, const std::string& /*req*/) {
    // 被动告警卡「信任此变更」：当前 MBR 重立为基线（磁盘工具合法改引导）
    bool ok = boot::Accept();
    if (ok) sf::ClearBootAlertActive();
    sf::WriteFramed(h, std::string("{\"cmd\":\"bootaccept\",\"ok\":true,\"report\":{\"ok\":") +
                (ok ? "true" : "false") + ",\"restored\":0,\"failed\":0,\"reason\":\"" +
                (ok ? "已信任当前引导记录并重立基线。"
                    : "重立基线失败：读盘或写入 ProgramData 被拒。") + "\"}}");
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "bootstatus",  CmdBootStatus  },
    { "bootrestore", CmdBootRestore },
    { "bootaccept",  CmdBootAccept  },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_boot = {
    "boot",
    nullptr,        // Init（引导防护的初始化仍在 ServiceMain 显式进行：
                    // 它需要 SetStopEvent + SetAlertCallback，属于主干装配范畴）
    nullptr,        // Run（无线程：5 秒级监视线程由 bootguard 内部管理）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
