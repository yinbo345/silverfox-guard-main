// mod_keys.cpp — 分体：勒索密钥截获的查看与清理
//
// 迁移自 service.cpp 的管道 if-else 链（keylist / keyread / keyclear / keydir）。
// 实现逻辑逐字保留（包括 keyclear 的语义说明），仅去掉 continue 与缩进。
//
// 本分体**无独立线程** —— 密钥的实际截获由回滚引擎（rollback.cpp）在写监视路径上完成，
// 这里只是把已捕获的结果暴露给 UI/维护者。
#include "module.h"

#include "common.h"     // WriteFramed / JsonString / JsonGetInt
#include "rollback.h"   // rb::ListCapturedKeysJson / ReadCapturedKeyHex / ClearCapturedKeys ...

#include <string>

namespace {

bool CmdKeyList(HANDLE h, const std::string& /*req*/) {
    // 用户/维护者可查看已捕获的疑似勒索密钥，并导出内容做解密或取证。
    sf::WriteFramed(h, "{\"cmd\":\"keylist\",\"ok\":true,\"data\":" +
                   sf::rb::ListCapturedKeysJson() + "}");
    return true;
}

bool CmdKeyRead(HANDLE h, const std::string& req) {
    // index 缺省为 0（最近捕获的那份往往就是当前攻击用的密钥）
    int idx = sf::JsonGetInt(req, "index");
    if (idx < 0) idx = 0;
    sf::WriteFramed(h, "{\"cmd\":\"keyread\",\"ok\":true,\"data\":" +
                   sf::rb::ReadCapturedKeyHex((size_t)idx) + "}");
    return true;
}

bool CmdKeyClear(HANDLE h, const std::string& req) {
    // ------------------------------------------------------------------
    //  ⚠️ 2026-09-19 语义变更（务必理解后再改前端）
    //
    //  默认**不删已确认的密钥**，只清"从未时序关联成立"的误报候选。
    //  原因：副本一旦删除，磁盘上再无第二份 —— 密钥原件早被勒索者删了。
    //  误报期顺手点一次清空，真中招时那批里可能就有真密钥，却已经没了。
    //
    //  要真删全部，前端必须传 force=1（UI 需二次确认弹窗）。
    // ------------------------------------------------------------------
    if (sf::JsonGetInt(req, "force") == 1) {
        sf::rb::ClearCapturedKeysForce();
        sf::WriteFramed(h, "{\"cmd\":\"keyclear\",\"ok\":true,\"forced\":true}");
    } else {
        sf::rb::ClearCapturedKeys();
        sf::WriteFramed(h, "{\"cmd\":\"keyclear\",\"ok\":true,\"forced\":false}");
    }
    return true;
}

bool CmdKeyDir(HANDLE h, const std::string& /*req*/) {
    // 密钥留存目录（UI 展示"密钥在哪"，方便用户手动备份该目录）
    sf::WriteFramed(h, "{\"cmd\":\"keydir\",\"ok\":true,\"dir\":" +
                   sf::JsonString(sf::rb::KeyDir()) + "}");
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "keylist",  CmdKeyList  },
    { "keyread",  CmdKeyRead  },
    { "keyclear", CmdKeyClear },
    { "keydir",   CmdKeyDir   },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_keys = {
    "keys",
    nullptr,        // Init
    nullptr,        // Run（无线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
