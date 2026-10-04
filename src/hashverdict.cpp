// hashverdict.cpp — 病毒库点查实现（唯一实现，见 hashverdict.h 的说明）
//
// 2026-09-27：从 service.cpp 的 static HashDbVerdict 原样搬出，做成公共实现。
//   搬运时**逻辑一行未改**（只把函数名换成 MaliciousVerdict），
//   目的是让沙箱模块与实时判定链共用同一判据，避免口径漂移。
//   service.cpp 的两处调用已改为 sf::hashverdict::MaliciousVerdict。
#include "hashverdict.h"

#include "pehash.h"
#include "hashshare.h"

namespace sf {
namespace hashverdict {

int MaliciousVerdict(const std::string& path, std::string* outWhy) {
    if (outWhy) outWhy->clear();

    // ① 整文件 SHA-256（精准哈希）
    std::string sha;
    if (sf::pehash::FileSha256Cached(path, sha, nullptr)) {
        std::string why;
        if (sf::hashshare::HitMalicious(sf::hashshare::kAlgoSha256, sha, &why)) {
            if (outWhy) *outWhy = why + "，整文件 SHA-256 " + sha.substr(0, 16) + "…";
            return 2;
        }
    }

    // ② imphash（派生哈希，等值语义）
    //    ★ 只在对**文件本身**判定时用。非 PE 会在读头部后立刻返回 false，
    //      不构成开销；而它救的正是"同一 loader 换壳"这一类。
    std::string imp;
    if (sf::pehash::ImphashCached(path, imp)) {
        const std::string key = sf::pehash::ImphashKey(imp);
        if (!key.empty()) {
            std::string why;
            if (sf::hashshare::HitMalicious(sf::hashshare::kAlgoImphash, key, &why)) {
                if (outWhy) *outWhy = why + "，导入表 imphash " + imp.substr(0, 16) + "…";
                return 2;
            }
        }
    }

    // ③ 整文件 MD5（精准哈希）。键空间与 SHA-256 正交，复用同一套 hashdb
    //   （32 字节不透明键），但落在独立的 malicious_md5.sfh，物理隔离避免混用。
    std::string md5;
    if (sf::pehash::FileMd5Cached(path, md5, nullptr)) {
        const std::string md5Key = sf::pehash::Md5Key(md5);
        if (!md5Key.empty()) {
            std::string why;
            if (sf::hashshare::HitMalicious(sf::hashshare::kAlgoMd5, md5Key, &why)) {
                if (outWhy) *outWhy = why + "，整文件 MD5 " + md5.substr(0, 16) + "…";
                return 2;
            }
        }
    }

    // ④ 整文件 SHA-1（精准哈希，同上）。
    std::string sha1;
    if (sf::pehash::FileSha1Cached(path, sha1, nullptr)) {
        const std::string sha1Key = sf::pehash::Sha1Key(sha1);
        if (!sha1Key.empty()) {
            std::string why;
            if (sf::hashshare::HitMalicious(sf::hashshare::kAlgoSha1, sha1Key, &why)) {
                if (outWhy) *outWhy = why + "，整文件 SHA-1 " + sha1.substr(0, 16) + "…";
                return 2;
            }
        }
    }
    return 0;
}

}  // namespace hashverdict
}  // namespace sf
