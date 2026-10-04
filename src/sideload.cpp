// sideload.cpp — DLL 劫持 / 侧加载检测实现（契约见 sideload.h）
//
// 设计取舍记录（改动前请先读）：
//   · 判据严格优先。本模块的**误报代价极高** —— 它直接驱动隔离动作，
//     而隔离一个正常软件的同目录 DLL 会让该软件直接无法启动。
//     所以「不确定」时一律返回 None，宁可漏报。
//   · 只对**同目录真的存在**的 DLL 做签名校验。一个正常 exe 的导入表有
//     几十个 DLL，若逐个 WinVerifyTrust 会白白付出几十次磁盘+密码学开销，
//     而其中绝大多数目录里根本没有副本。
#include "sideload.h"

#include "common.h"      // BaseName / DirName / FileExists / LogDbg
#include "probe.h"       // ImportedDlls
#include "behavior.h"    // FileIsSigned
#include "sfutils.h"     // ExtLower

#include <windows.h>

#include <algorithm>
#include <string>
#include <vector>

namespace sf {
namespace sideload {

// ---------------------------------------------------------------------------
//  攻击者高频盗用的系统 / 第三方 DLL 名（小写）
//
//  这份清单的两个用途（都只是"加权"，不能单独定罪）：
//    ① 同目录存在同名副本时提高可疑度（尤其 System32 也有同名的情况）
//    ② 日志与卡片里能说清"为什么挑这个名字" —— 便于人工复核
//
//  ⚠️ 清单里的名字**单独出现不构成问题**：正常软件同目录带一份有签名的
//     同厂商 DLL 是完全正常的。错的是"无签名副本"。
// ---------------------------------------------------------------------------
static const char* kHijackTargets[] = {
    // —— Windows 系统 DLL（不在 KnownDLLs 列表里，可被同目录劫持）——
    "version.dll", "winmm.dll", "dwmapi.dll", "uxtheme.dll", "cryptbase.dll",
    "dbghelp.dll", "secur32.dll", "profapi.dll", "propsys.dll", "mpr.dll",
    "netapi32.dll", "authz.dll", "bcrypt.dll", "wtsapi32.dll", "cryptdll.dll",
    "rasapi32.dll", "samcli.dll", "sensapi.dll", "setupapi.dll", "pdh.dll",
    "wldap32.dll", "msimg32.dll", "comctl32.dll", "msvcrt.dll",
    // —— 图形/游戏相关（游戏启动器场景高发）——
    "d3d9.dll", "d3dx9_43.dll", "dinput8.dll", "dsound.dll", "xinput1_3.dll",
    // —— 第三方组件（白加黑最爱的"看起来合理"的名字）——
    "libcurl.dll", "libssl.dll", "sqlite3.dll", "zlib1.dll", "nss3.dll",
    "mozglue.dll", "freetype.dll", "libxml2.dll", "ssleay32.dll", "libeay32.dll",
    "python27.dll", "python38.dll", "ffmpeg.dll", "avcodec-58.dll",
};

bool IsCommonHijackTarget(const std::string& lowerDllName) {
    for (const char* t : kHijackTargets)
        if (lowerDllName == t) return true;
    return false;
}

// ---------------------------------------------------------------------------
//  落地高发区判定
//  与 scanner.cpp 的 InSuspLoc 同为"可疑位置"概念，但这里是**本模块私有的窄口径**：
//  只列"正常软件的组件绝不会被安装到此"的位置。特意**不含** Program Files ——
//  那是正常软件的安装地，同目录带无签名私有 DLL 在那里很常见。
// ---------------------------------------------------------------------------
static bool InLandedZone(const std::string& lowerFullPath) {
    static const char* kZones[] = {
        "\\temp\\", "\\tmp\\", "\\downloads\\", "\\desktop\\",
        "\\appdata\\local\\temp\\", "\\programdata\\", "\\users\\public\\",
        "\\favorites\\", "\\documents\\",
    };
    for (const char* z : kZones)
        if (lowerFullPath.find(z) != std::string::npos) return true;
    // 盘根（C:\xxx.dll 这种直接躺在根目录的）
    if (lowerFullPath.size() > 3 && lowerFullPath[1] == ':' &&
        lowerFullPath[2] == '\\' &&
        lowerFullPath.find('\\', 3) == std::string::npos) return true;
    return false;
}

static std::string ToLowerAscii(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return o;
}

// ---------------------------------------------------------------------------
//  主检测
// ---------------------------------------------------------------------------
std::vector<Finding> Find(const std::string& exePath) {
    std::vector<Finding> out;
    if (exePath.empty()) return out;
    if (!FileExists(exePath)) return out;

    // 1) 导入表 → 这个 exe 会加载哪些 DLL
    std::vector<std::string> dlls;
    if (!sf::ImportedDlls(exePath, dlls) || dlls.empty()) return out;

    const std::string dir = DirName(exePath);
    if (dir.empty()) return out;

    // 2) System32 路径（用来判"是否有同名系统 DLL"）
    char sysDir[MAX_PATH] = {0};
    UINT n = GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string sysLower;
    if (n > 0 && n < MAX_PATH) {
        sysLower = ToLowerAscii(std::string(sysDir));
        if (!sysLower.empty() && sysLower.back() != '\\') sysLower.push_back('\\');
    }

    for (const std::string& dll : dlls) {
        if (dll.empty()) continue;

        // ★ 前置条件：同目录必须真的存在这个 DLL。
        //   这一条排除了绝大多数情况（正常 exe 的导入项都由 System32 提供）。
        std::string cand = dir;
        if (!cand.empty() && cand.back() != '\\') cand.push_back('\\');
        cand += dll;
        if (!FileExists(cand)) continue;

        // 同目录有副本 → 校验它是否有有效签名。
        // 有签名 = 正常软件携带的私有/同厂商组件，直接放过（这是最主要的降误报手段）。
        std::string signer;
        if (FileIsSigned(cand, &signer)) continue;

        // 无签名副本 —— 进入分档判定
        Finding f;
        f.dllPath = cand;
        f.dllName = dll;
        f.hostExe = BaseName(exePath);
        f.level   = (int)Level::None;
        f.reason.clear();

        // System32 里是否有同名？（有 = 系统本就提供，此处副本属多余 → 劫持）
        bool sysHasIt = false;
        if (!sysLower.empty()) {
            std::string sp = sysLower + dll;
            // SysWOW64 也要看：32 位程序会从那里加载
            if (FileExists(sp)) sysHasIt = true;
            else {
                char wow[MAX_PATH] = {0};
                UINT m = GetSystemWow64DirectoryA(wow, MAX_PATH);
                if (m > 0 && m < MAX_PATH) {
                    std::string w = ToLowerAscii(std::string(wow));
                    if (!w.empty() && w.back() != '\\') w.push_back('\\');
                    if (FileExists(w + dll)) sysHasIt = true;
                }
            }
        }

        const bool landed = InLandedZone(ToLowerAscii(cand));
        const bool known  = IsCommonHijackTarget(dll);

        // ⚠️ 2026-10-02 事故记录（改动本段前必读）
        //   在 System32 里的系统 exe 上，本段会出现「自指」：被测 exe 在 System32
        //   → dir = System32 → 它导入的 uxtheme.dll / esent.dll 也解析到 System32，
        //   于是 cand 与下面判定的「系统同名 DLL」**是同一个文件**。
        //   当 FileIsSigned 又把这类「只有目录签名（.cat）」的微软系统 DLL 误判成
        //   「无签名」时，二者叠加 → 判「档2 铁证：侧加载劫持」。日志实证：
        //     [sideload] 铁证 dll=…\uxtheme.dll  host=msra.exe
        //     [sideload] 铁证 …esent.dll          host=TieringEngineService.exe
        //
        //   根因已修在 FileIsSigned（补目录签名回退），**本段刻意不改**：
        //   若在这里加一句「cand 落在系统目录就跳过」，会连「System32 里的 DLL 被
        //   替换成恶意版本」这类真实攻击一起放过 —— 而 sysHasIt 这条分支正是为它准备的。
        //   所以修根因、不修表象；此处仅作记录，避免后人重复踩同一个坑。
        if (sysHasIt) {
            // 档 2 铁证：系统已提供同名 DLL，同目录却有无签名副本
            f.level = (int)Level::Hijack;
            f.reason = "「" + f.hostExe + "」所在目录存在无签名的 " + dll +
                       "，而系统目录已提供同名 DLL —— 典型侧加载劫持（白加黑）";
        } else if (landed) {
            // 档 1 可疑：无签名副本落在落地高发区
            f.level = (int)Level::Suspected;
            f.reason = "「" + f.hostExe + "」所在目录（落地高发区）存在无签名的 " + dll +
                       "，不符合任何正常软件的发行方式";
        } else if (known) {
            // 名字在易劫持清单里，但 System32 无同名、也不在高发区。
            // ★ 这里刻意**不报** —— 属于"绿色软件自带组件"的形态，报了就是误报。
            //   保留这个分支是为了让判定逻辑完整可读（而不是漏掉一种组合）。
            continue;
        } else {
            continue;
        }

        LogDbg("[sideload] " + std::string(f.level >= 2 ? "铁证" : "可疑") +
               " dll=" + f.dllPath + " host=" + f.hostExe +
               (known ? "（名字属高频劫持目标）" : ""));
        out.push_back(f);
    }

    return out;
}

std::string Describe(const std::vector<Finding>& fs) {
    if (fs.empty()) return std::string();
    std::string s;
    for (size_t i = 0; i < fs.size(); ++i) {
        if (i) s += "；";
        s += fs[i].reason;
    }
    return s;
}

}  // namespace sideload
}  // namespace sf
