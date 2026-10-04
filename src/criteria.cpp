// criteria.cpp — 纯判据实现（2026-10-03，C3）
//
//  ★ **本文件是生产代码与回归测试的同一份实现** —— 不是复刻版。
//  抽取理由与设计约束见 criteria.h 顶部。
//
//  ★★ 改动纪律（抽取后新增的真约束）：
//    这三个函数被 criteria_regress.cpp 直接测。改它们之前先跑一遍回归，
//    尤其注意**反例**（不该命中的形态）：今天落地捕获那一处改了四版才做对，
//    每一版都是被反例打回的，不是被 code review 看出来的。
#include "criteria.h"

#include <cstring>

namespace sf {
namespace crit {

// ================================================================
// ① 带词边界的子串匹配
// ================================================================
//  分隔符集合刻意与 behavior.cpp 的 lNoExe 后缀集合保持一致 ——
//  两者不一致会出现「一边认为在词边界、一边不认为」的口径分裂。
bool IsCmdSep(char c) { return c == ' ' || c == '\\' || c == '/'; }

bool HasWord(const std::string& hay, const char* needle) {
    if (needle == nullptr || *needle == '\0') return false;
    const size_t n = strlen(needle);
    if (n == 0 || hay.size() < n) return false;
    size_t from = 0;
    while (from + n <= hay.size()) {
        const size_t p = hay.find(needle, from);
        if (p == std::string::npos) return false;
        const size_t e = p + n;
        const bool frontOk = (p == 0) ? true : IsCmdSep(hay[p - 1]);
        const bool backOk  = (e >= hay.size()) ? true : IsCmdSep(hay[e]);
        if (frontOk && backOk) return true;
        from = p + 1;
    }
    return false;
}

// ================================================================
// ② 文件名是否呈「随机名」形态
// ================================================================
//  【为什么不能用「数字密度」近似随机性】
//    短尾巴里 1~2 个数字是常态 —— `1dhaf` 只有 1 个数字，
//    `digits*3 >= len` 直接判否（这一版 bug 让银狐解包中间态整个漏掉）。
//    ⇒ 只能认**形态规范**：解包器惯用的「短前缀 + 4~8 位随机串」。
//
//  【为什么顺序号要排除】
//    正常安装器大量使用 `is-0001.tmp` `is-0002.tmp` …（顺序号），
//    若把它们当随机名 ⇒ 每次安装都触发落地捕获 + 送检 ⇒ 配额打爆。
//    判据：尾巴必须**字母数字混杂**（al>0 且 dg>0）⇒ 顺序号（全数字）与
//    纯字母（is-abcdef，人为命名）都被排除。
bool LooksLikeRandomName(const std::string& baseLower) {
    size_t dot = baseLower.find_last_of('.');
    std::string stem = (dot == std::string::npos) ? baseLower : baseLower.substr(0, dot);

    // ---- 解包中间态规范形态：is- / is_ / is. / tmp / ~$ + 4~8 位随机串 ----
    if (stem.size() >= 6) {
        static const char* kStubPrefix[] = { "is-", "is_", "is.", "tmp", "~$" };
        for (const char* pfx : kStubPrefix) {
            const size_t pl = strlen(pfx);
            if (stem.size() < pl + 4) continue;
            if (stem.compare(0, pl, pfx) != 0) continue;
            const int tail = (int)stem.size() - (int)pl;
            if (tail > 8) break;                    // 太长，不是解包器短随机名
            int dg = 0, al = 0;
            for (size_t i = pl; i < stem.size(); ++i) {
                const char c = stem[i];
                if (c >= '0' && c <= '9') ++dg;
                else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) ++al;
            }
            // 顺序号（is-0001，全数字）与纯字母（is-abcdef）都不算随机
            if (dg > 0 && al > 0) return true;
            break;
        }
    }

    // ---- 以下为原有两条判据，门槛不能提前（提前会让它们永远够不着）----
    if (stem.size() < 8) return false;

    // 纯 hex 命名（16 位以上）——恶意载荷最常见的形态
    bool allHex = true;
    for (char c : stem)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { allHex = false; break; }
    if (allHex && stem.size() >= 16) return true;

    // 数字与字母高混杂（正常程序名极少如此）
    int digits = 0, upper = 0, lower = 0;
    for (char c : stem) {
        if (c >= '0' && c <= '9') ++digits;
        else if (c >= 'A' && c <= 'Z') ++upper;
        else if (c >= 'a' && c <= 'z') ++lower;
    }
    const int n = (int)stem.size();
    if (digits * 3 >= n && (upper + lower) * 2 >= n) return true;
    return false;
}

// ================================================================
// ③ 紧邻父目录是否呈「程序随机新建」形态
// ================================================================
//  【它是为了给「PE 头兜底」配一个量能闸门】
//    PE 头判据单独用会收走正常安装器的一切临时文件（全是 PE）⇒ 配额打爆。
//    银狐的落点形态是 `…\yCcAU\WlBU\is-1DHAF.tmp`：两层父目录都是随机名；
//    Office / PackageCache 是 `…\{GUID}\` —— 规范、可预测。
bool ParentDirLooksRandom(const std::string& fullLower) {
    const size_t slash = fullLower.find_last_of("\\/");
    if (slash == std::string::npos || slash == 0) return false;
    // 取紧邻的父目录名（只取最后一段，不看整条链 —— 银狐那条链最外层是固定名）
    const size_t p2 = fullLower.find_last_of("\\/", slash - 1);
    const size_t beg = (p2 == std::string::npos) ? 0 : p2 + 1;
    const std::string dir = fullLower.substr(beg, slash - beg);
    if (dir.size() < 4 || dir.size() > 24) return false;

    // GUID 形态 = 系统/安装器的规范临时目录，排除。
    // 判据用「首尾花括号」这个结构特征，**不用长度阈值** ——
    // `{5A2C}`（PackageCache，6 字符）与 `{FF23EA53-…}`（38 字符）都要排掉，
    // 写死长度会漏掉前者（自测抓到过）。
    if (dir.size() >= 4 && dir.front() == '{' && dir.back() == '}') return false;

    // 固定名白名单：系统/程序的规范目录名，不是随机新建的
    static const char* kFixed[] = {
        "appdata", "temp", "tmp", "cache", "downloads", "desktop", "documents",
        "programdata", "program files", "windows", "users", "local", "roaming",
        "microsoft", "mozilla", "packages", "package-cache", "windowsinstaller",
    };
    for (const char* f : kFixed)
        if (dir == f) return false;

    int digits = 0, alpha = 0;
    for (char c : dir) {
        if (c >= '0' && c <= '9') ++digits;
        else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) ++alpha;
    }
    if (alpha == 0) return false;                 // 纯数字目录（可能是系统卷）→ 排除
    if (digits > 0) return true;                  // 字母数字混杂：yCcAU / swNmu / Wg3w

    // 无数字时只认**短形态**（≤5）。
    //   ★ 6 位一律不收 —— 这条是判据自测抓出来的真漏洞：
    //     原实现对 6 字符要求「大小写混杂」，而 `Chrome`（C 大写）`Office`（O 大写）
    //     这类**真实存在的系统目录名**恰好满足该条件 ⇒ 会被当成随机名
    //     ⇒ 配合 PE 头兜底就把用户浏览器/Office 的临时文件全收走。
    //     而 6 位正是可读英文单词的主要长度（Chrome / Office / Safari / Firefox…），
    //     随机名极少落在这个长度。**宁漏不误**：真载荷还有 `digits>0` 与
    //     `LooksLikeRandomName`（is-XXXXXX / 纯 hex 16）两条路可走。
    if (dir.size() <= 5) return true;
    return false;
}

}  // namespace crit
}  // namespace sf
