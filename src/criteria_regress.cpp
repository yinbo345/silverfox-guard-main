// criteria_regress.cpp — 判据自测套件（C3，2026-10-03）
//
// ================================================================
//  ★ 为什么必须有这个文件
// ================================================================
//  今天为「判据写死表面特征」这一类 bug 反复返工：落地捕获那一处改了
//  **四版**才做对（v1 加 .tmp 扩展名 → v2 stub 前缀+数字密度 → v3 试图用
//  字符计数近似随机性 → v4 换成形态规范），每一版都是被「**不该收的反例**」
//  逼出来的：
//     · is-0001.tmp       顺序号，被当成随机名收走 → 送检配额打爆
//     · {FF23EA53-…}       Office GUID 临时目录 → 全盘安装器临时文件被收
//     · {5A2C}             短 GUID，写死长度判据漏掉 → PackageCache 被收
//     · %TEMP%\is-abc.tmp  固定名父目录 → 同上
//
//  也就是说：**只看正例的测试，三版都过不了。** 正例谁都会写，反例才拦得住。
//  而这四版没有一次是被 code review 看出来的，是被测试打回的 ——
//  ⇒ 判据类改动**必须**有反例常驻，否则下次照样错。
//
// ================================================================
//  纪律（每次改判据后必跑）
// ================================================================
//  ① 每个用例都要写明**为什么**（注释里标「★ 正例」/「★ 反例：不该收」）；
//  ② **反例数量必须不少于正例** —— 只测正例等于没测；
//  ③ 收紧判据时重点跑反例（确认没误伤），放宽时重点跑正例（确认没漏）；
//  ④ 期望值改动必须写明为什么 —— 否则就成了「为了让测试过而改测试」。
//
// ================================================================
//  ★ 覆盖范围与已知盲区
// ================================================================
//  【覆盖】criteria.cpp 三个判据：HasWord / LooksLikeRandomName / ParentDirLooksRandom
//        —— 这三个是**生产与本测试共用同一份实现**（生产侧转发到它），
//        所以这里测的就是真正在跑的代码。
//  【盲区】① `nc -e` 这类**规则级**判据（走 JudgeCommandLine，需加载外置规则，
//           而 behavior.cpp 依赖十几个服务层符号、无法单独链接 —— 这正是
//           criteria.cpp 被抽出来的原因）；
//          ② masquerade 的「按组件名单豁免」（需 JudgeImagePath，同样不可单测）；
//          ③ 扩展名白名单表本身（在 rollback.cpp，未抽出）。
//        ⇒ 改这三处时本套件兜不住，需另跑专项验证。
//
//  编译（单独编，不进服务；build.sh 的 src/*.cpp 通配自动跳过 *_regress.cpp）：
//    cl /nologo /MT /std:c++17 /utf-8 /O2 /EHsc criteria_regress.cpp criteria.cpp
//       /Fe:criteria_regress.exe
// ===========================================================================
#include "criteria.h"

#include <cstdio>
#include <string>

namespace {

int g_pass = 0, g_fail = 0;

void Check(bool cond, const char* what) {
    if (cond) { ++g_pass; printf("  [OK]   %s\n", what); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what); }
}

// ================================================================
//  判据一：HasWord —— 带词边界的子串匹配
// ================================================================
//  事故：`H|2|rat|nc -e` 这条 5 字符 needle 命中了
//  C:\Windows\System32\mobsync.exe —— 微软**已签名**的同步中心，
//  被硬规则终止两次（VM 日志 22:04:36 / 22:11:03）。
//
//  真因不是「needle 太短」这么笼统：behavior.cpp 构造了第二份匹配串 lNoExe
//  （归一化后**去掉 .exe 后缀**），于是
//      原始 l    = `...\system32\mobsync.exe -e ...`   → 不含 `nc -e`
//      去 exe 后 = `...\system32\mobsync -e ...`      → **命中** `nc -e`
//  （mobsync 末尾的 nc + 空格 + -e 恰好拼出 needle）
//  ⇒ 「贴心的去后缀机制」反过来把合法进程名变成了攻击特征。
void TestHasWord() {
    printf("\n=== 判据一：HasWord（nc -e 误杀事故复现）===\n");

    // ── 正例（真攻击必须命中）──
    Check(sf::crit::HasWord("c:\\tools\\nc.exe -e cmd.exe", "nc.exe -e"),
          "★正例：nc.exe -e cmd.exe 必须命中");
    Check(sf::crit::HasWord("nc.exe -e cmd.exe", "nc.exe -e"),
          "★正例：nc.exe -e（串首）必须命中");
    Check(sf::crit::HasWord("nc.exe -e", "nc.exe -e"),
          "★正例：needle 恰好是整串必须命中");
    Check(sf::crit::HasWord("c:\\tools\\ncat.exe -e powershell.exe", "ncat.exe -e"),
          "★正例：ncat.exe -e powershell.exe 必须命中");
    Check(sf::crit::HasWord("c:\\a\\nc.exe -e", "nc.exe -e"),
          "★正例：路径形态 \\nc.exe -e 必须命中");

    // ── 反例（绝不能命中 —— 这几个是今天真实的误杀/绕过路径）──
    Check(!sf::crit::HasWord("c:\\windows\\system32\\mobsync -e something", "nc -e"),
          "★反例：mobsync 去掉 .exe 后末尾的 nc + 空格 + -e 不得命中");
    Check(!sf::crit::HasWord("c:\\program files\\sync -e", "nc -e"),
          "★反例：sync 去后缀后不得命中");
    Check(!sf::crit::HasWord("c:\\tools\\nc.exe -listener -p 4444", "nc.exe -e"),
          "★反例：nc.exe -listener（无 -e）不得命中 nc.exe -e");
    Check(!sf::crit::HasWord("c:\\tools\\xnc.exe -e", "nc.exe -e"),
          "★反例：xnc.exe 的尾部不得命中（词边界不成立）");

    // ── 边界条件 ──
    Check(!sf::crit::HasWord("abc", ""), "边界：空 needle 判否");
    Check(!sf::crit::HasWord("abc", nullptr), "边界：nullptr needle 判否");
    Check(!sf::crit::HasWord("ab", "abcdef"), "边界：needle 比 hay 还长判否");
    Check(sf::crit::HasWord("a b", "a b"), "边界：空格是分隔符，整串仍命中");
}

// ================================================================
//  判据二：LooksLikeRandomName —— 文件名是否呈随机名形态
// ================================================================
//  事故：银狐解包中间态 `is-1DHAF.tmp` 的 stem = "is-1dhaf"（8 字符、
//  **只有 1 个数字**）⇒ 原判据 `digits*3 >= 长度`（3 < 8）判否
//  ⇒ 而 `.tmp` 又不在扩展名表里 ⇒ 落地捕获整条静默跳过，载荷零送检。
void TestLooksLikeRandomName() {
    printf("\n=== 判据二：LooksLikeRandomName（is-1DHAF.tmp 漏报复现）===\n");

    // ── 正例（解包中间态形态必须收）──
    Check(sf::crit::LooksLikeRandomName("is-1dhaf.tmp"),
          "★正例：is-1DHAF.tmp（银狐实测形态）必须判随机名");
    Check(sf::crit::LooksLikeRandomName("is-3f2a.dat"),
          "★正例：is-3f2a.dat（换扩展名）必须判随机名");
    Check(sf::crit::LooksLikeRandomName("is-9a8b7c.tmp"),
          "★正例：is-9a8b7c.tmp（6 位尾巴）必须判随机名");
    Check(sf::crit::LooksLikeRandomName("a1b2c3d4e5f6.dat"),
          "★正例：a1b2c3d4e5f6（纯 hex 16 位）必须判随机名");
    Check(sf::crit::LooksLikeRandomName("ab12cd34.exe"),
          "★正例：ab12cd34.exe（数字字母高混杂）必须判随机名");

    // ── 反例（正常文件绝不能收 —— 收错就是送检配额打爆）──
    Check(!sf::crit::LooksLikeRandomName("is-0001.tmp"),
          "★反例：is-0001.tmp（安装器顺序号）不得判随机名");
    Check(!sf::crit::LooksLikeRandomName("is-0002.tmp"),
          "★反例：is-0002.tmp 同上");
    Check(!sf::crit::LooksLikeRandomName("is-abc.tmp"),
          "★反例：is-abc.tmp（纯字母，尾巴太短）不得判随机名");
    Check(!sf::crit::LooksLikeRandomName("is-notinstalled.tmp"),
          "★反例：is-notinstalled.tmp（英文单词）不得判随机名");
    Check(!sf::crit::LooksLikeRandomName("setup.exe"),
          "★反例：setup.exe（正常安装器名）不得判随机名");
    Check(!sf::crit::LooksLikeRandomName("report.docx"),
          "★反例：report.docx（正常文档）不得判随机名");
    Check(!sf::crit::LooksLikeRandomName("program.exe"),
          "★反例：program.exe（可读单词）不得判随机名");

    // ── 边界 ──
    Check(!sf::crit::LooksLikeRandomName("noext"),
          "边界：noext（无扩展名、stem 4 字符）判否");
    Check(!sf::crit::LooksLikeRandomName("a.b.c"),
          "边界：a.b.c（多点在 stem 之前）判否");
}

// ================================================================
//  判据三：ParentDirLooksRandom —— 父目录是否呈随机新建形态
// ================================================================
//  它是给「PE 头兜底」配的**量能闸门**：PE 头单独用会收走正常安装器的一切
//  临时文件（全是 PE）⇒ 配额打爆 ⇒ 真载荷反而挤不进队列。
void TestParentDirLooksRandom() {
    printf("\n=== 判据三：ParentDirLooksRandom（PE 头兜底的量能闸门）===\n");
    const char* S = "\\";

    // ── 正例（银狐式随机父目录必须放行给 PE 头判据）──
    {
        std::string p = std::string("c:") + S + "msys64" + S + "lbrq7" + S + "eibq" + S + "yccau" + S + "wlbu" + S + "a.tmp";
        Check(sf::crit::ParentDirLooksRandom(p), "★正例：…\\wlbu\\ 判随机（银狐落点形态）");
    }
    {
        std::string p = std::string("c:") + S + "msys64" + S + "lbrq7" + S + "a9b2c3.tmp";
        Check(sf::crit::ParentDirLooksRandom(p), "★正例：…\\a9b2c3\\ 判随机（数字混杂）");
    }
    {
        std::string p = std::string("c:") + S + "x" + S + "yCcAU" + S + "f.exe";
        Check(sf::crit::ParentDirLooksRandom(p), "★正例：…\\yCcAU\\ 判随机（大小写混杂）");
    }

    // ── 反例（正常安装器 / 系统临时目录必须排除，否则配额打爆）──
    {
        std::string p = std::string("c:") + S + "users" + S + "tl" + S + "appdata" + S + "local" + S + "temp" + S + "is-0001.tmp";
        Check(!sf::crit::ParentDirLooksRandom(p), "★反例：%TEMP%\\is-0001.tmp 的 temp 固定名须排除");
    }
    {
        std::string p = std::string("c:") + S + "users" + S + "tl" + S + "appdata" + S + "local" + S + "temp" + S + "{FF23EA53-5070-4DF8-B5D8-3573BDA406E0}" + S + "is-abc.tmp";
        Check(!sf::crit::ParentDirLooksRandom(p), "★反例：Office GUID 临时目录须排除");
    }
    {
        std::string p = std::string("c:") + S + "programdata" + S + "package-cache" + S + "{5A2C}" + S + "is-q.tmp";
        Check(!sf::crit::ParentDirLooksRandom(p), "★反例：PackageCache 短 GUID {5A2C} 须排除（写死长度会漏）");
    }
    {
        std::string p = std::string("c:") + S + "users" + S + "tl" + S + "documents" + S + "a.docx";
        Check(!sf::crit::ParentDirLooksRandom(p), "★反例：Documents 固定名须排除");
    }
    {
        std::string p = std::string("c:") + S + "program files" + S + "common files" + S + "x.dll";
        Check(!sf::crit::ParentDirLooksRandom(p), "★反例：Program Files 须排除");
    }

    // ── 边界 ──
    Check(!sf::crit::ParentDirLooksRandom("c:\\onlyone.exe"),
          "边界：盘根下的单层文件（无父目录）判否");
    Check(!sf::crit::ParentDirLooksRandom("no-slash-at-all"),
          "边界：不含分隔符判否");
    {
        std::string p = std::string("c:") + S + "Chrome" + S + "f.exe";
        Check(!sf::crit::ParentDirLooksRandom(p),
              "★反例：6 字符 Chrome（大写 C）须排除 —— 自测抓出的真漏洞");
    }
    {
        std::string p = std::string("c:") + S + "Office" + S + "d.dll";
        Check(!sf::crit::ParentDirLooksRandom(p),
              "★反例：6 字符 Office（大写 O）须排除");
    }
    {
        std::string p = std::string("c:") + S + "Firefox" + S + "d.dll";
        Check(!sf::crit::ParentDirLooksRandom(p),
              "★反例：7 字符 Firefox 须排除");
    }
}

}  // namespace

int main() {
    printf("=== 判据自测套件（C3，2026-10-03）===\n");
    printf("    纪律：每个用例都要写明正例/反例；反例数量不得少于正例。\n");
    printf("    覆盖：HasWord / LooksLikeRandomName / ParentDirLooksRandom\n");
    printf("          （与生产代码共用 criteria.cpp，测的就是真正在跑的代码）\n");

    TestHasWord();
    TestLooksLikeRandomName();
    TestParentDirLooksRandom();

    printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("    ★ 已知盲区（本套件兜不住，改这几处要另跑专项）：\n"
               "      · 规则级判据（nc -e 等，走 JudgeCommandLine + 外置规则）\n"
               "      · masquerade 的「按组件名单豁免」（走 JudgeImagePath）\n"
               "      · 扩展名白名单表本身（在 rollback.cpp）\n");
    }
    return g_fail == 0 ? 0 : 1;
}
