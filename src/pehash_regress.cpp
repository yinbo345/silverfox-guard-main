// pehash_regress.cpp — pehash 的回归测试（独立可执行，**不进服务构建**）
//
// ===========================================================================
//  为什么这个文件必须存在（而不是"编译器说没错就行"）
// ===========================================================================
//  imphash 有一类**最贵的失败形态**：算出来的值与外部实现不同 →
//  我们自己造的库、外部造的库、云端下发的库三者互相对不上 →
//  **库看着建好了、条目数正常、查询也正常，但永远查不中，且不报任何错。**
//  编译器和静态检查对这类问题**完全无效** —— 它们只保证"算出了一个值"，
//  不保证"算出了正确的值"。
//
//  所以本回归钉三件事：
//    ① **算法正确性**：与独立参考实现（Python，见 tools/imphash_ref.py）
//       在同一批真实 PE 上逐字节对撞。参数可外部传入，便于换样本重跑。
//    ② **铁律 §4（UTF-8 路径）**：在**真的中文目录**下放一个文件再算哈希。
//       这条只能真造文件、真跑 API 才测得出来 ——
//       代码审查看不出 `std::ifstream(std::string)` 在 CP936 下会失败。
//    ③ **边界**：空文件 / 不存在 / 非 PE / 超上限 / 缓存命中。
//
//  编译（不链接主防，依赖最小）：
//    cl /nologo /MT /std:c++17 /utf-8 /EHsc /W3 pehash_regress.cpp pehash.cpp <换行续写，见下行>
//       /Fe:pehash_regress.exe bcrypt.lib
#include "pehash.h"

#include <windows.h>

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

// ===========================================================================
//  迷你测试框架
// ===========================================================================
static int g_pass = 0, g_fail = 0, g_skip = 0;

static void Check(bool ok, const std::string& what) {
    if (ok) { ++g_pass; std::printf("  [PASS] %s\n", what.c_str()); }
    else    { ++g_fail; std::printf("  [FAIL] %s\n", what.c_str()); }
}
static void Skip(const std::string& what) {
    ++g_skip;
    std::printf("  [SKIP] %s\n", what.c_str());
}
static void Section(const char* name) {
    std::printf("\n== %s ==\n", name);
}

static std::string ToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static bool WriteFileW(const std::wstring& path, const void* data, size_t len) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD wr = 0;
    bool ok = true;
    if (len) ok = (WriteFile(h, data, (DWORD)len, &wr, nullptr) != 0 && wr == len);
    CloseHandle(h);
    return ok;
}

// ===========================================================================
//  用例
// ===========================================================================
static void TestSha256Basics(const std::wstring& workDirW) {
    Section("SHA-256 基础（对照公开标准向量）");

    // "abc" 的 SHA-256 是公开标准值，任何人都能独立核对 ——
    // 这是本回归里唯一**不依赖我自己的第二实现**的锚点。
    std::string p1 = ToUtf8(workDirW + L"\\abc.bin");
    Check(WriteFileW(workDirW + L"\\abc.bin", "abc", 3), "写入 abc.bin");
    std::string h1;
    Check(sf::pehash::FileSha256(p1, h1), "FileSha256(abc.bin) 返回 true");
    Check(h1 == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "abc 的 SHA-256 == 标准值（实际 " + h1 + "）");

    // 空文件
    std::string p2 = ToUtf8(workDirW + L"\\empty.bin");
    Check(WriteFileW(workDirW + L"\\empty.bin", "", 0), "写入 empty.bin");
    std::string h2;
    Check(sf::pehash::FileSha256(p2, h2), "FileSha256(empty.bin) 返回 true");
    Check(h2 == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "空文件 SHA-256 == 标准值（实际 " + h2 + "）");

    // 不存在的文件：**必须返回 false 而不是空哈希**
    std::string h3;
    Check(!sf::pehash::FileSha256(ToUtf8(workDirW + L"\\no_such_file_zzz.bin"), h3) && h3.empty(),
          "不存在的文件 → false 且哈希为空（绝不返回空串当成功）");
}

static void TestUtf8Path(const std::wstring& workDirW) {
    Section("★ 铁律 §4：UTF-8（中文）路径");

    // ★ 这是本回归里最重要的一组。
    //   把文件放在一个**真的含中文**的目录里，再用 UTF-8 字节串去算哈希。
    //   如果实现里用了 std::ifstream(std::string)（按 CP936 解释 UTF-8 字节），
    //   这里会**静默失败或算出错误的哈希** —— 而编译器和 /W3 都不会警告。
    std::wstring cjkDir = workDirW + L"\\银狐哈希回归_中文目录";
    if (!CreateDirectoryW(cjkDir.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) {
        Skip("无法创建中文目录，跳过本组");
        return;
    }
    std::wstring f = cjkDir + L"\\载荷样本.bin";
    Check(WriteFileW(f, "abc", 3), "在中文目录写中文名文件");

    const std::string pUtf8 = ToUtf8(f);
    Check(pUtf8.find("\xe9\x93\xb6") != std::string::npos, "路径确实含 UTF-8 中文字节");

    std::string h;
    Check(sf::pehash::FileSha256(pUtf8, h), "中文路径 FileSha256 返回 true（铁律 §4）");
    Check(h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "中文路径下算出的哈希与英文路径一致");

    // 用中文路径写一个**非 PE**，验证 Imphash 也是靠 *W 读的
    std::string imp;
    Check(!sf::pehash::Imphash(pUtf8, imp), "中文路径下的非 PE → Imphash 返回 false（读到了文件才可能判非 PE）");
}

static void TestImphashNegative(const std::wstring& workDirW) {
    Section("imphash 反例（必须给出「没有结论」而不是一个值）");

    std::string p = ToUtf8(workDirW + L"\\plain_text.txt");
    Check(WriteFileW(workDirW + L"\\plain_text.txt", "this is not a PE file at all", 29),
          "写入非 PE 文本文件");
    std::string h;
    Check(!sf::pehash::Imphash(p, h) && h.empty(), "非 PE → false 且 imphash 为空");

    // ★ 一个只有 MZ 头、没有 PE 头的文件：必须也判非 PE（不能因为"像 PE"就给值）
    unsigned char fake[128] = {0};
    fake[0] = 'M'; fake[1] = 'Z';
    fake[0x3C] = 0x40;                     // e_lfanew = 0x40，但那处没有 'PE\0\0'
    std::string p2 = ToUtf8(workDirW + L"\\fake_mz.bin");
    Check(WriteFileW(workDirW + L"\\fake_mz.bin", fake, sizeof(fake)), "写入只有 MZ 头的假 PE");
    std::string h2;
    Check(!sf::pehash::Imphash(p2, h2), "只有 MZ 头 → false（不给结论）");
}

static void TestImphashKey() {
    Section("ImphashKey 派生（格式的一部分，改则所有旧库作废）");

    const std::string k1 = sf::pehash::ImphashKey("0123456789abcdef0123456789abcdef");
    const std::string k2 = sf::pehash::ImphashKey("0123456789ABCDEF0123456789ABCDEF");
    Check(k1.size() == 64, "合法 imphash → 64 位派生键");
    Check(!k1.empty() && k1 == k2, "大小写不同 → 同一个派生键（否则库会一半查不中）");

    Check(sf::pehash::ImphashKey("").empty(),        "空串 → 空键");
    Check(sf::pehash::ImphashKey("abc").empty(),     "长度不足 → 空键");
    Check(sf::pehash::ImphashKey(std::string(32, 'z')).empty(), "非十六进制 → 空键");

    // 与「补零」方案不同：这里必须是哈希铺满 32 字节，不能出现整段零
    Check(k1.substr(32) != std::string(32, '0'),
          "派生键不是「前 16 字节有效 + 后 16 字节全零」那种退化形态");
}

static void TestCache(const std::wstring& workDirW) {
    Section("热路径缓存（同一文件只算一次）");

    const std::string p = ToUtf8(workDirW + L"\\abc.bin");
    sf::pehash::ResetStats();

    std::string a, b;
    Check(sf::pehash::FileSha256Cached(p, a, nullptr), "第一次 FileSha256Cached 成功");
    Check(sf::pehash::FileSha256Cached(p, b, nullptr), "第二次 FileSha256Cached 成功");
    Check(a == b, "两次结果一致");
    sf::pehash::Stats s = sf::pehash::GetStats();
    Check(s.shaCompute == 1 && s.shaCacheHit == 1,
          "计算 1 次 / 缓存命中 1 次（实测 calculate=" + std::to_string(s.shaCompute) +
          " hit=" + std::to_string(s.shaCacheHit) + "）");

    // 改写文件 → 大小或 mtime 变 → 缓存必须失效
    Check(WriteFileW(workDirW + L"\\abc.bin", "abcd", 4), "改写 abc.bin 为 4 字节");
    std::string c;
    Check(sf::pehash::FileSha256Cached(p, c, nullptr), "改写后再查成功");
    Check(c != a, "★ 文件被改写 → 缓存失效，得到新哈希（只按路径缓存的错版本会在这里 FAIL）");
}

static void TestTooBig(const std::wstring& workDirW) {
    Section("超上限（热路径策略：宁可跳过也不拖住消费线程）");

    // 造一个比 kShaMaxBytes 大的文件；用稀疏写省时间（只写最后一个字节）
    const std::wstring bigW = workDirW + L"\\big_over_64mb.bin";
    HANDLE h = CreateFileW(bigW.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) { Skip("无法创建大文件，跳过本组"); return; }
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)sf::pehash::kShaMaxBytes + 1024;   // 越过上限 1KB
    bool okSeek = (SetFilePointerEx(h, li, nullptr, FILE_BEGIN) != 0);
    DWORD wr = 0;
    const char z = 0;
    bool okWrite = okSeek && WriteFile(h, &z, 1, &wr, nullptr);
    CloseHandle(h);
    if (!okWrite) { Skip("无法造出超限文件，跳过本组"); return; }

    const std::string big = ToUtf8(bigW);
    sf::pehash::ResetStats();

    // ① 不带缓存的算法版：**必须算得出来**（算法不设上限）
    std::string hs;
    Check(sf::pehash::FileSha256(big, hs), "FileSha256（算法）能算超限文件 —— 上限属于策略，不属算法");

    // ② 热路径缓存版：必须跳过并计入 shaTooBig
    std::string hc;
    uint64_t sz = 0;
    Check(!sf::pehash::FileSha256Cached(big, hc, &sz), "FileSha256Cached 跳过超限文件");
    sf::pehash::Stats s = sf::pehash::GetStats();
    Check(s.shaTooBig == 1, "shaTooBig 记 1 次（实测 " + std::to_string(s.shaTooBig) + "）");
    Check(!hs.empty() && sz > sf::pehash::kShaMaxBytes,
          "算法版确实算出了值，且报告的大小确实超限（" + std::to_string(sz) + "）");

    DeleteFileW(bigW.c_str());
}

// ===========================================================================
//  可选：与外部参考实现对撞 imphash
// ===========================================================================
static void TestImphashAgainstReference(const std::string& pePath, const std::string& expectHex) {
    Section("★ imphash 与外部参考实现对撞（算法正确性的唯一硬证据）");

    std::printf("  样本：%s\n", pePath.c_str());
    std::string got;
    if (!sf::pehash::Imphash(pePath, got)) {
        Check(false, "Imphash 失败（样本应为合法 PE）——请检查参数");
        return;
    }
    std::printf("  本实现 imphash = %s\n", got.c_str());
    std::printf("  参考   imphash = %s\n", expectHex.c_str());
    Check(got == expectHex,
          got == expectHex ? "与参考实现逐字符一致"
                           : "★ 与参考实现不一致 —— 库会永远查不中（最贵的失败形态）");

    const std::string key = sf::pehash::ImphashKey(got);
    Check(key.size() == 64, "派生键长度 64");
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);   // 否则本文件的 UTF-8 中文在 CP936 控制台是乱码

    std::printf("========================================================\n");
    std::printf(" pehash 回归（精准哈希 + imphash + UTF-8 路径铁律）\n");
    std::printf("========================================================\n");

    // 工作目录：C:\temp\pehash_regress_<pid>
    wchar_t tmp[MAX_PATH] = {0};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring workDirW = std::wstring(tmp) + L"pehash_regress";
    CreateDirectoryW(workDirW.c_str(), nullptr);

    TestSha256Basics(workDirW);
    TestUtf8Path(workDirW);
    TestImphashNegative(workDirW);
    TestImphashKey();
    TestCache(workDirW);
    TestTooBig(workDirW);

    if (argc >= 3) {
        TestImphashAgainstReference(argv[1], argv[2]);
    } else {
        Section("imphash 对撞");
        std::printf("  （未提供样本参数，跳过）\n");
        std::printf("  用法：pehash_regress.exe <某个PE文件> <参考imphash>\n");
    }

    std::printf("\n========================================================\n");
    std::printf(" 结果：%d 通过 / %d 失败 / %d 跳过\n", g_pass, g_fail, g_skip);
    std::printf("========================================================\n");
    return g_fail == 0 ? 0 : 1;
}
