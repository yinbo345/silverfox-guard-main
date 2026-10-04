// sfclock_regress.cpp — 自有时间基准（sfclock）回归测试
//
// ===========================================================================
//  为什么必须测这个模块
// ===========================================================================
//  sfclock 的 bug **不会崩溃**，只会静默让时间窗判据失效 ——
//  而全部速率型判据都拿 T1 当度量单位：
//      · rollback.h:95  windowSeconds=10 + filesThreshold=40（10 秒改 40 个文件 = 勒索）
//      · rollback.h    renameThreshold=15 / noteThreshold=2
//      · burstWindowSec=30 + burstFileTrigger=5 / keyWindowSec=30
//  T1 一旦倒退或冻结，窗口会被无限拉长或归零，判据方向可能从「收紧」翻成「放宽」
//  —— 那等于给攻击者开后门，而日志里什么都看不出来。
//  所以这里把 T1 的三条铁律钉成用例：**不倒退 / 重启补时 / 超限拒绝**。
//
// ===========================================================================
//  编译（单独编，不进服务）
// ===========================================================================
//  build.sh 的 src/*.cpp 通配会自动跳过 *_regress.cpp，无需改脚本。
//  手工编译：
//    cl /nologo /MT /std:c++17 /utf-8 /O2 /EHsc sfclock_regress.cpp sfclock.cpp ^
//       /link winhttp.lib shell32.lib advapi32.lib
//
// ===========================================================================
//  ★ 全部用例都在隔离目录里跑
// ===========================================================================
//  DebugIsolatePersistence() 会把状态目录重定向到 C:\temp\sfclock_test 并关闭
//  注册表读写 —— 绝不触碰生产基线（ProgramData\...\clock_state.bin 与 HKLM）。
//  否则测试里伪造的「200 天前 / 未来 30 天」会被写进真实基线，
//  此后线上全部时间窗判据静默错位，且极难回溯到「是那次跑测试搞的」。
#include "sfclock.h"

#include <cstdio>
#include <string>

#ifdef _WIN32
#  include <windows.h>
#endif

// ---------------------------------------------------------------------------
//  LogDbgC / LogDbg 桩
// ---------------------------------------------------------------------------
//  sfclock.cpp 只前向声明了这两个（见其文件头），刻意不 include common.h。
//  回归程序同样**刻意不链接 common.cpp** —— 那会拖进 bcrypt / crypt32 /
//  wintrust / wtsapi32 一整串依赖，而这里只需要两个日志函数。
//  ★ 参数签名必须与 common.h 完全一致，否则链接期报未解析外部符号。
namespace sf {
void LogDbgC(const char* msg) { printf("         | %s\n", msg ? msg : ""); }
void LogDbg(const std::string& msg) { printf("         | %s\n", msg.c_str()); }
}

using namespace sf::ck;

static int g_pass = 0, g_fail = 0;

static void Check(bool cond, const char* what) {
    if (cond) { ++g_pass; printf("  [OK]   %s\n", what); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what); }
}

// 反推当前墙上时间（Unix 毫秒）—— 与 sfclock 内部公式一致，供用例算期望值
static uint64_t WallMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart / 10000ull - 11644473600000ull;
}

// 反推当前系统启动时刻（Unix 毫秒）
static uint64_t BootMs() {
    uint64_t now = WallMs();
    uint64_t tick = GetTickCount64();
    return (now > tick) ? (now - tick) : 0;
}

static uint64_t AbsDiff(uint64_t a, uint64_t b) { return (a > b) ? (a - b) : (b - a); }

// ---------------------------------------------------------------------------
//  ★ 2026-10-03 补齐：本文件 [1]~[3] 段用的辅助函数在 [4]~[9] 段缺失，
//    且 [4]~[9] 段写于 sfclock.h 加 bootTimeMs 参数之前 —— 是一次未完工的重写。
//    （C2065/C3861/C2660 共 17 个编译错全部来自这里，不是别的问题。）
// ---------------------------------------------------------------------------
static const uint64_t kDayMs = 86400000ull;   // 1 天 = 86,400,000 毫秒

static int g_skip = 0;

// 近似断言：|实际-期望| <= tol 就算通过（时间类判据不能用等值）
static void CheckNear(uint64_t actual, uint64_t expect, uint64_t tol, const char* what) {
    if (AbsDiff(actual, expect) <= tol) { ++g_pass; printf("  [OK]   %s\n", what); }
    else {
        ++g_fail;
        printf("  [FAIL] %s  (实际=%llu 期望=%llu 差=%llu 容差=%llu)\n", what,
               (unsigned long long)actual, (unsigned long long)expect,
               (unsigned long long)AbsDiff(actual, expect), (unsigned long long)tol);
    }
}

// 条件不满足时「跳过」而不是判失败 —— 用于依赖外部环境的用例
// （网络不可达 / ACL 保护导致打不开状态文件等），否则回归在离线环境永远红。
static void Skip(const char* what, const char* why) {
    ++g_skip;
    printf("  [SKIP] %s  (%s)\n", what, (why && *why) ? why : "无");
}

// 近似当前系统启动时刻（Unix 毫秒）—— 与 sfclock 内部「boot 判据」同源
static uint64_t ApproxBootTimeMs() { return BootMs(); }

int main() {
    const wchar_t* kTestDir = L"C:\\temp\\sfclock_test";

    printf("=== sfclock 回归测试（自有时间基准 / 时钟静态站客户端）===\n");
    printf("    隔离目录：C:\\temp\\sfclock_test  —— 不触碰生产基线\n");

    DebugIsolatePersistence(kTestDir);
    printf("    状态文件将写到：%s\n\n", StatePathUtf8());

    // -----------------------------------------------------------------------
    printf("[1] 首次初始化 —— 用系统时钟建立基线\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    Check(Init(), "Init() 首次调用返回成功");
    {
        uint64_t t1 = T1Ms(), w = WallMs();
        Check(AbsDiff(t1, w) < 5000, "首次 T1 落在系统时钟附近（5 秒内）");
        Check(ClockSane(), "首次初始化后 ClockSane()==true");
        Check(DebugReadPersistedT1() != 0, "基线已持久化（可从磁盘读回，非 0）");
    }

    // -----------------------------------------------------------------------
    printf("\n[2] 同一开机周期内重启服务 —— 纯单调推进，完全不读系统时钟\n");
    // -----------------------------------------------------------------------
    // 这是「不跟系统时钟走」最纯粹的体现：只要 boot 判定为同一次，
    // 系统时钟此刻被改成什么都不影响结果。
    ResetForTest();
    {
        uint64_t nowMono = MonoMs();
        uint64_t baseT1  = nowMono;              // 故意用「mono 毫秒」这种怪值当 T1
        DebugInjectState(baseT1, nowMono - 60000ull, BootMs());
        Init();
        uint64_t got = T1Ms();
        // 期望：baseT1 + (本次 mono - 保存时 mono) = baseT1 + 60000（±执行耗时）
        printf("        注入 T1=%llu，读回 T1=%llu（差 %lld ms，期望 ≈60000）\n",
               (unsigned long long)baseT1, (unsigned long long)got,
               (long long)got - (long long)baseT1);
        Check(got >= baseT1 + 59000ull && got <= baseT1 + 63000ull,
              "同 boot 重启 → T1 = 旧 T1 + 经过的单调时间（≈ +60 秒）");
        Check(AnomalyCount() == 0, "正常路径不应产生异常计数");
    }

    // -----------------------------------------------------------------------
    printf("\n[3] 跨重启 + gap 合理（1 小时）—— 采纳系统时钟补时\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    {
        uint64_t w = WallMs();
        DebugInjectState(w - 3600ull * 1000, 4294967295ull, w - 86400000ull);  // boot 变
        Init();
        uint64_t got = T1Ms();
        Check(AbsDiff(got, w) < 5000, "gap=1 小时（合理）→ T1 采纳系统时钟");
        Check(AnomalyCount() == 0, "合理补时不应产生异常计数");
    }

    // -----------------------------------------------------------------------
    printf("\n[4] ★ 跨重启 + gap 超上限（200 天）—— 拒绝采纳、冻结、绝不倒退\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    {
        uint64_t w = WallMs();
        uint64_t oldT1 = w - 200ull * 86400000ull;
        DebugInjectState(oldT1, 4294967295ull, w - 86400000ull);
        Init();
        uint64_t got = T1Ms();
        Check(got >= oldT1, "★ T1 绝不倒退（取到值 >= 注入的旧值）");
        Check(got <= oldT1 + 5000ull, "超上限 → 拒绝采纳系统时钟，T1 冻结在旧值");
        Check(AnomalyCount() > 0, "已记录异常（AnomalyCount > 0）");
        Check(!ClockSane(), "ClockSane()==false（明确标记不可信）");
    }

    // -----------------------------------------------------------------------
    printf("\n[5] ★ 系统时钟回退（基线在「未来」30 天）—— 仍不得回退 T1\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    {
        uint64_t w = WallMs();
        uint64_t oldT1 = w + 30ull * 86400000ull;
        DebugInjectState(oldT1, 4294967295ull, w - 86400000ull);
        Init();
        uint64_t got = T1Ms();
        Check(got >= oldT1, "★ 系统时钟回退 → T1 保持不减（不跟着回退）");
        Check(AnomalyCount() > 0, "已记录回退异常");
    }

    // -----------------------------------------------------------------------
    printf("\n[6] SubmitExternalAnchor —— 只接受更大的锚点（单调不减）\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    {
        Init();
        uint64_t before = T1Ms();
        SubmitExternalAnchor(before - 1000000ull, "test-small");
        Check(T1Ms() >= before, "更小的锚点被忽略（T1 未下降）");
        SubmitExternalAnchor(before + 10000000ull, "test-big");
        Check(T1Ms() >= before + 10000000ull, "更大的锚点被采纳（T1 抬升）");
        SubmitExternalAnchor(0, "test-zero");
        Check(T1Ms() >= before + 10000000ull, "0 锚点被忽略（T1 未被拉回）");
    }

    // -----------------------------------------------------------------------
    printf("\n[7] ★ 真实访问时钟静态站 —— 端到端「通不通」的判据\n");
    // -----------------------------------------------------------------------
    ResetForTest();
    {
        SetCloudEnabled(true);
        bool netOk = SyncCloudNow();
        const char* note = LastCloudNote();
        printf("        云端返回：%s\n", note);
        Check(netOk, "SyncCloudNow() 成功取回云端时间（网络可达）");
        std::string n(note ? note : "");
        Check(n.find("成功") != std::string::npos || n.find("采纳") != std::string::npos,
              "云端查询结果为「成功」或已「采纳」外部锚点");
    }

    // -----------------------------------------------------------------------
    printf("\n[4] 跨重启 + 合理 gap：采纳系统时钟补时\n");
    // -----------------------------------------------------------------------
    {
        sf::ck::DebugIsolatePersistence(L"C:\\temp\\sfclock_test\\t4");
        sf::ck::ResetForTest();

        // monoAtSave 取一个**未来值** → nowMono < monoAtSave → 必然判定为"重启过"
        // （判据一：单调时钟不会倒退。这是最可靠的跨重启证据。）
        uint64_t t1inj = WallMs() - 2 * 3600 * 1000;     // 2 小时前
        sf::ck::DebugInjectState(t1inj, sf::ck::MonoMs() + 10 * kDayMs, 0);

        sf::ck::Init();
        uint64_t t1 = sf::ck::T1Ms();
        CheckNear(t1, WallMs(), 3000, "gap=2 小时（合理）→ 采纳系统时钟，T1≈现在");
        Check(sf::ck::AnomalyCount() == 0, "合理补时不算异常");
    }

    // -----------------------------------------------------------------------
    printf("\n[5] ★ 跨重启 + gap 超上限（>90 天）：拒绝采纳，时间冻结 + 进告警\n");
    // -----------------------------------------------------------------------
    {
        sf::ck::DebugIsolatePersistence(L"C:\\temp\\sfclock_test\\t5");
        sf::ck::ResetForTest();

        // 模拟"一觉睡了 200 天"（或系统时钟被前拨 200 天）
        uint64_t t1inj = WallMs() - 200 * kDayMs;
        sf::ck::DebugInjectState(t1inj, sf::ck::MonoMs() + 10 * kDayMs, 0);

        sf::ck::Init();
        uint64_t t1 = sf::ck::T1Ms();

        // 关键断言：T1 应当**冻结在注入值**，而不是盲信系统时钟跳到"现在"
        CheckNear(t1, t1inj, 3000, "gap 超限 → T1 冻结在旧值（**未**采纳可疑的系统时钟）");
        Check(t1 < WallMs(), "T1 明显小于可疑的墙上时间（证明拒绝采纳生效）");
        Check(sf::ck::AnomalyCount() >= 1, "已记入异常计数（不许静默吞掉）");
        Check(!sf::ck::ClockSane(), "ClockSane()==false（状态已标记不可信）");
        const char* why = sf::ck::LastAnomaly();
        Check(why && why[0] != 0, "异常描述非空（可归因）");
        printf("        异常描述 = %s\n", why ? why : "(null)");
    }

    // -----------------------------------------------------------------------
    printf("\n[6] ★ 系统时钟回退（比记录的 T1 还早）：绝不倒退\n");
    // -----------------------------------------------------------------------
    {
        sf::ck::DebugIsolatePersistence(L"C:\\temp\\sfclock_test\\t6");
        sf::ck::ResetForTest();

        // T1 处于"未来" 200 天 → 当前墙上时间比它早 → 走回退分支
        uint64_t t1inj = WallMs() + 200 * kDayMs;
        sf::ck::DebugInjectState(t1inj, sf::ck::MonoMs() + 10 * kDayMs, 0);

        sf::ck::Init();
        uint64_t t1 = sf::ck::T1Ms();

        // ★ 铁律 (a)：只许向前。取小值就是 bug。
        Check(t1 >= t1inj, "★ T1 未发生任何倒退（铁律：只许向前）");
        Check(sf::ck::AnomalyCount() >= 1, "时钟回退已被记录为异常");
        printf("        异常描述 = %s\n", sf::ck::LastAnomaly());
    }

    // -----------------------------------------------------------------------
    printf("\n[7] 持久化：双冗余 + 校验和抗误改\n");
    // -----------------------------------------------------------------------
    {
        const wchar_t* dir = L"C:\\temp\\sfclock_test\\t7";
        sf::ck::DebugIsolatePersistence(dir);
        sf::ck::ResetForTest();

        uint64_t t1inj = WallMs() - 7 * kDayMs;
        sf::ck::DebugInjectState(t1inj, sf::ck::MonoMs(), ApproxBootTimeMs());

        uint64_t back = sf::ck::DebugReadPersistedT1();
        CheckNear(back, t1inj, 1, "注入值可被原样读回（写入/读出路径对称）");

        // ---- 篡改校验和：改动 t1 字段但不改 check，读取必须失败 ----
        // 这钉住的是"文件被误改/被工具破坏时不会被当成合法基线采纳"。
        std::wstring filePath = std::wstring(dir) + L"\\clock_state.bin";
        HANDLE h = CreateFileW(filePath.c_str(), GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) {
            Skip("校验和抗误改", "打不开状态文件（可能被 ACL 保护，属正常）");
        } else {
            // 偏移 8 = t1 字段（magic 4 + version 4）
            LARGE_INTEGER off; off.QuadPart = 8;
            SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
            unsigned char b = 0;
            DWORD rd = 0;
            if (ReadFile(h, &b, 1, &rd, nullptr) && rd == 1) {
                b ^= 0xFF;                       // 翻转 8 位
                SetFilePointerEx(h, off, nullptr, FILE_BEGIN);
                DWORD wr = 0;
                WriteFile(h, &b, 1, &wr, nullptr);
            }
            CloseHandle(h);

            uint64_t tampered = sf::ck::DebugReadPersistedT1();
            // 注册表在隔离模式下整体关闭 → 文件失败后应返回 0
            Check(tampered == 0,
                  "★ 被篡改的基线被拒绝采纳（校验和生效，未把脏数据当基线）");
        }
    }

    // -----------------------------------------------------------------------
    printf("\n[8] ★ 云端时钟旁站：真实联网取时（本用例是「时钟到底通不通」的实证）\n");
    // -----------------------------------------------------------------------
    {
        sf::ck::DebugIsolatePersistence(L"C:\\temp\\sfclock_test\\t8");
        sf::ck::ResetForTest();
        sf::ck::SetCloudEnabled(true);

        // 先建立一条"当前时间"基线，让 SubmitExternalAnchor 的"只接受更大值"
        // 有机会成立（否则 T1 若在用例 6 里被顶到未来 200 天，云端值会被忽略）。
        sf::ck::Init();
        uint64_t t1Before = sf::ck::T1Ms();

        bool ok = sf::ck::SyncCloudNow();
        const char* note = sf::ck::LastCloudNote();
        printf("        云端回执 = %s\n", note ? note : "(null)");

        if (!ok) {
            // 网络不可达属环境问题，不是代码缺陷 —— 记 SKIP 而不记 FAIL，
            // 否则离线环境下整个回归套件永远"红着"，真缺陷会被淹没。
            Skip("云端取时", note ? note : "网络不可达");
        } else {
            Check(true, "SyncCloudNow() 成功返回");
            uint64_t t1After = sf::ck::T1Ms();
            CheckNear(t1After, WallMs(), 8000, "T1 已锚定到云端时间（与墙上时间一致）");
            Check(t1After >= t1Before, "★ 采纳云端锚点后 T1 仍未倒退（同守铁律 a）");
            Check(sf::ck::DebugReadPersistedT1() != 0, "云端锚点已持久化（重启后仍有效）");
        }
    }

    // -----------------------------------------------------------------------
    printf("\n[9] Tick 漂移检测：正常环境不产生噪音\n");
    // -----------------------------------------------------------------------
    {
        sf::ck::DebugIsolatePersistence(L"C:\\temp\\sfclock_test\\t9");
        sf::ck::ResetForTest();
        sf::ck::SetCloudEnabled(false);      // 关掉联网，隔离出纯本地检测路径
        sf::ck::Init();

        uint32_t before = sf::ck::AnomalyCount();
        for (int i = 0; i < 5; ++i) sf::ck::Tick();
        uint32_t after = sf::ck::AnomalyCount();

        // 系统时钟在这几毫秒内不可能被改 60 秒以上（那是触发门槛）
        Check(after == before, "连续 Tick 不产生假异常（<60 秒偏差静默，防噪音）");
        Check(sf::ck::DriftMs() < 60000 && sf::ck::DriftMs() > -60000,
              "DriftMs() 处于正常范围（|累积偏差| < 60 秒）");
    }

    printf("\n=== 结果：%d 通过 / %d 失败 / %d 跳过 ===\n", g_pass, g_fail, g_skip);
    return g_fail == 0 ? 0 : 1;
}
