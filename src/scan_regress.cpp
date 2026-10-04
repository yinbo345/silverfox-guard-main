// scan_regress — 全盘扫描误报回归（直接链接 scanner.cpp，不装服务、不弹窗）
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include "scanner.h"

int main(int argc, char** argv) {
    ScannerInit();
    printf("开始全盘扫描（约 20-60 秒）...\n");
    fflush(stdout);
    RunFullScan();
    printf("\n=== 结果 ===\n");
    printf("status = %s   score = %d   findings = %zu   selfCheck = %d\n",
           g_result.status.c_str(), g_result.score, g_result.findings.size(), (int)g_result.selfCheck);
    std::map<std::string, int> byTitle;
    for (const auto& f : g_result.findings) byTitle[f.category + "/" + f.severity + "/" + f.title]++;
    printf("\n--- 发现项分布 ---\n");
    for (const auto& kv : byTitle) printf("  %4d  %s\n", kv.second, kv.first.c_str());
    printf("\n--- 明细（含路径）---\n");
    for (size_t i = 0; i < g_result.findings.size(); ++i) {
        const auto& f = g_result.findings[i];
        printf("%2zu. [%s/%s] %s\n", i + 1, f.category.c_str(), f.severity.c_str(), f.title.c_str());
        if (!f.path.empty()) printf("      path = %s\n", f.path.c_str());
    }
    ScannerCleanup();
    return 0;
}
