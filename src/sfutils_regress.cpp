// sfutils_regress.cpp — 公共契约（sfutils）回归测试
//
// 为什么必须测这几个函数：
//   它们的 bug 不会崩溃，只会**静默判定错误** —— 例如 IsUnderDir 若退化成子串
//   匹配，"C:\TempX\x.exe" 会被当成在 "C:\Temp" 之下，导致落地捕获把无关文件
//   隔离；PathEqualsCi 若漏掉大小写归一，回滚引擎会误认"文件没变过"而跳过恢复。
//   这类问题在真实环境里极难复现，只能靠用例钉住。
//
// 编译（与 trace_regress 同法）：
//   cl /nologo /MT /std:c++17 /utf-8 /O2 /EHsc sfutils_regress.cpp common.cpp <换行续写，见下行>
//      /link shell32.lib advapi32.lib bcrypt.lib crypt32.lib wintrust.lib wtsapi32.lib
#include "sfutils.h"
#include <cstdio>
#include <string>

static int g_pass = 0, g_fail = 0;

static void Check(bool cond, const char* what) {
    if (cond) { ++g_pass; printf("  [OK]   %s\n", what); }
    else      { ++g_fail; printf("  [FAIL] %s\n", what); }
}

static void CheckEq(const std::string& got, const std::string& want, const char* what) {
    if (got == want) { ++g_pass; printf("  [OK]   %s\n", what); }
    else { ++g_fail; printf("  [FAIL] %s\n        期望=\"%s\" 实际=\"%s\"\n", what, want.c_str(), got.c_str()); }
}

int main() {
    using namespace sf;

    printf("[1] ExtLower —— 小写扩展名\n");
    CheckEq(ExtLower("C:\\a\\b.EXE"), ".exe", "大写扩展名归一为小写");
    CheckEq(ExtLower("C:\\a\\b.txt"), ".txt", "普通扩展名");
    CheckEq(ExtLower("C:\\a\\noext"), "", "无扩展名返回空");
    // ★ 关键边界：目录里含点，文件本身无扩展名 —— 必须只取最后一段的点
    CheckEq(ExtLower("C:\\a.b\\file"), "", "目录含点+文件无扩展名 → 空（不误取目录里的点）");
    CheckEq(ExtLower("C:\\a.b\\file.dll"), ".dll", "目录含点+文件有扩展名 → 取文件的");
    CheckEq(ExtLower("C:\\a\\.gitignore"), "", "点开头（隐藏文件）视为无扩展名");

    printf("\n[2] NormPath —— 归一化分隔符\n");
    CheckEq(NormPath("C:/a/b/c"), "C:\\a\\b\\c", "正斜杠转反斜杠");
    CheckEq(NormPath("C:\\a\\b\\"), "C:\\a\\b", "去掉尾分隔符");
    CheckEq(NormPath("C:\\a\\b\\\\"), "C:\\a\\b", "去掉多个尾分隔符");
    CheckEq(NormPath("C:\\"), "C:\\", "盘根保留分隔符（不能剥成 C:）");
    CheckEq(NormPath("\\"), "\\", "单反斜杠根保留");
    CheckEq(NormPath(""), "", "空串安全");
    CheckEq(NormPath("C:\\A\\B"), "C:\\A\\B", "不改大小写（保持用户可见原样）");

    printf("\n[3] PathEqualsCi —— 大小写不敏感判等\n");
    Check(PathEqualsCi("C:\\Windows\\System32", "c:\\windows\\system32"), "大小写不同视为相等");
    Check(PathEqualsCi("C:\\a\\b\\", "C:\\a\\b"), "尾分隔符差异视为相等");
    Check(PathEqualsCi("C:/a/b", "C:\\a\\b"), "分隔符风格差异视为相等");
    Check(!PathEqualsCi("C:\\a\\b", "C:\\a\\c"), "不同路径不相等");
    Check(!PathEqualsCi("", "C:\\a"), "空串与非空不等");
    Check(PathEqualsCi("", ""), "空串与空串相等");

    printf("\n[4] IsUnderDir —— 目录归属（★ 不得退化成子串匹配）\n");
    Check(IsUnderDir("C:\\Windows\\Temp\\x.exe", "C:\\Windows\\Temp"), "直接子文件在目录下");
    Check(IsUnderDir("C:\\Windows\\Temp\\a\\b\\x.exe", "C:\\Windows\\Temp"), "深层子文件在目录下");
    Check(IsUnderDir("C:\\Windows\\Temp\\x.exe", "C:\\Windows\\Temp\\"), "目录带尾分隔符也正确");
    Check(IsUnderDir("c:\\windows\\temp\\x.exe", "C:\\Windows\\Temp"), "大小写不敏感");
    // ★ 这两个是子串匹配写法会判错、而本实现必须判对的反例
    Check(!IsUnderDir("C:\\Windows\\TempX\\x.exe", "C:\\Windows\\Temp"), "同前缀的兄弟目录**不算**（TempX vs Temp）");
    Check(!IsUnderDir("C:\\Windows\\Temp", "C:\\Windows\\Temp"), "目录自身不算在自己的子项里");
    Check(!IsUnderDir("C:\\a\\x.exe", "C:\\a\\b"), "父级文件不算在子目录下");
    Check(!IsUnderDir("", "C:\\a"), "空路径不算");
    Check(!IsUnderDir("C:\\a\\x.exe", ""), "空目录不算");

    printf("\n[5] NowStr —— 时间戳格式唯一性\n");
    std::string ts = NowStr();
    // 必须严格是 "YYYY-MM-DD HH:MM:SS"：长度 19、分隔符位置固定
    Check(ts.size() == 19, "长度恰为 19");
    Check(ts.size() >= 19 && ts[4] == '-' && ts[7] == '-' && ts[10] == ' ' &&
          ts[13] == ':' && ts[16] == ':', "分隔符位置符合 YYYY-MM-DD HH:MM:SS");
    bool allNum = true;
    if (ts.size() >= 19) {
        for (int i : {0,1,2,3,5,6,8,9,11,12,14,15,17,18})
            if (ts[i] < '0' || ts[i] > '9') allNum = false;
    }
    Check(allNum, "数字位全为数字（无 locale 干扰）");
    // 年份应在合理区间（防止 localtime 用错系统调用）
    int year = ts.size() >= 4 ? atoi(ts.substr(0, 4).c_str()) : 0;
    Check(year >= 2020 && year <= 2100, "年份在合理区间");
    // 连续两次调用应相同或递增（不倒退）
    std::string ts2 = NowStr();
    Check(ts2 >= ts, "时间不倒退（单调不减）");

    printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
