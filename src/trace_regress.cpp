// trace_regress — 行为图模块回归测试
//
// 为什么需要它：行为图的输出是给用户看的 JSON，一旦格式错（漏逗号、转义错、
// 下标越界）前端整块渲染不出来，而弹窗是"用完即退"的一次性进程，现场难排查。
// 所以这里在编译期外单独喂数据、单独断言。
//
// 编译（见 build 末尾的 regress 段）：
//   cl /MT /std:c++17 /utf-8 trace_regress.cpp trace.cpp common.cpp <换行续写，见下行>
//      /Fe:trace_regress.exe /link advapi32.lib bcrypt.lib
//
// 断言项：
//   ① 空缓冲：GraphJson 不能崩，且返回合法 JSON 骨架
//   ② 六类事实各记一条 → summary.fact == 6，sources 顺序稳定
//   ③ 落地+自启（无进程）→ 生成 1 条 exec 推断；再加进程事实 → 推断消失
//   ④ 密钥 + 进程 → 生成 encrypt 推断
//   ⑤ token 焦点定位正确（focus 指向 token 对应的节点）
//   ⑥ 2 秒内同路径同类型去重
//   ⑦ 容量上限（>512 条不越界）
//   ⑧ JSON 基本合法性：括号配平、无裸换行、无未转义引号
#include <windows.h>
#include <cstdio>
#include <string>
#include "trace.h"

static int g_pass = 0, g_fail = 0;

static void Check(bool ok, const char* what) {
    if (ok) { ++g_pass; printf("  [OK]   %s\n", what); }
    else    { ++g_fail; printf("  [FAIL] %s\n", what); }
}

// 极简 JSON 合法性自检：括号配平 + 字符串外的换行/控制字符
static bool JsonRoughOK(const std::string& s) {
    if (s.empty() || s.front() != '{' || s.back() != '}') return false;
    int depth = 0; bool inStr = false, esc = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (esc) { esc = false; continue; }
        if (inStr) {
            if (c == '\\') { esc = true; continue; }
            if (c == '"')  { inStr = false; continue; }
            if ((unsigned char)c < 0x20) return false;   // 字符串里不许有裸控制字符
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '{' || c == '[') ++depth;
        else if (c == '}' || c == ']') { if (--depth < 0) return false; }
        else if (c == '\n' || c == '\r') return false;
    }
    return depth == 0 && !inStr;
}

static int CountOccur(const std::string& s, const std::string& needle) {
    int n = 0; size_t p = 0;
    while ((p = s.find(needle, p)) != std::string::npos) { ++n; p += needle.size(); }
    return n;
}

int main() {
    // 本文件是 UTF-8 源码，控制台按 UTF-8 输出，避免中文断言描述变乱码
    SetConsoleOutputCP(65001);
    printf("=== trace_regress：行为图模块回归 ===\n");

    // ---- ① 空缓冲 ----
    printf("\n[1] 空缓冲\n");
    trace::Reset();
    {
        std::string js = trace::GraphJson();
        Check(JsonRoughOK(js), "空缓冲 GraphJson 是合法 JSON");
        Check(js.find("\"nodes\":[]") != std::string::npos, "空缓冲 nodes 为空数组");
        Check(js.find("\"focus\":-1") != std::string::npos, "空缓冲 focus = -1");
    }

    // ---- ② 六类事实齐全 ----
    printf("\n[2] 六类事实齐全\n");
    trace::Reset();
    trace::Record(trace::Kind::Landed, "a.exe",
                  "在 Temp 目录落地且形态可疑，已自动隔离",
                  "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe",
                  "30ab12cd34", true, 200);
    trace::Record(trace::Kind::RegRun, "a.exe",
                  "试图通过注册表自启动建立持久化，已自动移除该启动项",
                  "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe",
                  "20cd34ef56", true, 200);
    trace::Record(trace::Kind::Process, "a.exe",
                  "命中行为规则（office-spawn-host），已自动终止该进程",
                  "C:\\Users\\x\\AppData\\Local\\Temp\\a.exe", "", true, 200);
    trace::Record(trace::Kind::Boot, "diskpart.exe",
                  "正在修改系统引导扇区（MBR），已自动终止并恢复引导记录",
                  "C:\\Windows\\System32\\diskpart.exe", "10ff00aa11", true, 200);
    trace::Record(trace::Kind::Key, "b.exe",
                  "发现批量文件改写，疑似密钥落盘", "C:\\Users\\x\\Documents\\b.exe", "", false, 150);
    trace::Record(trace::Kind::Rollback, "b.exe",
                  "已还原 12 个被改写文件，3 个无快照不可恢复", "", "", true, 200);
    {
        std::string js = trace::GraphJson();
        Check(JsonRoughOK(js), "六类事实 GraphJson 是合法 JSON");
        Check(js.find("\"fact\":6") != std::string::npos, "summary.fact == 6");
        Check(CountOccur(js, "\"type\":\"fact\"") >= 6, "事实节点 >= 6");
        // sources 顺序：process 在 landed 之前（固定顺序，前端稳定渲染）
        size_t pProc = js.find("\"process\"");
        size_t pLand = js.find("\"landed\"");
        Check(pProc != std::string::npos && pLand != std::string::npos && pProc < pLand,
              "sources 顺序稳定（process 在 landed 之前）");
        // 有 Process 事实 → 不应出现 exec 推断
        Check(js.find("\"kind\":\"exec\"") == std::string::npos,
              "已有进程事实时不生成 exec 推断（不给用户看没有的东西）");
        // 有 Key 事实 → 应有 encrypt 推断
        Check(js.find("\"kind\":\"encrypt\"") != std::string::npos,
              "密钥事实存在时生成 encrypt 推断");
        // 推断节点必须带 basis + confidence
        Check(js.find("\"confidence\":\"mid\"") != std::string::npos, "推断节点带 confidence");
        Check(js.find("\"basis\":[") != std::string::npos, "推断节点带 basis");
        // 中文必须被原样保留（UTF-8，不转 \uXXXX）
        Check(js.find("已自动隔离") != std::string::npos, "中文 detail 未被转义成 \\uXXXX");
        // 反斜杠路径必须被转义（JSON 合法性）
        Check(js.find("C:\\\\Users\\\\x") != std::string::npos, "Windows 路径反斜杠已转义");
    }

    // ---- ③ 落地+自启、无进程 → exec 推断 ----
    printf("\n[3] 落地+自启 无进程 → exec 推断\n");
    trace::Reset();
    trace::Record(trace::Kind::Landed, "c.exe", "落地即捕获可疑载荷",
                  "C:\\Temp\\c.exe", "30aa000001", true, 200);
    trace::Record(trace::Kind::RegRun, "c.exe", "已自动移除该启动项",
                  "C:\\Temp\\c.exe", "20bb000002", true, 200);
    {
        std::string js = trace::GraphJson();
        Check(js.find("\"kind\":\"exec\"") != std::string::npos,
              "落地+自启组合生成 exec 推断");
        Check(js.find("\"infer\":1") != std::string::npos, "summary.infer == 1");
        // ★ 别用 CountOccur(js, "\"type\":\"infer\"") 断言节点数 ——
        //   边也用 "type":"infer"，会一并数进去（第一次写这个用例时误判过）。
        //   节点与边的区分特征是"后面跟的是逗号/右括号（节点对象）还是索引（边对象）"，
        //   这里用更直接的判据：infer 节点必带 confidence 字段，事实节点没有。
        Check(CountOccur(js, "\"confidence\":") == 1, "推断节点恰好 1 个（数 confidence）");
        // 推断边必须以 "type":"infer"} 结尾（区别于事实边的 "type":"fact"}）
        Check(CountOccur(js, "\"type\":\"infer\"}") == 2,
              "2 条推断边（两条依据各连一条）");
    }

    // ---- ④ 只有自启、无落地无进程 → persist 推断 ----
    printf("\n[4] 仅自启 → persist 推断\n");
    trace::Reset();
    trace::Record(trace::Kind::RegRun, "d.exe", "已自动移除该启动项",
                  "C:\\Temp\\d.exe", "20cc000003", true, 200);
    {
        std::string js = trace::GraphJson();
        Check(js.find("\"kind\":\"persist\"") != std::string::npos, "仅自启生成 persist 推断");
        Check(js.find("\"kind\":\"exec\"") == std::string::npos, "无落地时不生成 exec 推断");
    }

    // ---- ⑤ token 焦点定位 ----
    //  ★ 注意：每条要用**不同的 path**，否则会被 2 秒去重逻辑合并成一条
    //  （第一次写这个用例时踩过：5 条同路径事件只剩 1 条，误以为焦点算错了）。
    printf("\n[5] token 焦点定位\n");
    trace::Reset();
    for (int i = 0; i < 5; ++i) {
        char tok[16]; snprintf(tok, sizeof(tok), "30aa0000%02d", i);
        char p[64];   snprintf(p, sizeof(p), "C:\\Temp\\e%d.exe", i);
        trace::Record(trace::Kind::Landed, "e.exe", "落地捕获", p, tok, true, 200);
    }
    {
        std::string js = trace::GraphJson("30aa000003");
        // 5 条事实，焦点是第 4 条（下标 3）
        Check(js.find("\"focus\":3") != std::string::npos, "focus 指向 token 对应节点（下标 3）");
        Check(js.find("\"fact\":5") != std::string::npos, "窗口内 5 条事实");
    }

    // ---- ⑥ 去重 ----
    printf("\n[6] 2 秒内同路径同类型去重\n");
    trace::Reset();
    trace::Record(trace::Kind::Landed, "f.exe", "短", "C:\\Temp\\f.exe", "", true, 200);
    trace::Record(trace::Kind::Landed, "f.exe", "更长的说明文本保留这条", "C:\\Temp\\f.exe", "", true, 200);
    {
        int n = trace::Count();
        Check(n == 1, "同路径同类型 2 秒内只记一条");
        std::string js = trace::GraphJson();
        Check(js.find("更长的说明文本") != std::string::npos, "保留信息量更大的那条");
    }

    // ---- ⑦ 容量上限 ----
    printf("\n[7] 容量上限 %d\n", trace::kCapacity);
    trace::Reset();
    for (int i = 0; i < trace::kCapacity + 200; ++i) {
        char p[64]; snprintf(p, sizeof(p), "C:\\Temp\\n%d.exe", i);
        char d[64]; snprintf(d, sizeof(d), "事件 %d", i);
        trace::Record(trace::Kind::Process, d, d, p, "", true, 100);
    }
    {
        int n = trace::Count();
        Check(n == trace::kCapacity, "缓冲不超容量（丢弃最旧）");
        std::string js = trace::GraphJson();
        Check(JsonRoughOK(js), "满载后 GraphJson 仍合法");
        Check(js.size() > 100, "满载后输出非空");
    }

    // ---- ⑦.5 ★ 节点分隔逗号（真实踩过的非法 JSON bug）----
    //  症状：输出里出现 `…,"extra":""}{"i":2,…` —— 事实节点与推断节点之间漏了逗号，
    //        前端 JSON.parse 直接抛异常，整块行为图渲染不出来。
    //  根因：推断节点循环用「循环下标 k/total」判断要不要加逗号，
    //        而事实节点数为 0 时第一条推断的下标也是 0，于是判成"首个元素"。
    //  这个用例专门构造"事实齐全但边界相邻"的组合，断言节点之间必有逗号。
    printf("\n[7.5] 节点分隔逗号（非法 JSON 回归）\n");
    trace::Reset();
    {
        // 只有一条事实 + 会生成推断的组合 → 事实与推断直接相邻
        trace::Record(trace::Kind::RegRun, "h.exe", "已自动移除该启动项",
                      "C:\\Temp\\h.exe", "20dd000009", true, 200);
        std::string js = trace::GraphJson();
        Check(JsonRoughOK(js), "单事实+推断 仍是合法 JSON");
        Check(js.find("}\"}{") == std::string::npos &&
              js.find("\"}{\"") == std::string::npos,
              "节点之间没有缺失逗号（无 `}{\"` 相邻）");
    }
    {
        // 零事实不可能有推断，但仍要保证骨架合法
        trace::Reset();
        std::string js = trace::GraphJson();
        Check(JsonRoughOK(js), "零事实骨架合法");
    }

    // ---- ⑧ RecentJson ----
    printf("\n[8] RecentJson\n");    trace::Reset();
    trace::Record(trace::Kind::Process, "g.exe", "已自动终止", "C:\\Temp\\g.exe", "", true, 200);
    {
        std::string js = trace::RecentJson(10);
        Check(JsonRoughOK(js), "RecentJson 合法");
        Check(js.find("\"count\":1") != std::string::npos, "RecentJson count == 1");
    }
    trace::Reset();
    {
        std::string js = trace::RecentJson();
        Check(JsonRoughOK(js), "空缓冲 RecentJson 合法");
    }

    printf("\n=== 结果：%d 通过 / %d 失败 ===\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
