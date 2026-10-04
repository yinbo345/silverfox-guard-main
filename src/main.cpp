// main.cpp — 银狐主防服务主入口（模式分发）
// 本程序无托盘、无独立页面、无本地端口；常驻为 Windows 服务，结果只在扩展内查看。
// P6 起：主界面（--gui / 双击）为独立 WebView2 窗口 + 系统托盘，数据经命名管道直连服务。
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>   // IsUserAnAdmin

#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <string>

#include "common.h"
#include "service.h"
#include "gui.h"
#include "sandbox.h"   // 沙箱分析（阶段一），供 --sandbox-scan 调试钩子使用
#include "errhold.h"  // 无结论决策待决表（--errhold-selftest）

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

#ifndef IDI_SHIELD
#define IDI_SHIELD 101
#endif

static bool HasArg(int argc, char** argv, const char* name) {
    std::string t = std::string("--") + name;
    for (int i = 1; i < argc; ++i) if (t == argv[i]) return true;
    return false;
}
static std::string GetArg(int argc, char** argv, const char* name) {
    std::string n = std::string("--") + name + "=";
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind(n, 0) == 0) {
            std::string v = a.substr(n.size());
            // 去掉外壳可能带入的引号（如安装包 --ext-id="xxx"）
            if (!v.empty() && v.front() == '"' && v.back() == '"') v = v.substr(1, v.size() - 2);
            return v;
        }
    }
    return "";
}

// 用我们的品牌盾牌图标弹窗（替代系统默认图标）
static void ShowShieldMsg(const wchar_t* text) {
    HICON hIcon = (HICON)LoadImageW(GetModuleHandle(NULL),
                                    (LPCWSTR)MAKEINTRESOURCEW(IDI_SHIELD),
                                    IMAGE_ICON, 0, 0, LR_DEFAULTSIZE | LR_SHARED);
    MSGBOXPARAMSW mbp = { sizeof(mbp) };
    mbp.hwndOwner   = NULL;
    mbp.hInstance   = GetModuleHandle(NULL);
    mbp.lpszText    = text;
    mbp.lpszCaption = L"银狐主防";
    mbp.dwStyle     = MB_OK | MB_USERICON;
    mbp.lpszIcon    = (LPCWSTR)hIcon;
    MessageBoxIndirectW(&mbp);
}

static void GuiNotify(bool ok, const wchar_t* msg) {
    if (GetConsoleWindow() != NULL) return;   // 命令行下不打扰，交给 printf
    ShowShieldMsg(msg);
}

// ASCII 字符串 → wstring（status/score 均为 ASCII 范围，逐字节映射即可）
static std::wstring A2W(const std::string& s) {
    std::wstring w; w.resize(s.size());
    for (size_t i = 0; i < s.size(); ++i) w[i] = (wchar_t)(unsigned char)s[i];
    return w;
}

// ANSI(GBK) → wstring：命令行中文参数按系统 ANSI 代码页传入，逐字节映射会变乱码
static std::wstring AnsiToW(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// wstring → UTF-8（供 --sandbox-* 钩子把命令行宽参数转回服务内部使用的 UTF-8 路径）
static std::string W2U8(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return "";
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

// 从宽命令行里取 --name=value（支持中文 / 空格值；--file= 路径用此取，避免 argv 的 ANSI 截断）
static std::wstring GetArgW(const std::wstring& nameEq) {
    int wargc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
    if (!wargv) return L"";
    std::wstring out;
    for (int i = 0; i < wargc; ++i) {
        std::wstring a(wargv[i]);
        if (a.rfind(nameEq, 0) == 0) { out = a.substr(nameEq.size()); break; }
    }
    LocalFree(wargv);
    return out;
}

// ===== 自保：服务不在运行时的自愈（NM 宿主触发）=====
// 背景：GuardThread 里每 30 分钟 EnsureServiceRegistered() 只能在「服务活着」时防删除；
// 若银狐 \`sc stop\` 停掉服务（正常停止不触发 SCM 失败自启），服务就再也起不来。
// 此处由【浏览器拉起 NM 宿主】触发：连不上服务管道 → 尝试注册并启动服务（自保）。
// 因 NM 宿主由浏览器以用户会话拉起，默认非管理员，SvcInstall/Start 常失败——但我们仍
// 尝试：多数被停的服务仅缺 START（LocalSystem 服务可被普通用户 StartService 的场景
// 有限），因此自愈优先尝试 StartService（无需提权），失败才尝试重建（需管理员）。
// 纯自愈逻辑，静默失败不影响主流程。
static void SelfHealService() {
    if (sf::IsServiceRunning()) return;   // 已在跑 → 无需动作
    // ★ 维护模式闸门（2026-09-27）：这是"删了也回来"的**真凶**——它由【浏览器拉起
    //   NM 宿主】触发，只要用户开一次浏览器就会把被删/被停的服务重新装上并启动，
    //   所以用户"怎么停都停不掉"。维护模式标记存在时直接退出，不做任何自愈。
    //   标记文件由服务端(SYSTEM)创建并收紧 ACL，普通权限无法伪造（见 common.h）。
    if (sf::MaintenanceActive()) {
        static bool logged = false;
        if (!logged) { logged = true; sf::LogDbg("[maint] 维护模式生效：NM 宿主跳过服务自愈"); }
        return;
    }
    // 1) 已注册：直接尝试启动（普通用户 StartService 对 SYSTEM 服务通常被拒，但成本极低）
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, sf::SVC_NAME, SERVICE_START);
    if (svc) {
        StartServiceW(svc, 0, nullptr);
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }
    CloseServiceHandle(scm);
    // 2) 服务已被删除：尝试重建（需管理员；普通用户失败则留给下次扩展重装/安装器接管）
    sf::SvcInstall();
    // 3) 重建后立刻尝试启动
    scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm) {
        svc = OpenServiceW(scm, sf::SVC_NAME, SERVICE_START);
        if (svc) { StartServiceW(svc, 0, nullptr); CloseServiceHandle(svc); }
        CloseServiceHandle(scm);
    }
}

// ---- 预热结果文件（与 toast.cpp 的 PrewarmResultPathW 保持一致）----
static std::wstring PrewarmResultPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\prewarm_result.txt";
}
static void WritePrewarmResult(const std::string& status, int score) {
    std::wstring path = PrewarmResultPathW();
    DeleteFileW(path.c_str());
    std::string data = "status=" + status + " score=" + std::to_string(score);
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
                           nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, data.c_str(), (DWORD)data.size(), &w, nullptr);
    CloseHandle(h);
}
static bool PrewarmResultExists() {
    return GetFileAttributesW(PrewarmResultPathW().c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 弹窗去重（落盘版）：浏览器扩展每次轮询都会拉起【新宿主进程】，进程内 static 去重
// 会被重置 → status 非 normal 时每 30 秒弹一次（用户反馈的 bug）。改为写盘记录
// 「已通知状态 + 时间戳」：同状态在 TTL 内不重复弹，状态变化立即弹，TTL 后允许复弹。
// 路径：C:\ProgramData\SilverFoxGuard\toast_dedup.txt，内容 "status|unix秒"
static std::wstring ToastDedupPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\toast_dedup.txt";
}
// 返回 true=应弹窗（未在 TTL 内通知过相同状态）；false=去重跳过
static bool ShouldToast(const std::string& status, const int ttlSec) {
    std::wstring path = ToastDedupPathW();
    // 读旧记录
    std::string prev;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        char buf[128] = {0}; DWORD n = 0;
        ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
        CloseHandle(h);
        if (n) prev.assign(buf, n);
    }
    long long now = (long long)time(nullptr);
    std::string cur = status + "|" + std::to_string(now);
    // 解析旧状态与时间
    if (!prev.empty()) {
        size_t bar = prev.find('|');
        if (bar != std::string::npos) {
            std::string pSt = prev.substr(0, bar);
            long long pT  = atoll(prev.c_str() + bar + 1);
            if (pSt == status && (now - pT) < ttlSec) return false;   // 同状态且未过 TTL
        }
    }
    // 写新记录
    h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD w = 0; WriteFile(h, cur.c_str(), (DWORD)cur.size(), &w, nullptr);
        CloseHandle(h);
    }
    return true;
}

// 单程序兼任 Native Messaging 宿主：被浏览器拉起时 stdin 是管道。
// 与服务的命名管道保持【单一长连接】，所有 status/rescan 帧复用同一连接，
// 不再每次轮询都重连（避免反复拉起新宿主进程 / 扩展侧掉线）。
static void RunNmHost() {
    HANDLE inh  = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE outh = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetFileType(inh) != FILE_TYPE_PIPE) return;

    HANDLE pipe = INVALID_HANDLE_VALUE;
    auto connectPipe = [&]() -> bool {
        for (int i = 0; i < 25; ++i) {
            pipe = CreateFileW(sf::PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
            if (pipe != INVALID_HANDLE_VALUE) return true;
            Sleep(300);
        }
        return false;
    };

    while (true) {
        if (pipe == INVALID_HANDLE_VALUE) {
            if (!connectPipe()) {
                // 服务还没起来：①先自保恢复（若被 sc stop / delete 则重建并启动——开源仓库不含此逻辑）②
                // 告知扩展离线，稍后自动重试（保持进程存活，待服务就绪即复用）
                SelfHealService();   // 自保：服务不在运行则拉起，静默失败不影响后续
                sf::WriteFramed(outh, "{\"type\":\"service_unavailable\"}");
                Sleep(2000);
                continue;
            }
        }
        std::string req;
        if (!sf::ReadFramed(inh, req)) break;   // 浏览器关闭端口 → 退出
        std::string type = sf::JsonGetString(req, "type");
        // clean 也复用同一条命名管道：扩展面板里的「一键清除」由服务以最高权限执行（无需 UAC）
        std::string cmd, extra;
        if (type == "rescan") cmd = "rescan";
        else if (type == "clean") cmd = "clean";
        else if (type == "history") cmd = "history";
        else if (type == "gpuget") cmd = "gpuget";
        else if (type == "gpuprog") cmd = "gpuprog";   // 地图加载进度（扩展端进度条轮询）
        else if (type == "gpu") { cmd = "gpu"; extra = ",\"on\":" + std::to_string(sf::JsonGetInt(req, "on")); }
        // 勒索回滚（对齐卡巴 System Watcher）：状态查询 / 快照清单 / 手动回滚 / 清空缓存
        else if (type == "rollbackstatus") cmd = "rollbackstatus";
        else if (type == "rollbacklist")   cmd = "rollbacklist";
        else if (type == "rollbackdo") {
            cmd = "rollbackdo";
            extra = ",\"reason\":\"" + sf::JsonEscape(sf::JsonGetString(req, "reason")) + "\"";
        }
        else if (type == "rollbackclean")  cmd = "rollbackclean";
        else if (type == "rollbackundo") {
            cmd = "rollbackundo";
            extra = ",\"token\":\"" + sf::JsonEscape(sf::JsonGetString(req, "token")) + "\"";
        }
        else cmd = "status";

        // 预热：rescan 会触发全量扫描（约 20 秒），期间提前预热 WebView2，扫描出异常即可立即显示，
        // 省去扫描完成后弹窗的冷启动 5~8 秒。
        if (cmd == "rescan") {
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring precmd = std::wstring(L"\"") + exepath + L"\" --scanprogress";
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            if (CreateProcessW(nullptr, (LPWSTR)precmd.c_str(), nullptr, nullptr, FALSE,
                               0, nullptr, nullptr, &si, &pi)) {
                if (pi.hThread) CloseHandle(pi.hThread);
                if (pi.hProcess) CloseHandle(pi.hProcess);
            }
        }

        if (!sf::WriteFramed(pipe, "{\"cmd\":\"" + cmd + "\"" + extra + "}")) {
            CloseHandle(pipe); pipe = INVALID_HANDLE_VALUE;   // 连接断了，下一轮重连
            continue;
        }
        std::string resp;
        if (!sf::ReadFramed(pipe, resp)) {
            CloseHandle(pipe); pipe = INVALID_HANDLE_VALUE;
            continue;
        }
        sf::WriteFramed(outh, resp);

        // —— 弹窗触发 ——
        // NM 宿主由浏览器拉起，运行在【用户桌面会话】，这里拉起的 --toast 100% 可见有声（Session 0
        // 服务跨会话弹窗在 VM/RDP 下不可见）。rescan 场景优先由预热进程显示（读结果文件）；
        // 预热进程消费结果（删文件）则不再重复拉起，未消费（预热失败）才回退正常 --toast。
        static std::string s_lastNmToast;
        std::string st = sf::JsonGetString(resp, "status");
        int sc = sf::JsonGetInt(resp, "score");   // 必须用 JsonGetInt：JSON 里 score 是裸数字，JsonGetString 取不到
        if (cmd == "rescan") {
            WritePrewarmResult(st, sc);
            bool consumed = false;
            for (int i = 0; i < 15 && PrewarmResultExists(); ++i) Sleep(200);   // 最多等 3 秒
            consumed = !PrewarmResultExists();
            if (consumed) {
                s_lastNmToast = st;   // 预热进程已消费（异常显示 / 正常退出），更新去重，避免后续 status 重复弹
                continue;
            }
        }
        if (!st.empty() && st != "normal" && st != s_lastNmToast && ShouldToast(st, 900)) {
            s_lastNmToast = st;
            wchar_t exepath[MAX_PATH];
            GetModuleFileNameW(nullptr, exepath, MAX_PATH);
            std::wstring tcmd = std::wstring(L"\"") + exepath + L"\" --toast --status=" + A2W(st)
                             + L" --score=" + std::to_wstring(sc);
            STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
            // bInheritHandles=FALSE：避免子进程继承本宿主的 stdin 管道而被误判为 NM 宿主模式
            if (CreateProcessW(nullptr, (LPWSTR)tcmd.c_str(), nullptr, nullptr, FALSE,
                              0, nullptr, nullptr, &si, &pi)) {
                if (pi.hThread) CloseHandle(pi.hThread);
                if (pi.hProcess) CloseHandle(pi.hProcess);
            }
        }
    }
    if (pipe != INVALID_HANDLE_VALUE) CloseHandle(pipe);
}

// GUI 子系统（/SUBSYSTEM:WINDOWS）下进程默认没有控制台，--console 调试模式需手动挂载：
// 优先附着父进程控制台（从 cmd 运行时可见），失败则新建一个。同时把 std 流重定向到控制台，
// 否则 printf 无处可去（GUI 进程的 stdout 默认不连任何设备）。
static void EnsureConsoleForDebug() {
    // 已被重定向到文件/管道（如脚本里 \`> out.txt\`）时直接沿用，绝不能 AllocConsole：
    DWORD t = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
    if (t == FILE_TYPE_DISK || t == FILE_TYPE_PIPE) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS) && !AllocConsole()) return;
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
    freopen_s(&f, "CONIN$", "r", stdin);
}

// P3 主动防御：进程加固（所有入口最先执行）。
// 本程序是安全软件自身，禁止动态代码生成/修改 → 注入的 shellcode 无法在本进程内执行
// （防 AtomBombing / ATL thunk / 各类 WriteProcessMemory+远程线程 的注入落地）。
// 纯 C++/MT 单文件，无 JIT，无影响。
static void HardenSelf() {
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dcp{};
    dcp.ProhibitDynamicCode = 1;
    SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dcp, sizeof(dcp));
}

int main(int argc, char** argv) {
    // WebView2 宿主模式（--gui / --toast / --prewarm）不启用「禁止动态代码」策略：
    // Chromium browser 进程需动态分配可执行内存，被 ProcessDynamicCodePolicy 禁止后
    // 渲染进程初始化失败 → 页面白屏、NavigationCompleted 永不触发（P3 加固曾致 GUI/弹窗
    // 双双白屏，本修复按模式豁免 WebView2 宿主，其余入口仍加固）。
    const bool wv2Host = HasArg(argc, argv, "gui") || HasArg(argc, argv, "toast") || HasArg(argc, argv, "prewarm");
    if (!wv2Host) HardenSelf();
    // 浏览器通过 Native Messaging 拉起本程序时，stdin 是匿名管道
    //
    // ★★ 2026-10-03 修正（实测卡死 18 分钟）：**显式程序开关优先于 NM 判定**。
    //   原写法只看 `GetFileType(stdin)==FILE_TYPE_PIPE` 就进 NM 宿主，
    //   位置在所有 `--xxx` 分派**之前**。后果：任何**脚本化调用**都会踩 ——
    //   shell 的 `if cmd; then` / `cmd | tee` 会把 stdio 接成管道，
    //   于是 `--errhold-selftest` 这类自测**根本走不到**，
    //   进程进去读管道 ⇒ 永久阻塞，且**不报错、不退出**（构建看起来只是"卡住"）。
    //   实测：为此卡死 18 分钟。
    //
    //   ⚠️ 判据不能用「argc>1」：NM 宿主模式下 Chromium 传的**也是** `--` + payload
    //   （见 toast-app 的 parseArgs：唯一可靠来源就是 `--` 之后那一段），
    //   所以 argc>1 在宿主场景同样成立，会把真宿主误判成程序调用。
    //   ⇒ 只能用**已知程序开关白名单**：这些名字只可能来自人手或脚本，
    //     NM 宿主永远不会带（它的载荷是 `status=…&score=…` 这种 k=v 形态）。
    static const char* const kProgSwitches[] = {
        "gui", "toast", "prewarm", "console", "install", "uninstall", "run-service",
        "errhold-selftest", "sandbox-scan", "sandbox-qtest",
        "sandbox-result", "sandbox-progress", "scanprogress", "probe",
    };
    bool hasProgSwitch = false;
    for (const char* sw : kProgSwitches)
        if (HasArg(argc, argv, sw)) { hasProgSwitch = true; break; }

    const bool pipeStdin = (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_PIPE);
    if (pipeStdin && !hasProgSwitch) {
        RunNmHost();
        return 0;
    }
    if (pipeStdin && hasProgSwitch) {
        // 明确记一行：否则「参数被吃掉」这类故障在日志里完全看不见
        //  （现象是"命令没反应 + 没有报错"，极难定位）。
        fprintf(stderr, "[银狐主防] 提示：检测到 stdin 是管道但命令行带程序开关，"
                        "按程序模式处理（不进入 NM 宿主）。\n");
    }

    if (HasArg(argc, argv, "install") || HasArg(argc, argv, "uninstall")) {
        if (!IsUserAnAdmin())
            fprintf(stderr, "[银狐主防] 提示：安装 / 卸载需以管理员身份运行。\n");
    }

    if (HasArg(argc, argv, "run-service")) { sf::RunService(); return 0; }

    // ---- 无结论决策待决表自测（2026-10-03）----
    //  单独保留的理由：errhold 是「删文件」的唯一授权闸门（只认令牌），
    //  它的两类失效都**不报错**：令牌校验松 ⇒ 任何本地程序能让服务删任意文件；
    //  回调缺装配 ⇒ 文件被永久锁死。所以必须有自测兜底并纳入构建硬失败。
    if (HasArg(argc, argv, "errhold-selftest")) {
        return sf::errhold::RunSelfTest();
    }

    // 沙箱分析调试钩子（2026-09-27，阶段一）：
    //     --sandbox-scan=<样本路径> [--dryrun] [--wait=<秒>]
    // 用途：在**不依赖界面**的前提下，端到端验证"环境探测 → 快照 → 送检 →
    //   diff → 病毒库点查 → 评分 → 播报"这条链本身是否成立 —— 阶段一最该先
    //   证明的就是这条链，而不是先做界面。
    // 两个刻意的设计：
    //   ① 报告同时写一份 JSON 到 %TEMP%\sf_sandbox_report.json —— 本程序是
    //      GUI 子系统（/SUBSYSTEM:WINDOWS），没有控制台时 printf 什么都看不见，
    //      只靠 stdout 会让"跑通了但像没跑"。
    //   ② --dryrun 不送检，只走快照/diff/评分。沙箱服务（SbieSvc）未就绪时，
    //      这是唯一能验证判定核心的路径。
    // 注意：以本方式运行时病毒库可能尚未加载，哈希点查会返回"无意见"——
    //      那是"这条判据没看到"，**不是"这个文件干净"**。完整判定请走服务端
    //      管道命令 sandboxscan（库已由服务加载）。
    // ★★ 2026-09-27 实测踩坑（首次真机验证就中）：
    //   `--sandbox-scan` 是**带值参数**，必须用 GetArg 取。
    //   原写法 `if (HasArg(argc, argv, "sandbox-scan"))` 是错的 ——
    //   HasArg 用 `t == argv[i]` 做**完全相等**比较，而命令行里是
    //   `--sandbox-scan=C:\...\probe.bat`，永远不相等 → **分支被静默跳过**。
    //   后果：进程一路落到末尾「无参数」分支、**把 Electron 主界面拉起来了**，
    //   退出码 0、stdout 一个字都没有，报告 JSON 也没生成。
    //   这正是本项目最经典的「半通故障」家族：功能没生效 + 没有报错 +
    //   表面上看不出（只能靠"报告文件不存在 / 日志无 [sandbox] 行"反推）。
    //   ⇒ 通用规则：**flag 参数用 HasArg（`--x`），带值参数用 GetArg（`--x=v`）**，
    //     判"用户有没有给"时要两者都看。
    const std::string sbxPath = GetArg(argc, argv, "sandbox-scan");
    if (!sbxPath.empty() || HasArg(argc, argv, "sandbox-scan")) {
        const std::string p = sbxPath;
        const bool dry = HasArg(argc, argv, "dryrun");
        std::string ws = GetArg(argc, argv, "wait");
        const int wait = ws.empty() ? 0 : atoi(ws.c_str());
        if (p.empty()) {
            printf("[沙箱] 用法：--sandbox-scan=<样本路径> [--dryrun] [--wait=秒]\n");
            return 2;
        }
        printf("[沙箱] 开始分析 %s（dryrun=%d，wait=%d）...\n", p.c_str(), dry ? 1 : 0, wait);
        sf::sandbox::Report r;
        sf::sandbox::Scan(p, dry, wait, r);
        printf("[沙箱] 结论：%s    分数：%d    用时：%ds\n",
               r.verdict.c_str(), r.score, r.elapsedSec);
        printf("[沙箱] 说明：%s\n", r.summary.c_str());
        if (!r.err.empty()) printf("[沙箱] 错误：%s\n", r.err.c_str());
        printf("[沙箱] 落地物 %d 个：\n", (int)r.artifacts.size());
        for (size_t i = 0; i < r.artifacts.size() && i < 50; i++) {
            printf("   [%-3s] %-70s %10llu B  +%d  %s\n",
                   r.artifacts[i].action.c_str(),
                   r.artifacts[i].rel.c_str(),
                   r.artifacts[i].size,
                   r.artifacts[i].score,
                   r.artifacts[i].why.c_str());
        }
        // 落盘一份 JSON：GUI 子系统下 stdout 看不见时靠它取证
        {
            char tmp[MAX_PATH] = { 0 };
            if (GetTempPathA(MAX_PATH, tmp)) {
                std::string out = std::string(tmp) + "sf_sandbox_report.json";
                FILE* f = fopen(out.c_str(), "wb");
                if (f) {
                    std::string js = sf::sandbox::LastReportJson();
                    fwrite(js.data(), 1, js.size(), f);
                    fclose(f);
                    printf("[沙箱] 报告已写入：%s\n", out.c_str());
                }
            }
        }
        return 0;
    }

    // =======================================================================
    //  沙箱送检队列自检（2026-09-27）
    // =======================================================================
    // 【为什么必须单独做这个自检】
    //   自动送检是本产品第一条"判定链**自己**发起沙箱送检"的路径，而它
    //   **没法用界面点出来** —— 要触发它得先制造一个"静态初筛判拿不准"的
    //   落地样本，还得等它落进监视目录。等真机部署后才发现队列机制不对，
    //   代价太高（本项目最贵的一类返工）。
    //   所以把机制部分（去重 / 队列上限 / 自动限流 / 结果投递）做成
    //   可独立跑的**确定性**自检。
    //
    // 【两种模式（互斥）】
    //   --sandbox-qtest              机制自检：只入队、不真跑（毫秒级）
    //   --sandbox-qtest=<样本路径>   投递自检：真跑一份（默认 dryrun），
    //                                验证 sink 确实收到了报告
    //
    // 【★ 断言为什么读做差而不是绝对值】
    //   机制自检用的是 dedup=true 那条路，也就是**会消耗自动送检的小时配额**。
    //   同一小时内反复跑，第 13 次起可入队数会变成 0 —— 那不是 bug。
    //   所以断言全部基于"前后两次 QueueStatsJson 的差值"，配额已用过的
    //   情况下依然准确。
    //
    // 【★ 最关键的一条断言：queued + throttled == 尝试次数】
    //   它保证**没有任何一次送检请求静默消失** —— 要么入队、要么被限流计数。
    //   这正是本项目最贵的故障家族（半通故障：请求被受理了，然后没了）。
    // =======================================================================
    {
        const std::string qtPath = GetArg(argc, argv, "sandbox-qtest");
        if (!qtPath.empty() || HasArg(argc, argv, "sandbox-qtest")) {
            int fails = 0;
            auto stat = [](const char* key) -> long long {
                std::string j = sf::sandbox::QueueStatsJson();
                return (long long)sf::JsonGetInt(j, key);
            };

            if (qtPath.empty()) {
                // ---------------- 模式一：机制自检 ----------------
                printf("=== 沙箱队列机制自检（只入队，不真跑）===\n");
                const std::string same = "C:\\__sf_qtest_same.bin";
                const std::string before = sf::sandbox::QueueStatsJson();
                printf("[起点] %s\n", before.c_str());

                const long long q0 = stat("queued"), t0 = stat("throttled");

                // (1) 同一路径 + dedup=true 连入两次 → 只应入 1（去重生效）
                sf::sandbox::EnqueueScan(same, false, 5, true);
                sf::sandbox::EnqueueScan(same, false, 5, true);
                const long long d1 = stat("queued") - q0;
                printf("[1 去重]        同一路径 dedup=true 连入两次 → 入队 %lld（期望 1）\n", d1);
                if (d1 != 1) { printf("   ★ 失败：去重没生效\n"); ++fails; }

                // (2) 同一路径 + dedup=false → 应**再**入 1（人工送检不被去重挡）
                const long long q1 = stat("queued");
                sf::sandbox::EnqueueScan(same, false, 5, false);
                const long long d2 = stat("queued") - q1;
                printf("[2 人工旁路]    同一路径 dedup=false 入一次 → 入队 %lld（期望 1）\n", d2);
                if (d2 != 1) { printf("   ★ 失败：人工送检被去重挡住了\n"); ++fails; }

                // (3) 灌 30 个不同路径（dedup=true）→ 触发限流
                //     断言：入队 + 被限流 == 30（一次都没丢）
                const long long q2 = stat("queued"), t2 = stat("throttled");
                const int N = 30;
                for (int i = 0; i < N; ++i)
                    sf::sandbox::EnqueueScan("C:\\__sf_qtest_x" + std::to_string(i) + ".bin",
                                             false, 5, true);
                const long long dq = stat("queued") - q2;
                const long long dt = stat("throttled") - t2;
                printf("[3 限流]        灌 %d 个不同路径 → 入队 %lld / 限流 %lld（合计应= %d）\n",
                       N, dq, dt, N);
                if (dq + dt != N) {
                    printf("   ★ 失败：有 %lld 次送检请求**静默消失**（既没入队也没计数）\n",
                           (long long)N - dq - dt);
                    ++fails;
                }
                if (dt <= 0) {
                    printf("   ★ 失败：限流没有触发（灌 %d 个却一个都没被限）\n", N);
                    ++fails;
                }

                // (4) depth 应等于本轮入队总数（没有消费者在跑，不应被取走）
                const long long depth = stat("depth");
                printf("[4 队列深度]    depth=%lld（= 本轮入队总数，期望 >= 2）\n", depth);
                if (depth < 2) { printf("   ★ 失败：队列深度异常\n"); ++fails; }

                // (5) 消费循环在已请求停止时应立刻退出、不处理任何任务
                //     （这一步顺带验证"停止信号能打断消费循环"——服务停止路径的关键）
                sf::RequestStop();
                const long long done0 = stat("done");
                sf::sandbox::ConsumePendingLoop();
                const long long dd = stat("done") - done0;
                printf("[5 停止响应]    已请求停止后跑消费循环 → 处理了 %lld 个（期望 0）\n", dd);
                if (dd != 0) { printf("   ★ 失败：停止信号没能打断消费循环\n"); ++fails; }

                printf("[终点] %s\n", sf::sandbox::QueueStatsJson().c_str());
                printf("=== 结果：%s（失败 %d 项）===\n", fails ? "★ 不通过" : "通过", fails);
                return fails ? 1 : 0;
            }

            // ---------------- 模式二：投递自检（真跑一份）----------------
            printf("=== 沙箱队列投递自检：%s ===\n", qtPath.c_str());
            // 为什么 sink 里直接 RequestStop：本模式只用消费循环跑**一份**，
            // 收到报告就收工 —— 这样单线程、无需额外同步，也顺带验证了
            // "结果确实被交到回调手上"（而不是只进了界面卡片）。
            static int s_got = 0;
            static std::string s_verdict, s_summary;
            static int s_score = 0, s_elapsed = 0;
            sf::sandbox::SetSink([](const sf::sandbox::Report& r) {
                s_got++;
                s_verdict = r.verdict;
                s_summary = r.summary;
                s_score   = r.score;
                s_elapsed = r.elapsedSec;
                sf::RequestStop();
            });
            std::string ws = GetArg(argc, argv, "wait");
            const bool dry = HasArg(argc, argv, "dryrun") || !HasArg(argc, argv, "nosend");
            // ★ 默认 dryrun：投递自检的目的是验证**队列→消费→回调**这条链，
            //   不是验证沙箱本身（那条链有 --sandbox-scan）。dryrun 让它在
            //   没有 SbieSvc 的机器上也能跑通。
            sf::sandbox::EnqueueScan(qtPath, dry, ws.empty() ? 5 : atoi(ws.c_str()), false);
            printf("[入队后] %s\n", sf::sandbox::QueueStatsJson().c_str());
            sf::sandbox::ConsumePendingLoop();
            printf("[收到报告] 次数=%d  verdict=%s  score=%d  用时=%ds\n",
                   s_got, s_verdict.c_str(), s_score, s_elapsed);
            printf("[摘要] %s\n", s_summary.c_str());
            printf("=== 结果：%s ===\n", (s_got == 1) ? "通过（sink 收到 1 份报告）"
                                                     : "★ 不通过：sink 没收到报告");
            return (s_got == 1) ? 0 : 1;
        }
    }

    if (HasArg(argc, argv, "install")) {
        std::string c = GetArg(argc, argv, "ext-id");
        std::string e = GetArg(argc, argv, "edge-ext-id");
        bool silent = HasArg(argc, argv, "silent");
        bool ok = sf::DoInstall(c, e);
        printf(ok ? "[银狐主防] 安装完成。\n" : "[银狐主防] 安装失败，请检查权限。\n");
        if (!silent) {
            const wchar_t* okMsg   = L"银狐主防已安装并启动。\n\n可在浏览器扩展「主防」中查看盾牌状态（绿=正常 / 红=感染）。";
            const wchar_t* failMsg = L"银狐主防安装失败。\n\n请右键本程序以管理员身份运行后再试。";
            GuiNotify(ok, ok ? okMsg : failMsg);
        }
        return ok ? 0 : 1;
    }

    if (HasArg(argc, argv, "uninstall")) {
        bool silent = HasArg(argc, argv, "silent");
        sf::DoUninstall();
        printf("[银狐主防] 已卸载。\n");
        if (!silent) GuiNotify(true, L"银狐主防已卸载。\n\n相关 Windows 服务与注册表项已清除。");
        return 0;
    }

    if (HasArg(argc, argv, "toast")) {
        std::string st = GetArg(argc, argv, "status");
        std::string sc = GetArg(argc, argv, "score");
        std::string rk = GetArg(argc, argv, "risk");
        std::string ud = GetArg(argc, argv, "undo");
        std::string rb = GetArg(argc, argv, "rolledback");
        int score = sc.empty() ? 0 : atoi(sc.c_str());
        if (st.empty()) st = "infected";
        return sf::RunToast(st, score, rk, ud, rb == "1");
    }

    if (HasArg(argc, argv, "prewarm")) { return sf::RunPrewarm(); }

    if (HasArg(argc, argv, "scanprogress")) { return sf::RunScanProgress(); }

    // 右键自定义查杀（--probe --file=<path>）：由资源管理器以用户会话拉起本进程，
    // 连服务管道执行单文件启发式判定，拿到结果后渲染右下角 WebView2 卡片（可点「立即清除」）。
    if (HasArg(argc, argv, "probe")) {
        std::wstring wfile;
        int wargc = 0;
        LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
        if (wargv) {
            for (int i = 0; i < wargc; ++i) {
                std::wstring a = wargv[i];
                if (a.rfind(L"--file=", 0) == 0) { wfile = a.substr(7); break; }
            }
            LocalFree(wargv);
        }
        if (wfile.empty()) { ShowShieldMsg(L"银狐主防：未提供待查杀文件路径。"); return 1; }
        return sf::RunProbeToast(wfile);
    }

    // 沙箱动态分析弹窗（测试 / 调试钩子，与真实判定逻辑解耦——判定策略另议）：
    //   --sandbox-progress --file=<path> --eta=<秒>  → 进度卡（带倒计时）
    //   --sandbox-result   --file=<path> --verdict=<malicious|suspicious|clean>
    //                      --score=<0-200> --summary=<行为摘要>  → 结果卡
    // file / summary 经宽命令行取参并转 UTF-8，支持中文；内部再 URL 编码进 Electron 载荷。
    if (HasArg(argc, argv, "sandbox-progress")) {
        std::string file = W2U8(GetArgW(L"--file="));
        int eta = 30;
        std::string etaS = W2U8(GetArgW(L"--eta="));
        if (!etaS.empty()) { int v = atoi(etaS.c_str()); if (v > 0) eta = v; }
        sf::NotifySandboxProgress(file, eta);
        return 0;
    }
    if (HasArg(argc, argv, "sandbox-result")) {
        std::string file    = W2U8(GetArgW(L"--file="));
        std::string verdict = W2U8(GetArgW(L"--verdict="));
        std::string summary = W2U8(GetArgW(L"--summary="));
        int score = 0;
        std::string sc = W2U8(GetArgW(L"--score="));
        if (!sc.empty()) score = atoi(sc.c_str());
        sf::NotifySandboxResult(file, verdict, score, summary);
        return 0;
    }


    // ⚠️ 同 2026-09-27 的坑：`--notice` 可带值，故判存在时也要看 GetArg，
    //    否则 `--notice=文本` 会被 HasArg 的完全相等比较挡掉、静默不弹窗。
    if (!GetArg(argc, argv, "notice").empty() || HasArg(argc, argv, "notice")) {
        std::string t = GetArg(argc, argv, "notice");
        if (t.empty()) t = "银狐主防：任务已就绪。";
        ShowShieldMsg(AnsiToW(t).c_str());
        return 0;
    }

    if (HasArg(argc, argv, "console")) { EnsureConsoleForDebug(); sf::RunConsole(); return 0; }

    // ---- 主界面 ----
    // ★ 2026-09-19 主界面已迁 Electron（gui\SilverFoxGUI.exe，由安装包附带）：
    //   双击主程序 / 开始菜单快捷方式打开的都是 Electron 窗口；
    //   WebView2 版（--gui）仅留作开发兜底（Electron 包缺失时自动退回）。
    if (HasArg(argc, argv, "gui")) return sf::RunGui();

    // 无参数：用户双击 → 优先拉起 Electron 主界面（同目录 gui\SilverFoxGUI.exe）。
    //   服务后台常驻，Electron 界面经命名管道实时拉取；服务未运行时界面显示离线状态。
    {
        wchar_t exePath[MAX_PATH] = L"", dir[MAX_PATH] = L"", guiExe[MAX_PATH] = L"";
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* cut = wcsrchr(exePath, L'\\');
        if (cut) {
            *cut = L'\0';
            lstrcpynW(dir, exePath, MAX_PATH);
            wsprintfW(guiExe, L"%s\\gui\\SilverFoxGUI.exe", dir);
            *cut = L'\\';
        }
        if (guiExe[0] && GetFileAttributesW(guiExe) != INVALID_FILE_ATTRIBUTES) {
            STARTUPINFOW si{}; si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            if (CreateProcessW(guiExe, nullptr, nullptr, nullptr, FALSE, 0,
                               nullptr, dir, &si, &pi)) {
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return 0;
            }
        }
    }
    // 退回：Electron 包缺失（如绿色免安装场景）→ 打开内置 WebView2 版主界面。
    return sf::RunGui();
}
