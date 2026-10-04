// gui.cpp — 银狐主防主界面（WebView2 窗口 + 命名管道直连 + 系统托盘）
//
// 与 toast（右下角通知小卡）完全独立进程：主界面是常驻面板（可最小化到托盘），
// 数据不走文件，由本进程直连服务命名管道（\\\\.\\pipe\\SilverFoxGuard）拿实时结果：
//   {cmd:status}  → BuildResultJson 完整对象（status/score/findings…）
//   {cmd:rescan}  → 触发一轮全盘扫描（服务端 20s 级，回包即完成）
//   {cmd:clean}   → 一键清除（含清除报告）
//   {cmd:history} → 清除历史记录
// 前端「设置」页的 GPU 加速开关读写注册表 gpu_scan（默认关）。
// WebView2 渲染复用 toast 的固定运行时方案（自带 WebView2Runtime，--no-sandbox）。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <shellapi.h>
#include <shlobj.h>
#include <commctrl.h>
#include <webview2.h>
#include <wrl.h>
#include <dwmapi.h>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <sstream>
#include <chrono>

#include "common.h"
#include "compute.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shcore.lib")
#pragma comment(lib, "comctl32.lib")

using namespace Microsoft::WRL;

#ifndef IDI_SHIELD
#define IDI_SHIELD 101
#endif
#define WM_APP_TRAY    (WM_APP + 3)
#define WM_APP_PIPE    (WM_APP + 4)

// 单实例互斥体：主界面常驻托盘，用户反复双击 exe 不应开出一堆重复窗口。
// 第二个实例发现已有窗口时，向它发 WM_APP_SHOW 唤起后自行退出。
static const wchar_t* kGuiMutexName = L"Local\\SilverFoxGuardGuiSingleInstance";
#define WM_APP_SHOW    (WM_APP + 5)

namespace sf {

namespace {
HWND g_hwnd = nullptr;
ComPtr<ICoreWebView2> g_wv;
ComPtr<ICoreWebView2Controller> g_ctrl;
std::atomic<bool> g_trayInited{ false };
std::atomic<bool> g_hidden{ false };
std::atomic<bool> g_polling{ true };
std::string g_lastStatusJson;   // 最近一次管道结果（供 JS 拉取兜底）
std::mutex  g_resMtx;
// 是否有重活在跑（全盘扫描 / 清除 / 回滚）。UI 线程置位、后台线程清零，
// 必须原子：普通 bool 下「检查 + 置位」非原子，连点两次会双开重活。
std::atomic<bool> g_scanning{ false };

// ---- 固定运行时目录（与 toast 相同约定；安装后为 $INSTDIR\WebView2Runtime）----
static std::wstring WvRuntimePath() {
    wchar_t ep[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, ep, MAX_PATH)) return L"";
    std::wstring p = ep;
    size_t q = p.find_last_of(L'\\');
    std::wstring dir = (q == std::wstring::npos) ? L"" : p.substr(0, q + 1);
    std::wstring rt = dir + L"WebView2Runtime";
    wchar_t env[512] = {0};
    if (GetEnvironmentVariableW(L"SF_WV2_DIR", env, 512) && env[0]) rt = env;
    return rt;
}
static std::wstring WvUserData() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard\\WV2DataGui";
    else dir = L"C:\\ProgramData\\SilverFoxGuard\\WV2DataGui";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

// UTF-8 → wstring（ExecuteScript/导航用宽字符）
static std::wstring U8W(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w; w.resize(n ? n : 0);
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 标题等宽字符串：以 ASCII 转义形式内嵌 UTF-8 字节（\xE9\x93\xB6... 源文件纯 ASCII，
// 不依赖编译器源码编码设置），运行时经 CP_UTF8 转宽 —— 杜绝「源码按 GBK 解析 → 宽字面量乱码」。
static std::wstring BrandTitle() {
    // 银狐主防 = E9 93 B6 E7 8B 90 E4 B8 BB E9 98 B2
    return U8W(std::string("\xE9\x93\xB6\xE7\x8B\x90\xE4\xB8\xBB\xE9\x98\xB2", 12));
}

static std::string LoadGuiHtml() {
    // 优先安装目录 assets/gui.html；找不到退回内嵌内置版本（见 kGuiHtmlFallback）
    wchar_t ep[MAX_PATH];
    if (GetModuleFileNameW(nullptr, ep, MAX_PATH)) {
        std::wstring p = ep;
        size_t q = p.find_last_of(L'\\');
        if (q != std::wstring::npos) {
            std::wstring f = p.substr(0, q + 1) + L"assets\\gui.html";
            std::ifstream in(f, std::ios::binary);
            if (in) {
                std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
                if (s.size() > 1000) return s;
            }
        }
    }
    return "";   // 无 HTML → 由调用方给兜底占位页
}

// ---- 服务管道协议（每次请求一次连接，简洁可靠）----
static bool PipeRequest(const std::string& json, std::string& out) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 25; ++i) {
        h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        Sleep(200);
    }
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = WriteFramed(h, json) && ReadFramed(h, out);
    CloseHandle(h);
    return ok;
}

// 周期轮询：每 3s 拉一次 status，推给前端 JS
static void PollLoop() {
    while (g_polling.load()) {
        std::string resp;
        if (PipeRequest("{\"cmd\":\"status\"}", resp) && !resp.empty()) {
            {
                std::lock_guard<std::mutex> lk(g_resMtx);
                g_lastStatusJson = resp;
            }
            if (g_wv && IsWindow(g_hwnd)) {
                std::string js = "window.__render && window.__render("
                    + resp + ");";
                g_wv->ExecuteScript(U8W(js).c_str(), nullptr);
            }
        }
        for (int i = 0; i < 30 && g_polling.load(); ++i) Sleep(100);   // 3s
    }
}

// ---- 托盘 ----
static void EnsureTray() {
    if (g_trayInited.exchange(true)) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = WM_APP_TRAY;
    nid.hIcon = (HICON)LoadImageW(GetModuleHandle(nullptr), (LPCWSTR)MAKEINTRESOURCEW(IDI_SHIELD),
                                  IMAGE_ICON, 16, 16, LR_SHARED);
    std::wstring tipW = BrandTitle();
    wcscpy_s(nid.szTip, tipW.c_str());
    Shell_NotifyIconW(NIM_ADD, &nid);
}
static void RemoveTray() {
    if (!g_trayInited.load()) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_hwnd;
    nid.uID = 1;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

static void TrayMenu() {
    HMENU m = CreatePopupMenu();
    AppendMenuW(m, MF_STRING, 1, L"打开主界面");
    AppendMenuW(m, MF_STRING, 2, L"立即检查威胁");
    AppendMenuW(m, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(m, MF_STRING, 3, L"退出（后台服务保持运行）");
    POINT pt{};
    GetCursorPos(&pt);
    SetForegroundWindow(g_hwnd);
    int r = TrackPopupMenu(m, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, g_hwnd, nullptr);
    DestroyMenu(m);
    if (r == 1) {
        ShowWindow(g_hwnd, SW_SHOW);
        ShowWindow(g_hwnd, SW_RESTORE);
        SetForegroundWindow(g_hwnd);
        g_hidden = false;
    } else if (r == 2) {
        ShowWindow(g_hwnd, SW_SHOW); ShowWindow(g_hwnd, SW_RESTORE);
        g_hidden = false;
        if (g_wv) {
            std::string resp;
            bool ok = PipeRequest("{\"cmd\":\"rescan\"}", resp);
            if (ok && g_wv) {
                std::string js = "window.__render && window.__render(" + resp + ");";
                g_wv->ExecuteScript(U8W(js).c_str(), nullptr);
            }
        }
    } else if (r == 3) {
        g_polling = false;
        DestroyWindow(g_hwnd);
    }
}

// ---- 往前端推一帧响应（统一入口，避免各处重复拼 ExecuteScript）----
static void PushToJs(const std::string& resp) {
    if (resp.empty() || !g_wv || !IsWindow(g_hwnd)) return;
    std::string js = "window.__render && window.__render(" + resp + ");";
    g_wv->ExecuteScript(U8W(js).c_str(), nullptr);
}

// 在后台线程发一条管道请求，回包推给前端。
// 用于所有「服务端会做重活」的命令（rescan / clean / clean_adv / rollbackdo …），
// 绝不能放 UI 线程同步等 —— 全盘扫描 20~90 秒会直接冻住窗口。
static void RequestAsync(const char* reqJson) {
    std::string req = reqJson;
    std::thread([req]() {
        std::string r;
        bool ok = PipeRequest(req, r);
        g_scanning = false;
        if (ok) PushToJs(r);
    }).detach();
}

// ---- JS 消息桥 ----
static void OnWebMessage(const std::string& msg) {
    std::string cmd = JsonGetString(msg, "cmd");

    // GPU 开关：写注册表 + 触发探测/构建特征地图（服务端 gpu 命令）
    if (cmd == "gpu") {
        bool on = JsonGetString(msg, "on") == "true";
        std::string r;
        PipeRequest(std::string("{\"cmd\":\"gpu\",\"on\":") + (on ? "1" : "0") + "}", r);
        compute::SetGpuEnabled(on);
        PushToJs(r);                     // 回包 cmd=gpu，前端据此定位开关
        std::string js = "window.__gpuState && window.__gpuState(" + std::string(on ? "true" : "false") + ");";
        if (g_wv) g_wv->ExecuteScript(U8W(js).c_str(), nullptr);
        return;
    }
    if (cmd == "win") {
        std::string a = JsonGetString(msg, "action");
        if (a == "close") {
            // 最小化到托盘（服务继续防护）
            ShowWindow(g_hwnd, SW_HIDE);
            g_hidden = true;
        } else if (a == "minimize") {
            ShowWindow(g_hwnd, SW_MINIMIZE);
        } else if (a == "drag") {
            ReleaseCapture();
            SendMessageW(g_hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0);
        }
        return;
    }

    std::string resp;

    // ---- 重活：后台线程，回包推前端 ----
    //   scan/rescan 全盘精扫 · clean 一键清除 · clean_adv 高级删除
    //   rollbackdo 手动回滚 · rollbackclean 清空快照 · rollbackundo 撤销自动处置
    if (cmd == "scan" || cmd == "rescan" || cmd == "clean" ||
        cmd == "clean_adv" || cmd == "rollbackdo" || cmd == "rollbackclean" ||
        cmd == "rollbackundo" || cmd == "probeclean") {
        if (g_scanning.exchange(true)) return;   // 已有重活在跑，忽略重复请求
        if (cmd == "scan") {
            RequestAsync("{\"cmd\":\"rescan\"}");
        } else if (cmd == "probeclean") {
            // 单文件清除：把前端传来的 path 原样透传（JsonGetString 已解转义）
            std::string p = JsonGetString(msg, "path");
            if (p.empty()) { g_scanning = false; return; }
            RequestAsync(("{\"cmd\":\"probeclean\",\"path\":" + JsonString(p) + "}").c_str());
        } else if (cmd == "rollbackdo") {
            std::string why = JsonGetString(msg, "reason");
            if (why.empty()) why = "用户在主界面手动触发";
            RequestAsync(("{\"cmd\":\"rollbackdo\",\"reason\":" + JsonString(why) + "}").c_str());
        } else if (cmd == "rollbackundo") {
            std::string tok = JsonGetString(msg, "token");
            RequestAsync(("{\"cmd\":\"rollbackundo\",\"token\":" + JsonString(tok) + "}").c_str());
        } else {
            RequestAsync(("{\"cmd\":\"" + cmd + "\"}").c_str());
        }
        return;
    }

    // ---- 轻活：同步取回（服务端直接返回缓存，毫秒级）----
    if (cmd == "status") {
        // 启动 / 30 秒轮询的热路径：保持**同步**取回（服务端直接返回缓存，毫秒级），
        // 不必为一个线程调度多绕一圈。
        PipeRequest("{\"cmd\":\"status\"}", resp);
        PushToJs(resp);
    } else if (cmd == "gpuget") {
        // 这一条**不能**靠兜底：它除了解析开关，还要在本地把状态直接推给前端
        // （__gpuState），并顺带补一次地图进度帧 —— 属于"有本地副作用"的命令。
        std::string js = "window.__gpuState && window.__gpuState(" +
                         std::string(compute::IsGpuEnabled() ? "true" : "false") + ");";
        if (g_wv) g_wv->ExecuteScript(U8W(js).c_str(), nullptr);
        if (compute::IsGpuEnabled()) {
            PipeRequest("{\"cmd\":\"gpuprog\"}", resp);
            PushToJs(resp);
        }
    } else if (!cmd.empty()) {
        // ---- ★ 兜底：原样转发给服务端（2026-09-22 主干式架构）----
        //  改造前：未在此登记的 cmd 会被**静默丢弃** —— 这正是"新增管道命令要
        //  改两处，漏一处就是管道能通、GUI 点了没反应"那个最难查的半通故障来源。
        //
        //  现在改为原样转发：服务端按**分体清单**（见 module.h / modules_list.cpp）
        //  查表分发，认不出的走服务端自己的兜底（返回当前扫描结果）。
        //  于是分体新增命令时，GUI 侧**零改动** —— 这是"加功能只改 1 处"的 GUI 侧半边。
        //
        //  ⚠️ 用 RequestAsync（后台线程）而非同步 PipeRequest：
        //    分体命令可能是重活（扫描 / 清除 / 全盘复查），在 UI 线程同步等会冻住窗口。
        //  ⚠️ 空 cmd 不转发：那类消息（无 cmd 字段）本就不该有响应。
        RequestAsync(msg.c_str());
    }
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) {
        g_polling = false;
        RemoveTray();
        if (g_ctrl) g_ctrl->Close();
        PostQuitMessage(0);
        return 0;
    }
    if (m == WM_TIMER && w == 3) {
        KillTimer(h, 3);
        sf::LogDbg("[gui] watchdog: NavigationCompleted 30s 未触发（渲染可能失败）");
        return 0;
    }
    if (m == WM_APP_TRAY) {
        if (l == WM_RBUTTONUP || l == WM_CONTEXTMENU) TrayMenu();
        else if (l == WM_LBUTTONDBLCLK) {
            ShowWindow(h, SW_SHOW); ShowWindow(h, SW_RESTORE);
            g_hidden = false;
        }
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

static void MarkGui(const std::string& tag) {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    HANDLE h = CreateFileW((dir + L"\\gui_debug.txt").c_str(), FILE_APPEND_DATA,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    std::wstring line = U8W(tag) + L"\r\n";
    DWORD w = 0; WriteFile(h, line.c_str(), (DWORD)(line.size() * 2), &w, nullptr);
    CloseHandle(h);
}

// 控制器创建完成：设置边界 + 监听关闭消息 + 导航，导航完成后才显示窗口
HRESULT OnController(HRESULT hr, ICoreWebView2Controller* ctrl) {
    char hbM[128]; sprintf_s(hbM, "OnController hr=0x%08X ctrl=%p", (unsigned)hr, (void*)ctrl);
    MarkGui(hbM);
    if (FAILED(hr) || !ctrl) return S_OK;
    ctrl->get_CoreWebView2(&g_wv);
    RECT rc{}; GetClientRect(g_hwnd, &rc);
    ctrl->put_Bounds(rc);
    // 消息桥：前端 postMessage({cmd:...})
    EventRegistrationToken tok{};
    g_wv->add_WebMessageReceived(
        Callback<ICoreWebView2WebMessageReceivedEventHandler>(
            [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* a) -> HRESULT {
                LPWSTR p = nullptr;
                if (SUCCEEDED(a->get_WebMessageAsJson(&p)) && p) {
                    int n = WideCharToMultiByte(CP_UTF8, 0, p, -1, nullptr, 0, nullptr, nullptr);
                    std::string s; if (n > 1) { s.resize(n - 1); WideCharToMultiByte(CP_UTF8, 0, p, -1, &s[0], n, nullptr, nullptr); }
                    CoTaskMemFree(p);
                    OnWebMessage(s);
                }
                return S_OK;
            }).Get(), &tok);
    std::string html = LoadGuiHtml();
    sf::LogDbg("[gui] LoadGuiHtml len=" + std::to_string(html.size()));
    if (html.empty()) {
        // 兜底：找不到 gui.html 时给一个最小占位（提示安装不完整）
        html = "<!doctype html><html><body style='font-family:Microsoft YaHei;display:grid;place-items:center;height:100vh;margin:0;background:#f4f5f7;color:#5a6170'>"
               "主界面资源缺失，请重新安装 SilverFoxGuard。</body></html>";
    }
    int nb = MultiByteToWideChar(CP_UTF8, 0, html.c_str(), -1, nullptr, 0);
    std::wstring whtml(nb, 0);
    MultiByteToWideChar(CP_UTF8, 0, html.c_str(), -1, &whtml[0], nb);
    EventRegistrationToken tokNav{};
    g_wv->add_NavigationCompleted(
        Callback<ICoreWebView2NavigationCompletedEventHandler>(
            [](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs* e) -> HRESULT {
                BOOL ok = FALSE; if (e) e->get_IsSuccess(&ok);
                sf::LogDbg(std::string("[gui] nav completed ok=") + (ok ? "1" : "0"));
                return S_OK;
            }).Get(), &tokNav);
        SetTimer(g_hwnd, 3, 30000, nullptr);   // 30s 看门狗：nav 未完成则记日志（排查白屏）
    HRESULT nh = g_wv->NavigateToString(whtml.c_str());
    char hb[64]; sprintf_s(hb, "[gui] NavigateToString hr=0x%08X", (unsigned)nh);
    sf::LogDbg(hb);
    EnsureTray();
    std::thread poll(PollLoop);
    poll.detach();
    return S_OK;
}
}  // namespace

int RunGui() {
    // ---- 单实例：已有主界面在跑 → 唤起它然后退出 ----
    // 用有名互斥体 + 窗口类名 FindWindow 双保险（互斥体防并发创建，FindWindow 用来发唤起消息）。
    HANDLE hOnce = CreateMutexW(nullptr, TRUE, kGuiMutexName);
    bool already = (hOnce && GetLastError() == ERROR_ALREADY_EXISTS);
    if (already) {
        HWND prev = FindWindowW(L"SilverFoxGuardGui", nullptr);
        if (prev) {
            PostMessageW(prev, WM_APP_SHOW, 0, 0);   // 让它自己从托盘冒出来
            CloseHandle(hOnce);
            return 0;
        }
        // 互斥体在但窗口没了（上次异常退出）→ 继续走创建流程
    }

    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", L"--no-sandbox --disable-gpu");

    // 与 toast 窗口类名区分（toast 为 “SFEnvToast”）
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hIcon = (HICON)LoadImageW(GetModuleHandle(nullptr), (LPCWSTR)MAKEINTRESOURCEW(IDI_SHIELD),
                                 IMAGE_ICON, 32, 32, LR_SHARED);
    wc.lpszClassName = L"SilverFoxGuardGui";
    RegisterClassExW(&wc);

    const int W = 1120, H = 720;
    RECT wr{0, 0, W, H};
    AdjustWindowRectEx(&wr, WS_OVERLAPPEDWINDOW, FALSE, 0);
    int x = (GetSystemMetrics(SM_CXSCREEN) - (wr.right - wr.left)) / 2;
    int y = (GetSystemMetrics(SM_CYSCREEN) - (wr.bottom - wr.top)) / 2;
    g_hwnd = CreateWindowExW(0, L"SilverFoxGuardGui", BrandTitle().c_str(),
        WS_OVERLAPPEDWINDOW, x, y, wr.right - wr.left, wr.bottom - wr.top,
        nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    if (!g_hwnd) { CoUninitialize(); return 1; }
    int corner = 2;   // DWMWCP_ROUND（Win11 生效，Win10 静默失败）
    DwmSetWindowAttribute(g_hwnd, 33, &corner, sizeof(corner));
    ShowWindow(g_hwnd, SW_SHOW);

    // 固定版本运行时
    std::wstring runtime = WvRuntimePath();
    std::wstring userData = WvUserData();
    // 崩溃残留可能导致 profile 损坏 → 白屏（导航完成不触发）；启动时清掉旧的让 WebView2 重建
    std::error_code ec2;
    try { std::filesystem::remove_all(userData, ec2); } catch (...) {}

    ComPtr<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> envH;
    envH = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            char hb[128]; sprintf_s(hb, "env callback hr=0x%08X env=%p", (unsigned)hr, (void*)env);
            MarkGui(hb);
            if (FAILED(hr) || !env) return S_OK;
            ComPtr<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> ctrlH;
            ctrlH = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(OnController);
            env->CreateCoreWebView2Controller(g_hwnd, ctrlH.Get());
            return S_OK;
        });
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        runtime.empty() ? nullptr : runtime.c_str(), userData.c_str(), nullptr, envH.Get());
    char hb[128]; sprintf_s(hb, "CreateEnvironment direct hr=0x%08X runtime=%ls", (unsigned)hr, runtime.c_str());
    MarkGui(hb);
    if (FAILED(hr)) {
        // 环境创建失败：托盘仍可给入口，提示用户
        EnsureTray();
    }
    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    CoUninitialize();
    return 0;
}

}  // namespace sf