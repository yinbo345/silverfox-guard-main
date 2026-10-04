// toast.cpp — 右下角 WebView2 通知（自带完整固定版本运行时，不依赖系统 Edge）
//
// 渲染/动画修复要点：
//   ① 窗口先创建在屏幕外（仍属「可见」状态，WebView2 的 put_Bounds / navdone 照常触发），
//      用户全程看不到空窗/黑框/白屏闪烁；navdone 成功后才 SetWindowPos 滑入右下角。
//      （早期 hidden 会令 navdone 永不触发，已弃用；分层窗口 WS_EX_LAYERED 会令 WebView2
//       不合成内容，亦弃用——故采用屏幕外方案。）
//   ② navdone 成功后才用 JS 给 body 加 .show 触发进场（淡入上浮）动画。
//   ③ 内容初始 opacity:0，✕ 点击先加 .hide（淡出下落）动画，260ms 后再 postMessage('close')，
//      web 消息回调才 DestroyWindow —— 出场动画恢复。
//   ④ 渲染进程沙箱在非系统目录运行时崩溃，已加 WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--no-sandbox；
//      该参数会令首帧 CSS 动画被跳过，故进场/出场改为 JS 显式触发（见②③）。
//   ⑤ 仅在 WebView2 初始化真正失败时才弹兜底 MessageBox（g_fallbackDone 防重复）。
//   ⑥ 自带完整 WebView2Runtime（browserExecutableFolder 指向 $INSTDIR\WebView2Runtime），
//      与系统 Edge / 系统 WebView2 Runtime 完全隔离。
#include <windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <fstream>
#include <tlhelp32.h>
#include <WebView2.h>
#include <wtsapi32.h>
#include <mmsystem.h>
#include <wrl.h>
#include <dwmapi.h>
#include <shlobj.h>
#include <userenv.h>   // CreateEnvironmentBlock / DestroyEnvironmentBlock / GetUserProfileDirectory
#include "common.h"
#include "cleaner.h"   // ReadCleanProgress（读取服务写入的清除进度）

#pragma comment(lib, "userenv.lib")

// 自定义窗口消息：后台清除线程完成 → 主线程渲染结果卡片
#define WM_APP_CLEAN_DONE (WM_APP + 1)

#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "dwmapi.lib")
#pragma comment(lib, "shcore.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

using namespace Microsoft::WRL;

// ---- 前置声明：单文件查杀卡片（实现见文件尾 sf 段）----
namespace sf {
std::wstring BuildProbeHtml(int level, int score, const std::string& type, const std::string& title,
                            const std::wstring& fileW, const std::string& hitsRaw);
std::wstring BuildProbeCleanHtml(const std::string& cleanResp, const std::wstring& pathW);
std::wstring BuildUndoResultHtml(const std::string& undoResp);   // 撤销结果卡（勒索回滚场景）
std::wstring BuildBootResultHtml(const std::string& resp,        // 引导扇区操作结果卡（恢复/信任）
                                 const std::wstring& okTitle, const std::wstring& okSub);
}
namespace {

HWND g_hwnd = nullptr;
ComPtr<ICoreWebView2> g_webview;
ComPtr<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler> g_envH;
ComPtr<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler> g_ctrlH;
ComPtr<ICoreWebView2WebMessageReceivedEventHandler> g_msgH;
ComPtr<ICoreWebView2Controller> g_ctrl;   // 必须长期持有，否则 Controller 释放后导航完成回调收不到、窗口不显示
std::wstring g_html;
std::wstring g_theme;            // L"light" / L"dark"
bool g_closing = false;
bool g_fallbackDone = false;    // 兜底 MessageBox 是否已弹（防止重复弹出）
bool g_ready = false;           // navdone 是否成功触发（看门狗据此判断是否需要兜底）
bool g_prewarm = false;         // 预热模式标志：占位页 navdone 不触发进场，等扫描结果再决定显示/退出
bool g_cleaning = false;        // 正在执行「一键清除」（期间忽略重复触发）
bool g_cleanOk = false;         // 清除请求是否成功往返服务
bool g_advStage = false;        // 当前是否处于「高级删除」阶段（普通删除未删完 → 升级）
std::string g_currentStatus;    // 当前告警卡状态（确认卡取消后返回此状态渲染）
int  g_currentScore = 0;        // 当前告警卡评分
// ---- 勒索回滚场景的上下文（由 --risk / --undo / --rolledback 传入）----
std::wstring g_risk;            // L"high"|L"suspect"|L"mbr"|L"proc"|L"regrun"|L"landed"|L"hashlanded"|空（普通扫描告警）
std::string  g_undoToken;       // 撤销凭据（ANSI，仅 [0-9a-f]，已白名单过滤）
bool         g_rolledBack = false;  // 本次是否真的发生过覆盖写
int  g_resDeleted = 0, g_resDeferred = 0, g_resFailed = 0, g_resKilled = 0, g_resExtraDll = 0;
// 普通删除阶段的结果快照（高级删除完成后，最终结果卡显示 普通+高级 的合并数字）
int  g_normDeleted = 0, g_normDeferred = 0, g_normFailed = 0, g_normKilled = 0, g_normExtraDll = 0;
int  g_lastPct = -1;            // 上次渲染的进度百分比（避免重复刷 DOM）
std::wstring g_lastPhase;       // 上次渲染的阶段（避免重复刷 DOM）
long g_lastHr = 0;             // 最近一次 WebView2 初始化 HRESULT（调试用）
std::wstring g_probePath;             // 右键查杀：被查杀文件宽路径
std::wstring g_probeIn;               // 右键查杀：输入路径（显示用）
int g_posX = 0, g_posY = 0, g_w = 0, g_h = 0;  // 最终停靠位置/尺寸（屏幕外生成，navdone 后滑入）
std::wstring g_logPath;   // 调试日志路径（懒初始化，指向 C:\ProgramData\SilverFoxGuard\guard.log）
std::mutex    g_logMtx;

// 判断目录是否可用：能创建，或已存在，即视为可写
static bool DirUsable(const std::wstring& d) {
    if (CreateDirectoryW(d.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

// WebView2 userData 根目录（含 SilverFoxGuard 段）。要求【绝对路径】+【实测可写】：
// 服务经 CreateProcessAsUser 拉起的进程里存在两个坑：① SHGetFolderPathW(CSIDL_LOCAL_APPDATA) 可能失败；
// ② 若未传用户环境块，%LOCALAPPDATA% 仍是服务（LocalSystem）的值
// （C:\Windows\system32\config\systemprofile\AppData\Local），对以用户身份运行的进程既无权限也建不出
// WebView2 的 profile —— 实测导致 CreateCoreWebView2Controller 直接失败（hr=0x8000FFFF）并退化成兜底弹窗。
// 故每一级候选目录都必须【实测可写】，不可写就换下一级，最后兜到 Everyone 可建的 ProgramData。
static std::wstring Wv2BaseDir() {
    auto tryDir = [](const std::wstring& base) -> std::wstring {
        if (base.empty()) return L"";
        std::wstring d = base + L"\\SilverFoxGuard";
        return DirUsable(d) ? d : L"";
    };
    wchar_t p[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, p)) && p[0]) {
        std::wstring d = tryDir(p);
        if (!d.empty()) return d;
    }
    wchar_t env[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", env, MAX_PATH) && env[0]) {
        std::wstring d = tryDir(env);
        if (!d.empty()) return d;
    }
    wchar_t tmp[MAX_PATH] = {0};
    if (GetTempPathW(MAX_PATH, tmp) && tmp[0]) {
        std::wstring d = tryDir(tmp);
        if (!d.empty()) return d;
    }
    wchar_t cp[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, cp)) && cp[0]) {
        std::wstring d = tryDir(cp);
        if (!d.empty()) return d;
    }
    CreateDirectoryW(L"C:\\ProgramData\\SilverFoxGuard", nullptr);
    return L"C:\\ProgramData\\SilverFoxGuard";
}

// 调试日志统一写到 C:\ProgramData\SilverFoxGuard\guard.log，确保 VM 也可访问与回捞
static std::wstring GetLogPath() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\guard.log";
}

void WriteDbg(const std::wstring& s) {
    std::lock_guard<std::mutex> lk(g_logMtx);
    if (g_logPath.empty()) g_logPath = GetLogPath();
    HANDLE hf = CreateFileW(g_logPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            OPEN_ALWAYS, 0, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    SetFilePointer(hf, 0, nullptr, FILE_END);
    DWORD w = 0;
    std::wstring line = s; if (line.empty() || line.back() != L'\n') line += L"\r\n";
    WriteFile(hf, line.c_str(), (DWORD)(line.size() * sizeof(wchar_t)), &w, nullptr);
    CloseHandle(hf);
}

// UTF-8 → wstring
std::wstring U8W(const std::string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w; w.resize(n);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 播放提示音（安装目录 assets 下；文件缺失则静默跳过，不影响通知）
// 各步骤返回码写调试日志：MCI 的 mpegvideo 解码器在部分系统上不可用，失败原先是静默的，无从排查。
void PlayNotifySound() {
    wchar_t exepath[MAX_PATH];
    if (!GetModuleFileNameW(nullptr, exepath, MAX_PATH)) { WriteDbg(L"[sound] GetModuleFileName failed\r\n"); return; }
    std::wstring dir = exepath; size_t p = dir.find_last_of(L'\\');
    if (p == std::wstring::npos) return; dir = dir.substr(0, p);
    std::wstring mp3 = dir + L"\\assets\\dragon-studio-new-notification-3-398649.mp3";
    if (GetFileAttributesW(mp3.c_str()) == INVALID_FILE_ATTRIBUTES) {
        WriteDbg(L"[sound] mp3 missing: " + mp3 + L"\r\n");
        return;
    }
    mciSendStringW(L"close sfnotify", nullptr, 0, nullptr);
    std::wstring openCmd = L"open \"" + mp3 + L"\" type mpegvideo alias sfnotify";
    MCIERROR oe = mciSendStringW(openCmd.c_str(), nullptr, 0, nullptr);
    wchar_t b[96];
    swprintf_s(b, L"[sound] open err=0x%08X\r\n", (unsigned)oe);
    WriteDbg(b);
    if (oe == 0) {
        MCIERROR pe = mciSendStringW(L"play sfnotify", nullptr, 0, nullptr);
        swprintf_s(b, L"[sound] play err=0x%08X\r\n", (unsigned)pe);
        WriteDbg(b);
        if (pe == 0) return;   // MCI 正常发声，结束
    }
    // 兜底：MCI 的 mpegvideo 解码器在部分系统上不可用（open/play 返回非 0）时，退到系统告警音，
    // 保证「有异常一定听得到」，不因音频解码链路缺失而整体静默。
    BOOL fb = PlaySoundW(L"SystemAsterisk", nullptr, SND_ALIAS | SND_ASYNC | SND_NODEFAULT);
    swprintf_s(b, L"[sound] fallback SystemAsterisk ok=%d\r\n", (int)fb);
    WriteDbg(b);
}

// 系统「应用」深浅色（AppsUseLightTheme：1=浅色，0=深色）；读不到默认浅色
std::wstring GetSystemTheme() {
    HKEY hk; DWORD v = 1; DWORD sz = sizeof(v);
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_READ, &hk) == ERROR_SUCCESS) {
        RegQueryValueExW(hk, L"AppsUseLightTheme", nullptr, nullptr, (LPBYTE)&v, &sz);
        RegCloseKey(hk);
    }
    return v ? L"light" : L"dark";
}

// 获取工作区（屏幕减任务栏）右下角停靠坐标：弹窗贴任务栏上方，绝不覆盖任务栏。
// GetDesktopWindow 返回的是整个屏幕（含任务栏），用它定位会盖住任务栏，故一律改用 SPI_GETWORKAREA。
// ---- 单文件查杀：窄/宽互转 与 服务管道请求 ----
static std::string W2U8(const std::wstring& w) {
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return "";
    std::string u(n - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &u[0], n, nullptr, nullptr);
    return u;
}
static std::string ProbePipeRequest(const std::string& cmdJson) {
    std::string resp;
    HANDLE pipe = CreateFileW(sf::PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    for (int i = 0; i < 20 && pipe == INVALID_HANDLE_VALUE; ++i) {
        Sleep(150);
        pipe = CreateFileW(sf::PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    }
    if (pipe == INVALID_HANDLE_VALUE) return resp;
    sf::WriteFramed(pipe, cmdJson);
    sf::ReadFramed(pipe, resp);
    CloseHandle(pipe);
    return resp;
}
static std::string ProbeVerdictRequest(const std::wstring& path) {
    return ProbePipeRequest("{\"cmd\":\"probe\",\"path\":\"" + sf::JsonEscape(W2U8(path)) + "\"}");
}
static std::string ProbeCleanRequest(const std::wstring& path) {
    return ProbePipeRequest("{\"cmd\":\"probeclean\",\"path\":\"" + sf::JsonEscape(W2U8(path)) + "\"}");
}
// 撤销最近一次自动回滚：把 token 交给服务，服务调 rb::UndoLastRollback。
static std::string UndoPipeRequest(const std::string& token) {
    return ProbePipeRequest("{\"cmd\":\"rollbackundo\",\"token\":\"" + sf::JsonEscape(token) + "\"}");
}
// 从响应里原样抠出 "hits":[...] 数组段（普通查找平衡）
static std::string ExtractHitsRaw(const std::string& resp) {
    size_t hb = resp.find("\"hits\":[");
    if (hb == std::string::npos) return "[]";
    size_t ob = hb + 7, i = ob;
    int depth = 0;
    for (; i < resp.size(); ++i) {
        if (resp[i] == '{' || resp[i] == '[') ++depth;
        else if (resp[i] == '}' || resp[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
    }
    return resp.substr(ob, i - ob);
}

void GetDockPos(int& x, int& y, int w, int h, int margin) {
    RECT wa{}; SystemParametersInfoW(SPI_GETWORKAREA, 0, &wa, 0);
    x = wa.right - w - margin;
    y = wa.bottom - h - margin;
}

// 一次性兜底提示（仅初始化失败时调用，g_fallbackDone 保证只弹一次）
void FallbackMessage() {
    if (g_fallbackDone) return;
    g_fallbackDone = true;
    wchar_t buf[128];
    swprintf_s(buf, L"[fallback] 触发兜底，lastHr=0x%08X\r\n", (unsigned)g_lastHr);
    WriteDbg(buf);
    // 关键：不先 DestroyWindow 再 MessageBox。先 DestroyWindow 会触发 WM_DESTROY→PostQuitMessage，
    // 干扰 MessageBox 显示（表现即「只有系统警告音、看不到框」）。改为先弹框、返回后再销毁。
    MessageBoxW(g_hwnd, L"主防发现异常，请打开扩展「主防」查看详情。",
                L"银狐主防", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TOPMOST);
    if (g_hwnd && IsWindow(g_hwnd)) DestroyWindow(g_hwnd);
    PostQuitMessage(0);
}

// 构建通知 HTML（扁平化安全告警卡片：状态图标徽章 + 状态色微光 + 评分胶囊，
// 跟随系统深浅色，入场上浮淡入、柔和投影、圆形幽灵关闭钮，去除「AI 模板感」）
std::wstring BuildHtml(const std::string& status, int score, const std::wstring& theme) {
    std::wstring title, sub, accent, soft, line, glow, aura;
    // 勒索回滚场景：卡片语义与普通扫描告警完全不同，文案单独一套。
    //   high  = 引擎已自动处置 → 标题陈述"已拦截"，副标题给出撤销指引
    //   suspect = 仅拦截未动手 → 标题陈述"已拦截操作"，副标题说明需要用户决定
    // 判定"是否回滚场景"看 g_risk 非空（普通扫描告警不带 --risk 参数）。
    const bool isHigh    = (g_risk == L"high");
    const bool isSuspect = (g_risk == L"suspect");
    const bool isRollback = (isHigh || isSuspect);
    // ---- 正经杀软模式卡片（2026-09-19，银泊指示）：有风险活动 → 自动处理 → 问撤销 ----
    //   mbr    = 引导扇区防护（已拦截弹「撤销拦截」；被动弹「恢复引导/信任此变更」）
    //   proc   = 可疑进程行为已自动终止（进程不能复活，无撤销；文件副作用归回滚引擎管）
    //   regrun = 可疑自启动项已自动移除（撤销 = 写回注册表原值）
    //   landed = 落地载荷已自动隔离（撤销 = 移回原位）
    //   hashlanded = 病毒库命中的已知恶意样本已自动隔离（撤销 = 移回原位）
    //                ★ 与 landed 的区别 = 「确凿（字节同一性）」vs「疑似（形态可疑）」
    // 卡面上的「某某程序」归因文本由 JS 经管道取 lastalert 回填（见 alertdetail）。
    const bool isBoot    = (g_risk == L"mbr");
    const bool isProc    = (g_risk == L"proc");
    const bool isRegrun  = (g_risk == L"regrun");
    const bool isLanded  = (g_risk == L"landed");
    // ★★ hashlanded（2026-09-25 新增）= **病毒库（字节同一性）命中**的已知恶意样本，
    //   已自动隔离。刻意与 landed 分成两个 risk 值，理由是两者的语义强度不同：
    //     landed     = 「落在这个目录 + 形态可疑」→ 结论是**疑似**，用户该"看一眼再决定"
    //     hashlanded = 「与库中样本逐字节一致」  → 结论是**确凿**，用户只需"清掉"
    //   混成一张卡，用户就分不出「确凿」与「疑似」，也就无从判断该不该点「撤销」——
    //   而这两种情况点撤销的代价完全不同（确凿样本恢复回去 = 主动放行已知恶意）。
    //   撤销行为与 landed 完全一致（移回原位，token 前缀同为 30）。
    const bool isHashLanded = (g_risk == L"hashlanded");
    const bool isAutoKill = (isBoot || isProc || isRegrun || isLanded || isHashLanded);
    // 状态色：主色 accent、徽章底色 soft、描边 line、外发光 glow、光晕 aura（克制但有层次）
    if (isHigh) {
        title = L"勒索行为已拦截";
        sub   = g_rolledBack ? L"已终止肇事进程并还原被改写的文件，可在下方撤销本次处理。"
                             : L"已终止肇事进程。本次未发生文件覆盖，无须撤销。";
        accent = L"#ff4d57"; soft = L"rgba(255,77,87,.14)"; line = L"rgba(255,77,87,.32)";
        glow = L"rgba(255,77,87,.28)"; aura = L"rgba(255,77,87,.16)";
    } else if (isSuspect) {
        title = L"可疑操作已拦截";
        sub   = L"检测到疑似批量改写，已阻断但尚未改动你的文件。请确认是否还原。";
        accent = L"#f5a623"; soft = L"rgba(245,166,35,.16)"; line = L"rgba(245,166,35,.34)";
        glow = L"rgba(245,166,35,.26)"; aura = L"rgba(245,166,35,.18)";
    } else if (isBoot) {
        // 引导扇区：已拦截（有归因，撤销=写回隔离副本）/ 被动（无归因，交用户决定）
        title = g_rolledBack ? L"已自动拦截 · 引导扇区修改" : L"引导扇区被修改";
        sub   = g_rolledBack
                  ? L"<span id=\"alSub\">正在获取事件详情…</span>"
                  : L"检测到系统引导代码区（MBR）与安装基线不一致。若你近期没有安装系统或引导管理工具，"
                    L"这可能是 bootkit 正在建立开机持久化，建议「恢复引导」；磁盘工具的合法改动请选「信任此变更」。";
        accent = L"#ff4d57"; soft = L"rgba(255,77,87,.14)"; line = L"rgba(255,77,87,.32)";
        glow = L"rgba(255,77,87,.28)"; aura = L"rgba(255,77,87,.16)";
    } else if (isProc || isRegrun || isLanded || isHashLanded) {
        // 标题必须让用户一眼分清「确凿」与「疑似」：
        //   hashlanded → 「已知恶意样本」= 已与病毒库比对一致，不存在"可能误判"的余地
        //   landed     → 「落地载荷」    = 靠目录 + 形态推断出来的可疑
        title = isProc        ? L"可疑行为已自动拦截"
              : isRegrun      ? L"可疑自启动项已自动拦截"
              : isHashLanded  ? L"已知恶意样本已自动隔离"
                              : L"落地载荷已自动隔离";
        sub   = L"<span id=\"alSub\">正在获取事件详情…</span>";
        accent = L"#ff4d57"; soft = L"rgba(255,77,87,.14)"; line = L"rgba(255,77,87,.32)";
        glow = L"rgba(255,77,87,.28)"; aura = L"rgba(255,77,87,.16)";
    } else if (status == "infected") {
        title = L"高危：疑似环境异常";
        sub   = L"检测到银狐木马活动迹象，请立即处理。";
        accent = L"#ff4d57"; soft = L"rgba(255,77,87,.14)"; line = L"rgba(255,77,87,.32)";
        glow = L"rgba(255,77,87,.28)"; aura = L"rgba(255,77,87,.16)";
    } else if (status == "warning") {
        title = L"风险预警";
        sub   = L"发现可疑迹象，建议进一步排查。";
        accent = L"#f5a623"; soft = L"rgba(245,166,35,.16)"; line = L"rgba(245,166,35,.34)";
        glow = L"rgba(245,166,35,.26)"; aura = L"rgba(245,166,35,.18)";
    } else {
        title = L"环境已恢复正常";
        sub   = L"未检测到银狐木马活动迹象。";
        accent = L"#1fb574"; soft = L"rgba(31,181,116,.14)"; line = L"rgba(31,181,116,.32)";
        glow = L"rgba(31,181,116,.26)"; aura = L"rgba(31,181,116,.16)";
    }
    // 三种状态的线性图标（描边，随状态色 currentColor 着色），比色块/emoji 更有质感
    std::wstring icon;
    if (isHashLanded) {
        // 病毒库命中的**确凿**恶意 → 盾牌 + 叉；与「形态可疑」的盾牌 + 感叹号形成
        // 一眼可辨的区别（同 viewBox / 同描边风格，不破坏卡片设计统一性）。
        icon = L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" "
               L"stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
               L"<path d=\"M12 2l8 3v6c0 5-3.4 8.6-8 11-4.6-2.4-8-6-8-11V5l8-3z\"/>"
               L"<line x1=\"9.4\" y1=\"9.4\" x2=\"14.6\" y2=\"14.6\"/>"
               L"<line x1=\"14.6\" y1=\"9.4\" x2=\"9.4\" y2=\"14.6\"/></svg>";
    } else if (isHigh || isSuspect || isAutoKill || status == "infected") {
        icon = L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" "
               L"stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
               L"<path d=\"M12 2l8 3v6c0 5-3.4 8.6-8 11-4.6-2.4-8-6-8-11V5l8-3z\"/>"
               L"<line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"13\"/><circle cx=\"12\" cy=\"16.4\" r=\".9\" "
               L"fill=\"currentColor\" stroke=\"none\"/></svg>";
    } else if (status == "warning") {
        icon = L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" "
               L"stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
               L"<path d=\"M12 3l9.5 16.5H2.5L12 3z\"/><line x1=\"12\" y1=\"9.5\" x2=\"12\" y2=\"14.5\"/>"
               L"<circle cx=\"12\" cy=\"17.6\" r=\".9\" fill=\"currentColor\" stroke=\"none\"/></svg>";
    } else {
        icon = L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" "
               L"stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\">"
               L"<circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12.2l2.6 2.6L16 9.4\"/></svg>";
    }
    wchar_t scoreBuf[64];
    swprintf_s(scoreBuf, L"%d", score);

    int pct = score; if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    wchar_t pctBuf[16]; swprintf_s(pctBuf, L"%d", pct);

    // 动作区：三档互斥
    //   ① 高风险 + 确实覆盖写过 → 「撤销我的处理」+「知道了」（撤销是主操作，视觉加重）
    //   ② 可疑（仅拦截未动手） → 「还原文件」+「保持拦截」
    //   ③ 普通扫描告警         → 「清除威胁」（沿用旧行为）
    std::wstring action;
    if (isHigh && g_rolledBack) {
        // 撤销按钮走 doUndo()：前端先播一次确认态（覆盖写不可逆，误点代价高），
        // 用户再点一次才真正 postMessage 给宿主（见 WebMessageReceived 里的 'undo:' 分支）。
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">知道了</div>"
                 L"<div class=\"btn warn\" id=\"undoBtn\" onclick=\"doUndo()\">撤销我的处理</div>"
                 L"</div>";
    } else if (isSuspect) {
        // 注意：回滚引擎目前**不产出** Suspect 档位（见 rollback.cpp 的说明——
        // 回滚是覆盖写，误伤代价高于漏报）。本分支是预留给上层其他事件源
        // （文件落地 / 计划任务 / 注册表启动项）复用的：那些场景不涉及覆盖写，
        // 适合"先问用户再动手"。这里"还原文件"调的是手动的 rollbackdo
        // （把有快照的文件退回去），而不是 undo —— 因为尚未发生过自动回滚。
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">保持拦截</div>"
                 L"<div class=\"btn warn\" id=\"undoBtn\" onclick=\"doUndo()\">还原文件</div>"
                 L"</div>";
    } else if (isBoot && !g_rolledBack) {
        // 引导扇区被动告警（无归因）：交用户决定。「恢复引导」带二次确认（覆盖写不可逆）
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('boot-accept')\">信任此变更</div>"
                 L"<div class=\"btn warn\" id=\"bootBtn\" onclick=\"doBootAct()\">恢复引导</div>"
                 L"</div>";
    } else if (isBoot) {
        // 引导扇区自动拦截：终止 + 恢复已完成，「撤销拦截」写回隔离副本（复用 undo: 管道）
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">知道了</div>"
                 L"<div class=\"btn warn\" id=\"undoBtn\" onclick=\"doUndo()\">撤销拦截</div>"
                 L"</div>";
    } else if (isProc) {
        // 进程终止无法"撤销"（进程不能复活），只告知；文件副作用由回滚引擎另弹可撤销卡
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">知道了</div>"
                 L"</div>";
    } else if (isRegrun || isLanded || isHashLanded) {
        // 自启动移除 / 落地隔离（含病毒库命中隔离）：可撤销
        //（统一走 undo: 管道 → 服务按 token 前缀分发，30 = 隔离区还原）
        action = L"<div class=\"btns\">"
                 L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">知道了</div>"
                 L"<div class=\"btn warn\" id=\"undoBtn\" onclick=\"doUndo()\">撤销我的处理</div>"
                 L"</div>";
    } else if (status != "normal") {
        action = L"<div class=\"act\" onclick=\"window.chrome.webview.postMessage('clean')\">清除威胁</div>";
    }

    // 撤销按钮的二次确认脚本：把按钮换成"确认态"，3 秒无操作自动还原。
    // 2026-09-19 扩展：引导拦截卡（撤销拦截）/ 自启动移除 / 落地隔离都复用同一脚本，
    // 统一走 undo:<token> 管道 → 服务按 token 前缀分发（10=引导 20=自启 30=隔离）。
    const bool needsUndoJs = (isHigh || isSuspect || (isBoot && g_rolledBack) || isRegrun || isLanded || isHashLanded);
    std::wstring undoJs;
    if (needsUndoJs) {
        const std::wstring confirmTxt = isSuspect ? L"确认还原？" : (isBoot ? L"确认撤销拦截？" : L"确认撤销？");
        const std::wstring normalTxt  = isSuspect ? L"还原文件"   : (isBoot ? L"撤销拦截"     : L"撤销我的处理");
        undoJs =
            L"var _uArmed=0,_uTimer=null;function doUndo(){"
            L"var b=document.getElementById('undoBtn');if(!b)return;"
            L"if(!_uArmed){_uArmed=1;b.className='btn danger';"
            L"b.textContent='" + confirmTxt + L"';"
            L"_uTimer=setTimeout(function(){_uArmed=0;b.className='btn warn';"
            L"b.textContent='" + normalTxt + L"';},3000);return;}"
            L"clearTimeout(_uTimer);b.textContent='正在还原…';b.className='btn ghost';"
            L"window.chrome.webview.postMessage('undo:" + U8W(g_undoToken) + L"');}";
    }
    // 「恢复引导」二次确认（被动 mbr 卡）：覆盖写不可逆，误点代价高
    std::wstring bootJs;
    if (isBoot && !g_rolledBack) {
        bootJs =
            L"var _bArmed=0,_bTimer=null;function doBootAct(){"
            L"var b=document.getElementById('bootBtn');if(!b)return;"
            L"if(!_bArmed){_bArmed=1;b.className='btn danger';b.textContent='确认恢复引导？';"
            L"_bTimer=setTimeout(function(){_bArmed=0;b.className='btn warn';b.textContent='恢复引导';},3000);return;}"
            L"clearTimeout(_bTimer);b.textContent='正在恢复…';b.className='btn ghost';"
            L"window.chrome.webview.postMessage('boot-restore');}";
    }
    // 自动拦截卡的「某某程序」归因回填：页面加载即向宿主要 lastalert
    // （进程名不能拼进命令行 —— toast.exe 命令行是外部可写边界，有注入面）
    std::wstring detailJs;
    if (isAutoKill && !(isBoot && !g_rolledBack)) {
        detailJs = L"window.chrome.webview.postMessage('alertdetail');";
    }

    return
        L"<!doctype html><html data-theme=\"" + theme + L"\"><head><meta charset=\"utf-8\">"        L"<style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        // 卡片：状态色光晕（徽章后）+ 渐变底 + 状态描边 + 柔和投影；扁平化无内高光；初始透明供进场动画
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);--track:rgba(30,34,46,.10);"
        L"background:radial-gradient(160px 150px at 50px 50%,var(--accent-aura) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));"
        L"border-radius:18px;border:1px solid var(--accent-line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--accent-line);"
        L"color:var(--fg);display:flex;align-items:center;gap:18px;padding:22px 24px;position:relative;opacity:0;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;"
        L"--sub:rgba(232,234,242,.60);--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);"
        L"--track:rgba(255,255,255,.12);}"
        L"@media (prefers-color-scheme:dark){html:not([data-theme=\"light\"]) body{"
        L"--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--track:rgba(255,255,255,.12);}}"
        L"@keyframes rise{from{opacity:0;transform:translateY(14px) scale(.985);}to{opacity:1;transform:translateY(0) scale(1);}}"
        L".show{animation:rise .36s cubic-bezier(.22,.61,.36,1) both;}"
        L".hide{animation:fall .26s ease-in both;}"
        L"@keyframes fall{from{opacity:1;transform:translateY(0) scale(1);}to{opacity:0;transform:translateY(12px) scale(.99);}}"
        // 状态图标徽章：圆形、状态底色、状态描边、双重外发光（近处细描边 + 远处柔光晕）
        L".badge{flex:0 0 auto;width:54px;height:54px;border-radius:16px;display:grid;place-items:center;"
        L"color:var(--accent);background:var(--accent-soft);"
        L"box-shadow:inset 0 0 0 1px var(--accent-line),0 6px 16px var(--accent-glow);}"
        L".content{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:8px;}"
        L".title{font-size:16px;font-weight:800;letter-spacing:.3px;line-height:1.3;padding-right:24px;}"
        L".sub{font-size:12.5px;color:var(--sub);line-height:1.5;}"
        // 评分条：轨道 + 状态色填充 + 数值，量化呈现风险
        L".meter{display:flex;align-items:center;gap:12px;margin-top:1px;}"
        L".track{flex:1;height:6px;border-radius:999px;background:var(--track);overflow:hidden;}"
        L".fill{height:100%;border-radius:999px;background:var(--accent);width:" + std::wstring(pctBuf) + L"%;}"
        L".score{font-size:11.5px;color:var(--sub);white-space:nowrap;letter-spacing:.2px;}"
        L".score b{color:var(--accent);font-weight:800;font-size:15px;margin-left:3px;}"
        L".brand{position:absolute;left:24px;bottom:11px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        // 圆形幽灵关闭钮
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;"
        L"transition:background .15s,color .15s;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        // 「清除威胁」胶囊按钮：状态色实心、柔和外发光、按下微缩（非线性缓动）
        L".act{position:absolute;right:12px;bottom:10px;padding:5px 13px;border-radius:999px;"
        L"font-size:11.5px;font-weight:700;letter-spacing:.3px;color:#fff;cursor:pointer;"
        L"background:var(--accent);box-shadow:0 4px 12px var(--accent-glow);"
        L"transition:transform .16s cubic-bezier(.22,.61,.36,1),box-shadow .2s ease,filter .18s ease;}"
        L".act:hover{transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 7px 18px var(--accent-glow);}"
        L".act:active{transform:translateY(0) scale(.97);}"
        // 双按钮行（撤销场景）：等宽并排，主操作在右（符合中文界面「确认在右」的习惯）
        L".btns{position:absolute;right:24px;bottom:12px;left:24px;display:flex;gap:9px;}"
        L".btn{flex:1;text-align:center;padding:8px 0;border-radius:11px;font-size:12.5px;"
        L"font-weight:800;letter-spacing:.2px;cursor:pointer;user-select:none;"
        L"transition:transform .16s cubic-bezier(.22,.61,.36,1),background .18s ease,"
        L"box-shadow .2s ease,filter .18s ease;}"
        L".btn:active{transform:scale(.97);}"
        L".btn.ghost{background:rgba(127,127,127,.12);color:var(--fg);}"
        L".btn.ghost:hover{background:rgba(127,127,127,.2);}"
        // warn = 撤销入口常态（琥珀色，提醒"这是个反悔操作"但不必紧张）
        L".btn.warn{background:rgba(245,166,35,.16);color:#b06a00;"
        L"box-shadow:inset 0 0 0 1px rgba(245,166,35,.34);}"
        L".btn.warn:hover{background:rgba(245,166,35,.26);}"
        L"[data-theme=\"dark\"] .btn.warn{color:#f5c26b;}"
        // danger = 二次确认态（转为红色实心，视觉上明确进入"即将执行"）
        L".btn.danger{background:#e03225;color:#fff;box-shadow:0 4px 12px rgba(224,50,37,.32);}"
        L".btn.danger:hover{filter:brightness(1.07);}"
        // 撤销场景下品牌署名要让位给按钮行，避免重叠
        L"body.has-btns .brand{bottom:56px;}"
        L"</style></head><body class=\""
        + std::wstring(isRollback || isAutoKill ? L"has-btns" : L"") +
        L"\" style=\"--accent:" + accent + L";--accent-soft:" + soft + L";"
        L"--accent-line:" + line + L";--accent-glow:" + glow + L";--accent-aura:" + aura + L"\">"
        L"<div class=\"badge\">" + icon + L"</div>"
        L"<div class=\"content\">"
        L"<div class=\"title\">" + title + L"</div>"
        L"<div class=\"sub\">" + sub + L"</div>"
        L"<div class=\"meter\"><div class=\"track\"><div class=\"fill\"></div></div>"
        L"<div class=\"score\">风险评分<b>" + std::wstring(scoreBuf) + L"</b></div></div>"
        L"</div>"
        L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>"
        L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},260)\">✕</div>"
        + action +
        L"<script>" + bootJs + detailJs + undoJs + L"</script>" +
        L"</body></html>";
}

// ===========================================================================
//  「一键清除」流程：确认 → 进度卡片（读服务写的进度文件）→ 结果卡片
//  权限说明：真正的杀进程/删文件由【服务（LocalSystem）】执行，弹窗只负责确认与展示，
//  因此全程不会出现 UAC 提权窗口。
// ===========================================================================
#ifndef IDI_SHIELD
#define IDI_SHIELD 101
#endif

// ANSI(GBK) → wstring：文件路径是 ANSI 编码，不能按 UTF-8 解（会乱码）
static std::wstring A2WStr(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 把文本安全地嵌进 JS 单引号字符串（转义 \ ' 与控制字符）
static std::wstring JsSafe(const std::string& ansi) {
    std::wstring w = A2WStr(ansi), o;
    for (wchar_t c : w) {
        if (c == L'\\' || c == L'\'' || c == L'"') { o += L'\\'; o += c; }
        else if (c == L'\n' || c == L'\r' || c == L'\t') o += L' ';
        else o += c;
    }
    return o;
}

// 二次确认：清除不可恢复。原为系统 MessageBox，改为与告警卡同风格的 WebView2 确认卡
// （异步：用户点按钮后由消息回调继续流程，不再阻塞主线程）。
static std::wstring BuildCleanConfirmHtml() {
    return L"<!doctype html><html data-theme=\"" + g_theme + L"\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);--track:rgba(30,34,46,.10);"
        L"--red:#ff4d57;--red-soft:rgba(255,77,87,.12);--red-line:rgba(255,77,87,.35);"
        L"--red-glow:rgba(255,77,87,.22);"
        L"background:radial-gradient(150px 130px at 60px 40px,rgba(255,77,87,.13) 0%,transparent 70%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--red-line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--red-line);color:var(--fg);"
        L"display:flex;flex-direction:column;gap:10px;padding:16px 20px;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--track:rgba(255,255,255,.12);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".head{display:flex;align-items:center;gap:9px;}"
        L".badge{flex:0 0 auto;width:34px;height:34px;border-radius:11px;display:grid;place-items:center;"
        L"color:var(--red);background:var(--red-soft);box-shadow:inset 0 0 0 1px var(--red-line),0 5px 14px var(--red-glow);}"
        L".badge svg{width:19px;height:19px;}"
        L".t{font-size:14px;font-weight:800;letter-spacing:.3px;line-height:1.2;}"
        L".desc{font-size:11.5px;color:var(--sub);line-height:1.5;}"
        L".desc b{color:var(--red);font-weight:700;}"
        L".btns{display:flex;gap:9px;margin-top:2px;}"
        L".btn{flex:1;padding:8px 0;border-radius:10px;font-size:12.5px;font-weight:700;cursor:pointer;"
        L"border:1px solid transparent;transition:transform .15s cubic-bezier(.22,.61,.36,1),filter .15s ease;"
        L"text-align:center;}"
        L".btn:active{transform:scale(.97);}"
        L".btn.ghost{background:rgba(127,127,127,.10);color:var(--fg);border-color:rgba(127,127,127,.22);}"
        L".btn.danger{background:var(--red);color:#fff;box-shadow:0 5px 14px var(--red-glow);}"
        L".btn.danger:hover{filter:brightness(1.08);}"
        L"</style></head><body>"
        L"<div class=\"head\"><div class=\"badge\"><svg viewBox=\"0 0 24 24\" fill=\"none\">"
        L"<path d=\"M12 3 4 6v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V6l-8-3Z\" stroke=\"currentColor\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/>"
        L"<path d=\"M12 8v5M9.5 12.5 12 15l2.5-2.5\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg></div>"
        L"<div class=\"t\">确认清除检测到的威胁？</div></div>"
        L"<div class=\"desc\">将以最高权限结束占用进程并删除可疑文件。"
        L"<b>删除后无法恢复</b>；若文件仍被占用，会登记为下次重启后自动删除。</div>"
        L"<div class=\"btns\">"
        L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('clean-cancel')\">取消</div>"
        L"<div class=\"btn danger\" onclick=\"window.chrome.webview.postMessage('clean-ok')\">继续清除</div>"
        L"</div>"
        L"</body></html>";
}

// 通知服务执行清除（服务以 LocalSystem 运行，具备最高权限；此处无需提权）
// cmd：clean（普通删除）/ clean_adv（高级删除）
static bool CallServiceClean(const std::string& cmd, std::string& outResp) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 30; ++i) {
        h = CreateFileW(sf::PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        Sleep(200);
    }
    if (h == INVALID_HANDLE_VALUE) { WriteDbg(L"[clean] 连接服务管道失败\r\n"); return false; }
    std::string frame = "{\"cmd\":\"" + cmd + "\"}";
    bool ok = sf::WriteFramed(h, frame) && sf::ReadFramed(h, outResp);
    CloseHandle(h);
    { wchar_t b[96]; swprintf_s(b, L"[clean] %hs 服务返回 ok=%d len=%d\r\n", cmd.c_str(), (int)ok, (int)outResp.size()); WriteDbg(b); }
    return ok;
}

// 进度卡片：圆角卡片 + 状态色描边 + 脉冲指示点 + 圆角进度条（与告警卡片同一设计语言）
// adv=false：普通删除（第一阶段）；adv=true：高级删除（普通删不完后升级）
static std::wstring BuildCleaningHtml(bool adv) {
    const wchar_t* head = adv ? L"正在执行高级删除" : L"正在执行普通删除";
    const wchar_t* tip  = adv ? L"强制结束占用进程树并解除文件权限…" : L"结束占用进程并删除可疑文件…";
    return L"<!doctype html><html data-theme=\"" + g_theme + L"\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);--track:rgba(30,34,46,.10);"
        L"--line:rgba(255,77,87,.32);--glow:rgba(255,77,87,.22);"
        L"background:radial-gradient(160px 150px at 50px 50%,rgba(255,77,87,.14) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--line);color:var(--fg);"
        L"display:flex;flex-direction:column;gap:10px;padding:20px 24px;position:relative;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--track:rgba(255,255,255,.12);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".t{font-size:15px;font-weight:800;letter-spacing:.3px;display:flex;align-items:center;gap:9px;}"
        L".dot{width:9px;height:9px;border-radius:50%;background:#ff4d57;box-shadow:0 0 0 4px rgba(255,77,87,.16);"
        L"animation:pulse 1.1s ease-in-out infinite;}"
        L"@keyframes pulse{0%,100%{transform:scale(1);opacity:1;}50%{transform:scale(.68);opacity:.5;}}"
        L".s{font-size:12px;color:var(--sub);}"
        L".track{height:8px;border-radius:999px;background:var(--track);overflow:hidden;margin-top:2px;}"
        L".fill{height:100%;width:0%;border-radius:999px;background:linear-gradient(90deg,#ff7a82,#ff4d57);"
        L"box-shadow:0 0 10px var(--glow);transition:width .28s cubic-bezier(.22,.61,.36,1);}"
        L".row{display:flex;align-items:center;justify-content:space-between;gap:12px;}"
        L".pct{font-size:12px;font-weight:800;color:#ff4d57;white-space:nowrap;}"
        L".cur{font-size:10.5px;color:var(--brand);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}"
        L".brand{position:absolute;left:24px;bottom:9px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L"</style></head><body>"
        L"<div class=\"t\"><span class=\"dot\"></span>" + std::wstring(head) + L"</div>"
        L"<div class=\"s\" id=\"ph\">" + std::wstring(tip) + L"</div>"
        L"<div class=\"track\"><div class=\"fill\" id=\"bar\"></div></div>"
        L"<div class=\"row\"><div class=\"cur\" id=\"cur\"></div><div class=\"pct\" id=\"pct\">0%</div></div>"
        L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>"
        L"</body></html>";
}

// 高级删除确认卡（第二段）：普通删除未删完时弹出，说明剩多少并请求启用高级删除
static std::wstring BuildAdvancedPromptHtml(int failedCount) {
    wchar_t cnt[32]; swprintf_s(cnt, L"%d", failedCount);
    return L"<!doctype html><html data-theme=\"" + g_theme + L"\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);--track:rgba(30,34,46,.10);"
        L"--amber:#f5a623;--amber-soft:rgba(245,166,35,.13);--amber-line:rgba(245,166,35,.36);"
        L"--amber-glow:rgba(245,166,35,.24);"
        L"background:radial-gradient(150px 130px at 60px 40px,rgba(245,166,35,.13) 0%,transparent 70%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--amber-line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--amber-line);color:var(--fg);"
        L"display:flex;flex-direction:column;gap:8px;padding:14px 18px;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--track:rgba(255,255,255,.12);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".head{display:flex;align-items:center;gap:9px;}"
        L".badge{flex:0 0 auto;width:34px;height:34px;border-radius:11px;display:grid;place-items:center;"
        L"color:var(--amber);background:var(--amber-soft);box-shadow:inset 0 0 0 1px var(--amber-line),0 5px 14px var(--amber-glow);}"
        L".badge svg{width:19px;height:19px;}"
        L".t{font-size:14px;font-weight:800;letter-spacing:.3px;line-height:1.2;}"
        L".desc{font-size:11.5px;color:var(--sub);line-height:1.45;}"
        L".desc b{color:var(--amber);font-weight:800;}"
        L".btns{display:flex;gap:9px;margin-top:1px;}"
        L".btn{flex:1;padding:7px 0;border-radius:10px;font-size:12.5px;font-weight:700;cursor:pointer;"
        L"border:1px solid transparent;transition:transform .15s cubic-bezier(.22,.61,.36,1),filter .15s ease;"
        L"text-align:center;}"
        L".btn:active{transform:scale(.97);}"
        L".btn.ghost{background:rgba(127,127,127,.10);color:var(--fg);border-color:rgba(127,127,127,.22);}"
        L".btn.danger{background:var(--amber);color:#fff;box-shadow:0 5px 14px var(--amber-glow);}"
        L".btn.danger:hover{filter:brightness(1.08);}"
        L"</style></head><body>"
        L"<div class=\"head\"><div class=\"badge\"><svg viewBox=\"0 0 24 24\" fill=\"none\">"
        L"<path d=\"M12 3 4 6v6c0 5 3.4 8.5 8 9 4.6-.5 8-4 8-9V6l-8-3Z\" stroke=\"currentColor\" stroke-width=\"1.6\" stroke-linejoin=\"round\"/>"
        L"<path d=\"M12 8v5M9.5 12.5 12 15l2.5-2.5\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\"/></svg></div>"
        L"<div class=\"t\">部分威胁未能删除</div></div>"
        L"<div class=\"desc\">普通删除已完成，仍有 <b>" + std::wstring(cnt) + L" 个文件</b>未删除完。"
        L"这些文件多被木马进程占用或设置了删除保护，是否启用<b>高级删除</b>？（强制结束全部占用进程树、解除文件权限后删除）</div>"
        L"<div class=\"btns\">"
        L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('clean-adv-cancel')\">暂不处理</div>"
        L"<div class=\"btn danger\" onclick=\"window.chrome.webview.postMessage('clean-adv')\">启用高级删除</div>"
        L"</div>"
        L"</body></html>";
}

// 结果卡片：全成功=绿色；有失败/待重启=琥珀色。高级删除完成后展示 普通+高级 合并结果
static std::wstring BuildCleanResultHtml() {
    const bool ok = g_cleanOk;
    // 合并普通（快照）与高级（当前 g_res*）两段结果。
    // deleted/killed/extraDll 累计展示；failed/deferred 反映【最终状态】：
    // 服务端会把普通阶段 failed + deferred 的目标【全部纳入高级队列】，高级阶段要么硬删
    // 要么再次登记 → 最终残留 = 高级阶段回包的 g_resDeferred / g_resFailed。
    // （旧逻辑把普通 deferred 累加进最终值，但那些文件实际已被高级删除硬删 → 误报「仍有残留」。）
    const int td = g_resDeleted  + (g_advStage ? g_normDeleted  : 0);
    const int tk = g_resKilled   + (g_advStage ? g_normKilled   : 0);
    const int te = g_resExtraDll + (g_advStage ? g_normExtraDll : 0);
    const int td2 = g_resDeferred;             // 最终重启删除：高级完成后即高级剩余 deferred 数
    const int tf  = g_resFailed;               // 最终失败：高级完成后即高级剩余失败数
    const bool partial = ok && (tf > 0 || td2 > 0);
    std::wstring accent = !ok ? L"#ff4d57" : (partial ? L"#f5a623" : L"#1fb574");
    std::wstring title  = !ok ? L"清除请求未送达"
                       : (g_advStage
                          ? (partial ? L"高级删除后仍有残留" : L"高级删除完成")
                          : (partial ? L"部分威胁已处理" : L"已清除检测到的威胁"));
    std::wstring sub    = !ok ? L"服务未响应，请稍后在扩展面板重试。"
                              : L"占用进程已强制结束，相关文件（含载荷 DLL）已删除。";
    wchar_t b1[256];
    swprintf_s(b1, L"删除 %d 项 · 结束进程 %d 个 · 连坐载荷 DLL %d 个", td, tk, te);
    std::wstring line1 = b1;
    // 强调行：仍有 N 个文件将在重启后自动删除（醒目标注，不让用户漏看）
    std::wstring restartLine;
    if (td2) { swprintf_s(b1, L"另有 %d 个文件将在重启后自动删除", td2); restartLine = b1; }
    std::wstring failLine;
    if (tf) { swprintf_s(b1, L"%d 个文件删除失败", tf); failLine = b1; }
    return L"<!doctype html><html data-theme=\"" + g_theme + L"\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);"
        L"background:radial-gradient(160px 150px at 50px 50%,var(--aura) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--line);color:var(--fg);"
        L"display:flex;align-items:center;gap:16px;padding:18px 22px;position:relative;"
        L"animation:rise .34s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(12px) scale(.985);}to{opacity:1;transform:none;}}"
        L".badge{flex:0 0 auto;width:54px;height:54px;border-radius:16px;display:grid;place-items:center;"
        L"color:var(--accent);background:var(--soft);box-shadow:inset 0 0 0 1px var(--line),0 6px 16px var(--glow);}"
        L".content{flex:1 1 auto;min-width:0;display:flex;flex-direction:column;gap:5px;padding-right:22px;}"
        L".title{font-size:15.5px;font-weight:800;letter-spacing:.3px;}"
        L".sub{font-size:12px;color:var(--sub);line-height:1.45;}"
        L".d1{font-size:12px;color:var(--fg);font-weight:700;}"
        L".d2{font-size:11px;color:var(--sub);}"
        L".d3{font-size:11.5px;color:var(--accent);font-weight:800;}"
        L".brand{position:absolute;left:24px;bottom:11px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;"
        L"transition:background .15s,color .15s;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body style=\"--accent:" + accent + L";--soft:rgba(127,127,127,.10);"
        L"--line:" + accent + L"55;--glow:" + accent + L"44;--aura:" + accent + L"22\">"
        L"<div class=\"badge\">" + (ok && !partial
            ? L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><circle cx=\"12\" cy=\"12\" r=\"9\"/><path d=\"M8 12.2l2.6 2.6L16 9.4\"/></svg>"
            : L"<svg viewBox=\"0 0 24 24\" width=\"26\" height=\"26\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\"><path d=\"M12 3l9.5 16.5H2.5L12 3z\"/><line x1=\"12\" y1=\"9.5\" x2=\"12\" y2=\"14.5\"/><circle cx=\"12\" cy=\"17.6\" r=\".9\" fill=\"currentColor\" stroke=\"none\"/></svg>")
        + L"</div>"
        L"<div class=\"content\">"
        L"<div class=\"title\">" + title + L"</div>"
        L"<div class=\"sub\">" + sub + L"</div>"
        L"<div class=\"d1\">" + line1 + L"</div>"
        + (restartLine.empty() ? std::wstring() : L"<div class=\"d3\">" + restartLine + L"</div>")
        + (failLine.empty() ? std::wstring() : L"<div class=\"d2\">" + failLine + L"</div>") +
        L"</div>"
        L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>"
        L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},260)\">✕</div>"
        L"</body></html>";
}

// 轮询服务写入的进度文件并刷新进度条（服务在用户会话外，无法直接回调 DOM，故走文件）
static void UpdateCleanProgressUi() {
    std::string phase, cur; int done = 0, total = 0;
    if (!sf::ReadCleanProgress(phase, done, total, cur)) return;
    int pct = 0;
    if (g_advStage) {
        // 高级删除：遏制(advkill)→硬删(delete)→完成(done)，平滑映射 0→40→100
        if (phase == "advkill")     pct = total > 0 ? (int)(40.0 * done / total) : 6;
        else if (phase == "delete") pct = 40 + (total > 0 ? (int)(60.0 * done / total) : 0);
        else if (phase == "done")   pct = 100;
    } else {
        if (phase == "locate")      pct = total > 0 ? (int)(35.0 * done / total) : 4;
        else if (phase == "kill")   pct = 35 + (total > 0 ? (int)(15.0 * done / total) : 6);
        else if (phase == "delete") pct = 50 + (total > 0 ? (int)(50.0 * done / total) : 0);
        else if (phase == "done")   pct = 100;
    }
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    std::wstring label = g_advStage
        ? (phase == "advkill" ? L"强制结束占用进程树…"
           : phase == "delete" ? L"解除权限并删除文件…"
           : (phase == "done" ? L"完成" : L"高级删除中…"))
        : (phase == "locate" ? L"定位威胁文件…"
           : phase == "kill"   ? L"结束占用进程…"
           : phase == "delete" ? L"删除文件…"
                               : L"完成");
    if (pct == g_lastPct && label == g_lastPhase) return;   // 无变化不刷 DOM
    g_lastPct = pct; g_lastPhase = label;
    if (!g_webview) return;
    std::wstring js = L"(function(){var b=document.getElementById('bar');if(b){b.style.width='"
        + std::to_wstring(pct) + L"%';}var p=document.getElementById('pct');if(p){p.textContent='"
        + std::to_wstring(pct) + L"%';}var e=document.getElementById('ph');if(e){e.textContent='"
        + label + L"';}var c=document.getElementById('cur');if(c){c.textContent='" + JsSafe(cur) + L"';}})();";
    g_webview->ExecuteScript(js.c_str(), nullptr);
}

// 点击「清除威胁」→ 确认 → 切进度卡片 → 后台线程请服务执行 → 回主线程渲染结果
// 用户点「清除威胁」→ 先导航到自定义确认卡（异步），确认后真正执行清除
static void StartCleanFlow() {
    if (g_cleaning) return;
    WriteDbg(L"[clean] 弹出确认卡\r\n");
    if (g_webview) g_webview->NavigateToString(BuildCleanConfirmHtml().c_str());
}

// 确认卡里点「继续清除」→ 执行实际清除流程（进度 → 结果/高级升级）
static void ConfirmAndRunClean() {
    if (g_cleaning) return;
    g_cleaning = true; g_cleanOk = false; g_advStage = false;
    g_lastPct = -1; g_lastPhase.clear();
    g_resDeleted = g_resDeferred = g_resFailed = g_resKilled = g_resExtraDll = 0;
    WriteDbg(L"[clean] 用户确认，开始普通删除\r\n");
    if (g_webview) g_webview->NavigateToString(BuildCleaningHtml(false).c_str());
    SetTimer(g_hwnd, 2, 120, nullptr);
    std::thread([]() {
        std::string resp;
        bool ok = CallServiceClean("clean", resp);
        if (ok) {
            g_resDeleted  = sf::JsonGetInt(resp, "deleted");
            g_resDeferred = sf::JsonGetInt(resp, "deferred");
            g_resFailed   = sf::JsonGetInt(resp, "failed");
            g_resKilled   = sf::JsonGetInt(resp, "killed");
            g_resExtraDll = sf::JsonGetInt(resp, "extraDlls");
            // 快照普通阶段结果：高级删除完成后最终页合并显示
            g_normDeleted = g_resDeleted; g_normDeferred = g_resDeferred;
            g_normFailed  = g_resFailed;  g_normKilled = g_resKilled;
            g_normExtraDll = g_resExtraDll;
        }
        g_cleanOk = ok;
        if (g_hwnd) PostMessageW(g_hwnd, WM_APP_CLEAN_DONE, ok ? 1 : 0, 0);
    }).detach();
}

// 高级删除卡里点「启用高级删除」→ 对普通删除失败项执行高级清除（进度 → 最终结果）
static void RunAdvancedClean() {
    if (g_cleaning) return;
    g_cleaning = true; g_cleanOk = false; g_advStage = true;
    g_lastPct = -1; g_lastPhase.clear();
    g_resDeleted = g_resDeferred = g_resFailed = g_resKilled = g_resExtraDll = 0;
    WriteDbg(L"[clean] 用户启用高级删除\r\n");
    if (g_webview) g_webview->NavigateToString(BuildCleaningHtml(true).c_str());
    SetTimer(g_hwnd, 2, 120, nullptr);
    std::thread([]() {
        std::string resp;
        bool ok = CallServiceClean("clean_adv", resp);
        if (ok) {
            g_resDeleted  = sf::JsonGetInt(resp, "deleted");
            g_resDeferred = sf::JsonGetInt(resp, "deferred");
            g_resFailed   = sf::JsonGetInt(resp, "failed");
            g_resKilled   = sf::JsonGetInt(resp, "killed");
            g_resExtraDll = sf::JsonGetInt(resp, "extraDlls");
        }
        g_cleanOk = ok;
        if (g_hwnd) PostMessageW(g_hwnd, WM_APP_CLEAN_DONE, ok ? 1 : 0, 0);
    }).detach();
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) {
        mciSendStringW(L"close sfnotify", nullptr, 0, nullptr);
        // 正确关闭 WebView2：让渲染进程（msedgewebview2.exe）及时退出，
        // 避免残留孤儿进程锁住 userData 目录，导致下次弹窗渲染失败（NavigationCompleted 不触发）。
        if (g_ctrl) g_ctrl->Close();
        PostQuitMessage(0); return 0;
    }
    if (m == WM_DISPLAYCHANGE) {
        // VM / 多屏下分辨率会动态调整：始终把窗口重锚定到工作区右下角（贴任务栏上方，不盖任务栏）
        if (g_hwnd && g_w && g_h) {
            int nx, ny; GetDockPos(nx, ny, g_w, g_h, 18);
            SetWindowPos(g_hwnd, nullptr, nx, ny, 0, 0,
                         SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOSIZE);
        }
        return 0;
    }
    if (m == WM_TIMER && w == 1) {
        // 看门狗：WebView2 在 4 秒内未完成渲染（VM 下常见），退化兜底告警，确保告警不静默丢失
        KillTimer(g_hwnd, 1);
        if (!g_ready) FallbackMessage();
        return 0;
    }
    if (m == WM_TIMER && w == 2) {
        UpdateCleanProgressUi();   // 清除过程中轮询进度文件刷新进度条
        return 0;
    }
    if (m == WM_APP_CLEAN_DONE) {
        KillTimer(g_hwnd, 2);
        g_cleaning = false;
        if (!g_webview) return 0;
        if (g_advStage) {
            // 高级删除完成 → 最终结果卡
            g_webview->NavigateToString(BuildCleanResultHtml().c_str());
        } else if (g_cleanOk && (g_resFailed > 0 || g_resDeferred > 0)) {
            // 普通删除未删完（有失败 或 有登记重启删除）→ 升级提示卡（说明剩余数量，供启用高级删除）
            g_webview->NavigateToString(
                BuildAdvancedPromptHtml(g_resFailed + g_resDeferred).c_str());
        } else {
            // 普通删除全部完成 → 直接最终结果卡
            g_webview->NavigateToString(BuildCleanResultHtml().c_str());
        }
        return 0;
    }
    return DefWindowProc(h, m, w, l);
}

// 渲染就绪后：把窗口从屏幕外滑入右下角，并用 JS 给 body 加 .show 触发进场（淡入上浮）动画；
// 同时在此播放提示音，与弹窗出现时刻对齐（声画同步，不再「先响后弹」）
void TriggerEntrance() {
    g_ready = true;
    KillTimer(g_hwnd, 1);   // WebView2 渲染成功，关闭看门狗
    // 用「当前」工作区尺寸重算停靠点：VM / 多屏分辨率会动态变化，必须用实时值，
    // 不能用创建时缓存的 g_posX/g_posY（否则缩放窗口后窗口会落到可视区外）；
    // 且用工作区（减任务栏）定位，弹窗贴任务栏上方、不盖任务栏。
    int x, y; GetDockPos(x, y, g_w, g_h, 18);
    SetWindowPos(g_hwnd, nullptr, x, y, g_w, g_h,
                 SWP_NOZORDER | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    if (g_webview) {
        // 双 rAF：先强制绘制一帧「opacity:0 初始态」，下一帧再添加 .show，
        // 否则窗口刚移入可见区时首帧可能已错过动画起点，导致进场“直接出现”。
        g_webview->ExecuteScript(
            L"(function(){requestAnimationFrame(function(){requestAnimationFrame(function(){"
            L"document.body.classList.add('show');});});})();", nullptr);
    }
    PlayNotifySound();
}

// 控制器创建完成：设置边界 + 监听关闭消息 + 导航，导航完成后才显示窗口
HRESULT OnController(HRESULT hr, ICoreWebView2Controller* ctrl) {
    wchar_t b[128];
    swprintf_s(b, L"[ctrl] hr=0x%08X ctrl=%p\r\n", (unsigned)hr, (void*)ctrl);
    WriteDbg(b);
    if (FAILED(hr) || !ctrl) { g_lastHr = hr; FallbackMessage(); return S_OK; }
    ComPtr<ICoreWebView2Controller> c = ctrl;
    g_ctrl = c;   // 长期持有 Controller，否则函数返回后释放导致导航完成回调收不到
    HRESULT gh = c->get_CoreWebView2(&g_webview);
    swprintf_s(b, L"[ctrl] get_CoreWebView2 hr=0x%08X webview=%p\r\n", (unsigned)gh, (void*)g_webview.Get());
    WriteDbg(b);
    RECT rc; GetClientRect(g_hwnd, &rc); c->put_Bounds(rc);

    g_msgH = Callback<ICoreWebView2WebMessageReceivedEventHandler>(
        [](ICoreWebView2*, ICoreWebView2WebMessageReceivedEventArgs* a) -> HRESULT {
            LPWSTR p = nullptr;
            if (SUCCEEDED(a->get_WebMessageAsJson(&p)) && p) {
                std::wstring s = p; CoTaskMemFree(p);
                // ---- 撤销最近一次自动处置（勒索回滚场景）----
                // 前端在二次确认后才发 `undo:<token>`。这里校验 token 与启动时
                // 收到的一致（前端可能被 NavigateToString 重渲染，但 token 全程不变），
                // 再转成服务管道命令 rollbackundo。
                if (s.find(L"undo:") != std::wstring::npos) {
                    std::wstring tok = s.substr(s.find(L"undo:") + 5);
                    // 去掉 JSON 收尾引号（get_WebMessageAsJson 对字符串会带引号）
                    while (!tok.empty() && (tok.back() == L'"' || tok.back() == L'\\')) tok.pop_back();
                    std::string tokA = W2U8(tok);
                    WriteDbg(L"[undo] 用户确认撤销，token=" + tok + L"\r\n");
                    std::string resp = UndoPipeRequest(tokA);
                    g_html = sf::BuildUndoResultHtml(resp);
                    if (g_webview) g_webview->NavigateToString(g_html.c_str());
                } else if (s.find(L"alertdetail") != std::wstring::npos) {
                    // 自动拦截卡的「某某程序」归因回填：管道取 lastalert → ExecuteScript 填占位。
                    // 归因文本只存在于服务端（toast.exe 命令行是外部可写边界，不能走明文参数）。
                    std::string resp = ProbePipeRequest("{\"cmd\":\"lastalert\"}");
                    std::string subU8 = sf::JsonGetString(resp, "sub");
                    if (subU8.empty()) subU8 = "检测到风险活动，已自动处理。";
                    if (g_webview) {
                        std::wstring js = L"(function(){var e=document.getElementById('alSub');"
                                          L"if(e){e.textContent='" + JsSafe(subU8) + L"';}})();";
                        g_webview->ExecuteScript(js.c_str(), nullptr);
                    }
                } else if (s.find(L"boot-restore") != std::wstring::npos) {
                    // 引导扇区被动卡「恢复引导」：基线写回扇区 0，结果卡反馈
                    WriteDbg(L"[boot] 用户确认恢复引导\r\n");
                    std::string resp = ProbePipeRequest("{\"cmd\":\"bootrestore\"}");
                    g_html = sf::BuildBootResultHtml(resp, L"引导记录已恢复", L"已把磁盘引导代码还原为安装时的基线。");
                    if (g_webview) g_webview->NavigateToString(g_html.c_str());
                } else if (s.find(L"boot-accept") != std::wstring::npos) {
                    // 引导扇区被动卡「信任此变更」：当前 MBR 重立为基线（磁盘工具合法改引导）
                    WriteDbg(L"[boot] 用户信任当前引导记录\r\n");
                    std::string resp = ProbePipeRequest("{\"cmd\":\"bootaccept\"}");
                    g_html = sf::BuildBootResultHtml(resp, L"已信任当前引导记录", L"当前引导代码已重立为基线，此后不再就本次变更告警。");
                    if (g_webview) g_webview->NavigateToString(g_html.c_str());
                } else if (s.find(L"clean-adv") != std::wstring::npos) {
                    if (s.find(L"clean-adv-cancel") != std::wstring::npos) {
                        WriteDbg(L"[clean] 用户暂不启用高级删除\r\n");
                        g_closing = true; DestroyWindow(g_hwnd);   // 暂不处理 → 关闭弹窗
                    } else {
                        RunAdvancedClean();                       // 高级删除卡：启用高级删除
                    }
                } else if (s.find(L"clean-ok") != std::wstring::npos) {
                    ConfirmAndRunClean();         // 确认卡：继续清除
                } else if (s.find(L"clean-cancel") != std::wstring::npos) {
                    WriteDbg(L"[clean] 用户取消\r\n");
                    // 回到原告警卡（重新渲染当前状态），确认卡即关闭
                    if (g_webview) {
                        g_webview->NavigateToString(
                            BuildHtml(g_currentStatus, g_currentScore, g_theme).c_str());
                    }
                } else if (s.find(L"clean") != std::wstring::npos) {
                    StartCleanFlow();             // 「清除威胁」按钮 → 自定义确认卡
                } else if (s.find(L"probe-clean") != std::wstring::npos) {
                    // 右键查杀卡片「立即清除」：连服务管道执行单文件清除，结果卡重渲染
                    if (!g_probePath.empty()) {
                        WriteDbg(L"[probe] 用户点击「立即清除」\r\n");
                        std::string cleanResp = ProbeCleanRequest(g_probePath);
                        g_html = sf::BuildProbeCleanHtml(cleanResp, g_probePath);
                        if (g_webview) g_webview->NavigateToString(g_html.c_str());
                    }
                } else if (s.find(L"close") != std::wstring::npos && !g_closing) {
                    g_closing = true; DestroyWindow(g_hwnd);
                }
            }
            return S_OK;
        });
    EventRegistrationToken tokMsg{};
    g_webview->add_WebMessageReceived(g_msgH.Get(), &tokMsg);

    // 导航完成回调：渲染成功后置透明窗口为不透明并触发进场动画
    EventRegistrationToken tokNav{};
    g_webview->add_NavigationCompleted(
        Callback<ICoreWebView2NavigationCompletedEventHandler>(
            [](ICoreWebView2*, ICoreWebView2NavigationCompletedEventArgs* e) -> HRESULT {
                BOOL ok = FALSE; if (e) e->get_IsSuccess(&ok);
                wchar_t b[128];
                swprintf_s(b, L"[navdone] 触发 isSuccess=%d prewarm=%d\r\n", ok, (int)g_prewarm);
                WriteDbg(b);
                if (!ok) { WriteDbg(L"[navdone] 导航失败，内容可能未渲染\r\n"); return S_OK; }
                // 预热阶段（占位页）不触发进场：等扫描结果决定显示（异常时再次导航）或退出
                if (!g_prewarm) TriggerEntrance();
                return S_OK;
            }).Get(), &tokNav);

    WriteDbg(L"[nav] 调用 NavigateToString\r\n");
    HRESULT nh = g_webview->NavigateToString(g_html.c_str());
    swprintf_s(b, L"[nav] NavigateToString hr=0x%08X htmlLen=%d\r\n",
               (unsigned)nh, (int)g_html.size());
    WriteDbg(b);
    return S_OK;
}

}  // namespace

namespace sf {

// 跨会话拉起 --toast 子进程（鲁棒版）。
// 服务运行在 Session 0，必须用活动用户会话的 token 启动 UI，否则窗口创建在 Session 0 而用户
// 根本看不到（表现即「分数够了也不弹窗」）。优先 WTSQueryUserToken；某些 VM / 远程会话下该函数
// 会失败，则回退到从同会话的 explorer.exe 复制主 token（DuplicateTokenEx），确保一定能弹在用户桌面。
static HANDLE GetUserTokenForSession(DWORD sessionId) {
    HANDLE hToken = nullptr;
    if (WTSQueryUserToken(sessionId, &hToken)) return hToken;   // 常规路径
    // 回退：找该会话的 explorer.exe，复制其 token（更稳，VM/远程桌面下也可靠）
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD target = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "explorer.exe") != 0) continue;
            DWORD sid = 0; ProcessIdToSessionId(pe.th32ProcessID, &sid);
            if (sid == sessionId) { target = pe.th32ProcessID; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    if (!target) return nullptr;
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, target);
    if (!hProc) return nullptr;
    HANDLE hSrc = nullptr;
    if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hSrc)) {
        DuplicateTokenEx(hSrc, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenPrimary, &hToken);
        CloseHandle(hSrc);
    }
    CloseHandle(hProc);
    return hToken;
}

// 取该 token 对应用户的配置目录（用作子进程 cwd，避免 cwd 落到服务 EXE 所在目录）
static std::wstring ProfileDirFor(HANDLE hToken) {
    wchar_t buf[MAX_PATH] = {0}; DWORD n = MAX_PATH;
    if (hToken && GetUserProfileDirectoryW(hToken, buf, &n) && buf[0]) return buf;
    return L"";
}

// 在目标用户会话中拉起子进程（toast / prewarm 共用）。
// ⚠️ 三个必须做对的点，任一遗漏都会让 WebView2 在子进程里渲染失败（实测 hr=0x8000FFFF → 退化成兜底弹窗）：
//   ① 环境块：必须用 CreateEnvironmentBlock(hToken) 生成后传入。若传 nullptr，子进程继承的是
//      【服务进程（LocalSystem）的环境变量】——LOCALAPPDATA / USERPROFILE / TEMP 全指向
//      C:\Windows\system32\config\systemprofile\...，而进程实际以用户身份运行：既没权限写，
//      WebView2 也被指到一个建不出来的 userData 位置（profile 创建失败 → 控制器创建报 E_UNEXPECTED）。
//   ② si.lpDesktop 显式给 "winsta0\\default"：保证子进程有可交互桌面（GUI / WebView2 渲染必需）。
//   ③ lpCurrentDirectory 给用户配置目录：否则 cwd 继承服务目录，相对路径产物会落在程序目录里。
static bool SpawnInUserSession(HANDLE hToken, const std::wstring& cmd) {
    LPVOID pEnv = nullptr;
    if (hToken) CreateEnvironmentBlock(&pEnv, hToken, FALSE);
    std::wstring cwd = ProfileDirFor(hToken);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";
    PROCESS_INFORMATION pi{};
    // CREATE_NO_WINDOW：不分配控制台，避免任何黑框；CREATE_UNICODE_ENVIRONMENT：配合宽字符环境块。
    const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = FALSE;
    if (hToken) {
        ok = CreateProcessAsUserW(hToken, nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                                  flags, pEnv, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    }
    if (!ok) {   // token 缺失或 AsUser 失败 → 退化为同会话创建（环境块仍带上，减少二次劣化）
        ok = CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE,
                            flags, pEnv, cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    }
    if (ok) { if (pi.hThread) CloseHandle(pi.hThread); if (pi.hProcess) CloseHandle(pi.hProcess); }
    if (pEnv) DestroyEnvironmentBlock(pEnv);
    return ok != FALSE;
}

// ---------------------------------------------------------------------------
//  ★ 弹窗宿主选择（2026-09-21）：优先 Electron，失败回退 WebView2
//
//  背景：告警卡原本由本进程以 WebView2 渲染（main.cpp 的 --toast 分支）。
//  银泊指定改为独立 Electron 程序（无边框/不可缩放/不可移动/无托盘/只能由服务调起），
//  但同时要求**保留 WebView2 作为回退** —— 万一 Electron 运行时缺失或启动失败，
//  告警不能就此消失（告警是主防唯一能被用户看见的出口，静默失败后果严重）。
//
//  判定顺序：
//    ① 找 dist\toast\SilverFoxToast.exe（与主防服务同目录的相对路径）
//    ② 存在则用服务自己的进程令牌在用户会话里拉起它（与旧路径完全相同的会话注入）
//    ③ 拉起失败或文件不存在 → 回退旧 WebView2 路径（--toast）
//
//  注意：Electron 版的 UI 进程**不做任何防护动作**，全部经命名管道回到服务执行，
//  所以它跑在用户会话是安全的（不给它任何特权，它也无从提权）。
// ---------------------------------------------------------------------------
static std::wstring SvcDirW() {
    wchar_t exepath[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exepath, MAX_PATH);
    std::wstring p = exepath;
    size_t slash = p.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? std::wstring() : p.substr(0, slash);
}

static std::wstring ElectronToastPathW() {
    std::wstring dir = SvcDirW();
    if (dir.empty()) return std::wstring();
    // ★ 两个候选布局都要试（2026-09-23 修）：
    //   此前只查 `toast\` 子目录，而实际安装位把 SilverFoxToast.exe 放在**根目录**
    //   （与 SilverFoxGuardSvc.exe 同级）→ 一直静默回退 WebView2，
    //   用户看到的弹窗始终是旧 WebView2 卡（银泊实拍发现）。
    //   ① <INSTDIR>\toast\SilverFoxToast.exe —— 安装器把 toast.7z 解到 $INSTDIR\toast
    //   ② <INSTDIR>\SilverFoxToast.exe       —— 平铺布局（当前安装位就是这个）
    const wchar_t* kCands[] = { L"\\toast\\SilverFoxToast.exe", L"\\SilverFoxToast.exe" };
    for (const wchar_t* c : kCands) {
        std::wstring p = dir + c;
        DWORD attr = GetFileAttributesW(p.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) return p;
    }
    return std::wstring();
}

void NotifyAnomaly(const std::string& status, int score,
                   const std::string& risk, const std::string& undoToken, bool rolledBack) {
    // 撤销凭据经命令行传递：token 由引擎生成，字符集是 [0-9a-f]，无引号/空格风险。
    // 这里仍做一次白名单过滤——命令行是外部可写边界（任何进程都能带同名参数拉起本
    // 程序），若把任意字符串原样透传给服务，等于开了一个"诱导主防执行 undo"的口子。
    // ★ Electron 与 WebView2 两条路径共用这份过滤结果，避免只改一处漏掉另一处。
    std::string safeToken;
    if (!undoToken.empty()) {
        for (char c : undoToken) {
            bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            if (hex && safeToken.size() < 32) safeToken.push_back(c);
        }
    }

    // ---- 定位活动会话（两条路径都需要）----
    DWORD sid = WTS_CURRENT_SESSION;
    bool found = false;
    PWTS_SESSION_INFOW pInfo = nullptr; DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfo, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (pInfo[i].State == WTSActive) { sid = pInfo[i].SessionId; found = true; break; }
        }
        WTSFreeMemory(pInfo);
    }
    { wchar_t b[128]; swprintf_s(b, L"[notify] found=%d sessionId=%d\r\n", (int)found, (int)sid); WriteDbg(b); }

    HANDLE hToken = found ? GetUserTokenForSession(sid) : nullptr;

    // ---- ① 优先 Electron ----
    //
    // ★ 参数格式（2026-09-21 实测定型，改动前务必读这段）
    //
    //  Electron 启动时 Chromium 会先自己解析一遍命令行。实测（Electron 24）：
    //      SilverFoxToast.exe --status=infected
    //  **不会**报错，但整条 `--status=…` 被 Chromium 静默吞掉，参数进不去 JS；
    //  主进程照常启动却拿不到 status，于是走"非法调起"分支立刻退出 ——
    //  表现是「窗口闪一下就没了 / 压根没反应」，比直接报错难查得多。
    //  WebView2 无此限制（参数一直这么传），所以从 WebView2 迁过来时极易踩中。
    //
    //  正确写法：用 `--` 把 payload 推到 Chromium 解析范围之外，
    //  多个键值用 `;` 分隔：
    //      SilverFoxToast.exe -- sfx=status=infected;score=200;risk=landed;undo=30ab…;rolledback=1
    //  解析侧见 toast-app/resources/app/main.js 的 parseArgs()。
    //
    //  ★ 排查提醒：若在"父进程本身是 Electron/Node"的终端里（WorkBuddy / VS Code 等）
    //  手工试跑，环境里会带 `ELECTRON_RUN_AS_NODE=1`，Electron 退化成纯 Node.js，
    //  于是报 `bad option:` / `Cannot find module '…\sfx=…'`、`--version` 打出 Node 版本号。
    //  那是终端环境的锅，不是打包或代码问题 —— 服务经 CreateEnvironmentBlock 构造
    //  用户环境块调起时不存在该变量。main.js 顶部已加显式检测便于日后一眼定位。
    //
    //  为什么值里不用引号：status 只可能是 normal/warning/infected，
    //  risk 是固定的几个短标识，score 是数字，undo 已过 [0-9a-f] 白名单，
    //  rolledback 是 0/1 —— 全部是命令行安全字符，无需转义，
    //  也就自然没有引号注入面（这是刻意保持的，不要为了"通用"去支持任意字符串）。
    std::wstring elPath = ElectronToastPathW();
    if (!elPath.empty()) {
        std::wstring payload = L"sfx=status=" + U8W(status)
                             + L";score=" + std::to_wstring(score);
        if (!risk.empty())          payload += L";risk=" + U8W(risk);
        if (rolledBack)             payload += L";rolledback=1";
        if (!safeToken.empty())     payload += L";undo=" + U8W(safeToken);

        // 注意 `--` 与 payload 之间的空格 —— 这是让 Chromium 停止解析的关键
        std::wstring cmd = L"\"" + elPath + L"\" -- " + payload;

        if (SpawnInUserSession(hToken, cmd)) {
            WriteDbg(L"[notify] 已拉起 Electron 告警卡（用户会话）\r\n");
            if (hToken) CloseHandle(hToken);
            return;
        }
        // 拉起失败：不 return，继续走回退路径 —— 告警绝不能因为 UI 换宿主而丢失
        WriteDbg(L"[notify] Electron 拉起失败，回退 WebView2 路径\r\n");
    } else {
        WriteDbg(L"[notify] 未找到 SilverFoxToast.exe（已试 toast\\ 子目录与根目录），使用 WebView2 路径\r\n");
    }

    // ---- ② 回退：旧 WebView2 路径（与本函数原实现完全一致）----
    wchar_t exepath[MAX_PATH];
    GetModuleFileNameW(nullptr, exepath, MAX_PATH);
    std::wstring cmd = std::wstring(L"\"") + exepath + L"\" --toast --status=" + U8W(status)
                       + L" --score=" + std::to_wstring(score);
    if (!risk.empty())              cmd += L" --risk=" + U8W(risk);
    if (rolledBack)                 cmd += L" --rolledback=1";
    if (!safeToken.empty())         cmd += L" --undo=" + U8W(safeToken);

    bool ok = SpawnInUserSession(hToken, cmd);
    if (ok) WriteDbg(L"[notify] 已拉起 toast（用户环境块 + winsta0\\default）\r\n");
    else    WriteDbg(L"[notify] 拉起 toast 失败\r\n");
    if (hToken) CloseHandle(hToken);
}

// ---------------------------------------------------------------------------
//  ★ 沙箱弹窗（2026-09-27）：进度卡 + 结果卡
//
//  与 NotifyAnomaly 同一跨会话拉起机制（Electron 优先），但**只走 Electron 路径**：
//    · 沙箱卡是「进度告知 / 分析结果」性质，不像勒索告警那样不容有失；
//    · WebView2 回退卡（BuildHtml）的分支表里没有沙箱状态，硬塞会渲染成
//      「环境已恢复正常」—— 错误信息比没信息更糟，故 Electron 缺失时记日志跳过。
//
//  ★ payload 编码（与 main.js 的约定，改动前先读 toast-app/.../main.js parseArgs）：
//    parseArgs 按 ';' 切键值对、按 '=' 切键值。file / summary 是外部文本
//    （文件名 / 沙箱行为摘要，可能含空格、中文甚至 ';''='），必须先 URL 编码
//    再拼进 sfx=，JS 侧 decodeURIComponent 还原 —— 否则摘要里的分号会伪造
//    出第二个键（命令行注入面）。
// ---------------------------------------------------------------------------
static std::string UrlEncodeSfx(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        bool safe = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                    (c >= 'a' && c <= 'z') || c == '-' || c == '_' ||
                    c == '.' || c == '~';
        if (safe) out.push_back((char)c);
        else { out.push_back('%'); out.push_back(hex[c >> 4]); out.push_back(hex[c & 0xF]); }
    }
    return out;
}

static void SpawnSandboxCard(const std::string& payloadTail) {
    // ---- 定位活动会话（与 NotifyAnomaly 同一逻辑）----
    DWORD sid = WTS_CURRENT_SESSION;
    bool found = false;
    PWTS_SESSION_INFOW pInfo = nullptr; DWORD count = 0;
    if (WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pInfo, &count)) {
        for (DWORD i = 0; i < count; ++i) {
            if (pInfo[i].State == WTSActive) { sid = pInfo[i].SessionId; found = true; break; }
        }
        WTSFreeMemory(pInfo);
    }
    HANDLE hToken = found ? GetUserTokenForSession(sid) : nullptr;

    std::wstring elPath = ElectronToastPathW();
    if (elPath.empty()) {
        WriteDbg(L"[sandbox] 未找到 SilverFoxToast.exe，沙箱弹窗跳过"
                 L"（无 WebView2 回退：回退卡无沙箱分支，会渲染成误导文案）\r\n");
        if (hToken) CloseHandle(hToken);
        return;
    }
    // payloadTail 是纯 ASCII（URL 编码后），U8W 安全
    std::wstring payload = L"sfx=" + U8W(payloadTail);
    std::wstring cmd = L"\"" + elPath + L"\" -- " + payload;
    if (SpawnInUserSession(hToken, cmd))
        WriteDbg(L"[sandbox] 已拉起沙箱卡片（用户会话）\r\n");
    else
        WriteDbg(L"[sandbox] 拉起沙箱卡片失败\r\n");
    if (hToken) CloseHandle(hToken);
}

// 哨兵文件：结果卡发出时由服务写入（更新 mtime）。前端进度卡轮询其 mtime，
// 一旦发现"结果已出"就自行关闭 —— 解决「进度卡倒计时挂很久不消失」的问题。
// 背景：每张卡都是经 SpawnInUserSession 拉起的**独立 Electron 进程**，彼此无共享
// 状态，进度卡无法被结果卡直接关闭，只能靠这个跨进程信号协调。读不到（权限/不存在）
// 时进度卡按自身寿命自然关闭，属优雅降级，不会出错。
// 进度卡：「可疑文件正在送进沙箱检测，预计还剩 N 秒」。
// etaSec 由调用方按文件类型/体积估算（当前统一 30s，判定策略讨论后可细化）。
// ★★ 2026-10-02 修复：哨兵必须「每轮先删、由结果卡重建」，不能让服务端留着旧文件。
//
//   症状（银泊实测）：判定结果早就出来了，进度卡仍卡在「分析即将完成，正在生成报告…」，
//   必须手动关掉。
//
//   根因**不是**前端漏写哨兵 —— main.js 的 did-finish-load 分支里这段代码是有的。
//   问题是它写不进去，而且两条路都写不进去：
//     · 本目录（C:\ProgramData\SilverFoxGuard）的继承 ACE 对**文件**只给 Users:(RX)；
//       那条 (WD,AD,WEA,WA) 带 CI 标志，只作用于**子目录**、不作用于文件。
//     · 文件 owner 是谁都不影响 —— 权限来自 ACL，不是天然特权。
//   实测（以用户身份）：touch 既有哨兵 → Permission denied；新建文件 → 成功。
//   ⇒ 结果卡进程（用户会话）utimesSync 与 writeFileSync 双双 EACCES，被前端两层
//     catch 静默吞掉，**却仍打印 'result sentinel touched'（假绿日志）**。
//   ⇒ 进度卡 statSync 到的 mtime 永远停在旧值，判据 `mtimeMs > cardStart` 恒假，
//     只能等 main.js 的 5 分钟寿命兜底 —— 用户看到的就是"卡住不消失"。
//
//   修法：利用上面那个**不对称性**（用户能建、不能改）—— 服务端以 LocalSystem 身份
//   （对本目录有 F）在每轮拉起进度卡**之前**删掉哨兵；随后结果卡渲染完成时走
//   writeFileSync **新建**（创建只需目录的 WD 权限，必然成功），进度卡便能在 1 秒内
//   看到"刚刚"的时间戳并自行关闭。删除失败只留痕、不阻断（退回寿命兜底）。
//
//   ⚠️ 路径与前端 main.js 的 SENTINEL 常量必须**字面一致**，改一处必须改两处。
static void ResetSandboxResultSentinel() {
    const wchar_t* kSentinel = L"C:\\ProgramData\\SilverFoxGuard\\sb_result.sentinel";
    if (DeleteFileW(kSentinel)) {
        WriteDbg(L"[sandbox] 已清结果哨兵（本轮结果卡渲染完成后重建，用于关闭进度卡）\r\n");
        return;
    }
    const DWORD e = GetLastError();
    // FILE/PATH_NOT_FOUND 是正常路径（上一轮已清干净 / 首次运行），不算故障。
    if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND) {
        WriteDbg(L"[sandbox] ⚠ 清结果哨兵失败（err=" + std::to_wstring((unsigned long long)e) +
                 L"）→ 本轮进度卡可能只能靠寿命兜底关闭\r\n");
    }
}

void NotifySandboxProgress(const std::string& file, int etaSec) {
    if (etaSec <= 0) etaSec = 30;
    if (etaSec > 600) etaSec = 600;   // 上限 10 分钟：估算失真也不许卡片挂半天
    ResetSandboxResultSentinel();
    SpawnSandboxCard("status=sandbox_progress;eta=" + std::to_string(etaSec)
                   + ";file=" + UrlEncodeSfx(file));
}

// 结果卡：verdict = malicious / suspicious / clean / error / not_applicable。
void NotifySandboxResult(const std::string& file, const std::string& verdict,
                         int score, const std::string& summary,
                         const std::string& errToken, int errLeftSec) {
    // verdict 白名单（外部可写边界 —— 来自管道的字符串不可信，必须收敛到枚举）。
    //
    // ★★ 2026-10-01 修正：白名单必须包含 error / not_applicable。
    //   旧版只认三个值，其余**一律降级成 suspicious** —— 于是 sandbox 传来的
    //   "not_applicable"（沙箱不适用于此文件，如压缩包里没有可执行载荷）和
    //   "error"（沙箱没分析成）都被渲染成**琥珀色「可疑程序」**。
    //   把"没看清"说成"看着可疑"是**纯误报**，而且和另一种错法（渲染层把所有
    //   非恶意/可疑值都归成绿色「未发现威胁」）方向正好相反 ——
    //   一个假阳性、一个假阴性，同一个"瞎猜"来源。
    //
    //   未知值改降级到 "error" 而不是 "suspicious"：`error` 是**免责声明**，
    //   `suspicious` 是**指控**。分不清的时候不许指控别人。
    std::string v = verdict;
    if (v != "malicious" && v != "suspicious" && v != "clean" &&
        v != "error" && v != "not_applicable") {
        v = "error";
    }
    if (score < 0)   score = 0;
    // ★★ 2026-10-03（B3）：静默钳制改为**可观测**。
    //   【原状】`if (score > 200) score = 200;` 悄悄把分数压到 200，
    //   界面上「很严重」与「极严重」长得一模一样，而**日志里一个字都没有** ——
    //   又一次「拿不到就悄悄处理」（铁律 46 同族）。
    //   【为什么仍要钳制】下游解析（index.html deriveFlags / main.js parseArgs）
    //   的量程是 0~200，超出会显示异常。所以钳制本身要留，只是不许「静默」。
    //   【改法】钳制时打一行（节流到每次调用一条，因为这个函数每次沙箱结束才调一次，
    //   量级可忽略），并把**原始分**一并带出，供排查核对。
    // ★★ 无结论决策凭据（2026-10-03）：令牌 + 剩余秒数。
    //   只在 errToken 非空时带上（其余档位的 payload 保持原样，零影响）。
    //   ⚠️ 令牌**必须**经 URL 编码：它是服务端生成的 hex，虽只含 [0-9a-f]，
    //   但把"外部给的值直接拼进命令行样式字符串"本身就是坏习惯 ——
    //   一旦将来换成含分隔符的字符，会直接破坏参数解析（半通故障家族）。
    std::string tokPart;
    if (!errToken.empty()) {
        tokPart = ";errtoken=" + UrlEncodeSfx(errToken)
                + ";errleft=" + std::to_string(errLeftSec > 0 ? errLeftSec : 0);
    }
    if (score > 200) {
        const int raw = score;
        score = 200;
        LogDbgC((std::string("[toast] 沙箱结果分 ") + std::to_string(raw) +
                  " 超出下游量程 0~200，已钳制为 200（下游 deriveFlags/parseArgs 不支持更大值）")
                     .c_str());
        SpawnSandboxCard("status=sandbox_result;verdict=" + v
                       + ";score=" + std::to_string(score)
                       + ";file=" + UrlEncodeSfx(file)
                       + ";summary=" + UrlEncodeSfx(summary)
                       + tokPart
                       + ";rawscore=" + std::to_string(raw));
        return;
    }
    SpawnSandboxCard("status=sandbox_result;verdict=" + v
                   + ";score=" + std::to_string(score)
                   + ";file=" + UrlEncodeSfx(file)
                   + ";summary=" + UrlEncodeSfx(summary)
                   + tokPart);
}

int RunToast(const std::string& status, int score,
             const std::string& risk, const std::string& undoToken, bool rolledBack) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    // 固定版本运行时部署到非系统目录时，渲染进程沙箱常因权限崩溃（表现为渲染子进程反复崩溃重启、
    // 内容不显示）。关闭渲染进程沙箱以稳定渲染（本地通知工具，风险可接受）。
    SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", L"--no-sandbox");
    g_theme = GetSystemTheme();
    g_currentStatus = status;   // 记住当前状态/评分，确认卡取消后回渲染
    g_currentScore  = score;
    // risk 全部是固定的短 ASCII 标识（high/suspect/mbr/proc/regrun/landed/hashlanded），
    // 无引号无空格 —— 这是刻意保持的，可安全直接拼进命令行，不存在转义/注入面。
    // ★ 新增 risk 值时必须同步三处白名单：main.js:parseArgs、preload.js、本文件 BuildHtml。
    g_risk = U8W(risk);
    g_undoToken = undoToken;
    g_rolledBack = rolledBack;
    g_html = BuildHtml(status, score, g_theme);
    g_closing = false; g_fallbackDone = false;

    // 统一固定加高到 210：高级删除卡 / 最终结果卡内容较多，160 会太挤、按钮出边；
    // 固定一个高度让所有卡片（告警/确认/进度/高级/结果）共用，切换不跳动
    const int W = 384, H = 210, M = 18;
    int x, y; GetDockPos(x, y, W, H, M);

    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SFEnvToast";
    // 背景刷使用卡片渐变底色（bg2），使瞬时状态只是「空卡片」而非黑/白块
    wc.hbrBackground = CreateSolidBrush(g_theme == L"dark" ? RGB(15, 15, 20) : RGB(238, 240, 245));
    RegisterClassExW(&wc);

    // 仍创建在屏幕外（窗口「可见」但不在可视区域）：WebView2 默认底色为白，navdone 前会白屏一闪，
    // 故放在屏幕外等渲染完成（navdone）后再滑入右下角，彻底无白闪。
    // 之前「缩放窗口后窗口消失」的 bug 根因是 navdone 用了创建时缓存的旧桌面坐标；现已改为
    // navdone 用「当前」桌面重算停靠点（见 TriggerEntrance），并监听 WM_DISPLAYCHANGE 随时重锚定，
    // 故屏幕外方案同样对 VM 动态分辨率鲁棒，且不像终态创建那样有白屏。
    g_posX = x; g_posY = y; g_w = W; g_h = H;
    RECT scr; GetWindowRect(GetDesktopWindow(), &scr);
    int ox = scr.right + W + 40, oy = scr.bottom + H + 40; // 屏幕外坐标
    g_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"SFEnvToast", L"",
        WS_POPUP, ox, oy, W, H, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    if (!g_hwnd) { CoUninitialize(); return 1; }
    // 圆角 API（DWMWA_WINDOW_CORNER_PREFERENCE=33）仅 Win11+ 支持；Win10 上调用会静默返回
    // E_INVALIDARG 且窗口保持直角，不会崩溃也不影响功能，故直接调用、无需版本判断。
    int corner = 2; // DWMWCP_ROUND
    DwmSetWindowAttribute(g_hwnd, 33 /*DWMWA_WINDOW_CORNER_PREFERENCE*/, &corner, sizeof(corner));
    ShowWindow(g_hwnd, SW_SHOW);
    // 看门狗：WebView2 冷启动（独立 userData + 自带运行时首次建 profile）在慢机/高负载下实测可超过 12 秒
    // ——此前 12 秒会在正常渲染尚未完成时误触发兜底，用户看到的是系统 MessageBox 而非卡片（并连带控制台黑框）。
    // 故放宽到 25 秒；真正崩溃时兜底告警仍会到达，只是晚一点。
    SetTimer(g_hwnd, 1, 25000, nullptr);
    // 注意：提示音不在创建时播放，改到 TriggerEntrance（navdone 后窗口滑入、动画开始那一刻）
    // 同播，避免「声音先响、弹窗后到」的声画不同步。

    // 自带完整运行时：exe 同级（安装后为 $INSTDIR）下的 WebView2Runtime 目录
    char ep[MAX_PATH]; GetModuleFileNameA(nullptr, ep, MAX_PATH);
    std::string dir = ep; size_t p = dir.find_last_of('\\');
    std::wstring runtime = (p != std::string::npos) ? U8W(dir.substr(0, p + 1) + "WebView2Runtime") : L"";
    // 调试用：环境变量 SF_WV2_DIR 可强制指定运行库目录（不重编即可切换测试）
    wchar_t envbuf[512] = {0};
    if (GetEnvironmentVariableW(L"SF_WV2_DIR", envbuf, 512)) runtime = envbuf;
    {
        wchar_t buf[256];
        swprintf_s(buf, L"[runtime] folder=%ls\r\n", runtime.c_str());
        WriteDbg(buf);
    }
    // 每个 toast 用独立 userData 目录（带 PID）：共享目录会被残留渲染进程锁住，
    // 导致新弹窗渲染进程无法初始化（NavigationCompleted 永不触发 → 静默失败）。
    // 独立目录互不干扰，即使上次弹窗进程残留，也不影响本次。
    wchar_t pidbuf[32]; swprintf_s(pidbuf, L"_%lu", (unsigned long)GetCurrentProcessId());
    std::wstring userData = Wv2BaseDir() + L"\\WV2Data" + pidbuf;
    // 落盘 userData 与关键环境变量：服务拉起的进程里若环境块继承错（LOCALAPPDATA 指到 SYSTEM 配置目录），
    // WebView2 会因 profile 建不出来而失败，这里留下证据便于定位。
    {
        wchar_t e1[MAX_PATH] = {0}, e2[MAX_PATH] = {0}, e3[MAX_PATH] = {0};
        GetEnvironmentVariableW(L"LOCALAPPDATA", e1, MAX_PATH);
        GetEnvironmentVariableW(L"USERPROFILE", e2, MAX_PATH);
        GetEnvironmentVariableW(L"TEMP", e3, MAX_PATH);
        WriteDbg(L"[path] userData=" + userData + L"\r\n");
        WriteDbg(L"[path] env LOCALAPPDATA=" + std::wstring(e1) + L" | USERPROFILE=" +
                 std::wstring(e2) + L" | TEMP=" + std::wstring(e3) + L"\r\n");
    }

    g_envH = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(hr)) { g_lastHr = hr; WriteDbg(L"[env] CreateEnvironment FAILED\r\n"); FallbackMessage(); return S_OK; }
            WriteDbg(L"[env] 环境创建成功\r\n");
            g_ctrlH = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(OnController);
            env->CreateCoreWebView2Controller(g_hwnd, g_ctrlH.Get());
            return S_OK;
        });
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        runtime.empty() ? nullptr : runtime.c_str(), userData.c_str(), nullptr, g_envH.Get());
    if (FAILED(hr)) { g_lastHr = hr; WriteDbg(L"[outer] CreateEnvironment direct FAILED\r\n"); FallbackMessage(); CoUninitialize(); return 1; }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    CoUninitialize();
    return 0;
}

// ---- 预热结果文件（NM 宿主扫描后写入，预热进程轮询读取）----
static std::wstring PrewarmResultPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\prewarm_result.txt";
}

// 读结果文件（格式 "status=xxx score=yyy"），成功返回 true 并删除文件避免残留
static bool ReadPrewarmResult(std::string& status, int& score) {
    std::wstring path = PrewarmResultPathW();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[256] = {0}; DWORD n = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
    CloseHandle(h);
    if (n == 0) return false;
    DeleteFileW(path.c_str());   // 读后即删，避免下次预热读到陈旧结果
    std::string line(buf, n);
    status.clear(); score = 0;
    size_t a = line.find("status=");
    if (a != std::string::npos) {
        size_t b = line.find(' ', a);
        status = line.substr(a + 7, (b == std::string::npos ? line.size() : b) - (a + 7));
    }
    size_t c = line.find("score=");
    if (c != std::string::npos) {
        for (const char* q = line.c_str() + c + 6; *q >= '0' && *q <= '9'; ++q)
            score = score * 10 + (*q - '0');
    }
    return !status.empty();
}

int RunPrewarm() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", L"--no-sandbox");
    g_theme = GetSystemTheme();
    g_prewarm = true;
    g_html = BuildHtml("normal", 0, g_theme);   // 占位页：先渲染 normal 态，异常时再换对应状态
    g_closing = false; g_fallbackDone = false;

    const int W = 384, H = 160, M = 18;
    int x, y; GetDockPos(x, y, W, H, M);

    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SFEnvToast";
    wc.hbrBackground = CreateSolidBrush(g_theme == L"dark" ? RGB(15, 15, 20) : RGB(238, 240, 245));
    RegisterClassExW(&wc);

    g_posX = x; g_posY = y; g_w = W; g_h = H;
    RECT scr; GetWindowRect(GetDesktopWindow(), &scr);
    int ox = scr.right + W + 40, oy = scr.bottom + H + 40;
    g_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"SFEnvToast", L"",
        WS_POPUP, ox, oy, W, H, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    if (!g_hwnd) { CoUninitialize(); return 1; }
    int corner = 2; DwmSetWindowAttribute(g_hwnd, 33, &corner, sizeof(corner));
    ShowWindow(g_hwnd, SW_SHOW);
    // 预热阶段不设看门狗：扫描可能长达 20 秒，由下方轮询超时（30 秒）兜底

    char ep[MAX_PATH]; GetModuleFileNameA(nullptr, ep, MAX_PATH);
    std::string dir = ep; size_t p = dir.find_last_of('\\');
    std::wstring runtime = (p != std::string::npos) ? U8W(dir.substr(0, p + 1) + "WebView2Runtime") : L"";
    wchar_t envbuf[512] = {0};
    if (GetEnvironmentVariableW(L"SF_WV2_DIR", envbuf, 512)) runtime = envbuf;
    wchar_t pidbuf[32]; swprintf_s(pidbuf, L"_%lu", (unsigned long)GetCurrentProcessId());
    std::wstring userData = Wv2BaseDir() + L"\\WV2Data" + pidbuf;

    // 创建环境（预热）。失败则静默退出——扫描后 NM 宿主仍会走正常 --toast 弹窗兜底。
    g_envH = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(hr)) { g_lastHr = hr; WriteDbg(L"[prewarm] CreateEnvironment FAILED\r\n"); return S_OK; }
            WriteDbg(L"[prewarm] 环境创建成功\r\n");
            g_ctrlH = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(OnController);
            env->CreateCoreWebView2Controller(g_hwnd, g_ctrlH.Get());
            return S_OK;
        });
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        runtime.empty() ? nullptr : runtime.c_str(), userData.c_str(), nullptr, g_envH.Get());
    if (FAILED(hr)) { g_lastHr = hr; CoUninitialize(); return 0; }

    // 泵消息（处理 WebView2 事件）+ 轮询结果文件，最多 30 秒
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    MSG msg;
    while (std::chrono::steady_clock::now() < deadline) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { CoUninitialize(); return 0; }
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        std::string status; int score = 0;
        if (ReadPrewarmResult(status, score)) {
            WriteDbg(L"[prewarm] 读到结果 status=" + U8W(status) + L"\r\n");
            if (status == "normal" || status.empty()) {
                CoUninitialize(); return 0;   // 无异常：静默退出，不留进程
            }
            // 有异常：换对应状态 HTML 重新导航 → navdone（此时 g_prewarm=false）触发进场显示
            g_prewarm = false;
            g_html = BuildHtml(status, score, g_theme);
            if (g_webview) g_webview->NavigateToString(g_html.c_str());
            while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
            CoUninitialize(); return 0;
        }
        Sleep(200);
    }
    WriteDbg(L"[prewarm] 超时退出\r\n");
    CoUninitialize(); return 0;
}

// ---------------------------------------------------------------------------
//  手动扫描进度右下角弹窗（--scanprogress）
//  实例：扩展点「立即检查」→ 服务全盘扫描 → 本弹窗显示进度条与已扫描文件数，
//       扫描完成（scan_progress.txt 出现 done）→ 读 prewarm_result.txt 最终状态 →
//       切换结果卡（正常=绿色完成卡 / 异常=告警卡，异常可点击「清除威胁」）。
// ---------------------------------------------------------------------------
static std::wstring BuildScanProgressHtmlSafe() {
    return L"<!doctype html><html data-theme=\"" + g_theme + L"\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;"
        L"font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,-apple-system,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);"
        L"--brand:rgba(30,34,46,.38);--shadow:rgba(24,30,48,.20);--track:rgba(30,34,46,.10);"
        L"--blue:#2f6bff;--blue-soft:rgba(47,107,255,.12);--blue-line:rgba(47,107,255,.34);--blue-glow:rgba(47,107,255,.22);"
        L"background:radial-gradient(160px 150px at 50px 50%,rgba(47,107,255,.13) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--blue-line);"
        L"box-shadow:0 18px 46px var(--shadow),0 0 0 1px var(--blue-line);color:var(--fg);"
        L"display:flex;flex-direction:column;gap:10px;padding:20px 24px;position:relative;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--track:rgba(255,255,255,.12);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".t{font-size:15px;font-weight:800;letter-spacing:.3px;display:flex;align-items:center;gap:9px;}"
        L".ic{width:20px;height:20px;color:var(--blue);}"
        L".s{font-size:12px;color:var(--sub);}"
        L".track{height:8px;border-radius:999px;background:var(--track);overflow:hidden;margin-top:2px;position:relative;}"
        L".fill{position:absolute;inset:0;width:38%;border-radius:999px;"
        L"background:linear-gradient(90deg,#7ea4ff,#2f6bff);animation:flow 1.6s ease-in-out infinite alternate;}"
        L"@keyframes flow{from{left:-22%;}to{left:78%;}}"
        L".row{display:flex;align-items:center;justify-content:space-between;gap:12px;}"
        L".cnt{font-size:12px;color:var(--sub);}"
        L".cnt b{color:var(--blue);font-weight:800;}"
        L".cur{font-size:10.5px;color:var(--brand);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}"
        L".brand{position:absolute;left:24px;bottom:9px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;transition:background .15s,color .15s;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body>"
        L"<div class=\"t\"><svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.7\" stroke-linecap=\"round\"><path d=\"M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z\"/><path d=\"M8.6 11.6l2.4 2.4 4.4-4.6\" stroke-linecap=\"round\"/></svg>正在全盘扫描</div>"
        L"<div class=\"s\" id=\"ph\">逐盘遍历所有固定磁盘，检查深层目录与盘根表层文件…</div>"
        L"<div class=\"track\"><i class=\"fill\"></i></div>"
        L"<div class=\"row\"><div class=\"cur\" id=\"cur\"></div><div class=\"cnt\">已扫描 <b id=\"cnt\">0</b> 个文件</div></div>"
        L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>"
        L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},220)\">✕</div>"
        L"</body></html>";
}

// 进度文件读取（供轮询）
static bool ReadScanProgress(std::string& phase, long long& done, std::string& cur) {
    phase.clear(); done = 0; cur.clear();
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    HANDLE h = CreateFileW((dir + L"\\scan_progress.txt").c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[1200] = {0}; DWORD n = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
    CloseHandle(h);
    if (!n) return false;
    std::string s(buf, n);
    size_t a = s.find("phase=");
    if (a != std::string::npos) {
        size_t b = s.find(' ', a);
        phase = s.substr(a + 6, (b == std::string::npos ? s.size() : b) - (a + 6));
    }
    a = s.find("done=");
    if (a != std::string::npos) {
        size_t b = a + 5;
        while (b < s.size() && s[b] >= '0' && s[b] <= '9') done = done * 10 + (s[b++] - '0');
    }
    a = s.find("current=");
    if (a != std::string::npos) cur = s.substr(a + 8);
    return true;
}

int RunScanProgress() {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", L"--no-sandbox");
    g_theme = GetSystemTheme();
    // 进度卡直接作为首导航：navdone 即进场显示（g_prewarm 保持 false）
    g_prewarm = false;
    g_html = BuildScanProgressHtmlSafe();
    g_closing = false; g_fallbackDone = false;

    const int W = 384, H = 200, M = 18;
    int x, y; GetDockPos(x, y, W, H, M);
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SFEnvToast";   // 与 toast 同名类，避免重复注册冲突（进程独立无碍）
    wc.hbrBackground = CreateSolidBrush(g_theme == L"dark" ? RGB(15, 15, 20) : RGB(238, 240, 245));
    RegisterClassExW(&wc);
    g_posX = x; g_posY = y; g_w = W; g_h = H;
    RECT scr; GetWindowRect(GetDesktopWindow(), &scr);
    int ox = scr.right + W + 40, oy = scr.bottom + H + 40;
    g_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"SFEnvToast", L"",
        WS_POPUP, ox, oy, W, H, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    if (!g_hwnd) { CoUninitialize(); return 1; }
    int corner = 2; DwmSetWindowAttribute(g_hwnd, 33, &corner, sizeof(corner));
    ShowWindow(g_hwnd, SW_SHOW);

    char ep[MAX_PATH]; GetModuleFileNameA(nullptr, ep, MAX_PATH);
    std::string dir = ep; size_t q = dir.find_last_of('\\');
    std::wstring runtime = (q != std::string::npos) ? U8W(dir.substr(0, q + 1) + "WebView2Runtime") : L"";
    wchar_t envbuf[512] = {0};
    if (GetEnvironmentVariableW(L"SF_WV2_DIR", envbuf, 512)) runtime = envbuf;
    wchar_t pidbuf[32]; swprintf_s(pidbuf, L"_%lu", (unsigned long)GetCurrentProcessId());
    std::wstring userData = Wv2BaseDir() + L"\\WV2Data" + pidbuf;

    g_envH = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(hr) || !env) return S_OK;
            g_ctrlH = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(OnController);
            env->CreateCoreWebView2Controller(g_hwnd, g_ctrlH.Get());
            return S_OK;
        });
    HRESULT hr = CreateCoreWebView2EnvironmentWithOptions(
        runtime.empty() ? nullptr : runtime.c_str(), userData.c_str(), nullptr, g_envH.Get());
    if (FAILED(hr)) { CoUninitialize(); return 0; }

    // 轮询循环：显示进度 → 检测 done → 切换结果卡 / 超时退出
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(150);
    bool shownResult = false;
    MSG msg;
    while (std::chrono::steady_clock::now() < deadline) {
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) { CoUninitialize(); return 0; }
            TranslateMessage(&msg); DispatchMessageW(&msg);
        }
        std::string phase, cur; long long done = 0; std::string status; int score = 0;
        if (ReadScanProgress(phase, done, cur) && g_webview) {
            // 进度刷新
            std::wstring js = L"(function(){var c=document.getElementById('cnt');if(c)c.textContent='" +
                std::to_wstring(done) + L"';var e=document.getElementById('cur');if(e)e.textContent='" + JsSafe(cur) + L"';})();";
            g_webview->ExecuteScript(js.c_str(), nullptr);
            if (phase == "done" && !shownResult) {
                // 扫描完成：读最终状态（prewarm_result.txt 由 NM 宿主写入）
                if (ReadPrewarmResult(status, score)) {
                    shownResult = true;
                    g_prewarm = false;
                    g_html = BuildHtml(status, score, g_theme);   // normal=绿色卡 / 异常=告警卡
                    if (g_webview) g_webview->NavigateToString(g_html.c_str());
                }
            }
        }
        Sleep(200);
    }
    if (!shownResult) WriteDbg(L"[scanprog] timeout 150s without done\r\n");
    CoUninitialize(); return 0;
}

// ---- 第四部分：右键自定义查杀卡片（追加于 toast.cpp 的 namespace sf 内）----

// HTML 转义（嵌入卡片用）
static std::wstring EscHtmlW(const std::wstring& s) {
    std::wstring r;
    for (wchar_t c : s) {
        switch (c) {
            case L'&': r += L"&amp;"; break;
            case L'<': r += L"&lt;"; break;
            case L'>': r += L"&gt;"; break;
            case L'"': r += L"&quot;"; break;
            default: r += c;
        }
    }
    return r;
}

// 查杀结果卡片（level/score/type/title/file/hitsRawJson）
std::wstring BuildProbeHtml(int level, int score, const std::string& type, const std::string& title,
                            const std::wstring& fileW, const std::string& hitsRaw) {
    const wchar_t* fmt =
        L"<!doctype html><html data-theme=\"light\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);--brand:rgba(30,34,46,.38);"
        L"--shadow:rgba(24,30,48,.20);--line:rgba(30,34,46,.10);"
        L"background:radial-gradient(160px 150px at 50px 50%,rgba(47,107,255,.11) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow);color:var(--fg);display:flex;flex-direction:column;"
        L"padding:20px 24px 16px;position:relative;gap:12px;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--line:rgba(255,255,255,.10);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".top{display:flex;align-items:center;gap:9px;}"
        L".title{font-size:15px;font-weight:800;letter-spacing:.3px;}"
        L".sub{font-size:11px;color:var(--sub);margin-top:2px;}"
        L".file{margin-top:2px;font-size:11.5px;color:var(--fg);background:rgba(127,127,127,.09);"
        L"border-radius:9px;padding:7px 10px;word-break:break-all;line-height:1.5;}"
        L".badge{display:inline-flex;align-items:center;gap:6px;padding:4px 11px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.5px;}"
        L".b0{background:rgba(35,190,120,.13);color:#14975c;}"
        L".b1{background:rgba(232,168,34,.15);color:#c78a12;}"
        L".b2{background:rgba(235,68,60,.14);color:#e03225;}"
        L".mid{display:flex;align-items:center;justify-content:space-between;gap:10px;}"
        L".score{font-size:11px;color:var(--sub);}.score b{font-size:14px;color:var(--fg);}"
        L".hits{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:7px;min-height:0;}"
        L".hit{font-size:11.5px;line-height:1.55;border-radius:10px;padding:8px 11px;background:rgba(127,127,127,.07);}"
        L".hit b{font-weight:800;display:block;font-size:12px;}"
        L".hit .d{color:var(--sub);}"
        L".s3{border-left:3px solid #e03225;}.s2{border-left:3px solid #e0a018;}.s1{border-left:3px solid rgba(127,127,127,.5);}.s0{border-left:3px solid rgba(47,107,255,.5);}"
        L".btns{display:flex;gap:9px;}"
        L".btn{flex:1;text-align:center;padding:9px 0;border-radius:11px;font-size:13px;font-weight:800;cursor:pointer;user-select:none;}"
        L".btn.ghost{background:rgba(127,127,127,.12);color:var(--fg);transition:background .15s;}"
        L".btn.ghost:hover{background:rgba(127,127,127,.22);}"
        L".btn.danger{background:linear-gradient(135deg,#ff5f52,#e03225);color:#fff;box-shadow:0 6px 16px rgba(224,50,37,.35);transition:filter .15s;}"
        L".btn.danger:hover{filter:brightness(1.08);}"
        L".brand{font-size:9.5px;color:var(--brand);letter-spacing:.5px;text-align:right;}"
        L"::-webkit-scrollbar{width:5px;}::-webkit-scrollbar-thumb{background:rgba(127,127,127,.35);border-radius:9px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;transition:background .15s,color .15s;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body>";
    std::wstring h(fmt);
    h.replace(h.find(L"data-theme=\"light\""), 18, (std::wstring(L"data-theme=\"") + g_theme + L"\""));   // 主题注入（原写死 light）
    h += L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},220)\">✕</div>";
    h += L"<div class=\"top\"><span class=\"badge b" + std::to_wstring(level > 2 ? 2 : level) + L"\">" +
         (level >= 2 ? L"危险" : (level == 1 ? L"可疑" : L"正常")) + L"</span>"
         L"<div><div class=\"title\">" + U8W(title) + L"</div>"
         L"<div class=\"sub\">银狐主防 · 单文件查杀 · " + U8W(type) + L"</div></div></div>";
    h += L"<div class=\"file\">" + EscHtmlW(fileW) + L"</div>";
    h += L"<div class=\"mid\"><span class=\"score\">风险分 <b>" + std::to_wstring(score) + L"</b></span></div>";
    h += L"<div class=\"hits\" id=\"hits\"></div>";
    if (level >= 1) {
        h += L"<div class=\"btns\">";
        h += L"<div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">关闭</div>";
        h += L"<div class=\"btn danger\" onclick=\"window.chrome.webview.postMessage('probe-clean')\">立即清除</div>";
        h += L"</div>";
    } else {
        h += L"<div class=\"btns\"><div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">关闭</div></div>";
    }
    h += L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>";
    h += L"<script>var HITS=" + U8W(hitsRaw) +
         L";var box=document.getElementById('hits');var s2={3:'s3',2:'s2',1:'s1',0:'s0'};"
         L"if(HITS&&HITS.length){HITS.forEach(function(x){var d=document.createElement('div');"
         L"d.className='hit '+ (s2[x.sev]||'s0');"
         L"d.innerHTML='<b>'+x.name+'</b><span class=\"d\">'+x.desc+'</span>';box.appendChild(d);});}"
         L"else{var e=document.createElement('div');e.className='hit';"
         L"e.innerHTML='<b>未发现可疑特征</b><span class=\"d\">常规结构、名称与内容均未命中检测规则。</span>';box.appendChild(e);}</script>";
    h += L"</body></html>";
    return h;
}

// ===========================================================================
//  撤销结果卡
//
//  用户在告警卡上点「撤销我的处理」→ 服务执行反向回滚 → 这里展示结果。
//  注意语义：撤销是**把文件还原回"被自动回滚之前"的版本**（即用户当时那份
//  被引擎判为密文而覆盖掉的内容），不是"让文件变回正常"。卡片文案必须把这个
//  说清楚，否则用户会以为点完就万事大吉。
// ===========================================================================
std::wstring BuildUndoResultHtml(const std::string& undoResp) {
    // ⚠️ 注意响应有两层 ok：外层是管道帧的 {"cmd":"rollbackundo","ok":true,"report":{...}}，
    // 外层 ok 只表示"命令送达且被处理"，内层 report.ok 才是"撤销是否成功"。
    // 直接在整个响应串里找 "ok":true 会命中外层，把失败当成功渲染 —— 故先抠出 report 对象。
    std::string rep = undoResp;
    size_t rb = undoResp.find("\"report\":{");
    if (rb != std::string::npos) {
        size_t ob = rb + 9, i = ob; int depth = 0;
        for (; i < undoResp.size(); ++i) {
            if (undoResp[i] == '{' || undoResp[i] == '[') ++depth;
            else if (undoResp[i] == '}' || undoResp[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
        }
        rep = undoResp.substr(ob, i - ob);
    }
    // 服务未响应 / 管道连不上时 undoResp 为空 → 视为失败
    bool ok = !rep.empty() && (rep.find("\"ok\":true") != std::string::npos);
    long long restored = sf::JsonGetInt(rep, "restored");
    long long failed   = sf::JsonGetInt(rep, "failed");
    std::string reason = sf::JsonGetString(rep, "reason");
    if (!ok && reason.empty()) reason = "主防服务未响应，撤销未执行";

    const wchar_t* accent = ok ? L"#f5a623" : L"#ff4d57";
    const wchar_t* soft   = ok ? L"rgba(245,166,35,.16)" : L"rgba(255,77,87,.14)";
    const wchar_t* line   = ok ? L"rgba(245,166,35,.34)" : L"rgba(255,77,87,.32)";
    const wchar_t* glow   = ok ? L"rgba(245,166,35,.26)" : L"rgba(255,77,87,.28)";
    const wchar_t* aura   = ok ? L"rgba(245,166,35,.18)" : L"rgba(255,77,87,.16)";

    std::wstring title = ok ? L"已撤销本次处理" : L"撤销未执行";
    std::wstring sub;
    if (ok) {
        sub = L"已把 " + std::to_wstring(restored) + L" 个文件还原为「处理前」的版本。";
        if (failed > 0) sub += L"另有 " + std::to_wstring(failed) + L" 个文件还原失败（可能被占用）。";
    } else {
        sub = U8W(reason);   // 服务端 JSON 里的中文是 UTF-8
    }

    std::wstring h =
        L"<!doctype html><html data-theme=\"light\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);--brand:rgba(30,34,46,.38);"
        L"--shadow:rgba(24,30,48,.20);--line:rgba(30,34,46,.10);"
        L"background:radial-gradient(160px 150px at 50px 50%,var(--aura) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow);color:var(--fg);display:flex;flex-direction:column;"
        L"padding:22px 24px;position:relative;gap:9px;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--line:rgba(255,255,255,.10);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".t{font-size:15px;font-weight:800;display:flex;align-items:center;gap:9px;padding-right:24px;}"
        L".ic{width:20px;height:20px;flex:0 0 auto;color:var(--accent);}"
        L".s{font-size:12px;color:var(--sub);line-height:1.7;}"
        L".btns{display:flex;gap:9px;margin-top:4px;}"
        L".btn{flex:1;text-align:center;padding:8px 0;border-radius:11px;font-size:12.5px;font-weight:800;"
        L"cursor:pointer;user-select:none;background:rgba(127,127,127,.12);color:var(--fg);"
        L"transition:transform .16s cubic-bezier(.22,.61,.36,1),background .18s ease;}"
        L".btn:hover{background:rgba(127,127,127,.2);}"
        L".btn:active{transform:scale(.97);}"
        L".brand{position:absolute;left:24px;bottom:10px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body style=\"--accent:";
    h += accent;
    h += L";--aura:";
    h += aura;
    h += L"\">";
    h += L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},220)\">✕</div>";
    h += L"<div class=\"t\"><svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.9\" stroke-linecap=\"round\" stroke-linejoin=\"round\">";
    if (ok) h += L"<path d=\"M3 12a9 9 0 1 0 3-6.7\"/><path d=\"M3 4v5h5\"/>";
    else    h += L"<circle cx=\"12\" cy=\"12\" r=\"9\"/><line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"13\"/><circle cx=\"12\" cy=\"16.4\" r=\".9\" fill=\"currentColor\" stroke=\"none\"/>";
    h += L"</svg>";
    h += title;
    h += L"</div><div class=\"s\">";
    h += sub;
    h += L"</div>";
    h += L"<div class=\"btns\"><div class=\"btn\" onclick=\"window.chrome.webview.postMessage('close')\">关闭</div></div>";
    h += L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>";
    h += L"</body></html>";
    (void)soft; (void)line; (void)glow;   // 本轮改用 --aura 单变量，保留色板常量便于后续扩展
    h.replace(h.find(L"data-theme=\"light\""), 18, (std::wstring(L"data-theme=\"") + g_theme + L"\""));   // 主题注入（原写死 light）
    return h;
}

// 引导扇区操作结果卡（「恢复引导」/「信任此变更」执行后反馈）
// resp 为 bootrestore/bootaccept 管道响应原文；成功显示 okTitle/okSub，失败显示服务端 reason。
std::wstring BuildBootResultHtml(const std::string& resp,
                                 const std::wstring& okTitle, const std::wstring& okSub) {
    // 抠 report 对象（响应外层 {"cmd":...,"ok":true,"report":{...}}，内层才是操作结果）
    std::string rep = resp;
    size_t rb = resp.find("\"report\":{");
    if (rb != std::string::npos) {
        size_t ob = rb + 9, i = ob; int depth = 0;
        for (; i < (int)resp.size(); ++i) {
            if (resp[i] == '{' || resp[i] == '[') ++depth;
            else if (resp[i] == '}' || resp[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
        }
        rep = resp.substr(ob, i - ob);
    }
    bool ok = !rep.empty() && (rep.find("\"ok\":true") != std::string::npos);
    std::string reason = sf::JsonGetString(rep, "reason");
    if (!ok && reason.empty()) reason = "主防服务未响应，操作未执行";
    std::wstring title = ok ? okTitle : L"操作未完成";
    std::wstring sub   = ok ? okSub  : U8W(reason);

    const wchar_t* accent = ok ? L"#1fb574" : L"#ff4d57";
    const wchar_t* aura   = ok ? L"rgba(31,181,116,.16)" : L"rgba(255,77,87,.16)";

    std::wstring h =
        L"<!doctype html><html data-theme=\"light\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);--brand:rgba(30,34,46,.38);"
        L"--shadow:rgba(24,30,48,.20);--line:rgba(30,34,46,.10);"
        L"background:radial-gradient(160px 150px at 50px 50%,var(--aura) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow);color:var(--fg);display:flex;flex-direction:column;"
        L"padding:22px 24px;position:relative;gap:9px;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--line:rgba(255,255,255,.10);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".t{font-size:15px;font-weight:800;display:flex;align-items:center;gap:9px;}"
        L".ic{width:20px;height:20px;color:var(--accent);}"
        L".s{font-size:12px;color:var(--sub);line-height:1.7;}"
        L".btns{display:flex;gap:9px;margin-top:6px;}"
        L".btn{flex:1;text-align:center;padding:9px 0;border-radius:11px;font-size:13px;font-weight:800;cursor:pointer;user-select:none;}"
        L".btn.ghost{background:rgba(127,127,127,.12);color:var(--fg);}"
        L".btn.ghost:hover{background:rgba(127,127,127,.22);}"
        L".brand{position:absolute;left:24px;bottom:10px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body style=\"--accent:";
    h += accent;
    h += L";--aura:";
    h += aura;
    h += L"\">";
    h += L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},220)\">✕</div>";
    h += L"<div class=\"t\"><svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.9\" stroke-linecap=\"round\" stroke-linejoin=\"round\">";
    if (ok) h += L"<path d=\"M3 12a9 9 0 1 0 3-6.7\"/><path d=\"M3 4v5h5\"/>";
    else    h += L"<circle cx=\"12\" cy=\"12\" r=\"9\"/><line x1=\"12\" y1=\"8\" x2=\"12\" y2=\"13\"/><circle cx=\"12\" cy=\"16.4\" r=\".9\" fill=\"currentColor\" stroke=\"none\"/>";
    h += L"</svg>";
    h += title;
    h += L"</div><div class=\"s\">";
    h += sub;
    h += L"</div>";
    h += L"<div class=\"btns\"><div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">关闭</div></div>";
    h += L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>";
    h += L"</body></html>";
    h.replace(h.find(L"data-theme=\"light\""), 18, (std::wstring(L"data-theme=\"") + g_theme + L"\""));   // 主题注入（原写死 light）
    return h;
}

// 清除结果卡（cleanResp 为服务端响应的 JSON 原文）
std::wstring BuildProbeCleanHtml(const std::string& cleanResp, const std::wstring& pathW) {
    std::string cleanObj = "{}";
    size_t hb = cleanResp.find("\"clean\":{");
    if (hb != std::string::npos) {
        size_t ob = hb + 8, i = ob; int depth = 0;
        for (; i < cleanResp.size(); ++i) {
            if (cleanResp[i] == '{' || cleanResp[i] == '[') ++depth;
            else if (cleanResp[i] == '}' || cleanResp[i] == ']') { --depth; if (depth == 0) { ++i; break; } }
        }
        cleanObj = cleanResp.substr(ob, i - ob);
    }
    std::wstring h =
        L"<!doctype html><html data-theme=\"light\"><head><meta charset=\"utf-8\"><style>"
        L"*{margin:0;padding:0;box-sizing:border-box;}"
        L"html,body{width:100%;height:100%;overflow:hidden;font-family:\"Microsoft YaHei\",\"Segoe UI\",system-ui,sans-serif;}"
        L"body{--bg1:#ffffff;--bg2:#eef0f5;--fg:#242833;--sub:rgba(30,34,46,.58);--brand:rgba(30,34,46,.38);"
        L"--shadow:rgba(24,30,48,.20);--line:rgba(30,34,46,.10);"
        L"background:radial-gradient(160px 150px at 50px 50%,rgba(35,190,120,.12) 0%,transparent 72%),"
        L"linear-gradient(158deg,var(--bg1),var(--bg2));border-radius:18px;border:1px solid var(--line);"
        L"box-shadow:0 18px 46px var(--shadow);color:var(--fg);display:flex;flex-direction:column;"
        L"padding:22px 24px;position:relative;gap:10px;justify-content:center;"
        L"animation:rise .3s cubic-bezier(.22,.61,.36,1) both;}"
        L"[data-theme=\"dark\"] body{--bg1:#15161d;--bg2:#0f0f14;--fg:#e8eaf2;--sub:rgba(232,234,242,.60);"
        L"--brand:rgba(232,234,242,.40);--shadow:rgba(0,0,0,.55);--line:rgba(255,255,255,.10);}"
        L"@keyframes rise{from{opacity:0;transform:translateY(10px) scale(.99);}to{opacity:1;transform:none;}}"
        L".t{font-size:15px;font-weight:800;display:flex;align-items:center;gap:9px;}"
        L".ic{width:20px;height:20px;color:#17975d;}"
        L".s{font-size:12px;color:var(--sub);line-height:1.7;}"
        L".stat{font-size:12px;color:var(--sub);}"
        L".stat b{color:var(--fg);font-weight:800;}"
        L".row{display:flex;gap:14px;flex-wrap:wrap;margin-top:2px;}"
        L".chip{font-size:11.5px;border-radius:999px;padding:4px 10px;background:rgba(127,127,127,.09);color:var(--fg);}"
        L".chip.ok{background:rgba(35,190,120,.14);color:#14975c;}"
        L".chip.bad{background:rgba(235,68,60,.14);color:#e03225;}"
        L".btns{display:flex;gap:9px;margin-top:6px;}"
        L".btn{flex:1;text-align:center;padding:9px 0;border-radius:11px;font-size:13px;font-weight:800;cursor:pointer;user-select:none;}"
        L".btn.ghost{background:rgba(127,127,127,.12);color:var(--fg);}"
        L".btn.ghost:hover{background:rgba(127,127,127,.22);}"
        L".brand{position:absolute;left:24px;bottom:10px;font-size:9.5px;color:var(--brand);letter-spacing:.5px;}"
        L".close{position:absolute;top:12px;right:12px;width:24px;height:24px;border-radius:50%;"
        L"display:grid;place-items:center;font-size:13px;color:var(--sub);cursor:pointer;transition:background .15s,color .15s;}"
        L".close:hover{background:rgba(127,127,127,.16);color:var(--fg);}"
        L"</style></head><body>"
        L"<div class=\"close\" onclick=\"document.body.classList.add('hide');setTimeout(function(){window.chrome.webview.postMessage('close')},220)\">✕</div>"
        L"<div class=\"t\"><svg class=\"ic\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\"><path d=\"M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z\"/><path d=\"M8.6 11.6l2.4 2.4 4.4-4.6\"/></svg>查杀任务已处理</div>"
        L"<div class=\"s\">已对该文件尝试清除：终止关联进程、删除文件本体及 NTFS 附加数据流。下方为处理结果。</div>";
    h += L"<div class=\"file\" style=\"font-size:11.5px;color:var(--fg);background:rgba(127,127,127,.09);border-radius:9px;padding:7px 10px;word-break:break-all;\">" +
         EscHtmlW(pathW) + L"</div>";
    h += L"<div class=\"row\"><span class=\"chip ok\">已删除 <b id=\"cDel\">0</b></span>"
         L"<span class=\"chip bad\">删除失败 <b id=\"cFail\">0</b></span>"
         L"<span class=\"chip\">终止进程 <b id=\"cKill\">0</b></span>"
         L"<span class=\"chip\">连坐 DLL <b id=\"cDll\">0</b></span></div>";
    h += L"<div class=\"btns\"><div class=\"btn ghost\" onclick=\"window.chrome.webview.postMessage('close')\">关闭</div></div>";
    h += L"<div class=\"brand\">银狐主防 · SilverFox Guard</div>";
    h += L"<script>var C=" + U8W(cleanObj) +
         L";function s(n,d){var e=document.getElementById(n);if(e)e.textContent=(typeof d==='number'?d:0);}"
         L"s('cDel',C.deleted);s('cFail',(typeof C.failed==='number'?C.failed:(typeof C.deferred==='number'?C.deferred:0)));"
         L"s('cKill',C.killed);s('cDll',C.extraDlls);</script>";
    h += L"</body></html>";
    h.replace(h.find(L"data-theme=\"light\""), 18, (std::wstring(L"data-theme=\"") + g_theme + L"\""));   // 主题注入（原写死 light）
    return h;
}

// 右键自定义查杀主入口（explorer 拉起，用户会话，无需跨会话 token）
int RunProbeToast(const std::wstring& fileW) {
    g_probeIn = fileW;
    g_probePath = fileW;
    // 1) 同步向服务管道请求判定（服务以 SYSTEM 执行，可读受保护文件；大安装包解包可能数十秒，逐秒重试）
    std::string resp;
    for (int i = 0; i < 60 && resp.empty(); ++i) {
        resp = ProbeVerdictRequest(fileW);
        if (!resp.empty()) break;
        Sleep(500);
    }
    int level = sf::JsonGetInt(resp, "level");
    int ratio = sf::JsonGetInt(resp, "score");
    std::string type = sf::JsonGetString(resp, "type");
    std::string title = sf::JsonGetString(resp, "title");
    if (title.empty()) title = (level == 2) ? "疑似危险文件" : (level == 1 ? "存在可疑迹象" : "未发现可疑特征");
    std::string hitsRaw = ExtractHitsRaw(resp);

    // 2) WebView2 宿主初始化（同 RunToast / RunPrewarm 管线）
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    SetEnvironmentVariableW(L"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS", L"--no-sandbox");
    g_theme = GetSystemTheme();
    g_closing = false; g_fallbackDone = false; g_prewarm = false;
    g_html = BuildProbeHtml(level, ratio, type, title, g_probeIn, hitsRaw);

    const int W = 400, H = 430, M = 18;
    int x, y; GetDockPos(x, y, W, H, M);
    WNDCLASSEXW wc{}; wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = L"SFProbeToast";
    wc.hbrBackground = CreateSolidBrush(g_theme == L"dark" ? RGB(15, 15, 20) : RGB(238, 240, 245));
    RegisterClassExW(&wc);
    g_posX = x; g_posY = y; g_w = W; g_h = H;
    RECT scr; GetWindowRect(GetDesktopWindow(), &scr);
    int ox = scr.right + W + 40, oy = scr.bottom + H + 40;
    g_hwnd = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW, L"SFProbeToast", L"",
        WS_POPUP, ox, oy, W, H, nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    if (!g_hwnd) { CoUninitialize(); return 1; }
    int corner = 2; DwmSetWindowAttribute(g_hwnd, 33, &corner, sizeof(corner));
    ShowWindow(g_hwnd, SW_SHOW);

    char ep[MAX_PATH]; GetModuleFileNameA(nullptr, ep, MAX_PATH);
    std::string d = ep; size_t q = d.find_last_of('\\');
    std::wstring runtime = (q != std::string::npos) ? U8W(d.substr(0, q + 1) + "WebView2Runtime") : L"";
    wchar_t envbuf[512] = {0};
    if (GetEnvironmentVariableW(L"SF_WV2_DIR", envbuf, 512)) runtime = envbuf;
    wchar_t pidbuf[32]; swprintf_s(pidbuf, L"_%lu", (unsigned long)GetCurrentProcessId());
    std::wstring userData = Wv2BaseDir() + L"\\WV2Data" + pidbuf;

    g_envH = Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>(
        [](HRESULT hr, ICoreWebView2Environment* env) -> HRESULT {
            if (FAILED(hr)) { g_lastHr = hr; WriteDbg(L"[probe] env FAILED\r\n"); FallbackMessage(); return S_OK; }
            g_ctrlH = Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>(OnController);
            env->CreateCoreWebView2Controller(g_hwnd, g_ctrlH.Get());
            return S_OK;
        });
    HRESULT hrc = CreateCoreWebView2EnvironmentWithOptions(
        runtime.empty() ? nullptr : runtime.c_str(), userData.c_str(), nullptr, g_envH.Get());
    if (FAILED(hrc)) { g_lastHr = hrc; WriteDbg(L"[probe] env fatal\r\n"); FallbackMessage(); CoUninitialize(); return 0; }

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
    CoUninitialize();
    return 0;
}
}  // namespace sf