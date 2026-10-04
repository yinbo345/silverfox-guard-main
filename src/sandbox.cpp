// sandbox.cpp — 动态分析沙箱实现（阶段一：零注入 MVP）
//
// 设计原则与"没有落地 ≠ 干净"的纪律见 sandbox.h。
// 本文件只做五件事：
//   ① 探测沙箱环境（Start.exe / box / 虚拟化目录）
//   ② ★ 每一轮送检都新建一个**一次性 box**，用完连同 ini 段一起销毁
//   ③ 对**虚拟化根下的全部观察树**做前后快照并 diff 出落地物
//   ④ 离线解析沙箱的注册表 hive，识别持久化行为
//   ⑤ 对上述证据评分（病毒库点查 + 启发式），产出可解释的理由
//
// ===========================================================================
//  ★★★ 一次性沙箱（disposable box）—— 2026-09-27 架构改动
// ===========================================================================
//  【为什么不再复用固定 box】
//    旧实现固定用 [SilverFoxBox]，每次送检前后清空 drive\ 再跑。三条实测
//    理由说明这个模型不可靠：
//      1. **清理面必然不全**。真实布局有两棵主树（见下），旧清理只覆盖
//         drive\ → user\ 树里的落地物跨轮累积。实测同一轮里能看到上一轮
//         留下的同名 %TEMP% 探针文件。
//      2. **同名残留会让 diff 漏报**。上一轮留下的 `...\sfprobe_drop.txt`
//         在本轮"已存在"，diff 判为"旧文件"→ 不报。这比"看不见"更隐蔽：
//         观察确实发生了，但把新落地当成了旧残留。
//      3. **box 配置会被外部改写**。实测 SandMan/SbieSvc 会对 box 段做
//         "自动规范化"（补上一整套 Template=/ConfigLevel=），也就是说
//         这个段的内容并不完全受我们控制 —— 而它决定沙箱的安全语义。
//         历史上 ClosedIpcPath=* 就是这么进来的：一次手滑，之后每一轮
//         送检都静默失败（rc=1、无输出、不建目录），极难排查。
//
//  【做法】每轮：新建唯一 box → 送检 → 观察 → 销毁（删段 + 删目录）
//    · box 名唯一 → 目录全新 → 三棵树（含注册表 hive）都是干净的
//    · 用完即毁 → 上一轮的任何残留都不可能影响本轮
//    · 样本也无法通过"记住自己上次来过"做跨轮反沙箱
//
//  【两个关键接口（本机实测有效，依据 Sandboxie 官方命令行文档）】
//    · 新建/配置：`SbieIni.exe set <box> <setting> <value>`
//    · 销毁目录：`Start.exe /box:<box> delete_sandbox_silent`
//        —— 官方两阶段删除：先摘 reparse point（**只摘链不跟进**，所以
//           不会误删被链接的真实目录）、去只读属性、重命名长路径，再删。
//           这正是不该自己 rmtree 的原因：实测直接 rmtree 会 WinError 5
//           （目录被 SbieSvc 持有），而且一旦跟进 junction 就会删到真实文件。
//    · 销毁 ini 段：`SbieIni.exe set <box> * ""`
//        —— `*` 作为 setting 名 + 空值 = **移除该段所有行**（官方文档）。
//           注意：`SbieIni.exe delete <box>` **不是**删段，实测返回 1 且
//           会把段"规范化"（反而更糟）。这是个很容易踩错的坑。
//
//  【环境探测的位置】
//    实测：**全新 box 不需要任何"预热"**。`set <box> Enabled y` 之后立刻
//    /box: 送检即可正常工作（四种预热方案 —— /drv、Start.exe /reload、
//    SbieIni reload、等待 —— 全部无必要）。所以每轮现建现用是零成本的。
#include "sandbox.h"

#include "common.h"        // LogDbg / NotifySandboxProgress / NotifySandboxResult / JsonString
#include "errhold.h"        // 无结论文件的用户决策待决表（2026-10-03）
#include "sfutils.h"       // NowStr / ExtLower
#include "hashverdict.h"   // 病毒库点查（与实时判定链共用同一实现）
#include "sfstop.h"        // IsStopRequested
#include "probe.h"         // sf::Find7z / sf::ExtractArchiveTo（归档送检要用）
#include <iphlpapi.h>       // GetExtendedTcpTable（沙箱网络行为嗅探）
#include <tcpmib.h>          // MIB_TCP_STATE_ESTABLISHED / MIB_TCPTABLE_OWNER_PID
#include <tlhelp32.h>        // CreateToolhelp32Snapshot（进程树嗅探）
// ★ 2026-10-02 加：EnumProcessModulesEx 需要 psapi（LoadsBoxModule 换窄掩码实现，
//   原因见该函数上方注释 —— 旧 toolhelp 模块快照会以 PROCESS_ALL_ACCESS 开目标进程）
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <wtsapi32.h>        // WTSGetActiveConsoleSessionId / WTSQueryUserToken（会话感知启动）
#include <map>               // 驻留观察：pid → 镜像名
#include <set>               // 驻留观察：box 进程 PID 集合
#include <algorithm>         // std::sort / std::unique（连接列表去重）
#include <userenv.h>         // CreateEnvironmentBlock / DestroyEnvironmentBlock / GetUserProfileDirectoryW
#pragma comment(lib, "userenv.lib")   // toast.cpp 同款：userenv 不在 build.sh 的 /link 列表里

#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

namespace sf {
namespace sandbox {

// ---------------------------------------------------------------------------
//  字符串转换（本文件内部；项目铁律：UTF-8 路径必须转 UTF-16 再用 W 版 API）
// ---------------------------------------------------------------------------
static std::wstring U2W(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}
static std::string W2U(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}
static std::string LowerAscii(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}
static bool FileExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static bool DirExistsW(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}
static bool PathExistsW(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}
// 递归删除目录树（含只读文件）。给"清理临时解压目录"用 —— 解压出来的是恶意样本，
// 常带只读/隐藏属性，普通 DeleteFileW 会被属性挡住，所以先清属性再删。
// 返回 true = 路径已不存在（删成功 or 本来就没有）。
// ★ 调用方必须先过 SafeRemovePayloadDir 的路径闸门，本函数自身不做范围校验。
static bool RemoveTreeW(const std::wstring& dir, int depth) {
    if (depth > 32) return false;                        // 防御性：异常深的目录树直接放弃
    if (!PathExistsW(dir)) return true;

    const DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        // 目录：先递归清空子项
        std::wstring pat = dir;
        if (!pat.empty() && pat.back() != L'\\') pat.push_back(L'\\');
        pat += L"*";
        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW(pat.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
                std::wstring child = dir;
                if (!child.empty() && child.back() != L'\\') child.push_back(L'\\');
                child += fd.cFileName;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    RemoveTreeW(child, depth + 1);           // 子目录递归
                } else {
                    if (fd.dwFileAttributes & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN |
                                               FILE_ATTRIBUTE_SYSTEM)) {
                        SetFileAttributesW(child.c_str(), FILE_ATTRIBUTE_NORMAL);
                    }
                    DeleteFileW(child.c_str());
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_NORMAL);
        RemoveDirectoryW(dir.c_str());
    } else {
        // 文件
        if (attr != INVALID_FILE_ATTRIBUTES &&
            (attr & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM))) {
            SetFileAttributesW(dir.c_str(), FILE_ATTRIBUTE_NORMAL);
        }
        DeleteFileW(dir.c_str());
    }
    return !PathExistsW(dir);
}
// 无符号数转 base36（小写），左侧补 0 到 minDigits 位
static std::string ToBase36(unsigned long long v, int minDigits) {
    static const char* D = "0123456789abcdefghijklmnopqrstuvwxyz";
    std::string s;
    do { s.push_back(D[v % 36]); v /= 36; } while (v);
    std::reverse(s.begin(), s.end());
    while ((int)s.size() < minDigits) s.insert(s.begin(), '0');
    return s;
}

// ---------------------------------------------------------------------------
//  全局状态
// ---------------------------------------------------------------------------
static Config g_cfg;
static bool   g_detected = false;
static Report g_last;
static std::mutex g_mtx;

// 一次性 box 的会话内序号（唯一性来源之一）
static std::atomic<unsigned> g_boxSeq(0);

// 累计计数（给 sandboxstat 用，观测"沙箱这条链到底跑了多少次、抓到了什么"）
static unsigned long long g_runs    = 0;
static unsigned long long g_vMal    = 0;
static unsigned long long g_vSus    = 0;
static unsigned long long g_vClean  = 0;
static unsigned long long g_vError  = 0;
static unsigned long long g_artSum  = 0;
static unsigned long long g_boxMade = 0;   // 实际新建的一次性 box 数
static unsigned long long g_boxLeft = 0;   // 销毁失败留下的 box 数（★ 应长期为 0）

// ---------------------------------------------------------------------------
//  box 生命周期用到的通用子进程调用
// ---------------------------------------------------------------------------
// ★ 为什么不检查返回码当结论：实测多处返回码不可信 ——
//   `SbieIni.exe set GlobalSettings DebugTrace y` 曾返回 0 但未落盘；
//   `reload` 返回 1；`delete` 因权限恒返回 1。
//   与 service.cpp 修 ChangeServiceConfig2 假日志同一条纪律：
//   **不信返回码，只看回读到的文件事实**。返回码只在日志里留痕。
static DWORD RunToolW(const std::wstring& cmdLine, DWORD timeoutMs) {
    if (cmdLine.empty()) return (DWORD)-1;
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back(0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // CREATE_NO_WINDOW：送检与配置过程对用户应当是静默的
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return (DWORD)-1;
    }
    DWORD w = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD ec = (DWORD)-2;
    if (w == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
        ec = (DWORD)-3;                       // 超时
    } else {
        GetExitCodeProcess(pi.hProcess, &ec);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return ec;
}
static DWORD RunTool(const std::string& exe, const std::string& args, DWORD timeoutMs) {
    if (exe.empty()) return (DWORD)-1;
    std::wstring c = L"\"" + U2W(exe) + L"\"";
    if (!args.empty()) c += L" " + U2W(args);
    return RunToolW(c, timeoutMs);
}

// ---------------------------------------------------------------------------
//  ★ 会话感知启动（2026-09-30）：沙箱必须跑在"交互用户会话"里，不是 Session 0
// ---------------------------------------------------------------------------
//  实测（本机 2026-09-30 23:20~23:35 多轮）：服务以 LocalSystem 在 Session 0
//  直接 `CreateProcessW` 拉起 `Start.exe /box:<box> /silent /wait <样本>`
//    → Start.exe 挂死 ~150s 被强杀；box 里**只有 RegHive，没有 drive\、没有
//      beacon、没有孤儿样本进程** → 样本从未启动，结论恒为 clean score=0（假阴性）。
//  把同一命令行改以交互用户（会话 1）身份运行：1.6s 完成、drive\ 与 beacon 齐全。
//  原因：Sandboxie 的沙箱会话依赖交互会话里的**按会话辅助进程**
//    （SandboxieRpcSs.exe / SandboxieDcomLaunch.exe —— 实测只存在于 Console 会话）
//    与可交互桌面；Session 0 里全都不存在，Start.exe 只能阻塞（无人应答的错误框）。
//  ∴ ① 送检 / 终止 / 删除三个动作都改走"取交互用户令牌 → CreateProcessAsUserW 到会话 1"；
//     ② 沙箱根目录定为**交互用户**的 C:\Sandbox\<账号>（服务账号是 SYSTEM，
//        box 绝不会建在 C:\Sandbox\SYSTEM 下 —— 旧探测会选中那个空壳，导致
//        快照 / beacon 全读空）。
//  ⚠️ 这里与 UAC 无关：服务（LocalSystem）创建子进程根本不经过 UAC；UseSandboxieUAC=n
//     只是关掉 Sandboxie 自己的 UAC 代理。修的是**会话**，不是提权。
//  与 toast.cpp 的 GetUserTokenForSession / SpawnInUserSession 同源（同坑同解）。
// ---------------------------------------------------------------------------

// 取活动控制台会话（交互用户）的主令牌；失败返回 nullptr。
// WTSQueryUserToken 在部分 VM / 远程会话下会失败 → 回退到复制该会话 explorer.exe 的主令牌。
static HANDLE GetActiveUserToken(DWORD* outSession) {
    DWORD sid = WTSGetActiveConsoleSessionId();
    if (outSession) *outSession = sid;
    if (sid == 0xFFFFFFFF) return nullptr;
    HANDLE hToken = nullptr;
    if (WTSQueryUserToken(sid, &hToken) && hToken) return hToken;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    DWORD target = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "explorer.exe") != 0) continue;
            DWORD s2 = 0; ProcessIdToSessionId(pe.th32ProcessID, &s2);
            if (s2 == sid) { target = pe.th32ProcessID; break; }
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

// 令牌对应的账号名 —— Sandboxie 的 C:\Sandbox\<账号> 用的就是它（如 "tianl"）。
static std::wstring AccountNameFromToken(HANDLE hTok) {
    if (!hTok) return std::wstring();
    // ★★★ 2026-10-01 根因级修正：**绝不能用 GetUserNameW**。
    //   它的签名是 GetUserNameW(buf, &n) —— **根本不接收令牌参数**，返回的是
    //   【调用进程自身】的有效用户（服务 = "SYSTEM"），与传进来的 hTok 毫无关系。
    //   症状链（隐蔽性极强，全程静默）：会话感知探测把 "SYSTEM" 当账号名 →
    //   被 `_wcsicmp(acct, L"SYSTEM") != 0` 挡掉 → 不设 sandboxUserRoot →
    //   回退到 C:\Sandbox\* 枚举 → 选中残留的空壳 C:\Sandbox\SYSTEM →
    //   boxRoot 指向错误目录 → 快照/beacon 全读空 → 送检"永远未生效"，
    //   而**代码看起来完全正确**（有令牌、有函数、有回退），不报任何错。
    //   正解：走令牌自己的 TokenUser SID，再 LookupAccountSidW 反查账号名。
    DWORD need = 0;
    GetTokenInformation(hTok, TokenUser, nullptr, 0, &need);
    if (need == 0) return std::wstring();
    std::vector<BYTE> buf(need);
    if (!GetTokenInformation(hTok, TokenUser, buf.data(), need, &need)) return std::wstring();
    TOKEN_USER* tu = reinterpret_cast<TOKEN_USER*>(buf.data());
    wchar_t name[256] = { 0 }, dom[256] = { 0 };
    DWORD cn = 256, cd = 256;
    SID_NAME_USE use = SidTypeUnknown;
    if (!LookupAccountSidW(nullptr, tu->User.Sid, name, &cn, dom, &cd, &use)) return std::wstring();
    return std::wstring(name);   // 只要 account 名（不带域名）—— 正是 Sandboxie 目录名
}

// 环境块：优先用**用户令牌**的环境（%TEMP% / %APPDATA% 指向用户而非 systemprofile），
// token 为空则退回服务自身环境。
static std::wstring BuildUserEnv(HANDLE hTok) {
    std::wstring env;
    LPVOID pEnv = nullptr;
    if (hTok && CreateEnvironmentBlock(&pEnv, hTok, FALSE) && pEnv) {
        for (LPWCH p = (LPWCH)pEnv; *p; ) { std::wstring s = p; env += s; env += L'\0'; p += s.size() + 1; }
        DestroyEnvironmentBlock(pEnv);
        return env;
    }
    LPWCH envb = GetEnvironmentStringsW();
    if (envb) {
        for (LPWCH p = envb; ; ) { std::wstring s = p; if (s.empty()) break; env += s; env += L'\0'; p += s.size() + 1; }
        FreeEnvironmentStringsW(envb);
    }
    return env;
}

// 在交互用户会话中以该用户身份启动给定命令行（Start.exe）。
// 成功返回 true 并回填 pi（调用方负责 CloseHandle）；token 为空 / AsUser 失败
// → 退化为同会话（服务）启动，保住"至少能跑"的旧路径，绝不静默失效。
static bool LaunchInActiveSession(HANDLE hTok, const std::wstring& cmdLine,
                                  const std::wstring& envBlock, PROCESS_INFORMATION* outPi) {
    std::vector<wchar_t> buf(cmdLine.begin(), cmdLine.end()); buf.push_back(0);
    std::vector<wchar_t> eb(envBlock.begin(), envBlock.end()); eb.push_back(0);
    std::wstring cwd;
    if (hTok) {
        wchar_t pb[MAX_PATH] = { 0 }; DWORD n = MAX_PATH;
        if (GetUserProfileDirectoryW(hTok, pb, &n) && pb[0]) cwd = pb;
    }
    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.lpDesktop = (LPWSTR)L"winsta0\\default";   // 可交互桌面（Sandboxie 启动必需）
    PROCESS_INFORMATION pi{};
    const DWORD flags = CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT;
    BOOL ok = FALSE;
    if (hTok)
        ok = CreateProcessAsUserW(hTok, nullptr, buf.data(), nullptr, nullptr, FALSE, flags,
                                  eb.data(), cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    if (!ok)
        ok = CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, flags,
                            eb.data(), cwd.empty() ? nullptr : cwd.c_str(), &si, &pi);
    if (!ok) return false;
    if (outPi) *outPi = pi;
    else { if (pi.hThread) CloseHandle(pi.hThread); if (pi.hProcess) CloseHandle(pi.hProcess); }
    return true;
}

// 会话感知的 Start.exe 调用（终止 / 删除 box 用）。内部自取令牌，调用方无需持有。
// ★ 必须与送检同一个身份：box 是按用户隔离的，"以 SYSTEM 去删用户的 box" 会找错目录。
static DWORD RunStartToolW(const std::wstring& cmdLine, DWORD timeoutMs) {
    if (cmdLine.empty()) return (DWORD)-1;
    HANDLE hTok = GetActiveUserToken(nullptr);
    std::wstring env = BuildUserEnv(hTok);
    PROCESS_INFORMATION pi{};
    if (!LaunchInActiveSession(hTok, cmdLine, env, &pi)) {
        if (hTok) CloseHandle(hTok);
        return (DWORD)-1;
    }
    DWORD w = WaitForSingleObject(pi.hProcess, timeoutMs);
    DWORD ec = (DWORD)-2;
    if (w == WAIT_TIMEOUT) {
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 5000);
        ec = (DWORD)-3;
    } else {
        GetExitCodeProcess(pi.hProcess, &ec);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (hTok) CloseHandle(hTok);
    return ec;
}

// ---------------------------------------------------------------------------
//  ★★★ 2026-10-03：封锁补偿 —— 判「clean」后按原意图重新启动被挡的文件
// ---------------------------------------------------------------------------
//  问题（银泊）：送检封锁为了"抢在样本执行前把它按住"，会用**只共享删除**的
//  句柄锁住原件。副作用是：**用户此刻的双击（或任何本机启动）会直接失败**
//  （ERROR 32 共享冲突）。而如果我们跑完判「clean」，用户那一次启动就被静默
//  吞掉了 —— 用户视角是"我点了它，什么都没发生，防护软件也没告诉我"。
//  这是**我们造成的副作用**，必须由我们补偿。
//
//  补偿 = 判 clean 且文件仍存在时，**以交互用户身份**在用户会话里把它启动起来，
//        等价于"替用户把他刚才那次双击补上"。
//
//  ⚠️ 边界（刻意保守：宁可漏补，不可乱跑）：
//    · 只在 verdict == "clean" 时补 —— 其余档位要么已隔离(malicious)、要么
//      结论不确定(suspicious/error)：对不确定的东西"主动替用户运行"是放大风险。
//    · 只补**可执行映像**（.exe/.com/.scr）。.bat/.ps1/.lnk 需要 ShellExecute
//      才能正确启动，而服务里调 ShellExecute 会落到 Session 0（无桌面），
//      为不引入"半通"的启动路径，这里**明确不补**并写日志说明。
//    · 只补位于**用户启动区**（Downloads/Desktop/Temp/Documents/用户目录）的件。
//      ★ 方向说明：这里的路径限制是**收紧我们自己的动作面**，不是给对手放行 ——
//        与 HoldEligible「判据必须落在文件属性上、不能落在目录上」不冲突：
//        那条防的是"对手主动把载荷丢进某目录换放行"；这条防的是"我们误跑一个
//        无人问津的文件"。对手**无法**用目录换到额外好处（目录限得越死越安全）。
//    · 同一文件（路径+大小+改动时间）**只补一次**；并有全局限流，
//      避免任何回环把服务变成"自动执行器"。
// ---------------------------------------------------------------------------
static std::mutex           g_compMtx;
static std::set<std::string> g_compDone;      // path|size|mtime 去重（本次运行内）
static int                  g_compCount = 0;
static const int            kCompMaxPerRun = 20;   // 单次运行最多补跑 20 次

static bool IsUserLaunchZone(const std::string& low) {
    static const char* kZones[] = {
        "\\downloads\\", "\\desktop\\", "\\temp\\", "\\documents\\",
        "\\onedrive\\",  "\\download\\",
    };
    for (size_t i = 0; i < sizeof(kZones) / sizeof(kZones[0]); i++)
        if (low.find(kZones[i]) != std::string::npos) return true;
    return false;
}

// 返回 true = 已补跑；false = 未补（*why 写原因，供日志/报告）。
static bool TryCompensateLaunch(const std::string& origU8, const std::string& verdict,
                                std::string* why) {
    if (why) why->clear();
    auto deny = [&](const std::string& m) { if (why) *why = m; return false; };

    if (verdict != "clean") return deny("结论非 clean（" + verdict + "），不代跑");
    const std::string low = LowerAscii(origU8);
    const std::string ext = ExtLower(low);
    if (ext != ".exe" && ext != ".com" && ext != ".scr")
        return deny("非可执行映像（" + ext + "），不走 CreateProcess 代跑");
    if (!IsUserLaunchZone(low))
        return deny("不在用户启动区，不代跑（避免跑一个无人问津的文件）");

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExA(origU8.c_str(), GetFileExInfoStandard, &fad))
        return deny("文件已不存在（可能已被其它链路处理）");
    const std::string key = low + "|" + std::to_string(fad.nFileSizeLow) + "|" +
                            std::to_string(fad.ftLastWriteTime.dwLowDateTime);
    {
        std::lock_guard<std::mutex> lk(g_compMtx);
        if (g_compDone.count(key)) return deny("本次运行已补跑过同一文件，跳过");
        if (g_compCount >= kCompMaxPerRun) return deny("补跑次数达上限，跳过");
        g_compDone.insert(key);
        g_compCount++;
    }

    HANDLE hTok = GetActiveUserToken(nullptr);
    std::wstring env = BuildUserEnv(hTok);
    const std::wstring cmd = L"\"" + U2W(origU8) + L"\"";
    PROCESS_INFORMATION pi{};
    if (!LaunchInActiveSession(hTok, cmd, env, &pi)) {
        if (hTok) CloseHandle(hTok);
        return deny("以用户身份启动失败（令牌/会话不可用）");
    }
    if (pi.hThread)  CloseHandle(pi.hThread);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (hTok)        CloseHandle(hTok);
    LogDbg("[sandbox] ★封锁补偿：判 clean，已按原意图重新启动被挡的原件：" + origU8);
    if (why) *why = "已按原意图重新启动";
    return true;
}

// ---------------------------------------------------------------------------
//  读 Sandboxie.ini（UTF-16LE）
// ---------------------------------------------------------------------------
// ⚠️⚠️ 编码：Sandboxie.ini 是 **UTF-16LE 带 BOM**。实测 C:\Windows\Sandboxie.ini
//   开头四字节为 fffe 2300 0d00 0a00（即 BOM + "#\r\n"）。而 Read 工具会直接
//   把它判成"二进制文件"拒读 —— 若沿用 UTF-8 思路处理，"[SilverFoxBox]"
//   永远搜不到 → 误判"box 不存在"→ 反复重建 → 表面上一直"修好了"其实没修。
//   本项目已有"配置文件必须按正确编码读"的铁律（probe_rules.txt 被 0x1A
//   截断 46 条规则的事故），这里是同型问题的第二次现身，故写死按 UTF-16LE 解。
static bool ReadIniWhole(std::string* outPath, std::wstring* outText) {
    static const wchar_t* kInis[] = {
        L"C:\\Windows\\Sandboxie.ini",
        L"C:\\Program Files\\Sandboxie-Plus\\Sandboxie.ini",
        L"C:\\Program Files\\SandboxIsolation\\Sandboxie-Plus\\Sandboxie.ini",
    };
    for (auto* p : kInis) {
        if (!FileExistsW(p)) continue;
        FILE* f = nullptr;
        if (_wfopen_s(&f, p, L"rb") != 0 || !f) continue;
        std::string raw;
        {
            char buf[8192];
            size_t n = 0;
            while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.append(buf, n);
        }
        fclose(f);
        // 逐字节组装成 wstring —— 不能 reinterpret_cast：std::string 的
        // 数据缓冲区不保证 2 字节对齐，在 x64 上对 wchar_t* 解引用是 UB。
        size_t off = 0;
        if (raw.size() >= 2 &&
            (unsigned char)raw[0] == 0xFF && (unsigned char)raw[1] == 0xFE) off = 2;
        std::wstring w;
        w.reserve((raw.size() - off) / 2);
        for (size_t i = off; i + 1 < raw.size(); i += 2) {
            w.push_back((wchar_t)((unsigned char)raw[i] |
                                  ((wchar_t)(unsigned char)raw[i + 1] << 8)));
        }
        if (outPath) *outPath = W2U(p);
        if (outText) *outText = w;
        return true;
    }
    return false;
}

// box 段是否存在于 ini（判据用"配置文件里的事实"，而非工具返回码）
static bool BoxExistsInIni(const std::string& box, std::string* outIni) {
    std::wstring all;
    std::string p;
    if (!ReadIniWhole(&p, &all)) return false;
    if (outIni) *outIni = p;
    return all.find(L"[" + U2W(box) + L"]") != std::wstring::npos;
}

// 取出 [box] 段的正文（不含节标题行）。找不到该段返回 false。
static bool BoxSectionText(const std::string& box, std::string* outPath, std::string* outText) {
    std::wstring all;
    std::string p;
    if (!ReadIniWhole(&p, &all)) return false;
    const std::wstring want = L"[" + U2W(box) + L"]";
    const size_t pos = all.find(want);
    if (pos == std::wstring::npos) return false;

    size_t beg = all.find(L'\n', pos);
    if (beg == std::wstring::npos) {          // 节标题行没有换行 → 空段
        if (outPath) *outPath = p;
        if (outText) outText->clear();
        return true;
    }
    beg += 1;

    size_t end = all.find(L"\n[", pos + 1);   // 下一个节标题
    end = (end == std::wstring::npos) ? all.size() : (end + 1);

    if (outPath) *outPath = p;
    if (outText) {
        if (end > beg) *outText = W2U(all.substr(beg, end - beg));
        else           outText->clear();
    }
    return true;
}

// ---------------------------------------------------------------------------
//  ★★ 让沙箱"闭嘴"：关掉 GUI 代理自动启动 + 所有通知（2026-09-27 真机实测）
// ---------------------------------------------------------------------------
// 【问题现象】
//   用户反馈两点：① 托盘区冒出 Sandboxie 图标；② 时不时自己弹出弹窗。
//   实测（模式 D，未做任何修正时）：送检后
//       SandMan.exe 被拉起（PID 实测存在），并出现
//       cls=Qt683QWindowIcon  title='Sandboxie-Plus 通知'
//       cls=Qt683QWindowIcon  title='Sandboxie-Plus'
//   即：**每次送检都会把 Sandboxie 的 GUI 代理拉起来并弹通知**。
//
// 【根因】
//   Sandboxie.ini 的 [UserSettings_<hash>] 段里有
//       SbieCtrl_AutoStartAgent=SandMan.exe -autorun
//   语义是"启动沙箱进程时，若 GUI 代理没在运行，就自动把它拉起来"。
//   拉起动作的发起者是 **SbieSvc**（其二进制内含 SbieCtrl_AutoStartAgent
//   与 SbieCtrl_EnableAutoStart 两个字符串，实证见下），不是我们。
//
// 【三次被实测证伪的候选方案 —— 都别再试】
//   ① SbieCtrl_AutoStartAgent 置为空字符串
//      → ❌ 不是"禁用"，而是让 SbieSvc 回退到**硬编码默认的 SbieCtrl.exe**
//        （经典 GUI）。现象：托盘图标还在，但右键菜单从 Qt 现代样式变成
//        系统默认样式 —— 极易被误当成"改坏了"而回滚，从而错过真正的开关。
//   ② 删除 SbieCtrl_AutoStartAgent 整行
//      → ❌ 同上，一样回退到 SbieCtrl.exe。（SbieIni 省略 value = 删除该键）
//   ③ Start.exe 加 /silent
//      → ❌ **完全挡不住 agent 拉起**，弹窗照旧（模式 C 实测）。
//        曾误判它有效，原因是当时只查了 SandMan.exe、没查 SbieCtrl.exe。
//
// 【唯一有效方案】SbieCtrl_EnableAutoStart=n
//   官方布尔开关（SbieSettings.ini 的 [SbieCtrl_EnableAutoStart]：
//   "Controls whether Sandboxie Agent should start automatically"）。实测四组：
//     A  EnableAutoStart=n  无 /silent → 无 agent、无弹窗、样本正常执行
//     B  EnableAutoStart=n  有 /silent → 无 agent、无弹窗、样本正常执行
//     C  原值               有 /silent → ★agent 被拉起、弹窗出现
//     D  原值               无 /silent → ★agent 被拉起、弹窗出现
//   （"样本正常执行"以样本自身写的日志文件为证，5/5 次全部落盘 ——
//     这条很关键：否则"没弹窗"可能只是"样本压根没跑"的假阴性。）
//   附带效果：连沙箱窗口边框 Sandboxie_BorderWindow 也不再出现。
//
// 【作用域】写 [GlobalSettings] 即可：用户段无同名键时向全局继承。
//   且 SbieIni 对 Context=u 的键会自动落到正确的 UserSettings_<hash> 段，
//   因此**不需要**动态发现段名（不同机器 hash 不同）。
//
// 【为什么要连通知项一起关】
//   Sandboxie 有一批**默认 Y** 的通知，而本模块的工作流每一步都会踩中：
//     EditConfNotify / ReloadConfNotify / SettingChangeNotify —— 每轮都改配置
//     TerminateNotify                                        —— 样本退出
//     ShouldDeleteNotify                                     —— 每轮都销毁 box
//   只要 agent 在跑，每次送检都会连弹一串。故一并关掉（纵深防御：
//   即便将来 agent 被别的程序拉起，也不会弹到用户脸上）。
//
// 【★ 写入方式：先 delete 再 set】
//   实测重复 set 同一键会产生**重复行**（回读值成了 'n\r\nn'）——
//   SbieIni 的 set 对已存在键并不总是替换。故每条都先删后写。
static void QuietDown(const Config& cfg) {
    static bool done = false;          // 一个服务进程内只做一次（幂等且省时）
    if (done) return;
    if (!cfg.ready || cfg.sbieIni.empty()) return;

    struct KV { const char* k; const char* v; };
    static const KV kQuiet[] = {
        // —— 核心：不让 SbieSvc 拉起 GUI 代理（托盘图标 + 弹窗的总根源）——
        { "SbieCtrl_EnableAutoStart",     "n" },
        // —— 默认 Y 的通知项：本模块的工作流每一步都会踩中 ——
        { "SbieCtrl_EditConfNotify",      "n" },   // 配置文件被改动
        { "SbieCtrl_ReloadConfNotify",    "n" },   // 配置被重载
        { "SbieCtrl_SettingChangeNotify", "n" },   // 任何设置变更
        { "SbieCtrl_TerminateNotify",     "n" },   // 箱内进程退出
        { "SbieCtrl_ShouldDeleteNotify",  "n" },   // 删除沙箱内容前
        { "SbieCtrl_TerminateWarn",       "n" },   // 终止进程前警告
        { "SbieCtrl_ProcSettingsNotify",  "n" },
        { "SbieCtrl_ResMonNotify",        "n" },
        { "SbieCtrl_ShortcutNotify",      "n" },
        { "SbieCtrl_HideWindowNotify",    "n" },
        { "SbieCtrl_ExplorerNotify",      "n" },
        { "SbieCtrl_ExplorerWarn",        "n" },
        { "SbieCtrl_UpdateCheckNotify",   "n" },
        { "SbieCtrl_ShowWelcome",         "n" },
        // —— 不要把 Sandboxie 塞进用户的资源管理器/桌面（沉浸感）——
        { "SbieCtrl_AddContextMenu",      "n" },
        { "SbieCtrl_AddDesktopIcon",      "n" },
        { "SbieCtrl_AddQuickLaunchIcon",  "n" },
        { "SbieCtrl_AddSendToMenu",       "n" },
        // —— 沙箱事件类通知（其中几项默认就是 Y）——
        { "AlertBeforeStart",             "n" },
        { "AlertStartRunAccessDenied",    "n" },
        { "NotifyStartRunAccessDenied",   "n" },
        { "NotifyImageLoadDenied",        "n" },
        { "NotifyInternetAccessDenied",   "n" },
        { "NotifyMsiInstaller",           "n" },
        { "NotifyBoxProtected",           "n" },
        { "NotifyDirectDiskAccess",       "n" },
        { "NotifyForceProcessDisabled",   "n" },
        { "NotifyForceProcessEnabled",    "n" },
        { "NotifyNoCopy",                 "n" },
        { "NotifyProcessAccessDenied",    "n" },
        { "NotifyRootProtected",          "n" },
        // —— CopyLimitSilent=y：限额/阻断静默执行，不弹提示 ——
        { "CopyLimitSilent",              "y" },
        // —— ★ 安全加固：禁止箱内直接读写裸盘 ——
        //   实测发现箱内程序 CreateFile("\\.\PhysicalDrive0") 竟能拿到句柄，
        //   而该项官方说明明确标着 "(security risk)"。送检恶意样本必须关死。
        { "AllowRawDiskRead",             "n" },
        // —— 关掉 Sandboxie 自己的 UAC 代理（避免提权弹窗介入）——
        { "UseSandboxieUAC",              "n" },
    };

    const ULONGLONG t0 = GetTickCount64();
    int ok = 0, fail = 0;
    std::string failed;
    for (auto& kv : kQuiet) {
        // 先删（清掉可能存在的重复行），再写
        RunTool(cfg.sbieIni, std::string("set GlobalSettings ") + kv.k, 8000);
        const DWORD ec = RunTool(cfg.sbieIni,
                                 std::string("set GlobalSettings ") + kv.k + " " + kv.v, 8000);
        if (ec == 0) ++ok;
        else {
            ++fail;
            if (failed.size() < 160) { failed += kv.k; failed += ' '; }
        }
    }

    // ---- 回读验证：不信返回码，只看 ini 里的事实 ----
    std::wstring all;
    const bool readOk = ReadIniWhole(nullptr, &all);
    const std::string txt = readOk ? W2U(all) : std::string();
    const bool agentOff = txt.find("SbieCtrl_EnableAutoStart=n") != std::string::npos;

    LogDbg("[sandbox] 沙箱静默化：写入 " + std::to_string(ok) + " 项成功、" +
           std::to_string(fail) + " 项失败" +
           (fail ? ("（失败键：" + failed + "）") : "") +
           "，用时 " + std::to_string((unsigned long long)(GetTickCount64() - t0)) + "ms" +
           "；回读 SbieCtrl_EnableAutoStart=n → " +
           (agentOff
            ? "已生效（SbieSvc 不会拉起 Sandboxie GUI：无托盘图标、无弹窗）"
            : "★未生效（沙箱 UI 仍可能打扰用户，请检查 SbieIni 是否可用）"));

    // 只有确认生效才标记完成 —— 否则下次探测时再试一遍
    if (agentOff) done = true;
}

// ---------------------------------------------------------------------------
//  环境探测
// ---------------------------------------------------------------------------
// 找 Start.exe 的候选顺序（★ 2026-09-27 修正：以"真正在跑的那份"为准）
//
//   ① SbieSvc 服务的 ImagePath 反推目录 —— 最准。SbieSvc 才是与内核驱动
//      SbieDrv 配对的用户态服务，注册表里这条路径就是"活着的那一份"。
//      本机实测存在【三份】完整副本：
//          D:\SilverFoxEnvScan\SilverFoxGuard\Sandboxie-Plus\   （安装器布局）
//          C:\Users\tianl\Desktop\Sandboxie-Plus\               （用户手动副本）
//          D:\SandboxieTest\Sandboxie-Plus\                     （★ 注册表指向这份）
//      拿非注册副本的 Start.exe 去 /box: 送检，会因"Start 与 SbieSvc 不是同一
//      实例/版本"而失败，且报错信息极具误导性（指向样本，不指向这个根因）。
//   ② 本服务 exe 同目录下的 Sandboxie-Plus\（安装器布局，随主防卸载）
//   ③ SOFTWARE\Sandboxie-Plus 的 InstallDir —— 实测**本机根本不存在此键**，
//      仅作兜底保留，不能当主路径。
//   ④ 常见独立安装位置（调试/测试用）
//
// 探测**成功不代表可用**（SbieSvc 未就绪时送检会失败），可用性以实际送检为准。
bool Detect(Config& out, bool force) {
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_detected && !force) { out = g_cfg; return out.ready; }
    }

    Config c;
    c.box = "SilverFoxBox";        // 仅 dryrun / 探测展示用；正式送检用一次性 box
    std::string tried;

    std::vector<std::wstring> cands;

    // ① SbieSvc 服务 ImagePath → 安装目录 → \Start.exe
    {
        HKEY hk = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Services\\SbieSvc",
                          0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            wchar_t buf[1024] = { 0 };
            DWORD cb = sizeof(buf), type = 0;
            if (RegQueryValueExW(hk, L"ImagePath", nullptr, &type,
                                 (LPBYTE)buf, &cb) == ERROR_SUCCESS &&
                (type == REG_SZ || type == REG_EXPAND_SZ) && buf[0]) {
                std::wstring exe(buf);
                // 可能是 "\??\...\SbieSvc.exe"、"\"...\" --service"、"X.exe -k" 等形式
                if (!exe.empty() && exe[0] == L'"') {
                    size_t q = exe.find(L'"', 1);
                    exe = (q == std::wstring::npos) ? exe.substr(1) : exe.substr(1, q - 1);
                } else {
                    size_t sp = exe.find(L' ');
                    if (sp != std::wstring::npos) exe = exe.substr(0, sp);
                }
                // 剥掉内核对象路径前缀 "\??\"
                if (exe.compare(0, 4, L"\\??\\") == 0) exe = exe.substr(4);
                size_t sl = exe.find_last_of(L"\\/");
                if (sl != std::wstring::npos) {
                    std::wstring d = exe.substr(0, sl);
                    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
                    if (!d.empty()) cands.push_back(d + L"\\Start.exe");
                }
            }
            RegCloseKey(hk);
        }
    }
    // ② 服务 exe 同目录（安装器把沙箱装在这里，随主防卸载）
    {
        wchar_t self[MAX_PATH] = { 0 };
        DWORD n = GetModuleFileNameW(nullptr, self, MAX_PATH);
        if (n > 0) {
            std::wstring p(self, n);
            size_t sl = p.find_last_of(L"\\/");
            std::wstring dir = (sl == std::wstring::npos) ? p : p.substr(0, sl);
            cands.push_back(dir + L"\\Sandboxie-Plus\\Start.exe");
        }
    }
    // ③ 注册表（Sandboxie-Plus 的 InstallDir）—— 实测常不存在，仅兜底
    {
        static const wchar_t* kKeys[] = {
            L"SOFTWARE\\Sandboxie-Plus", L"SOFTWARE\\Sandboxie"
        };
        for (auto* k : kKeys) {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, k, 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
                wchar_t buf[1024] = { 0 };
                DWORD cb = sizeof(buf), type = 0;
                if (RegQueryValueExW(hk, L"InstallDir", nullptr, &type, (LPBYTE)buf, &cb) == ERROR_SUCCESS &&
                    type == REG_SZ && buf[0]) {
                    std::wstring d(buf);
                    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
                    cands.push_back(d + L"\\Start.exe");
                }
                RegCloseKey(hk);
            }
        }
    }
    // ④ 常见位置（含本项目测试位，便于在未装沙箱的机器上验证采集/评分链）
    cands.push_back(L"C:\\Program Files\\Sandboxie-Plus\\Start.exe");
    cands.push_back(L"C:\\Program Files\\SandboxIsolation\\Sandboxie-Plus\\Start.exe");
    cands.push_back(L"D:\\SandboxieTest\\Sandboxie-Plus\\Start.exe");

    for (auto& w : cands) {
        tried += W2U(w) + " | ";
        if (FileExistsW(w)) { c.startExe = W2U(w); c.ready = true; break; }
    }

    // ---- 沙箱根目录：C:\Sandbox\<user>（每轮的 box 目录 = 此目录 + \<box 名>）----
    // ★ 2026-09-28 修正：服务以 SYSTEM 身份运行，USERNAME 环境变量不可靠
    //   （为空或 "SYSTEM"），若直接用它拼接会指向 C:\Sandbox\SYSTEM
    //   （实测仅含 DONT-USE.TXT、无任何 box）→ RegHive 永远找不到 →
    //   系统性误报"送检未在沙箱中生效"。改为枚举 C:\Sandbox\* 找真实用户目录：
    //   优先含 box 子目录的，兜底任意非空（非 SYSTEM 占位）目录。
    {
        // ★★★ 2026-09-30 根因级修正：沙箱 box 由**交互用户会话**创建（见文件上方
        //   "会话感知启动"注释），故根目录必须是**交互用户**的 C:\Sandbox\<账号>。
        //   旧实现枚举 C:\Sandbox\* 并优先"含 box 子目录"者 —— 服务以 SYSTEM 跑时，
        //   若 C:\Sandbox\SYSTEM 下残留过一个错位 box，就会被选中 → boxRoot 指到
        //   服务账号的空壳目录 → 快照 / beacon 全读空、永远误判"送检未生效"。
        //   改为：先取交互用户账号，直接用它；取不到（无人登录等）再退回旧枚举。
        HANDLE hUserTok = GetActiveUserToken(nullptr);
        std::wstring acct = AccountNameFromToken(hUserTok);
        const bool tokOk = (hUserTok != nullptr);
        if (hUserTok) CloseHandle(hUserTok);
        if (!acct.empty() && _wcsicmp(acct.c_str(), L"SYSTEM") != 0) {
            c.sandboxUserRoot = W2U(L"C:\\Sandbox\\" + acct);
        }
        // ★ 2026-10-01：把探测路径打出来。本次事故就是"静默回退"造成的 ——
        //   AccountNameFromToken 恒返回 SYSTEM → 交互用户那条路被跳过 →
        //   悄悄退到枚举 → 选中空壳 C:\Sandbox\SYSTEM，全链无一条日志可查。
        //   有这行之后，"账号=SYSTEM" 一眼可见（那是 bug 的特征信号，正常应是用户名）。
        LogDbg("[sandbox] box根探测①：交互令牌=" + std::string(tokOk ? "取到" : "未取到") +
               " 账号=\"" + W2U(acct) + "\" → 初选根=\"" + c.sandboxUserRoot + "\"");

        std::wstring chosen;    // 优先：含真实 box 子目录的用户目录
        std::wstring fallback;  // 兜底：任意非 SYSTEM 占位的真实用户目录（可能暂时为空）
        WIN32_FIND_DATAW fd{};
        HANDLE h = FindFirstFileW(L"C:\\Sandbox\\*", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                std::wstring name = fd.cFileName;
                if (name == L"." || name == L"..") continue;
                std::wstring dir = L"C:\\Sandbox\\" + name;

                // ★ SYSTEM 占位目录（典型仅含 DONT-USE.TXT）直接跳过：
                //   它不是真实用户沙箱根，box 绝不会建在这里，留着只会误导。
                if (name == L"SYSTEM") {
                    bool onlyDontUse = true;
                    WIN32_FIND_DATAW g{};
                    HANDLE sh = FindFirstFileW((dir + L"\\*").c_str(), &g);
                    if (sh != INVALID_HANDLE_VALUE) {
                        do {
                            // ★ 2026-10-01 修正：原写 `g.cFileName == L"."` 是
                            //   **数组地址 vs 字面量地址**的比较（wchar_t[260] 退化成
                            //   指针），**恒为 false** → "." 与 ".." 从未被跳过 →
                            //   ① 下面"纯占位 SYSTEM 目录"判断被 "." 里的
                            //      std::wstring(".") != "DONT-USE.TXT" 直接判 false
                            //      → SYSTEM 不再被跳过；② hasSub 统计里 "." / ".."
                            //      都是目录 → **每个**目录都被算成"含子目录" →
                            //      遍历遇到的**第一个**目录直接 chosen 并 break。
                            //   两者叠加 = 选中字母序最靠前的 C:\Sandbox\SYSTEM。
                            //   必须用 wcscmp 做真正的内容比较。
                            if (wcscmp(g.cFileName, L".") == 0 || wcscmp(g.cFileName, L"..") == 0) continue;
                            // ★ 2026-10-01：Sandboxie 还会放 desktop.ini，它同样不是
                            //   "真实内容"。原判据只放行 DONT-USE.TXT → 实测
                            //   C:\Sandbox\SYSTEM 里躺着一个 desktop.ini，于是
                            //   onlyDontUse 恒为 false，"跳过纯占位目录"整段成了**死代码**。
                            //   把 desktop.ini 一并视作占位（仍不放过任何真实文件/box）。
                            {
                                std::wstring gn = g.cFileName;
                                if (gn == L"DONT-USE.TXT" || gn == L"desktop.ini") continue;
                            }
                            onlyDontUse = false; break;
                        } while (FindNextFileW(sh, &g));
                        FindClose(sh);
                    }
                    if (onlyDontUse) continue;   // 纯占位 → 跳过
                }

                // 统计是否有 box 子目录（当前/最近进行中的送检）
                bool hasSub = false;
                WIN32_FIND_DATAW g{};
                HANDLE sh = FindFirstFileW((dir + L"\\*").c_str(), &g);
                if (sh != INVALID_HANDLE_VALUE) {
                    do {
                        // 同上：必须 wcscmp，否则 "." / ".." 被当成真实子目录 → 恒 hasSub
                        if (wcscmp(g.cFileName, L".") == 0 || wcscmp(g.cFileName, L"..") == 0) continue;
                        if (g.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { hasSub = true; break; }
                    } while (FindNextFileW(sh, &g));
                    FindClose(sh);
                }
                // ★ 关键修正（2026-09-28 二次）：**不再因目录为空而跳过**。
                //   沙箱 box 是送检时动态创建、完即销毁；box 销毁后用户目录会暂时
                //   变空——若在此跳过，会回退到 USERNAME=SYSTEM → 找
                //   C:\Sandbox\SYSTEM 下的 RegHive（那里只有 DONT-USE.TXT）→ 永远
                //   找不到 → 系统性误报"送检未在沙箱中生效"。所以空目录也保留为
                //   兜底候选（真实用户目录即使暂时为空也应被选中）。
                if (hasSub && chosen.empty()) { chosen = dir; break; }   // 含 box 优先
                if (fallback.empty()) fallback = dir;                     // 任意真实目录兜底（含空）
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        if (c.sandboxUserRoot.empty() && !chosen.empty()) {
            c.sandboxUserRoot = W2U(chosen);
        } else if (c.sandboxUserRoot.empty() && !fallback.empty()) {
            c.sandboxUserRoot = W2U(fallback);
        } else if (c.sandboxUserRoot.empty()) {
            // 兜底：仍尝试 USERNAME（兼容非 SYSTEM 场景 / 纯净 dryrun 调试）
            wchar_t user[256] = { 0 };
            DWORD un = GetEnvironmentVariableW(L"USERNAME", user, 256);
            std::wstring u = (un > 0 && un < 256) ? std::wstring(user, un) : L"";
            if (!u.empty()) c.sandboxUserRoot = W2U(L"C:\\Sandbox\\" + u);
        }
        LogDbg("[sandbox] box根探测②：枚举候选 chosen=\"" + W2U(chosen) +
               "\" fallback=\"" + W2U(fallback) + "\" → 最终根=\"" + c.sandboxUserRoot + "\"");
        c.root            = c.sandboxUserRoot + "\\" + c.box;   // 探测展示用
        c.driveRoot       = c.root + "\\drive";
    }

    // ---- SbieIni.exe ----
    // ★ 2026-09-27 修正：**从已选定的 Start.exe 同目录取**。这是唯一不会错的
    //   方式 —— SbieIni 与 Start 永远同目录发布。原实现只查
    //   "C:\Program Files\Sandboxie-Plus\" 与 "C:\Windows\" 两个硬编码位置，
    //   本机实测两处**都不存在**（真实位置是注册表指向的 D:\SandboxieTest\…），
    //   于是 sbieIni 恒为空串 → 界面上显示成"缺组件"的**永久假故障**，
    //   而且因为它只是"展示字段"，没人会去查 —— 正是本项目最典型的一类坑。
    if (c.ready && !c.startExe.empty()) {
        std::wstring s = U2W(c.startExe);
        size_t sl = s.find_last_of(L"\\/");
        if (sl != std::wstring::npos) {
            std::wstring ini = s.substr(0, sl) + L"\\SbieIni.exe";
            if (FileExistsW(ini)) c.sbieIni = W2U(ini);
        }
    }
    if (c.sbieIni.empty()) {   // 兜底（理论上不会走到）
        std::wstring inis[] = {
            L"C:\\Program Files\\Sandboxie-Plus\\SbieIni.exe",
            L"C:\\Windows\\SbieIni.exe"
        };
        for (auto& w : inis) if (FileExistsW(w)) { c.sbieIni = W2U(w); break; }
    }

    c.note = c.ready ? ("已找到沙箱入口：" + c.startExe)
                     : ("未找到沙箱入口（Start.exe）。查找过：" + tried);
    if (c.sandboxUserRoot.empty()) c.note += "；未能确定沙箱根目录（C:\\Sandbox 下无可用用户目录，请确认 Sandboxie 已创建过 box）";
    if (!c.sbieIni.empty()) c.note += "；SbieIni=" + c.sbieIni;
    c.note += "；策略=每轮新建一次性 box 并在结束后销毁";

    // ★ 阶段二：探测随包部署的探针 DLL（注入沙箱内样本进程做时间加速 + 行为自报）
    //   放在服务 EXE 同目录（build.sh 会把它拷到 dist\）。缺失则阶段二禁用，
    //   不影响阶段一（快照 diff）继续工作 —— 这是**降级**不是**失败**。
    {
        std::string dir = DirName(GetExePath());
        std::string p64 = dir + "\\probe64.dll";
        std::string p32 = dir + "\\probe32.dll";
        if (FileExistsW(U2W(p64))) c.probeDll64 = p64;
        if (FileExistsW(U2W(p32))) c.probeDll32 = p32;
        c.probeBeaconRoot = "C:\\SilverFoxProbe";
        if (!c.probeDll64.empty())
            c.note += std::string("；探针DLL=有(") + (c.probeDll32.empty() ? "仅x64" : "x64+x86") + ")";
        else
            c.note += "；探针DLL=无(阶段二禁用，仅快照diff)";
    }

    // ★ 让沙箱"闭嘴"（2026-09-27）：关掉 SbieSvc 的 GUI 代理自动启动与全部通知。
    //   不这么做的话，每轮送检都会把 SandMan.exe 拉起来 → 用户托盘冒图标 + 弹窗，
    //   "沉浸感"无从谈起。详细实测依据见 QuietDown 的注释。
    //   放在这里（探测阶段）而不是每次送检：它是一次性的全局配置写入，
    //   QuietDown 内部有 static 守卫，不会重复写。
    if (c.ready && !c.sbieIni.empty()) QuietDown(c);

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_cfg = c; g_detected = true;
        out = c;
    }
    LogDbg("[sandbox] 环境探测：" + c.note);
    return c.ready;
}

// ---------------------------------------------------------------------------
//  唯一 box 名
// ---------------------------------------------------------------------------
// 约束：
//   · 只用 [A-Za-z0-9_]，避免路径注入（这个名字会成为目录名，且会被拼进
//     命令行 → 任何分隔符/引号都是危险面）
//   · 尽量短：box 目录下还有 user\current\AppData\Local\Temp\... 这种深路径，
//     名字越长越容易顶到 MAX_PATH（Sandboxie 内部会处理长路径，但没必要冒险）
//   · 唯一性 = 时间戳 ^ 进程内序号 ^ PID ^ 随机扰动，跨进程/跨重启都不撞
static std::string MakeBoxName() {
    const unsigned seq = g_boxSeq.fetch_add(1);
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    const unsigned long long t =
        ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    unsigned long long mix = (t / 10000000ULL)              // 秒级（hive 不关心毫秒）
                           ^ (GetTickCount64() & 0xFFFFFULL)
                           ^ ((unsigned long long)GetCurrentProcessId() << 9)
                           ^ ((unsigned long long)seq * 7919ULL);
    mix %= 2176782336ULL;                                    // 36^6
    return "SFx" + ToBase36(mix, 6) + ToBase36((unsigned long long)seq, 2);
}

// box 是否合法（自检用：名字由我们生成，但删除/清理前仍要过一遍）
static bool BoxNameSafe(const std::string& b) {
    if (b.size() < 3 || b.size() > 32) return false;
    for (char ch : b) {
        const bool ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '_';
        if (!ok) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  新建并配置一次性 box
// ---------------------------------------------------------------------------
// ★ 为什么"新建"之后还要写这几项（而不是直接 set Enabled=y 就跑）：
//   实测 Sandboxie 会对新 box 段做**自动规范化**（补上一整套 Template= /
//   ConfigLevel= / RecoverFolder=）。也就是说"新 box 的配置"并不等于
//   "我们写的配置"，必须显式校正以下几项，且**回读验证**。
//
//   ① Enabled=y            —— 启用（不启用则 /box: 直接失败）
//   ② DropAdminRights=y    —— 箱内降权：HKLM / 服务 / 驱动类操作会被拒，
//                             这是送检**恶意样本**的基本安全底线
//   ③ BlockDrivers=y       —— 阻止箱内加载内核驱动（挡 rootkit 型样本）
//
//   ★★ 安全关键（必须清，且必须回读确认）：
//   ④ RecoverFolder        —— **沙箱的"恢复"功能会把箱内文件写回真实系统！**
//                             规范化的 box 段默认带
//                               RecoverFolder=%Desktop% / %Personal% / ...
//                             对送检恶意样本来说这是**重大风险面**：任何一次
//                             误触发的恢复都会把样本放到用户真实桌面/文档。
//                             本模块从不调用恢复，但配置层面必须堵死。
//                             注意 `set <box> RecoverFolder ""` 的语义是
//                             "移除该 setting 的**所有行**"（官方文档），
//                             正好一次清干净。
//   ⑤ OpenFilePath / OpenKeyPath —— 这些是"直通真实系统"的路径（写入直接
//                             落到沙箱外）。若被规范化或外部工具加上，样本
//                             的落地物就会**绕过虚拟化**直接影响真机。
//   ⑥ ClosedIpcPath        —— 防御性清理。它是历史事故元凶：会让沙箱内任何
//                             进程都起不来（"在沙箱里创建进程"这条链路本身
//                             要走命名管道），且失败是静默的（rc=1、无输出、
//                             不建目录）。新 box 本不该有，但清一次成本极低。
static bool CreateBox(const Config& cfg, const std::string& box, std::string* outMsg) {
    if (!BoxNameSafe(box)) {
        if (outMsg) *outMsg = "★box 名不合法：" + box;
        return false;
    }
    if (cfg.sbieIni.empty()) {
        if (outMsg) *outMsg = "未找到 SbieIni.exe → 无法创建沙箱箱体";
        return false;
    }

    // 防御：同名残留（上次销毁失败）先清掉，避免"用着一个被污染的同名 box"
    if (BoxExistsInIni(box, nullptr)) {
        LogDbg("[sandbox] 发现同名残留 box，先销毁：" + box);
        // ★ 会话感知：以交互用户身份删（box 归属该用户，服务身份会找错目录）
        RunStartToolW(L"\"" + U2W(cfg.startExe) + L"\" /box:" + U2W(box) + L" delete_sandbox_silent", 120000);
        RunTool(cfg.sbieIni, "set " + box + " * \"\"", 20000);
    }

    // ① 必要设置（`set` 在段不存在时会自动创建整段）
    struct KV { const char* k; const char* v; };
    static const KV kWant[] = {
        { "Enabled",         "y" },
        // ★ 箱内降权：HKLM / 服务 / 驱动类操作会被拒（送检恶意样本的安全底线）。
        //   注意实测它在 SFBoxC 上"看起来没生效"（样本报 HKLM write = OK），
        //   但宿主注册表检查证明**全部未穿透**（HKLM\Software\SFPopTest、
        //   HKCU\Run、Services 键、C:\ 根文件都不存在）——
        //   即"OK"是虚拟化重定向后的成功，不是真写到了系统里。
        { "DropAdminRights", "y" },
        // ★ BlockDrivers 在官方设置清单（SbieSettings.ini）里已标注 [REMOVED]，
        //   说明该项在现代版本已被移除/合并。保留写入是"无害的冗余"
        //  （旧版本仍认它），但**不能指望它**，真正的驱动防护靠 SbieDrv 自身。
        { "BlockDrivers",    "y" },
        // ★★ 安全加固（2026-09-27 实测新增）：箱内程序
        //   CreateFileW(L"\\\\.\\PhysicalDrive0") 竟然**拿到了句柄**。
        //   官方对 AllowRawDiskRead 的说明明确写着 "(security risk)"。
        //   送检恶意样本必须关死，否则样本可读宿主裸盘数据、
        //   甚至绕过文件系统层的虚拟化。
        { "AllowRawDiskRead", "n" },
    };
    int okWant = 0, failWant = 0;
    for (auto& kv : kWant) {
        const DWORD ec = RunTool(cfg.sbieIni,
                                 std::string("set ") + box + " " + kv.k + " " + kv.v, 15000);
        if (ec == 0) okWant++; else failWant++;
    }

    // ② 安全清理（空值 = 删除该 setting 的所有行）
    static const char* kWipe[] = {
        "RecoverFolder", "OpenFilePath", "OpenKeyPath", "ClosedIpcPath",
    };
    int okWipe = 0, failWipe = 0;
    for (auto* k : kWipe) {
        const DWORD ec = RunTool(cfg.sbieIni,
                                 std::string("set ") + box + " " + k + " \"\"", 15000);
        if (ec == 0) okWipe++; else failWipe++;
    }

    // ②-b 阶段二：注入自编写探针 DLL（时间加速 + 行为自报）
    //   ★ 2026-09-30 修复：beacon 目录 C:\SilverFoxProbe 设为 box **OpenFilePath 直通真机**。
    //     原因：FlushBeacon 的 CreateFileW 在 box 内触发 Sandboxie 文件虚拟化死锁
    //     （HookThread 写 beacon 时 SbieSvc 忙、主线程随后 I/O 也卡同一把锁 → 进程死锁
    //     150s；实测 box 内零 I/O 痕迹、beacon 总数=0，样本"超时未退出强制结束"）。
    //     直通则 FlushBeacon 不碰虚拟化，不死锁。只这一个目录直通，样本落地点不会在此
    //     （beacon 经 silverfoxprobe 剔除不会被误判为样本落地物），安全。
    if (!cfg.probeDll64.empty()) {
        RunTool(cfg.sbieIni, "set " + box + " InjectDll64 \"" + cfg.probeDll64 + "\"", 15000);
        LogDbg("[sandbox] 注入探针(x64)：" + cfg.probeDll64);
    }
    if (!cfg.probeDll32.empty()) {
        RunTool(cfg.sbieIni, "set " + box + " InjectDll \"" + cfg.probeDll32 + "\"", 15000);
        LogDbg("[sandbox] 注入探针(x86)：" + cfg.probeDll32);
    }
    // ★ 2026-09-30：beacon 目录直通真机（见上方注释）。只这一个目录，不影响样本落地点虚拟化。
    RunTool(cfg.sbieIni, "set " + box + " OpenFilePath \"" + cfg.probeBeaconRoot + "\"", 15000);

    // ③ 回读验证：只看 ini 里的事实
    std::string secText;
    const bool created = BoxExistsInIni(box, nullptr);
    const bool haveSec = BoxSectionText(box, nullptr, &secText);
    const std::string low = LowerAscii(secText);
    const bool recoverLeft = low.find("recoverfolder") != std::string::npos;
    // ★ 2026-09-30 修正：本版**主动**把 beacon 目录设为 OpenFilePath 直通真机，
    //   故旧逻辑"ini 里出现 openfilepath 即判危险"会误杀本次修复。改为逐行解析：
    //   只允许值等于 probeBeaconRoot 的那一条直通；任何指向**其它**路径的直通
    //   （会放行样本落地点到真机）才是真正危险、必须中止。
    bool dangerousPassthrough = false;
    {
        std::istringstream iss(secText);
        std::string ln;
        std::string want = LowerAscii(cfg.probeBeaconRoot);
        while (!want.empty() && want.back() == '\\') want.pop_back();  // 尾斜杠免疫
        while (std::getline(iss, ln)) {
            std::string l = LowerAscii(ln);
            size_t eq = std::string::npos;
            if ((eq = l.find("openfilepath=")) != std::string::npos ||
                (eq = l.find("openkeypath="))   != std::string::npos) {
                size_t eqpos = l.find('=', eq);
                if (eqpos == std::string::npos) continue;
                std::string v = l.substr(eqpos + 1);
                size_t a = v.find_first_not_of(" \t\r\n\"");
                size_t b = v.find_last_not_of(" \t\r\n\"");
                if (a == std::string::npos) v.clear(); else v = v.substr(a, b - a + 1);
                while (!v.empty() && v.back() == '\\') v.pop_back();  // 尾斜杠免疫
                if (!v.empty() && v != want) dangerousPassthrough = true;
            }
        }
    }
    const bool ipcLeft = low.find("closedipcpath") != std::string::npos;
    const bool enabledOk = low.find("enabled=y") != std::string::npos;

    if (outMsg) {
        std::ostringstream os;
        os << "建箱 " << box << "（必要项 " << okWant << "成/" << failWant << "败"
           << "，安全清理 " << okWipe << "成/" << failWipe << "败"
           << "，段 " << (secText.size()) << "B"
           << "）→ 回读：" << (created ? "段已存在" : "★段不存在")
           << "，" << (enabledOk ? "Enabled=y" : "★未见 Enabled=y")
           << "，RecoverFolder " << (recoverLeft ? "★仍在" : "已清")
           << "，直通 " << (dangerousPassthrough ? "★存在危险直通(非beacon)" : "仅beacon(安全)")
           << "，ClosedIpcPath " << (ipcLeft ? "★仍在" : "已清");
        *outMsg = os.str();
    }
    LogDbg("[sandbox] " + (outMsg ? *outMsg : std::string("建箱结果未知")));

    if (!created || !enabledOk) return false;
    if (recoverLeft) {
        if (outMsg) *outMsg += " —— ★RecoverFolder 未清干净，中止送检";
        return false;
    }
    if (dangerousPassthrough) {
        // 硬失败：带着指向"非 beacon"的直通/开放路径送检恶意样本 =
        // 可能把样本落地点放回真机，宁可这次不做动态分析，也绝不冒这个险。
        if (outMsg) *outMsg += " —— ★存在非 beacon 直通路径(可能放行样本到真机)，已中止";
        return false;
    }
    if (ipcLeft) {
        if (outMsg) *outMsg += " —— ★ClosedIpcPath 未能清除，送检必然静默失败，已中止";
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
//  销毁一次性 box（删目录 + 删 ini 段）
// ---------------------------------------------------------------------------
// ★★ 这是"一次性沙箱"的收尾动作，也是本架构的核心价值所在：
//     每轮结束都把 box 彻底抹掉 → 下一轮从零开始。
//
// 三步，每步都以**回读事实**为判据（不信返回码）：
//   ① Start.exe /box:<box> /terminate   —— 终止箱内进程
//       目的：释放文件句柄，否则目录删不干净；也让注册表 hive 卸载
//       （离线解析 hive 需要它已卸载，见 HiveKeyList）
//   ② Start.exe /box:<box> delete_sandbox_silent —— 删除整个沙箱目录
//       为什么用官方命令而不是自己递归删：
//         · 实测直接 rmtree 会 WinError 5（目录/文件被 SbieSvc 持有）
//         · 官方实现会先摘掉 reparse point（**只摘链，不跟进**）——自己写
//           递归删一旦跟进 junction，就会删到被链接的真实目录，那是灾难
//         · 官方还会处理只读属性与超长路径
//   ③ SbieIni.exe set <box> * "" —— 移除该 ini 段所有行（官方文档的删箱语法）
//       注意 `delete <box>` 不是删段：实测返回 1，且会把段"规范化"，越搞越乱
//
// 任一环节失败 → 记入待回收清单（GcAdd），下一轮开始时重试（见 GcSweep）。
// 失败**不能静默**：残留的 box 会一直躺在 ini 和磁盘上。
static bool DestroyBox(const Config& cfg, const std::string& box, std::string* outMsg) {
    if (!BoxNameSafe(box)) {
        if (outMsg) *outMsg = "★box 名不合法，拒绝销毁：" + box;
        return false;
    }
    const std::string boxRoot = cfg.sandboxUserRoot + "\\" + box;

    // ① 终止箱内进程
    // ★ 会话感知（2026-09-30）：终止 / 删除都必须以**交互用户身份**发起 ——
    //   box 是按用户隔离的，"以 SYSTEM 去操作 tianl 的 box" 会找错目录、静默失败。
    if (!cfg.startExe.empty()) {
        RunStartToolW(L"\"" + U2W(cfg.startExe) + L"\" /box:" + U2W(box) + L" /terminate", 30000);
    }

    // ② 删目录（官方通道）
    bool dirGone = true;
    if (!cfg.startExe.empty()) {
        RunStartToolW(L"\"" + U2W(cfg.startExe) + L"\" /box:" + U2W(box) + L" delete_sandbox_silent", 120000);
        // 回读：给它一点时间落定
        for (int i = 0; i < 12; ++i) {
            if (!PathExistsW(U2W(boxRoot))) break;
            Sleep(500);
        }
        dirGone = !PathExistsW(U2W(boxRoot));
    } else {
        dirGone = !PathExistsW(U2W(boxRoot));
    }

    // ③ 删 ini 段
    bool segGone = true;
    if (!cfg.sbieIni.empty()) {
        RunTool(cfg.sbieIni, "set " + box + " * \"\"", 20000);
        segGone = !BoxExistsInIni(box, nullptr);
    }

    const bool allOk = dirGone && segGone;
    if (outMsg) {
        std::ostringstream os;
        os << "销毁 " << box << "：目录" << (dirGone ? "已删" : "★残留")
           << "、ini 段" << (segGone ? "已删" : "★残留");
        *outMsg = os.str();
    }
    LogDbg("[sandbox] " + (outMsg ? *outMsg : std::string()));

    if (!allOk) {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_boxLeft++;
    }
    return allOk;
}

// ---------------------------------------------------------------------------
//  阶段二：探针 beacon 读取 + 子进程环境构造
// ---------------------------------------------------------------------------
//  beacon 由探针 DLL 写在 C:\SilverFoxProbe\，被 Sandboxie 虚拟化进 box 目录
//  （典型路径 boxRoot\drive\C\SilverFoxProbe\pid.txt）。递归找出全部并解析。
static void FindFilesRecursive(const std::wstring& dir, const std::wstring& suffix,
                               std::vector<std::wstring>& out) {
    WIN32_FIND_DATAW fd{};
    std::wstring pat = dir + L"\\*";
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            FindFilesRecursive(dir + L"\\" + fd.cFileName, suffix, out);
        } else {
            std::wstring name = fd.cFileName;
            if (name.size() >= suffix.size() &&
                name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)
                out.push_back(dir + L"\\" + name);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// 前向声明：ClassifyHiveKey 定义在文件下方（1348 行），ReadProbeBeacons 需要用到。
// 注：ExtLower 已由上方 #include "sfutils.h" 提供声明，无需重复前向声明（重复 static 会与头文件外部链接声明冲突）。
static int ClassifyHiveKey(const std::string& low);

// ---------------------------------------------------------------------------
//  ★★ 每轮送检前清空 beacon 目录（2026-10-01 新增，P0）
// ---------------------------------------------------------------------------
//  事故：`C:\SilverFoxProbe\` 里躺着 7 个 10:25~12:35 的旧文件，19:29 那轮
//        仍然报「命中beacon=3」→ 拿**8 小时前**的文件判定"探针跑过了" →
//        闸门放行 → 结论 clean（而实际上样本连 box 都没进：drive=无）。
//  残留来源三条（都要靠"每轮清空"兜住，不能靠"读后删除"）：
//    ① 送检异常退出（超时 / 服务重启 / 崩溃）时 ReadProbeBeacons 根本没走到；
//    ② 非目标进程（box 里的 Start.exe、沙箱辅助进程）写的，_is_target=0_ 但也落盘；
//    ③ 早期 OpenFilePath 尚未生效时写进真机目录的历史遗留。
//  ★ 纪律：beacon 是"本轮"证据，**必须每轮从零开始**。只要允许跨轮残留，
//    归属就永远不可信 —— 这正是本轮"假 clean"能持续存在的物理基础。
static int ClearStaleBeacons(const Config& cfg) {
    std::vector<std::wstring> all;
    FindFilesRecursive(U2W(cfg.probeBeaconRoot), L".txt", all);
    int n = 0;
    for (auto& f : all) {
        if (DeleteFileW(f.c_str())) n++;
    }
    return n;
}

// ---------------------------------------------------------------------------
//  ★★ 2026-10-01：是否属于「用户数据区」
// ---------------------------------------------------------------------------
//  为什么需要单独一个判据：探针新补的 W(覆写)/D(删除) 和已有的 M(改名) 事件，
//  只有落在**用户数据区**时才是勒索特征。样本在自己的 Temp/AppData 里写多少文件
//  都不算 —— 那正是一个老实安装器也会做的事，也正是旧实现区分不出二者的原因。
//  ⚠️ 口径必须与探针端 WantRecordFile 的数据区补充一致（文档/图片/视频/音乐/OneDrive）。
//     Windows 中文版磁盘上的目录名仍是 Documents/Pictures/…（"文档"只是外壳显示名），
//     所以按 ASCII 匹配是可靠的；用户手工改过目录名的极端情况会漏，属已知边界。
static bool IsUserDataPath(const std::string& raw) {
    const std::string low = LowerAscii(raw);
    if (low.find("\\users\\") == std::string::npos) return false;
    static const char* kDataDirs[] = {
        "\\documents\\", "\\pictures\\", "\\videos\\", "\\music\\",
        "\\onedrive\\",  "\\favorites\\",
    };
    for (const char* d : kDataDirs)
        if (low.find(d) != std::string::npos) return true;
    return false;
}

static void ReadProbeBeacons(const std::string& boxRoot, Report& sub) {
    // ★ 2026-09-30 二次修正：OpenFilePath 直通**实测未生效** —— beacon 仍被 Sandboxie
    //   虚拟化进 boxRoot\drive\C\SilverFoxProbe\（实测 SFXRepl / SFTMkrInj 两轮 beacon
    //   全落在虚拟化目录，真机 C:\SilverFoxProbe 恒为空）。而本函数此前被改成只读真机
    //   → 服务读空目录、beacon 全丢（日志恒为"真机直通 txt总数=0"）。改为**两处都扫**：
    //     ① 真机 C:\SilverFoxProbe（若哪天直通生效）
    //     ② box 内虚拟化路径 boxRoot\drive（当前实际落点）
    //   下游按路径含 \silverfoxprobe\ 过滤（见下方解析循环同款判据），
    //   不会把样本自建的 txt 误当 beacon。
    const std::string beaconRoot = "C:\\SilverFoxProbe";
    std::vector<std::wstring> all;
    FindFilesRecursive(U2W(beaconRoot), L".txt", all);
    if (!boxRoot.empty()) FindFilesRecursive(U2W(boxRoot + "\\drive"), L".txt", all);
    {
        int probeCnt = 0;
        bool dirExists = false;
        WIN32_FIND_DATAW fd0{};
        HANDLE h0 = FindFirstFileW((U2W(beaconRoot) + L"\\*").c_str(), &fd0);
        dirExists = (h0 != INVALID_HANDLE_VALUE);
        if (h0 != INVALID_HANDLE_VALUE) FindClose(h0);
        for (auto& f : all) {
            std::wstring lw = f;
            for (auto& c : lw) if (c >= 'A' && c <= 'Z') c += 32;
            if (lw.find(L"\\silverfoxprobe\\") != std::wstring::npos) probeCnt++;
        }
        LogDbg("[sandbox] beacon诊断（真机+box内两处）：真机存在=" +
               std::string(dirExists ? "1" : "0") + " boxRoot=" + boxRoot +
               " 命中beacon=" + std::to_string(probeCnt) +
               " txt总数=" + std::to_string(all.size()));
    }
    // ★★ 2026-10-01：beacon **归属统计**（P0）。上一轮的事故就是"不知道这 3 个 beacon
    //   是谁写的" → 拿 8 小时前的残留文件当"探针跑过了"。现在逐个点名：
    //     目标进程 = is_target=1（送检样本本身）→ 这才是有效的执行证据
    //     非目标   = 箱子里的 Start.exe / 沙箱辅助进程写的 → 只算覆盖缺口
    int nTarget = 0, nOther = 0;
    for (auto& f : all) {
        std::wstring low = f;
        for (auto& c : low) if (c >= 'A' && c <= 'Z') c += 32;
        if (low.find(L"\\silverfoxprobe\\") == std::wstring::npos) continue;
        HANDLE h = CreateFileW(f.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        std::string content;
        content.resize(2 * 1024 * 1024);
        DWORD rd = 0;
        ReadFile(h, &content[0], (DWORD)content.size() - 1, &rd, nullptr);
        CloseHandle(h);
        content.resize(rd);
        DeleteFileW(f.c_str());  // 读后清理（beacon 已入引擎，避免真机 C:\SilverFoxProbe 积累）

        bool fileLoaded = false, fileTarget = false;
        int fc = 0, pc = 0, rc = 0, nc = 0, ev = 0, dc = 0, wc = 0;
        std::vector<std::string> det;
        std::set<std::string> dataSeen;   // ★ 用户数据区被破坏文件去重（本轮 beacon 内）
        size_t pos = 0;
        while (pos < content.size()) {
            size_t nl = content.find('\n', pos);
            std::string line = content.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
            pos = (nl == std::string::npos) ? content.size() : nl + 1;
            if (line.empty()) continue;
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;   // events 行也带 '='，走下面分支
            std::string k = line.substr(0, eq), v = line.substr(eq + 1);
            if (k == "dll_loaded")      fileLoaded = (v == "1");
            else if (k == "is_target")  fileTarget = (v == "1");
            else if (k == "file")       fc = atoi(v.c_str());
            else if (k == "process")    pc = atoi(v.c_str());
            else if (k == "reg")        rc = atoi(v.c_str());
            else if (k == "net")        nc = atoi(v.c_str());
            // ★ 2026-10-01 新增两项（探针 hook 面补齐后才有值）。
            //   探针端是"键=值"白名单式输出，旧解析器会**静默忽略**这两个键 ——
            //   这正是本次要修的一半：补了 hook 却不解析，等于又是"宣而不备"。
            else if (k == "del")        dc = atoi(v.c_str());
            else if (k == "wrote")      wc = atoi(v.c_str());
            else if (k == "events")   { det.push_back(v); ev++; }
        }
        if (fileTarget) {
            // ★★ 2026-10-01 归属修正（P0）：**只有 is_target=1 的 beacon 才能证明
            //   "送检样本真的在沙箱里跑起来了"**。探针经 box 的 InjectDll 会注入
            //   **箱内每一个进程**（含 Sandboxie 自己的 Start.exe）→ 它们的 beacon
            //   一定带 is_target=0。旧代码只凭 dll_loaded=1 就置 probeLoaded=true，
            //   于是闸门 `driveExists || probeLoaded` 恒真 → 样本根本没跑也判 clean
            //   （实测：`drive=无` 与 `样本执行=是` 同现，就是这个 bug）。
            sub.probeLoaded    = true;
            sub.probeTargetRan = true;
            nTarget++;
        } else if (fileLoaded) {
            // 注入生效、但落在非目标进程里 → 是"覆盖缺口"的证据，不是"样本跑过"的证据。
            sub.probeOtherLoaded = true;
            nOther++;
        }
        sub.probeFile  += fc; sub.probeProcess += pc;
        sub.probeReg   += rc; sub.probeNet     += nc;
        sub.probeEvents += ev;
        sub.probeDel    += dc;   // ★ 2026-10-01：勒索三要素之一（删原文件）
        sub.probeWrite  += wc;   // ★ 2026-10-01：勒索三要素之一（原地覆写=加密）
        // ⚠️ 注意：`dataSeen` 是在**下面那个 `for (auto& d : det)` 循环里**被填充的，
        //   所以合并到 sub.dataTouched 的代码必须放在该循环**之后** ——
        //   放在这里（循环之前）会永远合并空集，dataTouched 恒为 0，
        //   表现为"勒索档永远不触发"却看不出任何报错。已实测踩过。
        for (auto& d : det) {
            if ((int)sub.probeDetail.size() < 4000) {
                if (!sub.probeDetail.empty()) sub.probeDetail += "\n";
                sub.probeDetail += d;
            }
            // ★ 阶段二增强：把进程内探针在 API 层捕获的真实行为，转为评分 artifact。
            //   根因：sandboxie 的 RegHive 快照 / 文件快照对**程序化写入**（尤其已存在键
            //   新增的值、以及被 DropAdminRights 抑制的敏感键）并不可靠——实测样本写入的
            //   IFEO/Run 键与释放的 exe 全部没进 hive / 快照，导致沙箱评分长期全 0、
            //   真假样本都判 clean。进程内 hook 在 API 调用层捕获，不受 sandboxie 虚拟化
            //   影响，是更可靠的真实行为证据；且能覆盖「给已存在 Run 键新增值」这种
            //   sandboxie hive 永远漏检的经典自启动手法（银狐主用）。
            if (d.size() >= 2 && d[1] == '|') {
                const char tag = d[0];
                const std::string val = d.substr(2);
                if (tag == 'R') {
                    const std::string low = LowerAscii(val);
                    if (ClassifyHiveKey(low) == 2) {     // 持久化 / 劫持类（IFEO/Run/Services/Winlogon…）
                        Artifact ar;
                        ar.rel    = val;
                        ar.tree   = "reg";
                        ar.size   = 0;
                        ar.action = "new(probe)";
                        ar.score  = 70;
                        ar.why    = "探针(API层)捕获到注册表持久化/劫持位置写入（" + val + "）；";
                        sub.artifacts.push_back(ar);
                    }
                } else if (tag == 'F' || tag == 'M') {   // 文件创建 / 复制 / 移动落地
                    const std::string low = LowerAscii(val);
                    if (low.find("silverfoxprobe") != std::string::npos) continue;  // 排除我们自己的 beacon
                    const std::string e = ExtLower(val);
                    if (e == ".exe" || e == ".dll" || e == ".sys" || e == ".scr" ||
                        e == ".com" || e == ".cpl" || e == ".ocx") {
                        Artifact ar;
                        ar.rel    = val;
                        ar.tree   = "file";
                        ar.size   = 0;
                        ar.action = "drop(probe)";
                        ar.score  = 40;
                        ar.why    = "探针(API层)捕获到落地可执行文件（" + val + "）；";
                        sub.artifacts.push_back(ar);
                    }
                }
                // ★★★ 2026-10-01：勒索三要素 —— 覆写(W) / 删除(D) / 改名(M、F) 落在
                //   **用户数据区**时，记为"被伤害的既有数据"。
                //   刻意与上面的"落地可执行物"分开：那个问的是"丢进来了什么载荷"，
                //   这个问的是"用户已有的数据被动了多少" —— 两个完全不同的事实，
                //   旧实现只有前者，所以真勒索与老实安装器在评分上无法区分。
                if (tag == 'D' || tag == 'W' || tag == 'M' || tag == 'F') {
                    if (IsUserDataPath(val)) dataSeen.insert(val);
                }
            }
        }
        // ★ 把本轮 beacon 里"用户数据区被破坏的文件"并入报告级去重集合。
        //   位置在 det 解析循环**之后**（见上面的 ⚠️）。
        for (auto& d : dataSeen) {
            if (sub.dataTouched.size() >= 4000) break;     // 上限，防异常样本刷爆
            bool dup = false;
            for (auto& x : sub.dataTouched) if (x == d) { dup = true; break; }
            if (!dup) sub.dataTouched.push_back(d);
        }
    }
    // ★★ 归属日志：无论成功失败都打（旧代码只在 probeLoaded 时才打，导致
    //   "一个 beacon 都没有"这种情况在日志里是**完全静默**的 —— 又一例"静默失效"）。
    LogDbg("[sandbox] 探针 beacon 归属：目标进程=" + std::to_string(nTarget) +
           "（is_target=1，**唯一**可证明样本执行过的证据）／非目标进程=" + std::to_string(nOther) +
           "（Start.exe 或沙箱辅助进程，只算覆盖缺口）→ loaded=" +
           std::string(sub.probeLoaded ? "1" : "0") +
           " targetRan=" + std::string(sub.probeTargetRan ? "1" : "0") +
           " otherLoaded=" + std::string(sub.probeOtherLoaded ? "1" : "0") +
           " file=" + std::to_string(sub.probeFile) +
           " proc=" + std::to_string(sub.probeProcess) +
           " reg=" + std::to_string(sub.probeReg) +
           " net=" + std::to_string(sub.probeNet) +
           " events=" + std::to_string(sub.probeEvents) +
           // ★ 2026-10-01：勒索三要素单独展示。放在这里而不是并进 file ——
           //   覆盖率必须**一眼可读**，否则下次"探针又瞎了"仍旧要翻 events 逐条数。
           " del=" + std::to_string(sub.probeDel) +
           " wrote=" + std::to_string(sub.probeWrite) +
           " 数据区被破坏=" + std::to_string(sub.dataTouched.size()));
}

// 构造子进程环境块：用**目标用户令牌**的环境做基座（%TEMP% / %APPDATA% 指向用户而非
// systemprofile —— 否则样本看到的环境与真实用户不一致），再注入探针所需的 3 个变量
// （CREATE_UNICODE_ENVIRONMENT）。这些变量会被 Start.exe 继承给样本进程，探针 DLL 在
// DllMain 里读取。hTok 为空 → BuildUserEnv 自动退回服务自身环境。
static std::wstring BuildChildEnv(HANDLE hTok, const std::string& target, const Config& cfg) {
    std::wstring env = BuildUserEnv(hTok);
    auto add = [&](const std::wstring& name, const std::wstring& val) {
        env += name; env += L'='; env += val; env += L'\0';
    };
    add(L"SILVERFOX_PROBE_TARGET", U2W(target));
    add(L"SILVERFOX_PROBE_WARP", std::to_wstring((long long)cfg.probeWarp));
    add(L"SILVERFOX_PROBE_BEACON", U2W(cfg.probeBeaconRoot));
    env += L'\0';   // 终结双 NUL
    return env;
}

// ===========================================================================
//  ★★★ 送检期间「封锁原件」—— 2026-10-02 新增（preview4 核心功能）
// ===========================================================================
//  【要堵的窗口】
//    文件落地被静态初筛拿不准（lv==1）时会 EnqueueScan 排队送沙箱。队列上限 16、
//    自动限流 12 次/小时、单件 30~90 秒 ⇒ 最坏可连续约 24 分钟。这段窗口里文件
//    **完好地留在原路径上**，用户可以双击把它跑起来 —— 而我们正在观察它。
//    （lv>=2 走 QuarantineLanded 直接移走，本来就没有这个窗口。）
//  【机制 —— 实测确定，不是推断】
//    对原件持有 `GENERIC_READ + FILE_SHARE_DELETE` 句柄：
//      · 挡住本机执行：加载映像本质是一次「读」，而该句柄**不共享读** ⇒
//        CreateProcessW 以 ERROR_SHARING_VIOLATION(32) 失败，连复制都读不出去；
//      · 仍允许改名/删除：隔离（QuarantineLanded 走 rename）在锁定期间照样能把
//        文件搬走。反之若用「不共享」，连我们自己都搬不动 —— **自锁**。
//    四组对照（C:\temp\lockprobe，victim = where.exe 副本）：
//      共享R      → 能执行（挡不住）／改名被挡
//      共享R|D    → 能执行（挡不住）／能改名
//      共享D      → ★挡执行／能改名   ← 唯一「封锁与隔离共存」的组合
//      不共享     → 挡执行／改名也被挡（自锁）
//  【为什么必须改跑副本】
//    同一把锁也把「沙箱读原件」挡掉了 —— 挡读正是封锁的机理，两者在句柄层面
//    无法分开。故：**原件加锁，另存副本送检，结论出来后解封锁、删副本**。
//  【副本放哪】
//    `%ProgramData%\SilverFoxGuard\holds\` —— 我们自己的目录名下，且该前缀
//    已在 rollback.cpp 的 IsExcluded 内 ⇒ 副本不会触发落地捕获（无自喂循环）。
//  【边界：fail-open】
//    封锁是**句柄级**的：服务崩溃/被强杀/重启 ⇒ 句柄随进程消亡 ⇒ 锁自动解除。
//    应用层做不到 fail-closed（要真 fail-closed 得进内核）。这是本机制的固有上限。
// ===========================================================================
const unsigned long long kHoldMaxBytes = 256ULL * 1024ULL * 1024ULL;  // 超过不封锁

// ---- 随附依赖的预算（2026-10-03）----
//  【为什么需要】只送一个孤立 EXE ⇒ 样本在箱内 0xC0000135 STATUS_DLL_NOT_FOUND
//  ⇒ 进程根本没起来 ⇒ 探针 targetRan=0 ⇒ verdict=error ⇒ 白跑一轮 90 秒，
//  且 error 还会走「解锁放行」。带依赖是根治，见 MakeHold 内注释。
//  【为什么必须有预算】送检在用户双击的关键路径上，多拷几百 MB 会放大延迟；
//  超预算就停手并留痕，宁可少带也不能让「送检」变成「卡住用户」。
const unsigned long long kDepBudgetBytes    =  64ULL * 1024ULL * 1024ULL;   // 随附总量上限
const unsigned long long kDepSingleMaxBytes =  16ULL * 1024ULL * 1024ULL;   // 单个依赖上限

struct HoldRec {
    HANDLE      h = INVALID_HANDLE_VALUE;  // 原件上的封锁句柄
    std::string orig;                      // 原件路径（UTF-8）
    std::string copy;                      // 副本路径（UTF-8，实际送检对象）
    std::string dir;                       // 副本所在子目录（用完删）
};

static std::mutex           g_holdMtx;
static std::vector<HoldRec> g_holds;       // 并发极少（≤ 队列深度），线性查找足够
static std::atomic<unsigned long long> g_holdOk{0};
static std::atomic<unsigned long long> g_holdFail{0};
static std::atomic<unsigned long long> g_holdActive{0};

static std::string HoldRootU8() {
    wchar_t buf[MAX_PATH] = { 0 };
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(buf) : L"C:\\ProgramData";
    return W2U(base + L"\\SilverFoxGuard\\holds");
}

// 副本 → 原件。用于把报告/卡片里的路径还原成用户认得的那个（副本路径对用户无意义）。
static bool OrigOfCopy(const std::string& copyU8, std::string* origOut) {
    const std::string k = LowerAscii(copyU8);
    std::lock_guard<std::mutex> lk(g_holdMtx);
    for (const auto& r : g_holds) {
        if (LowerAscii(r.copy) == k) { if (origOut) *origOut = r.orig; return true; }
    }
    return false;
}

// 面向界面/报告的路径：副本显示为原件，其余原样。
static std::string DisplayPath(const std::string& p) {
    std::string o;
    return OrigOfCopy(p, &o) ? o : p;
}

// 该文件是不是「本次运行期间新落地」的。
// 用于封锁资格的判据 —— 理由见 HoldEligible 里那段说明。
// 取不到信息时一律返回 true（= 按新落地处理，保留封锁能力；宁可靠判定修不再误锁，
// 也不在这里用"读不到就放过"悄悄削掉能力）。
static bool IsFreshDrop(const std::string& origU8) {
    FILETIME procCreate{}, e1{}, e2{}, e3{};
    if (!GetProcessTimes(GetCurrentProcess(), &procCreate, &e1, &e2, &e3)) return true;
    HANDLE h = CreateFileW(U2W(origU8).c_str(), FILE_READ_ATTRIBUTES,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return true;
    BY_HANDLE_FILE_INFORMATION bi{};
    const BOOL ok = GetFileInformationByHandle(h, &bi);
    CloseHandle(h);
    if (!ok) return true;
    // 创建时间晚于本进程启动 ⇒ 是本次运行期间落下来的
    return CompareFileTime(&bi.ftCreationTime, &procCreate) > 0;
}

// 该不该封锁。返回 false 表示「本次不封锁」，并把原因写进 why（供日志）。
static bool HoldEligible(const std::string& origU8, std::string* why) {
    const std::string low = LowerAscii(origU8);
    static const char* kDeny[] = {
        "\\programdata\\silverfoxguard\\",   // 自身数据目录（含本模块的 holds\）
        "\\silverfoxsandbox\\",              // 沙箱临时解压目录（自家产物）
        "\\temp\\sf_stash\\",                // 部署脚本暂存区
        "\\temp\\samples\\",                 // 测试样本仓库
    };
    for (const char* d : kDeny)
        if (low.find(d) != std::string::npos) { if (why) *why = "路径属我方产物"; return false; }

    // ★★ 2026-10-02 修正：封锁资格的唯一判据是「**是不是刚落地**」，不是「在哪个目录」。
    //
    //   封锁的**唯一价值**是：在本机阻止一个「刚写下来、还没机会执行」的载荷被执行 ——
    //   给我们争取到沙箱出结论前的那 60~90 秒。它从来不是"因为可疑所以锁"：
    //   · 对一个已经存在很久的文件，锁与不锁都不改变"它早就执行过"这个事实，价值≈0；
    //   · 而一旦我们的判定出错（2026-10-02 就出错了：JSON 转义未还原的路径带双反斜杠，
    //     击穿了 scanner.cpp 里 %SystemRoot% 前缀比较 → 8 个微软正版组件被判"无可信签名"），
    //     把一个早就存在的系统组件锁 90 秒是**纯损失**，且是系统级的。
    //
    //   ⚠️ 曾经写成"永不封锁 Windows / Program Files 下的原件"——**这是错的，已推翻**：
    //     那是按目录放行，等于给对手一个可主动利用的门（"把载荷丢进 Program Files 的可写子目录
    //     就没人锁我"）。而旁加载 / 替换系统组件这种攻击，恰恰就发生在这些目录里，
    //     也正是最该锁的。判据必须落在文件自身的属性上，不能落在它待的目录上。
    //
    //   为什么用**文件创建时间**而不是 rollback 的"落地初筛"结论：本次事故里 rollback 恰恰把
    //   这些多年老文件全报成了"落地初筛命中（1级）"（基线重建期的误报），拿它的结论当判据
    //   等于循环论证。文件自身的创建时间是独立证据。
    //
    //   能力上是**净增**不是净减：新落地文件在**任何**目录（含 System32 / Program Files）都照锁；
    //   只是不再去锁那些"锁了也没有意义"的老文件。判定与处置能力一分不减 ——
    //   本函数返回 false 时 EnqueueScan 会退化成"直接送检原件"（与锁失败 err=32 同一条路径），
    //   沙箱照跑、恶意结论照隔离，日志会明确写出原因。
    if (!IsFreshDrop(origU8)) {
        if (why) *why = "非新落地（创建时间早于本服务启动）—— 封锁对此文件没有意义，仍照常送检";
        return false;
    }

    const DWORD a = GetFileAttributesA(origU8.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) { if (why) *why = "文件已不存在或不可访问"; return false; }
    if (a & FILE_ATTRIBUTE_DIRECTORY) { if (why) *why = "目标是目录"; return false; }

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (GetFileAttributesExA(origU8.c_str(), GetFileExInfoStandard, &fad)) {
        const unsigned long long sz =
            ((unsigned long long)fad.nFileSizeHigh << 32) | (unsigned long long)fad.nFileSizeLow;
        if (sz > kHoldMaxBytes) {
            if (why) *why = "体积 " + std::to_string(sz / (1024ULL * 1024ULL)) + "MB 超过封锁上限";
            return false;
        }
    }
    return true;
}

// 复制副本 + 封锁原件。成功时 *submitOut = 副本路径（实际送检对象）。
static bool MakeHold(const std::string& origU8, std::string* submitOut, std::string* why) {
    if (why) why->clear();
    if (!HoldEligible(origU8, why)) return false;

    const std::wstring rootW = U2W(HoldRootU8());
    if (!CreateDirectoryW(rootW.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS) {
        if (why) *why = "无法创建封锁根目录 err=" + std::to_string(GetLastError());
        return false;
    }
    const std::wstring dirW = rootW + L"\\h" + U2W(MakeBoxName());
    if (!CreateDirectoryW(dirW.c_str(), nullptr)) {
        if (why) *why = "无法创建封锁子目录 err=" + std::to_string(GetLastError());
        return false;
    }
    // 副本**沿用原文件名**：IsArchivePath 判后缀、卡片显示、报告摘要都依赖它
    std::wstring nameW = U2W(BaseName(origU8));
    if (nameW.empty()) nameW = L"sample.bin";
    const std::wstring copyW = dirW + L"\\" + nameW;

    if (!CopyFileW(U2W(origU8).c_str(), copyW.c_str(), TRUE)) {
        const DWORD e = GetLastError();
        RemoveDirectoryW(dirW.c_str());
        if (why) *why = "复制副本失败 err=" + std::to_string(e);
        return false;
    }

    // ★★ 2026-10-03 修正（本轮最关键的漏报修复）：随附同目录依赖。
    //
    //  【原状（错在哪）】
    //    上面只 CopyFileW 了一个 EXE，就把副本路径交给 Start.exe 送检。
    //    ⇒ 样本在箱内是一个**孤立文件**，同目录的 DLL / 配置 / 数据全都不在。
    //
    //  【实证：VM 真样本轮 12:28~12:30】
    //    12:28:30  开始分析 box=SFx67dyha01（送的是 holds\hSFx67e2a200\OBWOcH.exe）
    //    12:28:39  样本已退出 exitCode=3221225781 = 0xC0000135 STATUS_DLL_NOT_FOUND
    //    12:30:07  探针 beacon 归属：目标进程=0 … targetRan=0
    //    12:30:07  送检未在沙箱中生效 ⇒ verdict=error
    //    ⇒ **样本是被我们饿死的**，不是反沙箱逃逸，更不是"干净"。
    //      0xC0000135 就是「找不到依赖 DLL」的铁证，与 anti-sandbox 无关。
    //
    //  【为什么必须带，而不是"改判 error 就够了"】
    //    error 只能产出"无结论"，而"无结论"这条链路已经证明会走成
    //    「解锁 → 放行 → 用户可执行 → 行为判定给 0 分」。带依赖才是根治。
    //
    //  【带什么】
    //    ① 导入表里点名的 DLL（sf::ImportedDlls 解析，精确、无猜测）；
    //    ② 主文件同目录下**全部**非可执行文件（.dat/.ini/.json/…）——
    //       很多壳把配置/密钥/解包用的表放在同目录，缺了同样起不来；
    //    ③ 同目录的其它 EXE（载荷常与壳同目录成对投放，壳负责拉起载荷）。
    //    保持**同名同层**（不做子目录重建）—— 旁加载靠的就是"同目录"这个事实。
    //
    //  【纪律：宁多不多，但有硬预算】
    //    · 依赖逐个按名在**源目录**找，找不到就跳过并计数（不猜、不去系统目录乱拷）；
    //    · 总预算 kDepBudgetBytes，超出即停手并打日志（送检延迟敏感，不能失控）；
    //    · 单文件超过上限的跳过；
    //    · ★ 随附文件只进副本目录，**绝不锁、不删原件**（原件的处置权只属于
    //      本函数上面那段 MakeHold 主体逻辑，不因随附而扩大）。
    {
        std::string srcDir = origU8;
        const size_t bs = srcDir.find_last_of("\\/");
        srcDir = (bs == std::string::npos) ? std::string() : srcDir.substr(0, bs);
        unsigned long long budget = kDepBudgetBytes;
        unsigned copied = 0, skipped = 0, tooBig = 0;
        std::vector<std::string> wanted;      // 导入表点名的 DLL（小写）

        // ① 导入表依赖（点名的才带，避免把整个系统目录拖进来）
        {
            std::vector<std::string> imports;
            if (sf::ImportedDlls(origU8, imports)) {
                for (const std::string& d : imports) {
                    const std::string ld = LowerAscii(d);
                    if (ld.empty()) continue;
                    if (ld.find("api-ms-win-") == 0) continue;   // API Set：系统提供，随 box 虚拟化可见
                    if (ld.find("ext-ms-") == 0) continue;
                    wanted.push_back(ld);
                }
            }
        }
        if (!srcDir.empty()) {
            WIN32_FIND_DATAA fd{};
            const std::string pat = srcDir + "\\*";
            HANDLE h = FindFirstFileA(pat.c_str(), &fd);
            if (h != INVALID_HANDLE_VALUE) {
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_NORMAL) &&
                        !(fd.dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)) continue;
                    const std::string nmU8 = fd.cFileName;
                    const std::string nm = LowerAscii(nmU8);
                    if (LowerAscii(nmU8) == LowerAscii(W2U(nameW))) continue;   // 主文件已复制
                    if (nmU8.size() < 3) continue;
                    const std::string ext = ExtLower(nmU8);
                    const bool isExe = (ext == ".exe" || ext == ".com" || ext == ".scr");
                    // ② / ③：同目录的 DLL 与非可执行文件一律带；EXE 只带"被导入点名"的
                    const bool isDll = (ext == ".dll" || ext == ".ocx" || ext == ".cpl" || ext == ".sys");
                    bool take = isDll || !isExe;
                    if (isExe) {
                        take = std::find(wanted.begin(), wanted.end(), nm) != wanted.end();
                    }
                    if (!take) continue;
                    const std::string srcW = srcDir + "\\" + nmU8;
                    // 预算与单文件上限
                    if ((unsigned long long)fd.nFileSizeHigh * 4294967296ULL +
                        (unsigned long long)fd.nFileSizeLow > kDepSingleMaxBytes) {
                        ++tooBig; continue;
                    }
                    if ((unsigned long long)fd.nFileSizeLow > budget) { ++skipped; break; }
                    const std::wstring dstW = dirW + L"\\" + U2W(nmU8);
                    if (!CopyFileW(U2W(srcW).c_str(), dstW.c_str(), FALSE)) { ++skipped; continue; }
                    budget -= fd.nFileSizeLow;
                    ++copied;
                } while (FindNextFileA(h, &fd));
                FindClose(h);
            }
        }
        LogDbg("[sandbox] 随附同目录依赖：已带 " + std::to_string(copied) + " 个（导入表点名 " +
               std::to_string(wanted.size()) + " / 跳过 " + std::to_string(skipped) +
               " / 超单文件上限 " + std::to_string(tooBig) + "），副本目录=" + W2U(dirW));
    }

    // ★ 封锁原件：**只共享删除** ⇒ 挡执行、但隔离仍能把它搬走（实测）
    HANDLE h = CreateFileW(U2W(origU8).c_str(), GENERIC_READ, FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        DeleteFileW(copyW.c_str());
        RemoveDirectoryW(dirW.c_str());
        if (why) *why = "原件加锁失败 err=" + std::to_string(e);
        return false;
    }

    HoldRec r;
    r.h    = h;
    r.orig = origU8;
    r.copy = W2U(copyW);
    r.dir  = W2U(dirW);
    {
        std::lock_guard<std::mutex> lk(g_holdMtx);
        g_holds.push_back(r);
        g_holdActive.store((unsigned long long)g_holds.size());
    }
    g_holdOk.fetch_add(1);
    if (submitOut) *submitOut = r.copy;
    LogDbg("[sandbox] ★送检封锁：原件已锁定（本机无法执行/无法复制），沙箱改跑副本 → " +
           origU8 + " ⇒ " + r.copy);
    return true;
}

// 解封锁 + 删副本。**每次送检结束都必须走到这里**（含被挤掉/异常分支）。
static void DropHold(const std::string& copyU8, const char* whyTag) {
    HoldRec r;
    bool found = false;
    {
        std::lock_guard<std::mutex> lk(g_holdMtx);
        const std::string k = LowerAscii(copyU8);
        for (size_t i = 0; i < g_holds.size(); ++i) {
            if (LowerAscii(g_holds[i].copy) == k) {
                r = g_holds[i];
                g_holds.erase(g_holds.begin() + (long)i);
                found = true;
                break;
            }
        }
        if (found) g_holdActive.store((unsigned long long)g_holds.size());
    }
    if (!found) return;

    // ★ 顺序：先放句柄（解除封锁），再删副本 —— 反过来的话副本可能仍被自身占用
    if (r.h != INVALID_HANDLE_VALUE) CloseHandle(r.h);

    // ★★ 2026-10-03：副本目录里现在**不止主文件**（随附了同目录依赖，见 MakeHold），
    //   只删 r.copy 再 RemoveDirectory 会**必然失败** ⇒ 依赖文件永久残留在 holds\ 下。
    //   （holds\ 是 ProgramData 下的目录，残留会逐轮累积，且落地捕获会把它们
    //     当成新落地再次送检 ⇒ 自喂循环。）所以这里改成「先清空目录内所有文件，再删目录」。
    bool gone = true;
    unsigned removed = 0;
    if (!r.dir.empty()) {
        WIN32_FIND_DATAA fd{};
        const std::string pat = r.dir + "\\*";
        HANDLE h = FindFirstFileA(pat.c_str(), &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                const std::string f = r.dir + "\\" + fd.cFileName;
                if (DeleteFileA(f.c_str())) ++removed;
                else gone = false;
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }
    }
    // 兜底：主文件按精确路径再删一次（目录枚举失败时至少保住它）
    if (!r.copy.empty() && !gone) {
        if (DeleteFileW(U2W(r.copy).c_str())) { gone = true; ++removed; }
        else if (GetLastError() == ERROR_FILE_NOT_FOUND) gone = true;
    } else if (!r.copy.empty() && !gone) {
        gone = true;   // 上面的目录枚举已清空
    }
    if (gone && !r.dir.empty()) {
        if (!RemoveDirectoryW(U2W(r.dir).c_str()) &&
            GetLastError() != ERROR_DIR_NOT_EMPTY &&
            GetLastError() != ERROR_FILE_NOT_FOUND) {
            gone = false;
        }
    }

    LogDbg(std::string("[sandbox] ★送检封锁解除（") + (whyTag ? whyTag : "-") +
           "）：原件已解锁 " + r.orig +
           (gone ? "，副本目录已清理（删 " + std::to_string(removed) + " 个文件，含随附依赖）"
                 : "，★副本残留（下次启动 GC）" + r.copy));
}

// 释放全部（服务停止时）
static void ReleaseAllHolds(const char* whyTag) {
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lk(g_holdMtx);
        for (const auto& r : g_holds) keys.push_back(r.copy);
    }
    for (const auto& k : keys) DropHold(k, whyTag);
}

// ---------------------------------------------------------------------------
//  公开原语（2026-10-03 无结论决策用，声明见 sandbox.h）
// ---------------------------------------------------------------------------

bool IsHeld(const std::string& copyPath) {
    const std::string k = LowerAscii(copyPath);
    std::lock_guard<std::mutex> lk(g_holdMtx);
    for (const auto& r : g_holds)
        if (LowerAscii(r.copy) == k) return true;
    return false;
}

void ReleaseHold(const std::string& copyPath) {
    // ★ 必须真的解掉封锁，而不只是"删副本"：DropHold 做的正是这件事
    //   （先 CloseHandle 放原件句柄 → 再清空副本目录）。
    //   为什么这步不可省：用户点「不删除」是要**继续用这个文件**。
    //   若只发条日志就把卡关了，文件却仍然打不开 —— 那是最坏的结局：
    //   既没删掉、也没让用，用户还白等了一个 30 秒倒计时。
    DropHold(copyPath, "用户选择不删除 ⇒ 解锁放行（已登记放行后行为监控）");
}

// ---------------------------------------------------------------------------
//  verdict=error 的「用户决策」等待（2026-10-03）
// ---------------------------------------------------------------------------
// 【旧行为（错在哪）】维持封锁 30 分钟 → **自动放行**，从不问用户。
//   整条链上用户收到的只是一张灰卡，写着「沙箱未能完成分析」——
//   没有按钮、没有倒计时、没有任何可做的事。而 30 分钟后自动放行的后果是
//   **裸奔**：用户双击即执行，而行为判定多半给 0 分（实测 VM 12:30 后 8 分钟如此）。
//   ⇒ 「锁着」最终总会滑向「放行」，放行等于放弃。
//
// 【新行为】维持封锁 + **把处置权交回用户**（银泊裁定）：
//   卡片三按钮（删掉 / 不删 / 知道了）+ 30 秒倒计时，不选则**自动删除**。
//   30 秒而非原定的 10 秒：10 秒连一张带三按钮的卡都读不完。
//
// 【为什么"超时=删除"而不是"超时=放行"】既然锁着必然滑向放行，
//   那不如在**还有决定机会**的时刻删掉；且删除前先隔离留底，
//   误删的代价是"去隔离区捞回来"，不是永久消失。
//
// 【为什么这能防住注入式】银狐的注入必须由**投递器启动**触发；
//   落地捕获在 MakeHold 那一刻就锁住了原件，投递器起不来 ⇒ 注入链断在源头。
//   （有道假安装包实测：送进沙箱那一刻还没注入任何进程 —— 银泊实测结论。
//     曾误推论「注入式只能靠进程级拦、文件级没用」，那个推论是错的。）
//
// 【为什么不需要独立线程】沙箱消费循环本身就是常驻的，扫一遍到期表即可。
static const unsigned kErrDecisionSeconds = 30;   // 卡片倒计时秒数（须与前端一致）

static uint64_t NowMsSteady() {
    return (uint64_t)GetTickCount64();
}

// 回收所有已到期的待决（由消费循环周期调用；数量极少，线性扫描足够）
static void ReapExpiredErrHolds() {
    // ★ 刻意**不判断回调是否装配**再决定要不要扫表 ——
    //   errhold::ReapExpired 内部自己会决定怎么处理（它需要服务层的隔离+强删能力，
    //   那部分通过 OnErrHoldTimeout 由 service.cpp 注入）。
    //   之前写成「没回调就跳过并打警告」，那会导致「装配漏了 ⇒ 文件永远锁着」
    //   而唯一的线索是一行日志 —— 静默的永久封锁比报错糟糕得多。
    //   现在统一走：到点 ⇒ 回调 ⇒ 没回调时 errhold 会明确记一行（见 errhold.cpp）。
    errhold::ReapExpired();
}

// 启动清理：上次进程被强杀时来不及删的副本（句柄随进程消亡自动释放，文件还在）
static void GcHoldsDir() {
    const std::wstring root = U2W(HoldRootU8());
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    int n = 0;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
        const std::wstring sub = root + L"\\" + fd.cFileName;
        WIN32_FIND_DATAW f2{};
        HANDLE h2 = FindFirstFileW((sub + L"\\*").c_str(), &f2);
        if (h2 != INVALID_HANDLE_VALUE) {
            do {
                if (f2.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                DeleteFileW((sub + L"\\" + f2.cFileName).c_str());
            } while (FindNextFileW(h2, &f2));
            FindClose(h2);
        }
        if (RemoveDirectoryW(sub.c_str())) ++n;
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
    if (n > 0)
        LogDbg("[sandbox] 启动清理：删除上次残留的封锁副本目录 " + std::to_string(n) + " 个");
}

// ---------------------------------------------------------------------------
//  待回收清单（销毁失败的 box 记在这里，下一轮开始时重试）
// ---------------------------------------------------------------------------
// 为什么需要：删目录要等 SbieSvc 释放句柄，偶尔会失败（尤其样本还在收尾）。
// 若不记账，这个 box 就永久留在 ini + 磁盘上，长期累积。
// 清单是纯文本、一行一个 box 名，放在数据目录下（与 guard.log 同处）。
static std::string GcFilePath() {
    wchar_t buf[MAX_PATH] = { 0 };
    // 与日志同目录（C:\ProgramData\SilverFoxGuard）
    DWORD n = GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH);
    std::wstring base = (n > 0 && n < MAX_PATH) ? std::wstring(buf) : L"C:\\ProgramData";
    return W2U(base + L"\\SilverFoxGuard\\sandbox_gc.txt");
}

static void GcLoad(std::vector<std::string>* out) {
    out->clear();
    FILE* f = nullptr;
    if (_wfopen_s(&f, U2W(GcFilePath()).c_str(), L"rb") != 0 || !f) return;
    std::string raw;
    {
        char buf[4096];
        size_t n = 0;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) raw.append(buf, n);
    }
    fclose(f);
    std::string cur;
    for (char ch : raw) {
        if (ch == '\r') continue;
        if (ch == '\n') {
            if (!cur.empty() && BoxNameSafe(cur)) out->push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty() && BoxNameSafe(cur)) out->push_back(cur);
}

static void GcSave(const std::vector<std::string>& v) {
    const std::wstring p = U2W(GcFilePath());
    if (v.empty()) { DeleteFileW(p.c_str()); return; }
    FILE* f = nullptr;
    if (_wfopen_s(&f, p.c_str(), L"wb") != 0 || !f) return;
    for (auto& b : v) { fwrite(b.c_str(), 1, b.size(), f); fwrite("\r\n", 1, 2, f); }
    fclose(f);
}

static void GcAdd(const std::string& box) {
    std::vector<std::string> v;
    GcLoad(&v);
    for (auto& x : v) if (x == box) return;      // 幂等
    v.push_back(box);
    GcSave(v);
}

// 轮初回收：对清单里的每个 box 再试一次销毁；成功的从清单移除。
// 上限 8 个/轮，避免一次积压太多时拖慢送检。
static void GcSweep(const Config& cfg) {
    std::vector<std::string> v;
    GcLoad(&v);
    if (v.empty()) return;

    std::vector<std::string> left;
    int done = 0;
    for (auto& b : v) {
        if (done >= 8) { left.push_back(b); continue; }
        done++;
        if (!DestroyBox(cfg, b, nullptr)) left.push_back(b);
    }
    GcSave(left);
    LogDbg("[sandbox] 回收残留 box：" + std::to_string(v.size()) + " 个尝试，"
           + "剩 " + std::to_string(left.size()) + " 个待下轮重试");
}

// ---------------------------------------------------------------------------
//  观察树快照与 diff
// ---------------------------------------------------------------------------
// ★★★ 观察面 = **整个虚拟化根**，不是只有 drive\（2026-09-27 重要修正）
//
//   本机实测 Sandboxie 的虚拟化根布局（C:\Sandbox\<user>\<box>\）：
//     drive\C\...                       对 C:\ 等非用户目录的虚拟化
//     user\current\AppData\Roaming\...  ★ 对 %USERPROFILE% 下的虚拟化
//     user\current\AppData\Local\Temp\...  ★
//     RegHive (+ .LOG / TMContainer)    注册表虚拟化 hive
//     desktop.ini / DONT-USE.TXT        元数据
//
//   **样本写 %APPDATA% / %TEMP% / 桌面 / 文档 全都落在 user 树**，而旧实现
//   只看 drive\ → 实测覆盖率只有 1/3（probe.bat 落 3 个文件，只看见 1 个）。
//   银狐样本最爱的落地位置恰恰是这些用户目录，所以这个漏看是致命的。
//
//   做法：遍历整个 boxRoot，排除元数据；树标识由相对路径首段给出
//   （"drive" / "user" / 将来新增的树也能自动纳入，不需要改代码）。
//
//   ⚠️ 跳过 FILE_ATTRIBUTE_REPARSE_POINT：沙箱里可能把某些路径映射成链接，
//      跟进去会读到**沙箱外的真实文件** → 把系统原有文件当成落地物 → 大量假阳性。
struct Snap {
    // 相对 boxRoot 的路径(小写) → (大小, 最后写时间 FILETIME)
    std::map<std::string, std::pair<unsigned long long, long long> > m;
};

// 硬上限：沙箱虚拟化根可能很大（它把整个 C:\ 映射进来）。
// 宁可截断并报出来，也不要让一次快照把服务卡死。
static const size_t kMaxEntries = 200000;
static const int    kMaxDepth   = 24;

// 元数据/非观察对象：注册表 hive 与其事务文件、Sandboxie 自己的标记文件
static bool IsMetaName(const std::string& lowRel) {
    if (lowRel.compare(0, 7, "reghive") == 0) return true;      // RegHive / RegHive.LOG1 / RegHive{...}.TM*
    if (lowRel == "desktop.ini") return true;
    if (lowRel == "dont-use.txt") return true;
    return false;
}

static void WalkDir(const std::wstring& dir, size_t baseLen, Snap& s, int depth, size_t& count) {
    if (count >= kMaxEntries || depth > kMaxDepth) return;
    std::wstring pat = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            // 跳过重解析点（沙箱里可能映射到真实目录，跟进去会读到沙箱外的文件，
            // 那会把"系统里原本就有的文件"当成落地物报出来 → 大量假阳性）
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                WalkDir(full, baseLen, s, depth + 1, count);
        } else {
            if (full.size() > baseLen + 1) {
                std::string rel = LowerAscii(W2U(full.substr(baseLen + 1)));
                for (auto& c : rel) if (c == '/') c = '\\';
                if (IsMetaName(rel)) { count++; continue; }
                long long mt = ((long long)fd.ftLastWriteTime.dwHighDateTime << 32) |
                               (long long)fd.ftLastWriteTime.dwLowDateTime;
                unsigned long long sz = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                s.m[rel] = std::make_pair(sz, mt);
                count++;
            }
        }
        if (count >= kMaxEntries) break;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

static bool TakeSnap(const std::string& boxRoot, Snap& out, size_t& count) {
    count = 0;
    std::wstring w = U2W(boxRoot);
    if (w.empty()) return false;
    DWORD a = GetFileAttributesW(w.c_str());
    if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) return false;
    WalkDir(w, w.size(), out, 0, count);
    return true;
}

// 树标识：相对路径的首段（"drive" / "user" / ...）
static std::string TreeOf(const std::string& rel) {
    const size_t sl = rel.find('\\');
    return (sl == std::string::npos) ? std::string("root") : rel.substr(0, sl);
}

static void DiffSnap(const Snap& before, const Snap& after, std::vector<Artifact>& out) {
    for (auto it = after.m.begin(); it != after.m.end(); ++it) {
        auto jt = before.m.find(it->first);
        const bool isNew = (jt == before.m.end());
        const bool isMod = (!isNew && (jt->second.second != it->second.second));
        if (!isNew && !isMod) continue;
        Artifact ar;
        ar.rel    = it->first;
        ar.size   = it->second.first;
        ar.action = isNew ? "new" : "mod";
        ar.tree   = TreeOf(it->first);
        ar.score  = 0;
        out.push_back(ar);
    }
}

// ---------------------------------------------------------------------------
//  注册表 hive 离线解析（识别持久化行为）
// ---------------------------------------------------------------------------
// ★ 为什么必须离线解析：实测"hive 文件大小"**不是**可靠判据 ——
//   RegHive 恒为 16384 字节（hive 的最小分配），样本写入少量键不会让它增长。
//   而沙箱内的 `reg query` 看到的是**合并视图**（真实 hive + 沙箱 overlay），
//   里面既有宿主真实的 Run 键（Steam/Edge/…），也有样本刚写的键，无法区分。
//   唯一可靠的办法：把 hive 文件加载起来看它**自己**有什么。
//
// ★ 安全性已验证：离线 hive 只包含沙箱内被重定向的写入。实测样本执行
//   `reg add HKLM\...` / `reg add HKCU\...\Run` 后，宿主注册表**没有**被改动
//   （HKCU Run 里查不到样本的键、HKLM 里也查不到），写入全部落在 hive 内。
//
// ★ 判据（用本机实测的 59 键干净基线校准，见 sandbox.cpp 里 ClassifyHiveKey）：
//   · 基线里**没有** `...\CurrentVersion\Run` —— 干净会话不自带此键
//   · 样本轮次出现 `...\CurrentVersion\Run` 与自建 `machine\software\<非系统名>`
//   所以"高危路径命中"就是"有进程写了持久化位置"的强证据。
typedef LSTATUS (WINAPI *PFN_RegLoadAppKeyW)(LPCWSTR, PHKEY, REGSAM, DWORD, DWORD);

// ★ 2026-09-30 重构：注册表项携带"值"信息（值名→数据，只收像可执行路径的），
//   并剪枝 COM 垃圾（machine\software\classes / user\...\classes）。
//   旧实现只枚举子键、预算 800 被 COM 注册表吃光 → 样本在 user 树写的
//   Run/IFEO 持久化键根本到不了 ClassifyHiveKey → +70 拿不到 → 漏报（压根不报）。
struct HiveEntry {
    std::string key;                                          // 键路径
    std::vector<std::pair<std::string, std::string>> values;  // 值名 → 值数据（仅收"像可执行路径"的）
};

// 枚举某键下的"值"，只保留数据看起来像可执行体的（省内存、降噪声）
static void EnumHiveValues(HKEY hk, std::vector<std::pair<std::string, std::string>>* out) {
    for (DWORD i = 0; ; ++i) {
        wchar_t vn[256] = { 0 }; DWORD vnLen = 255;
        DWORD type = 0; BYTE buf[1024]; DWORD bufLen = sizeof(buf);
        LSTATUS rc = RegEnumValueW(hk, i, vn, &vnLen, nullptr, &type, buf, &bufLen);
        if (rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        std::string data = W2U((wchar_t*)buf);
        std::string low = LowerAscii(data);
        static const char* kExts[] = { ".exe",".dll",".scr",".com",".bat",".cmd",".ps1",".vbs",".js",".jse" };
        bool looksExe = false;
        for (auto e : kExts) if (low.find(e) != std::string::npos) { looksExe = true; break; }
        if (looksExe) out->push_back({ W2U(vn), data });
    }
}

// COM 注册表垃圾：巨型且无害，展开会吃光预算 → 只记键、不递归
static bool IsComJunk(const std::string& low) {
    if (low == "machine\\software\\classes" || low == "user\\current\\software\\classes") return true;
    if (low.compare(0, 26, "machine\\software\\classes\\") == 0) return true;
    if (low.compare(0, 30, "user\\current\\software\\classes\\") == 0) return true;
    return false;
}

static void WalkRegKeys(HKEY root, const std::string& prefix, int depth,
                        std::vector<HiveEntry>* out, size_t* budget) {
    if (depth > 10 || *budget == 0) return;
    for (DWORD i = 0; *budget > 0; ++i) {
        wchar_t name[512] = { 0 };
        DWORD len = 511;
        if (RegEnumKeyExW(root, i, name, &len, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;
        const std::string nm = W2U(name);
        const std::string full = prefix.empty() ? nm : (prefix + "\\" + nm);
        (*budget)--;
        HiveEntry e; e.key = full;
        HKEY sub = nullptr;
        if (RegOpenKeyExW(root, name, 0, KEY_READ, &sub) == ERROR_SUCCESS) {
            EnumHiveValues(sub, &e.values);
            if (!IsComJunk(LowerAscii(full)))   // ★ 剪枝 COM 垃圾，把预算留给持久化键
                WalkRegKeys(sub, full, depth + 1, out, budget);
            RegCloseKey(sub);
        }
        out->push_back(std::move(e));
    }
}

// 读取 hive 里的键列表。失败时 outErr 给出原因（不抛异常、不崩）。
// ★ 兜底：RegLoadAppKey 要求 hive 未被加载；若被占用（ERROR_SHARING_VIOLATION=32），
//   就把 hive **复制一份**再加载（实测复制可行）。
static bool HiveKeyList(const std::string& hiveFile, std::vector<HiveEntry>* out, std::string* outErr) {
    out->clear();
    HMODULE adv = GetModuleHandleW(L"advapi32.dll");
    if (!adv) adv = LoadLibraryW(L"advapi32.dll");
    if (!adv) { if (outErr) *outErr = "无法加载 advapi32.dll"; return false; }
    PFN_RegLoadAppKeyW pLoad =
        (PFN_RegLoadAppKeyW)(void*)GetProcAddress(adv, "RegLoadAppKeyW");
    if (!pLoad) { if (outErr) *outErr = "系统不支持 RegLoadAppKeyW"; return false; }

    auto tryLoad = [&](const std::wstring& f) -> LSTATUS {
        HKEY hk = nullptr;
        LSTATUS rc = pLoad(f.c_str(), &hk, KEY_READ, 0, 0);
        if (rc != ERROR_SUCCESS) return rc;
        size_t budget = 20000;  // 2026-09-30：提高预算 + COM 垃圾剪枝，避免 Run/IFEO 持久化键被漏枚举
        WalkRegKeys(hk, "", 1, out, &budget);
        RegCloseKey(hk);     // App hive 在最后一个句柄关闭时自动卸载
        return ERROR_SUCCESS;
    };

    const std::wstring wf = U2W(hiveFile);
    LSTATUS rc = tryLoad(wf);
    if (rc == ERROR_SUCCESS) return true;

    // 兜底：复制后加载
    if (rc == ERROR_SHARING_VIOLATION || rc == ERROR_ACCESS_DENIED) {
        std::wstring tmp = U2W(GcFilePath());          // 同目录（ProgramData\SilverFoxGuard）
        size_t sl = tmp.find_last_of(L'\\');
        tmp = (sl == std::wstring::npos) ? L"C:\\Windows\\Temp\\sf_hive_tmp.dat"
                                         : (tmp.substr(0, sl) + L"\\sf_hive_tmp.dat");
        if (CopyFileW(wf.c_str(), tmp.c_str(), FALSE)) {
            out->clear();
            LSTATUS rc2 = tryLoad(tmp);
            DeleteFileW(tmp.c_str());
            if (rc2 == ERROR_SUCCESS) return true;
            rc = rc2;
        }
    }
    if (outErr) *outErr = "加载 hive 失败（rc=" + std::to_string((long long)rc) +
                          (rc == 32 ? " 共享冲突：沙箱仍持有 hive" : "") + "）";
    return false;
}

// hive 键分类：2=高危（持久化/劫持） 1=可疑（非系统自建） 0=系统/Sandboxie 自带
// ★ 顺序纪律：**高危判定必须在白名单之前** ——
//   `user\current\software\microsoft\windows\currentversion\run` 同时命中
//   `user\current\software\microsoft` 这个白名单前缀，若先走白名单就会漏报，
//   而它恰恰是银狐最核心的自启动位置。
static int ClassifyHiveKey(const std::string& low) {
    // ① 高危：自启动 / 服务 / 劫持类
    static const char* kHigh[] = {
        "\\currentversion\\run",                        // Run / RunOnce / RunServices
        "\\currentversion\\policies\\explorer\\run",
        "\\currentversion\\explorer\\shell folders",
        "\\currentversion\\explorer\\user shell folders",
        "\\winlogon",
        "\\image file execution options",
        "\\currentversion\\explorer\\browser helper objects",
        "\\currentversion\\shellserviceobjectdelayload",
    };
    for (size_t i = 0; i < sizeof(kHigh) / sizeof(kHigh[0]); ++i)
        if (low.find(kHigh[i]) != std::string::npos) return 2;

    // 服务安装（但排除 Sandboxie 自己写的 WinSock2 目录，实测基线里就有它）
    const size_t svc = low.find("\\services\\");
    if (svc != std::string::npos && low.find("\\winsock2") == std::string::npos) return 2;

    // ② 白名单：Sandboxie / Windows 会话初始化自带（实测 59 键基线归纳）
    static const char* kBase[] = {
        "machine\\software\\classes",
        "machine\\software\\microsoft",
        "machine\\software\\policies\\microsoft",
        "machine\\system\\currentcontrolset\\services\\winsock2",
        "user\\current\\software\\classes",
        "user\\current\\software\\microsoft",
        "user\\current\\software\\sandboxautoexec",
        "user\\current_classes",
    };
    for (size_t i = 0; i < sizeof(kBase) / sizeof(kBase[0]); ++i)
        if (low.compare(0, strlen(kBase[i]), kBase[i]) == 0) return 0;

    // 顶层容器键本身（machine / user / machine\software / user\current / …）
    if (low == "machine" || low == "user" || low == "machine\\software" ||
        low == "machine\\system" || low == "machine\\system\\currentcontrolset" ||
        low == "machine\\system\\currentcontrolset\\services" ||
        low == "machine\\software\\policies" || low == "user\\current" ||
        low == "user\\current\\software") return 0;

    // ③ 其余 = 样本/程序自建（如 machine\software\SFTESTKEY）
    return 1;
}

// ---------------------------------------------------------------------------
//  评分 v1
// ---------------------------------------------------------------------------
//  ★ 评分必须**可解释**：每一项都要能说出"为什么给这些分"。
//    说不出理由的分就是噪声，会让"调到不误报"变成盲调。
//
//  ★ 分档与阈值刻意保守：沙箱只是**多一个证据来源**，不是最终法官。
//    · 单条高危注册表键 = 70 分 → 落进 suspicious（需人工确认）。
//      为什么不直接判恶意：正常安装包也会写 Run 键（自启动本身不是恶意），
//      必须有第二个信号（落了可执行文件等）才跨过 120 的恶意阈值。
//    · 可执行落地 40 分/项，但整体封顶 80（"落多个 exe"不是恶意的证据，
//      正常安装包也落几十个）。
static const int kScoreHigh = 120;    // >= malicious
static const int kScoreSus  = 60;     // >= suspicious

// ---------------------------------------------------------------------------
//  ★★★ 2026-10-01：勒索「批量破坏用户数据」阈值（独立于累加分的一道判据）
// ---------------------------------------------------------------------------
//  为什么**必须独立成档**，不能靠累加分兜出来：
//    旧评分体系里"文件物"是按**个数**计分的，而个数根本区分不出勒索与安装器 ——
//    一个老实安装器会落几百个文件，勒索只落几个（加密是原地改写，不新增文件）。
//    也就是说，**越像勒索，旧评分给出的分越低**。这是一个方向性错误。
//  真正把两者分开的是"对**既有用户数据**的破坏"：
//    统计被覆写(W)/删除(D)/改名(M、F)的、位于 Documents/Pictures/Videos/Music/
//    OneDrive 下的**去重文件数**（见 IsUserDataPath）。正常软件写的是自己的
//    程序文件，不会去改用户的 .docx/.jpg —— 一旦一个进程在一轮分析里动到
//    这么多既有文档，它就是在加密它们。
//  ⚠️ 阈值刻意保守（宁可漏报不可误杀：沙箱结论会触发**真实隔离**）。
//     用户数据区里 20 个文件被批量改写，正常软件几乎不可能；
//     而真勒索动辄成百上千 —— 取 20 兼顾"最小样本也能测出来"与"不误伤"。
static const int kRansomUserFiles = 20;

// ---------------------------------------------------------------------------
//  ★★★ 2026-10-03：运行时宿主自生文件识别（解释器 / 包管理器类程序专用）
// ---------------------------------------------------------------------------
//  为什么需要（银泊裁定的「Agent 独立评分机制」同构改造）：
//    Python / Node / Java 这类**解释器宿主**一跑起来就天然产生一堆落地物 ——
//      __pycache__\*.pyc、site-packages\...、node_modules\...、.venv\...
//    这些不是"程序在往持久化位置驻留"，而是**运行时自己生成的缓存/依赖**。
//    旧评分把它们与"银狐往 AppData\Roaming 里丢载荷"一视同仁（各 +30），
//    于是 8 个 .pyc 缓存 = 240 分 → 越过恶意阈值 → **Python 被误判为恶意**。
//
//  ★ 为什么**不加白名单**（照抄 behavior.cpp 「改权重，不加白名单」的定调）：
//    白名单靠"名字/路径"识别谁是 Python，攻击者把载荷改名 python.exe、
//    换到任意目录即可白嫖豁免 —— 而改评分权重是**对所有进程一视同仁**：
//    攻击者伪装成解释器拿不到任何额外好处，它仍要落可执行体（+40）、
//    写**真正的**持久化位置（Startup/Tasks/Services/Drivers），这些路径
//    **不在**下面的豁免集里。安全强度由组合信号补回。
//
//  ★ 与 scanner.cpp「解释器父链不足以定性、须叠加独立旁证」同一条纪律：
//    单凭"落了一堆 .pyc"不再能定性；要判恶意必须叠加别的信号
//    （可执行体落地 / 高危注册表 / C2 外联 / 病毒库命中 / 批量破坏用户数据）。
// ---------------------------------------------------------------------------
static bool IsRuntimeSelfArtifact(const std::string& relLow) {
    static const char* kMarks[] = {
        "\\__pycache__\\",   "/__pycache__/",
        "\\site-packages\\", "/site-packages/",
        "\\dist-packages\\", "/dist-packages/",
        "\\node_modules\\",  "/node_modules/",
        "\\venv\\",          "/venv/",
        "\\.venv\\",         "/.venv/",
        "\\lib\\python",     "/lib/python",
        "\\.pip\\",          "\\.cache\\pip\\",
        "\\appdata\\local\\pip\\", "\\appdata\\local\\npm-cache\\",
    };
    for (size_t i = 0; i < sizeof(kMarks) / sizeof(kMarks[0]); i++)
        if (relLow.find(kMarks[i]) != std::string::npos) return true;
    // 扩展名侧：解释器编译产物（字节码缓存，永不可执行）
    const std::string ext = ExtLower(relLow);
    if (ext == ".pyc" || ext == ".pyo" || ext == ".pyz") return true;
    return false;
}

// ---------------------------------------------------------------------------
//  落地物评分（文件侧）
// ---------------------------------------------------------------------------
//  ★★★ 2026-10-03 三处结构性修正（Python 误报根因，银泊裁定）：
//    ① kPersist **收窄**：移除 `\appdata\roaming\` 与 `\programdata\`。
//       理由：这两个目录是**所有**程序写自己配置/数据的地方（浏览器、微信、
//       编辑器……全都在里面），把它们当"持久化自启动位"是路径语义判断错误 ——
//       真正的文件侧自启动位是 Startup / 计划任务 / Services / Drivers。
//       （注册表侧的自启动判定在 ClassifyHiveKey，与本函数无关，未动。）
//    ② 运行时宿主自生文件（见 IsRuntimeSelfArtifact）**不计持久化/临时分**。
//       .pyc 字节码缓存既不是持久化、也不是"落在可疑目录"，它只是编译产物。
//    ③ **非可执行落地物设总分封顶**（旧实现只封了可执行项）。
//       旧缺陷：非可执行项可以无上限累加 —— 这正是"8 个文件堆到 240 分"
//       那条通路。取封顶 60（= kScoreSus）：单靠"堆非可执行文件的个数"
//       最高只能到 suspicious，**永远够不到 malicious**；要判恶意必须叠加
//       可执行落地 / 高危注册表 / C2 外联 / 病毒库命中等独立旁证。
// ---------------------------------------------------------------------------
static void ScoreArtifacts(std::vector<Artifact>& arts) {
    for (auto& a : arts) {
        // ---- 注册表项（tree == "reg"）：分值在收集阶段已定 ----
        if (a.tree == "reg") {
            // 由 BuildRegArtifacts 写入 score/why，这里只做统计上限保护
            continue;
        }

        int s = 0;
        std::string why;
        const std::string ext = ExtLower(a.rel);   // 形如 ".exe"

        const bool isExec = (ext == ".exe" || ext == ".dll" || ext == ".sys" ||
                             ext == ".scr" || ext == ".cpl" || ext == ".ocx" || ext == ".com");
        const bool isScript = (ext == ".js" || ext == ".vbs" || ext == ".vbe" ||
                               ext == ".ps1" || ext == ".bat" || ext == ".cmd" ||
                               ext == ".hta" || ext == ".lnk" || ext == ".jar");
        if (isExec)        { s += 40; why += "落出可执行文件；"; }
        else if (isScript) { s += 25; why += "落出脚本/快捷方式；"; }

        // ★ 运行时宿主自生文件：不吃"持久化/临时目录"的分（见上方长注释②）
        const bool runtimeSelf = IsRuntimeSelfArtifact(a.rel);

        // 持久化 / 自启动敏感路径（文件侧）—— ★ 已收窄，见上方长注释①
        static const char* kPersist[] = {
            "\\startup\\", "\\start menu\\", "\\tasks\\", "\\taskcache\\",
            "\\services\\", "\\drivers\\"
        };
        bool persistHit = false;
        for (size_t i = 0; i < sizeof(kPersist) / sizeof(kPersist[0]); i++) {
            if (a.rel.find(kPersist[i]) != std::string::npos) { persistHit = true; break; }
        }
        if (persistHit) {
            if (runtimeSelf) {
                why += "★路径落在持久化位，但属运行时宿主自生文件（.pyc/依赖缓存），不计持久化分；";
            } else {
                s += 30; why += "落在自启动/持久化敏感路径；";
            }
        }

        if (!runtimeSelf &&
            (a.rel.find("\\temp\\") != std::string::npos ||
             a.rel.find("\\downloads\\") != std::string::npos)) {
            s += 15; why += "落在临时/下载目录；";
        }
        if (runtimeSelf) why += "★运行时宿主自生文件（解释器/包管理器产物），不计持久化分；";

        a.score = s;
        a.why   = why;
    }

    // ---- 数量封顶：把"堆个数"这条通路彻底掐死（见上方长注释③）----
    //  (a) 可执行项累计封顶 80 分（保留旧行为：正常安装器也落几十个 exe）
    //  (b) 非可执行项累计封顶 60 分（= kScoreSus，本轮新增）
    auto trim = [&](int cap, bool wantExec) {
        auto isExecArt = [](const Artifact& a) {
            const std::string e = ExtLower(a.rel);
            return (e == ".exe" || e == ".dll" || e == ".sys" || e == ".scr" ||
                    e == ".cpl" || e == ".ocx" || e == ".com");
        };
        int total = 0;
        for (auto& a : arts) {
            if (a.tree == "reg") continue;
            if (isExecArt(a) != wantExec) continue;
            total += a.score;
        }
        int over = total - cap;
        if (over <= 0) return;
        // 从尾部削（沿用旧实现的削法，保持"哪些项被削"的直觉不变）
        for (auto it = arts.rbegin(); it != arts.rend() && over > 0; ++it) {
            if (it->tree == "reg") continue;
            if (isExecArt(*it) != wantExec) continue;
            int cut = (it->score < over) ? it->score : over;
            it->score -= cut; over -= cut;
        }
    };
    trim(80, true);
    trim(kScoreSus, false);
}

// ---------------------------------------------------------------------------
//  归档解压 → 载荷清单
// ---------------------------------------------------------------------------
// ★★ 为什么压缩包不能直接送进沙箱（本模块最容易犯的假阴性）
//   沙箱能观察的只有**行为**，而行为来自"进程跑起来"。
//   压缩包不是可执行体 —— 把它交给沙箱，它既不会解压自己也不会执行任何东西，
//   于是"未观察到任何行为" → 报告会给出 clean。
//   但那个 clean 是**假的**：不是"包里的东西没问题"，而是**观察根本不适用**。
//   正确链路：压缩包 → 7z 解压出真实载荷 → 载荷逐个送进沙箱运行 → 聚合结论。
//
// ★ 与 probe.cpp 的关系：probe 也会解包，但那是**静态**判定（列条目、看名字
//   与内容特征），不产生"可以运行的文件"。这里要的是行为判定，必须先落盘。
//   7z 的调用（参数、超时、退出码语义）复用 sf::ExtractArchiveTo，
//   避免两条链路各自维护一份 7z 调用而悄悄漂移。

// 是否需要先解压（归档格式）。列表与 probe.cpp / packscan.cpp 保持一致。
bool IsArchivePath(const std::string& path) {
    const std::string low = LowerAscii(path);
    static const char* kExt[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lzh", ".iso",
        ".cab", ".arj", ".wim", ".rpm", ".deb", ".xar", ".tgz", ".tbz", ".txz",
        ".msix", ".msu", ".appx"
    };
    for (size_t i = 0; i < sizeof(kExt) / sizeof(kExt[0]); ++i) {
        const size_t n = strlen(kExt[i]);
        if (low.size() > n && low.compare(low.size() - n, n, kExt[i]) == 0) return true;
    }
    return false;
}

// 解压产物里哪些文件值得送进沙箱"跑"
//   · 可执行体：exe/scr/com/pif/msi + 动态库(cpl/ocx/ax —— 可被 rundll32 加载)
//   · 脚本：bat/cmd/ps1/vbs/vbe/js/jse/wsf/wsh/hta/jar
//   · 快捷方式：lnk（银狐常用 .lnk 指向 payload）
// ★ dll 也收：样本常把载荷做成 dll + rundll32 拉起，只收 exe 会漏。
static bool IsRunnablePayload(const std::string& low) {
    static const char* kExt[] = {
        ".exe", ".scr", ".com", ".pif", ".msi",
        ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh",
        ".hta", ".jar", ".lnk", ".cpl", ".ocx", ".ax", ".dll",
    };
    for (size_t i = 0; i < sizeof(kExt) / sizeof(kExt[0]); ++i) {
        const size_t n = strlen(kExt[i]);
        if (low.size() > n && low.compare(low.size() - n, n, kExt[i]) == 0) return true;
    }
    return false;
}
// 送检优先级：exe 先跑（银狐主载荷几乎都是 exe）
static int PayloadRank(const std::string& low) {
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".exe") == 0) return 0;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".scr") == 0) return 0;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".com") == 0) return 0;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".msi") == 0) return 1;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".ps1") == 0) return 1;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".bat") == 0) return 1;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".cmd") == 0) return 1;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".lnk") == 0) return 2;
    if (low.size() > 4 && low.compare(low.size() - 4, 4, ".dll") == 0) return 3;   // dll 自身通常不"跑"
    return 2;
}

struct PayloadCand {
    std::string path;       // 磁盘真实路径
    std::string label;      // 相对解压根（解压出什么就显示什么，便于人工定位）
    unsigned long long size = 0;
    int rank = 2;
};

// 解压体积/数量预算（防解压炸弹）
static const unsigned long long kArchMaxBytes = (1ull << 30);   // 1GB
static const size_t             kArchMaxFiles = 20000;
static const size_t             kArchMaxVictims = 6;            // 最多送 6 个载荷（每个都要跑一轮）

static void CollectPayloads(const std::wstring& dir, const std::wstring& root,
                            std::vector<PayloadCand>* out, size_t* fileCount,
                            unsigned long long* totalBytes, bool* truncated, int depth) {
    if (depth > 12 || *truncated) return;
    std::wstring pat = dir + L"\\*";
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW(pat.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.cFileName[0] == L'.' &&
            (fd.cFileName[1] == 0 || (fd.cFileName[1] == L'.' && fd.cFileName[2] == 0))) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                CollectPayloads(full, root, out, fileCount, totalBytes, truncated, depth + 1);
        } else {
            (*fileCount)++;
            if (*fileCount > kArchMaxFiles) { *truncated = true; break; }
            const unsigned long long sz =
                ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
            *totalBytes += sz;
            if (*totalBytes > kArchMaxBytes) { *truncated = true; break; }
            const std::string rel = W2U(full.substr(root.size() + 1));
            const std::string low = LowerAscii(rel);
            if (!IsRunnablePayload(low)) continue;
            PayloadCand c;
            c.path  = W2U(full);
            c.label = rel;
            c.size  = sz;
            c.rank  = PayloadRank(low);
            out->push_back(c);
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

bool ArchiveToTargets(const std::string& archivePath, const std::string& destDir,
                      std::vector<Target>* out, int* outFileCount, bool* outTruncated,
                      std::string* outErr) {
    out->clear();
    if (outFileCount) *outFileCount = 0;
    if (outTruncated) *outTruncated = false;
    if (outErr) outErr->clear();

    // ★ 解压失败必须与"包内无载荷"区分开（前者是覆盖缺口，必须报 error）
    if (!sf::ExtractArchiveTo(archivePath, destDir)) {
        if (outErr) *outErr = "7z 解压失败（加密 / 损坏 / 私有变体，或 7z.exe 不可用）";
        return false;
    }

    const std::wstring root = U2W(destDir);
    std::vector<PayloadCand> cands;
    size_t fileCount = 0;
    unsigned long long totalBytes = 0;
    bool truncated = false;
    CollectPayloads(root, root, &cands, &fileCount, &totalBytes, &truncated, 0);

    if (outFileCount) *outFileCount = (int)fileCount;

    // 排序：优先送 exe/脚本；同 rank 按体积从大到小（大文件更可能是主载荷）
    std::sort(cands.begin(), cands.end(), [](const PayloadCand& a, const PayloadCand& b) {
        if (a.rank != b.rank) return a.rank < b.rank;
        return a.size > b.size;
    });
    if (cands.size() > kArchMaxVictims) {
        cands.resize(kArchMaxVictims);
        truncated = true;
    }
    if (outTruncated) *outTruncated = truncated;

    for (auto& c : cands) {
        Target t;
        t.path  = c.path;
        t.label = c.label;
        out->push_back(t);
    }
    LogDbg("[sandbox] 归档解压：" + archivePath + " → 文件 " + std::to_string(fileCount) +
           " 个，总量 " + std::to_string(totalBytes) + "B，可送检载荷 " +
           std::to_string(out->size()) + " 个" + (truncated ? "（★已截断）" : ""));
    return true;
}

// ---------------------------------------------------------------------------
//  报告组装
// ---------------------------------------------------------------------------
static int SumScore(const std::vector<Artifact>& arts) {
    int t = 0; for (auto& a : arts) t += a.score; return t;
}
static int CountExec(const std::vector<Artifact>& arts) {
    int n = 0;
    for (auto& a : arts) {
        const std::string e = ExtLower(a.rel);
        if (e == ".exe" || e == ".dll" || e == ".sys" || e == ".scr" || e == ".cpl" || e == ".ocx") n++;
    }
    return n;
}

// ---------------------------------------------------------------------------
//  单载荷执行：建箱 → 快照 → 送检 → 事后快照 → 解析 → 评分 → 销毁
// ---------------------------------------------------------------------------
// 一个 Target = 一轮完整的一次性沙箱。
// 压缩包解出多个载荷时，每个载荷各跑一轮（各建各的箱、各销毁各的），
// 因为：
//   · 同一 box 里跑多个样本，落地物会互相污染，diff 结果不可归因；
//   · 一次性 box 的设计前提就是"一轮一箱"。
// 结果写进 sub（verdict/score/artifacts/victims 之外的全部字段）。
// 返回值：true = 流程走完（sub.verdict 有效）；false = 流程出错（sub.err 有效）。
// ---------------------------------------------------------------------------
//  ★ 2026-09-30：沙箱网络行为嗅探（C2 外联，此前是真空信号源）
// ---------------------------------------------------------------------------
//  为什么必须做：fake_mal_b 在沙箱内连 127.0.0.1:443，旧实现完全看不见
//  → 纯 C2 信标木马（不落盘/不持久化）一律判 clean。这是最大的泛化漏报缺口。
//  做法：收集送检进程树（Start.exe 及其子孙）在观察窗口内的外部连接，
//  过滤掉回环/私有内网/链路本地/0.0.0.0，剩下的就是"box 内进程主动连外网"——
//  正常程序在沙箱里极少主动外联，命中即强可疑（C2 信标 / 下载器回连）。
static void CollectPidTree(DWORD rootPid, std::set<DWORD>* tree) {
    tree->insert(rootPid);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    for (int pass = 0; pass < 6; ++pass) {            // 多趟：子进程可能后创建
        size_t before = tree->size();
        if (Process32First(snap, &pe)) {
            do {
                if (tree->count(pe.th32ParentProcessID)) tree->insert(pe.th32ProcessID);
            } while (Process32Next(snap, &pe));
        }
        if (tree->size() == before) break;
    }
    CloseHandle(snap);
}

// box 进程**集合**在观察窗口内建立的外部连接（IP:port 字符串）。
// ★ 2026-10-01 重构：由「按 Start.exe 根取整棵进程树」改为「按 PID 集合」——
//   驻留观察期 Start.exe 自己已退出、父链断裂，只能按 PID 集合嗅探（见 ResidentWatch）。
static void SniffTcpForPids(const std::set<DWORD>& pids, std::vector<std::string>* out) {
    if (pids.empty()) return;
    DWORD size = 0;
    if (GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != ERROR_INSUFFICIENT_BUFFER)
        return;
    std::vector<BYTE> buf(size);
    auto* t = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());
    if (GetExtendedTcpTable(t, &size, FALSE, AF_INET,
                            TCP_TABLE_OWNER_PID_CONNECTIONS, 0) != NO_ERROR) return;
    for (DWORD i = 0; i < t->dwNumEntries; ++i) {
        auto& r = t->table[i];
        if (r.dwState != 5) continue;   // 5 = MIB_TCP_STATE_ESTABLISHED（该 SDK 的 tcpmib.h 未暴露枚举，用常量）
        if (!pids.count(r.dwOwningPid)) continue;
        DWORD ra = r.dwRemoteAddr;
        unsigned char b1 = (ra >> 24) & 0xFF, b2 = (ra >> 16) & 0xFF;
        if ((ra & 0xFF) == 0x7F) continue;                          // 回环
        if (b1 == 10) continue;                                      // 私有 10/8
        if (b1 == 172 && b2 >= 16 && b2 <= 31) continue;            // 私有 172.16/12
        if (b1 == 192 && b2 == 168) continue;                       // 私有 192.168/16
        if (b1 == 169 && b2 == 254) continue;                       // 链路本地
        if (ra == 0) continue;
        u_short port = (u_short)(((r.dwRemotePort >> 8) & 0xFF) | ((r.dwRemotePort & 0xFF) << 8));
        std::string ip = std::to_string(b1) + "." + std::to_string(b2) + "." +
                         std::to_string((ra >> 8) & 0xFF) + "." + std::to_string(ra & 0xFF);
        out->push_back(ip + ":" + std::to_string(port));
    }
}

// 字符串向量去重（排序 + unique；顺序不重要）。
static void DedupStrings(std::vector<std::string>* v) {
    std::sort(v->begin(), v->end());
    v->erase(std::unique(v->begin(), v->end()), v->end());
}

// ---------------------------------------------------------------------------
//  ★ 2026-10-01 新增：box 内进程枚举（驻留观察的地基）
// ---------------------------------------------------------------------------
//  为什么不能继续用父子链：驻留观察期样本主进程与 Start.exe 都已退出，残留的守护子
//  进程成了**孤儿** —— Process32 里的 PPID 指向已消失的父进程，CollectPidTree 断链。
//  归属判据换成一个**与父链无关**的事实：沙箱内进程在启动时都被 SbieDll.dll 注入，
//  ∴「加载了 SbieDll.dll」= 它是 box 内进程。
//  再减去两类噪声：
//    · baseline —— 送检前就已存在的 PID（别的常驻沙箱程序，不属于本轮）；
//    · 基础设施镜像 —— Start.exe / SandboxieRpcSs.exe / SandboxieDcomLaunch.exe …
//      （它们也在 box 会话里、也加载 SbieDll，但不是"样本残留进程"）。
//  ⚠️ 已知边界：若用户在扫描窗口内**手动**新起别的沙箱程序，会被误算作本轮残留。
//     一次性 box + 服务端串行送检下，此风险极低；且残留进程**本身不定罪**（见评分纪律）。
// ---------------------------------------------------------------------------
static bool IsSandboxInfraImageW(const std::wstring& imgW) {
    std::wstring f = imgW;
    size_t sl = f.find_last_of(L"/\\");
    if (sl != std::wstring::npos) f = f.substr(sl + 1);
    for (auto& c : f) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c + 32);
    static const wchar_t* kInfra[] = {
        L"start.exe", L"sbiesvc.exe", L"sbiectrl.exe", L"sandman.exe",
        L"sbiemsg.dll", L"sbiertl.dll", L"sbieini.exe",
        L"sandboxierpcss.exe", L"sandboxiedcomlaunch.exe",
    };
    for (auto t : kInfra) if (f == t) return true;
    return false;
}

// 该进程是否加载了 SbieDll.dll（= 它是沙箱 box 内进程）。
//
// ★★★ 2026-10-02 换实现 —— 这是「缺陷 A」的**根因修复**，不是优化：
//   旧实现 CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, pid)
//   **会在内核里以 PROCESS_ALL_ACCESS(0x001FFFFF) 打开目标进程**（本机实测，
//   见 C:\temp\toolhelp_mask3_result.json；同 target 的 OpenProcess(0x1000) 对照组
//   掩码恒为 0x1000，证明测量链有效）。
//   而 0x1FFFFF 恰好完整包含 CREATE_THREAD(0x2)|VM_OPERATION(0x8)|VM_WRITE(0x20)
//   —— 正是 behavior.cpp JudgeInjectionActivity 的「注入能力齐备」判据。
//   后果：驻留观察期每一轮都对全系统 PID 逐个调用本函数 → 每开一个 PID 就在
//   NT 审计通道留下一条"注入能力齐备"的 NtOpenProcess 事件 → 注入检测器把
//   **我们自己**判成「对敏感进程(svchost/msedge)的注入」，一天刷出 504 条告警。
//
//   → 改用 OpenProcess(0x410 = QUERY_INFORMATION|VM_READ) + EnumProcessModulesEx：
//     语义**完全等价**（同一份模块列表、同样覆盖跨位数 32 位样本），
//     但掩码 0x410 不含任何注入位 → 不会再自触发。
//   ⚠️ LIST_MODULES_ALL 等价于原来的 TH32CS_SNAPMODULE32（64 位进程也能看到 32 位模块）。
//   ⚠️ 刻意**不**给 src==SilverFoxGuardSvc 开白名单 —— 那会把「我们真被利用来注入」
//      一并放行，属最糟修法。这里改的是我们**自己的调用方式**，判定层一字不动。
static bool LoadsBoxModule(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return false;
    bool found = false;
    HMODULE mods[512];
    DWORD need = 0;
    if (EnumProcessModulesEx(h, mods, sizeof(mods), &need, LIST_MODULES_ALL)) {
        DWORD n = need / sizeof(HMODULE);
        if (n > 512) n = 512;   // SbieDll 是注入时早期加载的，前 512 个模块足够覆盖
        wchar_t nm[MAX_PATH];
        for (DWORD i = 0; i < n; ++i) {
            if (GetModuleBaseNameW(h, mods[i], nm, MAX_PATH) &&
                _wcsicmp(nm, L"SbieDll.dll") == 0) {
                found = true;
                break;
            }
        }
    }
    CloseHandle(h);
    return found;
}

// 枚举全系统 PID（做基线用：送检前就存在的进程都不属于本轮 box）。
static void CollectAllPids(std::set<DWORD>* out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { if (pe.th32ProcessID) out->insert(pe.th32ProcessID); } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// 枚举"此刻活着、属于本 box 的样本相关进程"。输出 pid → 镜像名。
static void CollectBoxProcesses(const std::set<DWORD>& baseline,
                                std::map<DWORD, std::wstring>* liveNow) {
    liveNow->clear();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0) continue;
            if (baseline.count(pid)) continue;                // 送检前就存在 → 非本轮
            if (IsSandboxInfraImageW(pe.szExeFile)) continue; // 沙箱基础设施
            if (LoadsBoxModule(pid)) (*liveNow)[pid] = pe.szExeFile;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

// ---------------------------------------------------------------------------
//  ★★★ 2026-10-01 新增：驻留观察期 —— 主进程退出后，继续看 box 里究竟发生了什么
// ---------------------------------------------------------------------------
//  【为什么必须改】用户 2026-10-01 当面指正旧语义：
//      "一个进程完了就直接送检结束了…那个进程完了之后，还要观察沙箱里到底发生了什么。
//       不是这个进程结束了就检测完了。"
//    旧实现正是反面教材：样本主进程一退 → 立即 `Start.exe /box /terminate` 把整个 box
//    打死 → 才读 beacon 出结论。这等于**只采了样本运行的最后一帧**。
//    银狐类样本的典型形态恰恰是「主进程快速退出（伪装成安装器/文档，释放警觉）→
//    守护子进程驻留下来 → 继续外联 C2 / 二次落地 / 注册表守候 → 若干秒后再发作」。
//    旧实现把这些"退出之后"发生的一切全部丢掉 → 多阶段样本被当成"一闪而过"。
//
//  【本段做什么】主进程退出**不是**观察终点，而是"驻留观察段"的起点。继续盯三件事：
//    ① 残留进程：靠 SbieDll.dll 归属枚举 box 内还活着的进程（不依赖已断的父链）；
//    ② 二次落地：与**上一轮快照** diff（增量），主进程退出后新出现的文件；
//    ③ 持续外联：对累积 PID 集合嗅探新建立的外部连接（驻留 C2 的心跳）。
//  结束条件：**跑满预算**（或收到停止请求）。刻意不提前收敛 —— 理由见函数内注释。
//  ⚠️ 只有本函数返回后，调用方才执行 /terminate 收摊 —— 顺序绝不能反。
//  ⚠️ 本函数只**采集**，不做结论；计分纪律见 ScanOne 末尾（残留进程本身不定罪）。
// ---------------------------------------------------------------------------
static void ResidentWatch(const std::string& box,
                          const std::string& boxRoot, int budgetSec,
                          const Snap& before,
                          const std::set<DWORD>& baselinePids,
                          std::set<DWORD>* boxPids,
                          std::vector<std::string>* netConns,
                          Report& sub) {
    if (budgetSec < 10)  budgetSec = 10;
    if (budgetSec > 480) budgetSec = 480;

    const ULONGLONG r0 = GetTickCount64();
    Snap prev = before;                  // 上一轮快照（增量 diff 用，不能用事前快照）
    std::map<DWORD, std::wstring> lastLive;
    std::set<std::wstring> exeSeen;
    int peakResident = 0, newFilesTotal = 0;
    bool sawOutbound = false;
    int idleRounds = 0;                  // 连续无变化轮数（仅用于日志降噪，不再提前收摊）

    LogDbg("[sandbox] box=" + box + " 进入驻留观察期（预算 " + std::to_string(budgetSec) +
           "s）：主进程已退出，继续观察 box 内残留活动");

    for (;;) {
        if (sf::IsStopRequested()) {
            LogDbg("[sandbox] box=" + box + " 驻留观察：收到停止请求，提前结束");
            break;
        }
        const int el = (int)((GetTickCount64() - r0) / 1000);
        if (el > budgetSec) {
            LogDbg("[sandbox] box=" + box + " 驻留观察：达到预算上限 " + std::to_string(budgetSec) + "s");
            break;
        }

        // ① 当前活着的 box 进程（SbieDll 归属，不依赖父链）
        std::map<DWORD, std::wstring> liveNow;
        CollectBoxProcesses(baselinePids, &liveNow);
        int nNewProc = 0;
        for (auto& kv : liveNow) {
            if (!boxPids->count(kv.first)) { boxPids->insert(kv.first); ++nNewProc; }
            exeSeen.insert(kv.second);
        }
        const int resident = (int)liveNow.size();
        if (resident > peakResident) peakResident = resident;

        // ② 二次落地：与**上一轮快照** diff（增量），否则累计差会让收敛判定永不成立
        Snap cur; size_t nCur = 0;
        TakeSnap(boxRoot, cur, nCur);
        std::vector<Artifact> d;
        DiffSnap(prev, cur, d);
        prev = cur;
        int nNewFile = 0;
        for (auto& a : d) {
            if (LowerAscii(a.rel).find("silverfoxprobe") != std::string::npos) continue;
            ++nNewFile;
        }
        newFilesTotal += nNewFile;

        // ③ 新外联：对累积 PID 集合嗅探（驻留期 Start.exe 已不在，不能用进程树）
        const size_t connsBefore = netConns->size();
        SniffTcpForPids(*boxPids, netConns);
        DedupStrings(netConns);
        const int nNewConn = (int)(netConns->size() - connsBefore);
        if (nNewConn > 0) sawOutbound = true;

        const bool changed = (liveNow != lastLive) || nNewProc > 0 ||
                             nNewFile > 0 || nNewConn > 0;
        lastLive = liveNow;

        // ★★ 2026-10-01（银泊裁定）：**不再提前收敛** —— 留观必须跑满预算。
        //   旧实现有两条早退（box 空 2 轮 ≈4s / 连续 5 轮无变化 ≈10s），实测主进程
        //   秒退的样本只留观 4 秒就收摊，配上进度卡那个假倒计时，观感就是"样本一跑完
        //   就冒结果、压根没观察"。现在唯一的早退是"收到停止请求"，其余一律跑满 ——
        //   预算由调用方按「总预算 − 活跃期」算好（见 ScanOne），保证进度条走完 = 出结果。
        if (changed) {
            idleRounds = 0;
            LogDbg("[sandbox] box=" + box + " 驻留观察 +" + std::to_string(el) +
                   "s：残留进程 " + std::to_string(resident) + "（新 " + std::to_string(nNewProc) +
                   "）、新落地 " + std::to_string(nNewFile) + "、新外联 " +
                   std::to_string(nNewConn));
        } else if ((++idleRounds % 15) == 0) {
            // 每 15 轮（≈30s）一条心跳：既证明"确实在观察"，又不刷屏
            LogDbg("[sandbox] box=" + box + " 驻留观察 +" + std::to_string(el) +
                   "s：box 内暂无活动（残留进程 " + std::to_string(resident) + "）");
        }
        Sleep(2000);
    }

    sub.residentSec      = (int)((GetTickCount64() - r0) / 1000);
    sub.residentProcs    = peakResident;
    sub.residentPids     = (int)boxPids->size();
    sub.residentNewFiles = newFilesTotal;
    sub.residentOutbound = sawOutbound;
    for (auto& w : exeSeen) {
        if (sub.residentExe.size() >= 8) break;   // 去重后的镜名，最多 8 条
        std::wstring base = w;
        size_t sl = base.find_last_of(L"/\\");
        if (sl != std::wstring::npos) base = base.substr(sl + 1);
        sub.residentExe.push_back(W2U(base.c_str()));
    }
    LogDbg("[sandbox] box=" + box + " 驻留观察结束：时长 " + std::to_string(sub.residentSec) +
           "s，残留进程峰值 " + std::to_string(peakResident) +
           "，累计 box 进程 " + std::to_string(sub.residentPids) +
           "，退出后二次落地 " + std::to_string(newFilesTotal) +
           "，退出后外联 " + std::string(sawOutbound ? "有" : "无"));
}

// ---------------------------------------------------------------------------
//  ★★ 送检失败时的「目标文件体检」（2026-10-01 新增，取证用）
// ---------------------------------------------------------------------------
//  为什么需要：闸门判 error 时我们只知道"样本没在沙箱里跑起来"，却**分不清**
//  下面两类完全不同的原因，而二者的处置南辕北辙：
//    ① 文件本身有问题 —— 送检时目标还在被写入（**先建后写**的载荷）、或已自删、
//       或不是有效 PE → Start.exe 拉不动它 → 用户看到沙箱弹「无法运行该程序」。
//       处置：送检前加"文件稳定/PE 可解析"前置闸门。
//    ② 沙箱环境有问题 —— 文件是好的，但会话/权限/策略把启动挡住了。
//       处置：查 Start.exe 的退出码与 SbieSvc 状态。
//  所以这里把"文件此刻到底长什么样"落进日志（存在性、大小、MZ/PE 签名、架构）。
//  ★ 架构那一项还有独立价值：我们只有 64 位探针时，32 位样本**永远**写不出
//    is_target=1 的 beacon —— 这条能直接解释"探针没覆盖到"。
static std::string DescribeExeForDiag(const std::string& path) {
    std::wstring w = U2W(path);
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &fad)) {
        return "文件不存在或不可访问（err=" + std::to_string(GetLastError()) +
               "）→ 疑似送检时已被删除/改名";
    }
    ULONGLONG size = ((ULONGLONG)fad.nFileSizeHigh << 32) | (ULONGLONG)fad.nFileSizeLow;
    std::string s = "大小=" + std::to_string(size) + "B";

    HANDLE h = CreateFileW(w.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        return s + "；打开失败 err=" + std::to_string(GetLastError());
    }
    BYTE hdr[4096] = { 0 };
    DWORD rd = 0;
    ReadFile(h, hdr, sizeof(hdr), &rd, nullptr);
    CloseHandle(h);

    if (rd < 64) {
        return s + "；实际只读到 " + std::to_string(rd) +
               " 字节 → **疑似文件尚未写完**（送检撞上了「先建后写」的载荷）";
    }
    if (hdr[0] != 'M' || hdr[1] != 'Z') {
        return s + "；无 MZ 签名 → **不是有效可执行文件**（疑似仍在下写或已被覆盖）";
    }
    DWORD peOff = 0;
    for (int i = 0; i < 4; ++i) peOff |= ((DWORD)hdr[0x3C + i]) << (8 * i);
    if (peOff + 6 > rd || peOff < 0x40) {
        return s + "；PE 头偏移越界（" + std::to_string(peOff) + "）→ **文件不完整**";
    }
    if (!(hdr[peOff] == 'P' && hdr[peOff + 1] == 'E' && hdr[peOff + 2] == 0 && hdr[peOff + 3] == 0)) {
        return s + "；PE 签名错误 → **文件损坏/不完整**";
    }
    WORD machine = (WORD)(hdr[peOff + 4] | ((WORD)hdr[peOff + 5] << 8));
    const char* arch = (machine == 0x8664) ? "x64" :
                       (machine == 0x014C) ? "x86(32位)" :
                       (machine == 0xAA64) ? "ARM64" : "未知";
    std::string tail = (machine == 0x014C)
        ? "；⚠ 32 位样本：只有 64 位探针时**永远**不会写出 is_target=1 的 beacon"
        : "";
    return s + "；PE 有效，架构=" + std::string(arch) + tail;
}

// ---------------------------------------------------------------------------
//  ★ 送检前置闸门：这个文件「能不能被 Start.exe 直接启动」
// ---------------------------------------------------------------------------
// 起因（2026-10-01 银泊两轮反馈）：每次自动送检时 Sandboxie 都弹一个
//   「无法运行该程序」的对话框，样本根本没跑起来。
//   弹窗是 **Start.exe** 在"目标没法启动"时弹的；而我们的自动送检源是
//   **落地捕获**（service.cpp 的 `exeLike`），它把 `.exe/.com/.scr/.dll/.sys`
//   一股脑入队（见 service.cpp:2742）—— 其中：
//     · `.dll` / `.sys`：**根本无法被 Start.exe 直接启动**（DLL 没有可执行入口，
//       驱动要由内核加载）。银狐这类 loader 的投递物恰恰**大量是 DLL**。
//     · 「先建后写」的载荷：入队那一刻文件内容还没落全（旧账目见 06 号文档）。
//     · 落地后已被清理/改名/删除的空壳路径。
//   旧代码对这几种一律照送 → 每轮弹窗，还白烧一次沙箱名额 + 90 秒观察窗
//   （实测 107 次送检里 error 19 次 ≈ 18%）。
//   本闸门在**调用 Start.exe 之前**做一次可执行性体检：不合格就不送（因此也就
//   不会弹窗），并留下与 error 同级的取证日志。对"先建后写"用 6×500ms 重试兜住，
//   避免误杀真实样本。
//
// 返回值：true = 可以送检；false = 不予送检（*why 已写好原因，*verdict 已选定）
static bool PreflightRunnable(const std::string& path,
                              std::string* why, std::string* verdict) {
    auto hex4 = [](unsigned v) {
        static const char* d = "0123456789ABCDEF";
        char b[5] = { d[(v >> 12) & 0xF], d[(v >> 8) & 0xF], d[(v >> 4) & 0xF], d[v & 0xF], 0 };
        return std::string(b);
    };
    auto extOf = [](const std::string& p) -> std::string {
        const size_t dot = p.find_last_of('.');
        const size_t sep = p.find_last_of("\\/");
        if (dot == std::string::npos) return std::string();
        if (sep != std::string::npos && dot < sep) return std::string();
        return LowerAscii(p.substr(dot));
    };

    std::string transient;
    for (int attempt = 1; attempt <= 6; ++attempt) {
        const bool lastTry = (attempt == 6);
        transient.clear();

        const std::wstring w = U2W(path);
        WIN32_FILE_ATTRIBUTE_DATA fad{};
        if (!GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &fad)) {
            const DWORD e = GetLastError();
            // ★★ 2026-10-01 修正：「彻底消失了」≠「还没写完」。
            //   前者重试一万次也不会出现，白等 6×500ms 还照样出 error。
            //
            //   实证（银泊机器 21:20 两轮，日志原文）：
            //     C:\Users\tianl\AppData\Local\Temp\.tmp0WPEAt\uv-trampoline-27620.exe
            //   这是 **Node/libuv 的进程桩** —— libuv 在 Windows 上创建子进程时会先写
            //   一个 `%TEMP%\.tmpXXXX\uv-trampoline-<pid>.exe`，**用完即删**（连 .tmpXXXX
            //   目录一起）。落地捕获在它存在的瞬间抓到并送检；沙箱串行（单件 ~90s）排队
            //   轮到它时，文件**和它的父目录**都已销毁 → 只剩 err=3。
            //   此时唯一诚实的结论是「目标已不存在，无从分析」，而不是"尚未落盘"。
            //
            //   判据：连**父目录**都不存在 → 这是"回不来了"，立刻收手。
            //   ⚠️ 别用错误码判（父目录缺失时 Windows 可能给 FILE_NOT_FOUND 而非
            //      PATH_NOT_FOUND，按码判会漏）。直接问一句"父目录还在不在"就够了：
            //      「尚未落盘」的文件，父目录必然存在 —— 这是两者的充分分界。
            if (e == ERROR_PATH_NOT_FOUND || e == ERROR_FILE_NOT_FOUND) {
                std::wstring parent = w;
                const size_t sl = parent.find_last_of(L"\\/");
                if (sl != std::wstring::npos && sl > 0) parent = parent.substr(0, sl);
                else parent.clear();
                if (!parent.empty() &&
                    GetFileAttributesW(parent.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    *why = "目标及其所在目录都已不存在：文件已被其属主进程删除"
                           "（典型如 Node/libuv 用完即删的进程桩 "
                           "`%TEMP%\\.tmpXXXX\\uv-trampoline-<pid>.exe`）。"
                           "**不是**「尚未落盘」——父目录都没了，重试无意义。";
                    *verdict = "error";
                    return false;
                }
            }
            if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ||
                e == ERROR_SHARING_VIOLATION) {
                transient = "文件暂时不可访问（err=" + std::to_string(e) +
                            "）→ 疑似尚未落盘或正被写入";
            } else {
                *why     = "文件不存在或不可访问（err=" + std::to_string(e) + "）";
                *verdict = "error";
                return false;
            }
        } else if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            *why     = "目标是一个**目录**，不是可执行文件";
            *verdict = "error";
            return false;
        } else {
            const ULONGLONG size =
                ((ULONGLONG)fad.nFileSizeHigh << 32) | (ULONGLONG)fad.nFileSizeLow;
            if (size < 64) {
                transient = "文件仅 " + std::to_string(size) +
                            "B（<64）→ 疑似空文件或尚未写完（「先建后写」的载荷）";
            } else {
                HANDLE h = CreateFileW(w.c_str(), GENERIC_READ,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                       OPEN_EXISTING, 0, nullptr);
                if (h == INVALID_HANDLE_VALUE) {
                    transient = "文件被占用暂不可读（err=" +
                                std::to_string(GetLastError()) + "）";
                } else {
                    BYTE  hdr[4096] = { 0 };
                    DWORD rd = 0;
                    ReadFile(h, hdr, sizeof(hdr), &rd, nullptr);
                    CloseHandle(h);

                    const std::string ext = extOf(path);
                    if (rd < 64) {
                        transient = "只读到 " + std::to_string(rd) +
                                    " 字节 → 疑似尚未写完";
                    } else if (hdr[0] != 'M' || hdr[1] != 'Z') {
                        // 非 PE：只对"本应是 PE"的扩展名判不合格；脚本/数据类一律放行
                        static const char* kPeExt[] = { ".exe", ".dll", ".sys", ".scr",
                                                        ".com", ".cpl", ".ocx", ".drv",
                                                        ".efi", ".ax" };
                        bool peish = false;
                        for (size_t i = 0; i < sizeof(kPeExt) / sizeof(kPeExt[0]); ++i)
                            if (ext == kPeExt[i]) { peish = true; break; }
                        if (!peish) return true;                 // 脚本 / 数据类：可以送
                        transient = "扩展名 " + (ext.empty() ? std::string("(无)") : ext) +
                                    " 但**无 MZ 签名** → 内容是空的或尚未落全";
                    } else {
                        DWORD peOff = 0;
                        for (int i = 0; i < 4; ++i) peOff |= ((DWORD)hdr[0x3C + i]) << (8 * i);
                        if (peOff < 0x40 || peOff + 24 > rd) {
                            transient = "PE 头偏移越界（" + std::to_string(peOff) +
                                        "）或头部未读完 → 文件不完整";
                        } else if (!(hdr[peOff] == 'P' && hdr[peOff + 1] == 'E' &&
                                     hdr[peOff + 2] == 0 && hdr[peOff + 3] == 0)) {
                            transient = "PE 签名错误 → 文件损坏或不完整";
                        } else {
                            const WORD machine = (WORD)(hdr[peOff + 4] |
                                                        ((WORD)hdr[peOff + 5] << 8));
                            const WORD chars   = (WORD)(hdr[peOff + 22] |
                                                        ((WORD)hdr[peOff + 23] << 8));
                            // ★ IMAGE_FILE_DLL(0x2000)：DLL 没有可执行入口点，
                            //   Start.exe 收下它只会弹「无法运行该程序」。
                            if ((chars & 0x2000) || ext == ".dll" || ext == ".ax" ||
                                ext == ".ocx") {
                                *why = "目标是 **DLL**（PE 特征位 IMAGE_FILE_DLL 或扩展名 " +
                                       (ext.empty() ? std::string("?") : ext) +
                                       "）——Start.exe 无法直接启动 DLL，"
                                       "这正是「无法运行该程序」弹窗的**典型来源**。"
                                       "★ 这是覆盖缺口：DLL 载荷需要静态分析或 DLL 专用"
                                       "加载路径，当前未做动态观察。";
                                *verdict = "not_applicable";
                                return false;
                            }
                            if (ext == ".sys") {
                                *why = "目标是**内核驱动**（.sys）——Start.exe 无法启动驱动，"
                                       "弹「无法运行该程序」属必然。★ 覆盖缺口：驱动需单独"
                                       "的加载/静态分析路径。";
                                *verdict = "not_applicable";
                                return false;
                            }
                            if (machine != 0x8664 && machine != 0x014C) {
                                *why = "PE 架构不受支持（machine=0x" + hex4(machine) +
                                       "，仅支持 x64/x86）→ 本机无法直接运行，"
                                       "送进去只会弹「无法运行该程序」。";
                                *verdict = "not_applicable";
                                return false;
                            }
                            return true;   // ✅ 可执行性体检通过
                        }
                    }
                }
            }
        }

        if (!transient.empty() && lastTry) {
            *why     = transient + "（重试 6 次仍未就绪）";
            *verdict = "error";
            return false;
        }
        Sleep(500);   // 给「先建后写」留出把内容落全的时间
    }
    *why     = "可执行性体检未通过（重试 6 次仍不满足）";
    *verdict = "error";
    return false;
}

static bool ScanOne(const Config& cfg, const std::string& targetPath,
                    const std::string& label, bool dryrun, int waitSec, Report& sub) {
    sub = Report();
    sub.file   = targetPath;
    sub.when   = NowStr();
    sub.dryrun = dryrun;

    int wait = (waitSec > 0) ? waitSec : 90;
    if (wait < 10)  wait = 10;
    if (wait > 600) wait = 600;

    // ★★ 2026-10-01（银泊裁定）：`wait` 不是"只给样本跑的时间"，而是**送检总预算** ——
    //   进度卡显示的倒计时就是它（见 NotifySandboxProgress(targetPath, wait)），
    //   所以「活跃期 + 驻留观察期」必须凑满它，才能做到**进度条走完 = 结果卡出现**。
    //   旧实现的病灶：活跃期上限是 `wait + 60`，留观又能 4 秒自收敛 →
    //   样本 3 秒退出、8 秒出结果，而进度卡还在数它那 90 秒（用户："没等留观就弹结果"）。
    //   现在：活跃期最多吃掉 `wait - kMinResidentSec`，剩下的全部留给留观；
    //   留观再少也要跑满 kMinResidentSec（银泊："至少跑满固定时长"）。
    const int kMinResidentSec = 30;              // 留观保底时长
    int activeCapSec = wait - kMinResidentSec;   // 样本活跃期上限
    if (activeCapSec < 10) activeCapSec = 10;    // wait 很小（人工调试）时的兜底

    const std::string box     = dryrun ? cfg.box : MakeBoxName();
    const std::string boxRoot = cfg.sandboxUserRoot + "\\" + box;
    sub.box = box;

    LogDbg("[sandbox] 开始分析：" + targetPath +
           (label.empty() ? std::string() : ("（来源 " + label + "）")) +
           "（dryrun=" + std::string(dryrun ? "1" : "0") +
           "，观察 " + std::to_string(wait) + "s，box=" + box + "）");

    // ---- ★ 送检前置闸门（2026-10-01）----
    //   不满足"能被 Start.exe 直接启动"的文件**根本不调用 Start.exe** ——
    //   既从源头消除 Sandboxie「无法运行该程序」弹窗，也省下一次沙箱名额与观察窗。
    //   放在**建箱之前**：避免建了箱却因为不送检而白建又白销毁。
    if (!dryrun) {
        std::string preWhy, preVerdict;
        if (!PreflightRunnable(targetPath, &preWhy, &preVerdict)) {
            sub.verdict = preVerdict.empty() ? "error" : preVerdict;
            sub.summary = "未送入沙箱动态分析（前置体检未通过）。" + preWhy;
            sub.err     = preWhy;
            sub.cleanup = "未建箱，无需销毁";
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (sub.verdict == "error") g_vError++;
            }
            LogDbg("[sandbox] ★送检前置闸门拦截（未调用 Start.exe，因此不会有"
                   "「无法运行该程序」弹窗）→ verdict=" + sub.verdict +
                   "，原因：" + preWhy + "；文件：" + targetPath);
            return false;
        }
    }

    // ---- ⓪ 新建并配置一次性 box ----
    if (!dryrun) {
        std::string boxMsg;
        if (!CreateBox(cfg, box, &boxMsg)) {
            sub.verdict = "error";
            sub.err     = "无法创建沙箱箱体：" + boxMsg +
                          "。未送检 —— 请确认 SbieSvc 正在运行、SbieIni.exe 可用、"
                          "且系统里只有一份 Sandboxie 安装。";
            sub.cleanup = "未建箱，无需销毁";
            std::lock_guard<std::mutex> lk(g_mtx);
            g_vError++;
            LogDbg("[sandbox] " + sub.err);
            return false;
        }
        std::lock_guard<std::mutex> lk(g_mtx);
        g_boxMade++;
        // ★★ 2026-10-01（P0）：清空上一轮残留的 beacon，保证本轮归属可信。
        //   必须在**送检之前**、且在 ReadProbeBeacons 之前 —— 否则会拿旧文件
        //   判定"探针跑过了"（实测被 8 小时前的残留文件骗过）。
        {
            const int wiped = ClearStaleBeacons(cfg);
            if (wiped > 0)
                LogDbg("[sandbox] 送检前清空残留 beacon：删除 " + std::to_string(wiped) +
                       " 个（目录 " + cfg.probeBeaconRoot + "）—— 防止用上一轮文件判定本轮");
        }
    }

    // ---- ① 事前快照 ----
    // ★ 一次性 box 下"事前必空"是**结构性保证**（目录刚被新建、上一轮已销毁），
    //   而不是"希望它空"。所以事前集合为空是正常的，取不到也不算故障。
    Snap before, after;
    size_t nBefore = 0, nAfter = 0;
    const bool beforeExisted = DirExistsW(U2W(boxRoot));
    TakeSnap(boxRoot, before, nBefore);   // 目录不存在 → 空快照
    LogDbg("[sandbox] 事前快照：目录" + std::string(beforeExisted ? "已存在" : "尚不存在") +
           "，条目=" + std::to_string(nBefore) + "（一次性 box 应为 0）");

    const ULONGLONG t0 = GetTickCount64();

    // ★ 2026-10-01：驻留观察的基线 —— 送检前就已存在的进程 PID（见 ResidentWatch）。
    //   驻留期靠"加载了 SbieDll.dll"归属 box 进程，必须减去这批常驻进程，
    //   否则本机上**任何**已存在的沙箱程序都会被误算成本轮残留。
    std::set<DWORD> baselinePids;

    // ---- ② 送检（或 dryrun 只等待）----
    if (!dryrun) {
        // ★ /silent（2026-09-27 加入）：抑制 Start.exe 自身这一侧的提示类 UI。
        //   ⚠️ 必须说清它的**边界**：实测它**挡不住 SbieSvc 拉起 agent**
        //      （四组对照里"原值配置 + /silent"照样拉起 SandMan 并弹窗）。
        //      真正挡住的是 QuietDown 里的 SbieCtrl_EnableAutoStart=n。
        //      /silent 在这里是"顺手压掉 Start.exe 自己可能的气泡"的补充手段。
        //   ★ 安全性已验证：加 /silent 后样本**仍然正常执行**（样本自身写的
        //      日志文件 5/5 次完整落盘），不会造成"送检静默失效"的假阴性。
        std::wstring cmd = L"\"" + U2W(cfg.startExe) + L"\" /box:" + U2W(box) +
                           L" /silent /wait \"" + U2W(targetPath) + L"\"";
        // ★ 阶段二：把探针所需的 3 个环境变量塞进子进程（会被 Start.exe 继承给样本）。
        //   探针 DLL 在 DllMain 里读它们决定 is_target / 加速倍率 / beacon 目录。
        // ★★ 2026-09-30 根因修复：以**交互用户身份在会话 1**启动（见文件上方"会话感知
        //   启动"）。旧版裸 CreateProcessW 落在 Session 0 → Start.exe 挂死 ~150s、
        //   样本从不启动、结论恒 clean score=0（假阴性）。环境块也改用用户令牌构造。
        HANDLE hUserTok = GetActiveUserToken(nullptr);
        std::wstring childEnv = BuildChildEnv(hUserTok, targetPath, cfg);
        // ★ 进度卡只在此发一次（样本开跑即通知"正在检测"）。等待循环里**不再反复发** ——
        //   每发一次就经 SpawnInUserSession 起一个独立 Electron 进程=叠一张卡，多次调用会让
        //   "送进沙箱检测"倒计时卡一张接一张（即用户反馈的"没完没了 / 又倒计时30秒"）。
        //   卡片关闭由前端在结果卡到达时统一处理（toast main.js 轮询哨兵文件）。
        // ★ 显示用 DisplayPath：若本次是「封锁原件 + 送副本」，卡片必须显示**原件路径**
        //   （用户认得的那个），而不是 holds\ 下的副本路径（纯内部实现细节）。
        NotifySandboxProgress(DisplayPath(targetPath), wait);
        // ★ 2026-10-01：抓基线 —— 此刻系统里已有的一切进程都不属于本轮 box
        //   （放在送检前最后一刻，避免把 toast 等本进程自己拉起的东西算进来）。
        CollectAllPids(&baselinePids);
        PROCESS_INFORMATION pi{};
        if (!LaunchInActiveSession(hUserTok, cmd, childEnv, &pi)) {
            const DWORD e = GetLastError();
            if (hUserTok) CloseHandle(hUserTok);
            sub.verdict = "error";
            sub.err     = "无法在沙箱中启动样本（Start.exe 调用失败，err=" + std::to_string(e) + "）";
            LogDbg("[sandbox] " + sub.err);
            std::string dmsg; DestroyBox(cfg, box, &dmsg);
            sub.cleanup = dmsg;
            return false;
        }
        if (!hUserTok)
            LogDbg("[sandbox] ⚠ 未取到交互用户令牌，退回服务会话启动（沙箱可能挂死，结果不可信）");
        // 分片等待：每 5 秒检查一次停止信号与超时（进度卡只在样本开跑时发一次，
        // 见上方 CreateProcessW 前；循环内不再反复 NotifySandboxProgress，避免叠卡片）。
        std::vector<std::string> netConns;   // ★ 网络嗅探累积（活跃期 + 驻留期）
        std::set<DWORD> boxPids;             // ★ 本轮确认属于本 box 的 PID（累积）
        for (;;) {
            DWORD w = WaitForSingleObject(pi.hProcess, 2000);
            if (w != WAIT_TIMEOUT) break;
            CollectPidTree(pi.dwProcessId, &boxPids);     // ★ 累积样本进程树
            SniffTcpForPids(boxPids, &netConns);          // ★ 每 2 秒采一次网络
            const int el = (int)((GetTickCount64() - t0) / 1000);
            if (sf::IsStopRequested()) break;
            // 超时强杀：样本挂了/等待交互时不能让分析线程永远占着。
            // ★ 2026-10-01：上限由 `wait + 60` 收窄为 activeCapSec —— 把剩余时间让给留观期，
            //   否则样本拖满预算时留观就没时间可用了。
            if (el > activeCapSec) {
                LogDbg("[sandbox] 样本超时未退出（活跃期上限 " + std::to_string(activeCapSec) +
                       "s），强制结束并为驻留观察让出时间");
                TerminateProcess(pi.hProcess, 0);
                break;
            }
        }
        CollectPidTree(pi.dwProcessId, &boxPids);         // 退出前最后采一次
        SniffTcpForPids(boxPids, &netConns);
        DWORD ec = 0;
        GetExitCodeProcess(pi.hProcess, &ec);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        // ⚠️ ec 是**样本自身的退出码**：Start.exe /wait 会原样透传
        //   （实测样本 exit 3 / exit 7 → Start.exe 也返回 3 / 7）。
        //   所以 **不能拿 ec≠0 当"送检被拒"的判据**。送检是否真正发生，
        //   由下面 ③ 的"会话痕迹"闸门判定。
        LogDbg("[sandbox] 样本已退出，exitCode=" + std::to_string(ec) +
               "（样本自身退出码，不能作为送检成败判据）");

        // ★★★ 2026-10-01：驻留观察期（用户需求）—— 主进程退出 ≠ 行为结束。
        //   在这里（/terminate **之前**）继续观察 box 内残留进程 / 二次落地 / 持续外联。
        //   银狐类样本典型形态：主进程快速退出 → 守护子进程驻留 → 继续外联 C2 / 二次落地。
        //   旧实现样本一退立即 /terminate 全 box ⇒ 只采了运行最后一帧。详见 ResidentWatch。
        // ★★ 留观预算 = 总预算 − 已用掉的活跃期 —— 两者相加正好是进度卡的倒计时秒数。
        //   样本秒退 → 留观吃掉几乎全部预算；样本拖满 → 留观仍保底 kMinResidentSec。
        const int activeUsedSec = (int)((GetTickCount64() - t0) / 1000);
        int residentBudget = wait - activeUsedSec;
        if (residentBudget < kMinResidentSec) residentBudget = kMinResidentSec;
        LogDbg("[sandbox] 时间预算：总计 " + std::to_string(wait) + "s，样本活跃期已用 " +
               std::to_string(activeUsedSec) + "s → 驻留观察预算 " +
               std::to_string(residentBudget) + "s（进度卡走完即出结果）");
        ResidentWatch(box, boxRoot, residentBudget, before, baselinePids,
                      &boxPids, &netConns, sub);

        // ★ 网络行为去重记录（活跃期 + 驻留期合并）
        DedupStrings(&netConns);
        sub.netConns = netConns;
        sub.netC2    = !netConns.empty();

        // 终止箱内进程：① 让文件句柄释放（否则快照/diff 会读到半写状态）
        //               ② **让注册表 hive 卸载** —— 离线解析 hive 需要它已卸载
        // ★ 会话感知（同 DestroyBox）：以交互用户身份终止，否则会找错 box 目录
        RunStartToolW(L"\"" + U2W(cfg.startExe) + L"\" /box:" + U2W(box) + L" /terminate", 30000);
        Sleep(1500);   // 落定：沙箱内进程退出后写入可能仍在刷盘
        // ★ 阶段二：在销毁 box 之前读取探针 beacon（此时 box 还在，beacon 还在盘上）
        ReadProbeBeacons(boxRoot, sub);
    } else {
        // dryrun：不送检，只把观察窗口走完（人工在此期间操作沙箱目录）
        for (int el = 0; el < wait; el += 5) {
            if (sf::IsStopRequested()) break;
            Sleep(5000);
        }
    }

    // ---- ③ 事后快照 + "样本真的跑起来了"闸门 ----
    // ★★★ 判据（2026-09-30 重写）：**box 内是否出现 drive\ 或探针 beacon**
    //   旧判据 RegHive **已被证伪**：实测（23:35 那轮）SbieSvc 在 box 初始化阶段就
    //   把 RegHive 建好了 —— 当时样本因"会话错误"**根本没跑**，box 里却照样有 RegHive
    //   → 闸门误判成"送检生效"→ 结论 clean（**假阴性**，用户看到的"沙箱判定安全"）。
    //   RegHive 只能证明"SbieSvc 碰过这个 box"，不能证明"样本执行过"。
    //   真正可靠的是**样本进程在沙箱里活动过的痕迹**：
    //     · box\drive\ —— 沙箱进程一旦启动，Sandboxie 就会为它建虚拟化目录
    //       （实测：用户会话跑通的 box 全有 drive\；Session 0 挂死的那批全没有）；
    //     · 探针 beacon —— 注入的 probe DLL 只有在样本进程里跑起来才会写。
    //   两者皆无 → 样本从未执行 → error（结果不具参考价值），**绝不判 clean**。
    // ★★ 2026-10-01 二次修正（P0，闸门恒真 bug）：右腿必须用 `probeTargetRan`
    //   而不是 `probeLoaded`。旧代码用 `probeLoaded`，而它当时只看 dll_loaded=1
    //   —— 探针经 box InjectDll 会注入**箱内每个进程（含 Start.exe）**，那些
    //   beacon 必然带 is_target=0，于是右腿**恒真** → 闸门恒真 → **假 clean**。
    //   实测铁证：同一行日志里 `drive=无`（= 没有任何沙箱进程跑起来）与
    //   `样本执行=是` 同时出现 —— 自相矛盾，就是这条腿在骗人。
    //   现在：`probeLoaded` 只在 is_target=1 时置位，右腿改用 probeTargetRan，
    //   语义 = "**送检样本本体**确认在沙箱里执行过"。
    const bool afterExisted = TakeSnap(boxRoot, after, nAfter);
    const bool hiveExists   = FileExistsW(U2W(boxRoot + "\\RegHive"));
    const bool driveExists  = DirExistsW(U2W(boxRoot + "\\drive"));
    const bool ranEvidence  = driveExists || sub.probeTargetRan;

    if (!dryrun && !ranEvidence) {
        // ★ 取证：目标文件此刻的 PE 体检（区分"文件没写完"与"沙箱拒跑"）
        const std::string tgtDiag = DescribeExeForDiag(targetPath);
        LogDbg("[sandbox] 送检失败取证：目标文件 → " + tgtDiag);
        sub.verdict = "error";
        sub.err     = "送检未在沙箱中生效：box（" + box + "）跑完后既没有虚拟化目录 drive\\、"
                      "也没有任何**目标样本进程**写出的 beacon"
                      "（本轮非目标进程 beacon=" + std::to_string(sub.probeOtherLoaded ? 1 : 0) +
                      "，只证明探针 DLL 注入生效、不证明样本跑过），说明样本**根本没有在沙箱里执行**。"
                      "本次结果【不具参考价值】（不代表干净）。"
                      "★ 目标文件体检：" + tgtDiag + "。"
                      "★ 首要怀疑：① 服务与沙箱不在同一会话"
                      "（服务在 Session 0 直拉 Start.exe 会挂死；应以交互用户令牌 "
                      "CreateProcessAsUser 送到用户会话）；② Start.exe 起得来但**样本被拒**"
                      "（常见表现 = 沙箱弹出「无法运行该程序」类提示）；③ 检查 ClosedIpcPath=*、"
                      "SbieSvc 是否只有一份、Start.exe 是否取自 SbieSvc 注册表指向的安装。";
        sub.elapsedSec = (int)((GetTickCount64() - t0) / 1000);
        LogDbg("[sandbox] " + sub.err);
        std::string dmsg; DestroyBox(cfg, box, &dmsg);
        sub.cleanup = dmsg;
        return false;
    }
    DiffSnap(before, after, sub.artifacts);
    // ★ 阶段二：探针 beacon 文件本身不是"样本落地物"，必须剔除，否则会被当成恶意载荷评分
    {
        std::vector<Artifact> kept;
        kept.reserve(sub.artifacts.size());
        for (auto& a : sub.artifacts) {
            if (LowerAscii(a.rel).find("silverfoxprobe") != std::string::npos) continue;
            kept.push_back(a);
        }
        if (kept.size() != sub.artifacts.size())
            LogDbg("[sandbox] 已剔除 " + std::to_string(sub.artifacts.size() - kept.size()) +
                   " 个探针 beacon 伪落地物");
        sub.artifacts.swap(kept);
    }
    LogDbg("[sandbox] 事后快照：条目=" + std::to_string(nAfter) +
           "，hive=" + std::string(hiveExists ? "有" : "无") +
           "，drive=" + std::string(driveExists ? "有" : "无") +
           "，样本执行=" + std::string(ranEvidence ? "是" : "否") +
           "，diff=" + std::to_string(sub.artifacts.size()));

    // ---- ④ 注册表行为（离线解析 hive，2026-09-30 重构：枚举键 + 值）----
    std::string hiveErr;
    std::vector<HiveEntry> hiveEntries;
    bool hiveParsed = false;
    if (ranEvidence && !dryrun) {
        hiveParsed = HiveKeyList(boxRoot + "\\RegHive", &hiveEntries, &hiveErr);
    }

    int highReg = 0, susReg = 0;
    if (hiveParsed) {
        for (auto& e : hiveEntries) {
            const std::string low = LowerAscii(e.key);
            int cls = ClassifyHiveKey(low);
            // ★ 值数据指向可执行体 = 强持久化证据（Run 值 = "C:\evil\a.exe"、
            //   IFEO 的 Debugger 值 = 被劫持程序的 loader）。即使键路径未命中高危，
            //   值数据也能证明这是"自动拉起恶意载荷"的入口。
            bool valuePointsExe = false;
            for (auto& kv : e.values) {
                std::string vlow = LowerAscii(kv.second);
                bool sysSafe = (vlow.find("\\windows\\") != std::string::npos ||
                                vlow.find("\\program files") != std::string::npos ||
                                vlow.find("\\programdata\\microsoft") != std::string::npos);
                if (!sysSafe) { valuePointsExe = true; break; }
            }
            if (valuePointsExe && cls < 2) cls = 2;
            if (cls == 0) continue;
            Artifact ar;
            ar.rel   = e.key;             // 键路径并不是文件路径，tree 字段区分
            ar.tree  = "reg";
            ar.size  = 0;
            ar.action = "new";
            if (cls == 2) {
                ar.score = 70;
                ar.why   = "沙箱内写入注册表持久化位置（自启动/服务/劫持类，银狐核心行为）；";
                highReg++;
            } else {
                // ★ 2026-09-29 修正：非系统自建注册表键（程序写自己的配置键）
                //   是**最正常的程序行为**，绝不该计分。旧实现每个 +35 分，
                //   良性程序只要碰 15 个左右注册表键（常见）就累计 525 分越过
                //   恶意阈值(120) —— 导致沙箱**永远打不出 clean**，任何正常
                //   软件都被判 malicious。真正该打分的只有 cls=2 持久化/劫持位置。
                //   → 此处 score 归 0；susReg 计数保留，仍写进报告/日志作旁证观察。
                ar.score = 0;
                ar.why   = "沙箱内新建了非系统注册表项（程序自建配置键，正常行为，不计分）；";
                susReg++;
            }
            // ★ 记录值证据细节（写明样本到底写了什么自启动项）
            if (!e.values.empty()) {
                ar.why += " 写入值：";
                for (auto& kv : e.values) ar.why += kv.first + "=" + kv.second + "；";
            }
            sub.artifacts.push_back(ar);
        }
        LogDbg("[sandbox] 注册表解析：共 " + std::to_string(hiveEntries.size()) + " 键，高危 "
               + std::to_string(highReg) + "、可疑自建 " + std::to_string(susReg));
    } else if (ranEvidence && !dryrun) {
        // 解析失败**必须留痕**：否则"没解析到注册表"会被静默当成"没有注册表行为"
        LogDbg("[sandbox] ★注册表 hive 解析失败：" + hiveErr +
               " —— 本次报告未包含注册表行为，属**覆盖缺口**而非'干净'");
    }

    // ---- ⑤ 病毒库点查（最强判据，优先）----
    bool   anyHash = false;
    std::string hashWhy;
    {
        int checked = 0;
        for (auto& a : sub.artifacts) {
            if (a.tree == "reg") continue;          // 注册表键没有文件可哈希
            if (checked >= 120) {   // 防呆：落地物极多时不做无上限的哈希计算
                LogDbg("[sandbox] 落地物过多，哈希点查截断于 120 个");
                break;
            }
            const std::string e = ExtLower(a.rel);
            const bool worthChecking = (e == ".exe" || e == ".dll" || e == ".sys" ||
                                        e == ".scr" || e == ".cpl" || e == ".ocx" ||
                                        e == ".js" || e == ".vbs" || e == ".ps1" ||
                                        e == ".bat" || e == ".cmd" || e == ".hta" ||
                                        e == ".jar" || e == ".com" || e == ".zip" || e == ".7z" || e == ".rar");
            if (!worthChecking) continue;
            checked++;
            std::string phys = boxRoot + "\\" + a.rel;
            std::string why;
            if (sf::hashverdict::MaliciousVerdict(phys, &why) >= 2) {
                anyHash = true;
                a.score += 200;
                a.why   += "★病毒库命中（" + why + "）；";
                if (hashWhy.empty()) hashWhy = a.rel + " → " + why;
            }
        }
    }

    // ---- ⑥ 启发式评分 ----
    ScoreArtifacts(sub.artifacts);
    sub.score = SumScore(sub.artifacts);

    // ---- ⑦ 结论 ----
    // ★ 观测时长必须**先算出来**，因为下面的文案要用它（2026-09-27 修隐患）。
    sub.elapsedSec = (int)((GetTickCount64() - t0) / 1000);

    const int nExec = CountExec(sub.artifacts);
    int nFiles = 0;
    for (auto& a : sub.artifacts) if (a.tree != "reg") nFiles++;
    const std::string regNote = hiveParsed
        ? ("；注册表高危项 " + std::to_string(highReg) + " 个")
        : std::string("；★注册表未解析（覆盖缺口）");

    // ★ 结构化记录"这个结论是库命中得出的还是行为分推定的"（见 sandbox.h 该字段说明）
    sub.hashHit = anyHash;

    // =======================================================================
    //  ★★★ 2026-10-03：探针归属闸门（银泊裁定「评分采信探针归属」）
    // =======================================================================
    //  探针在**目标样本进程内部**做 hook —— 它看到的才是"样本干了什么"。
    //  而落地物 diff 只知道"沙箱目录比开始时多了哪些文件"，它**不区分是谁写的**：
    //  box 初始化残留、沙箱辅助进程、乃至解释器/运行时的自生缓存，全都会被算进来。
    //  （项目已有同型教训：diff 用的是**事后快照**，天然包含驻留观察期与运行时
    //   自生的全部产物 —— 见 DiffSnap 调用点。）
    //  ∴ 当探针确认目标进程跑过、却**一个行为都没观测到**时，diff 出来的东西
    //    不能归因给样本。此时若还让"分数堆积"单独判恶意，等于把**无法归属的
    //    噪声**当证据 —— 这正是 Python 误报的直接成因（8 个运行时自生缓存=240 分）。
    //
    //  ★ 为什么不是"探针没看到就一律放过"：护栏仍在 —— 只要存在任一**独立旁证**
    //    （病毒库命中 / 可执行体落地 / 高危注册表 / C2 外联 / 批量破坏用户数据），
    //    探针盲区就不能当免罪符（探针 hook 面可能有缺口，样本也可能绕过）。
    //    这与 scanner.cpp「解释器父链单信号不定性、须叠加独立旁证」同一条纪律。
    // =======================================================================
    const bool probeSawNothing = sub.probeTargetRan &&
                                 sub.probeFile == 0 && sub.probeProcess == 0 &&
                                 sub.probeReg == 0 && sub.probeNet == 0 &&
                                 sub.probeEvents == 0;
    const bool hasIndependentSignal = anyHash ||
                                      (int)sub.dataTouched.size() >= kRansomUserFiles ||
                                      highReg > 0 ||
                                      sub.netC2 ||
                                      nExec > 0;
    const bool scoreOnlyUnattributed = probeSawNothing && !hasIndependentSignal;

    if (anyHash) {
        sub.verdict = "malicious";
        sub.verdictStrong = true;          // 字节同一性 = 最高置信
        if (sub.score < 200) sub.score = 200;
        sub.summary = "沙箱内落出 " + std::to_string(nFiles) +
                      " 个文件，其中命中病毒库：" + hashWhy;
    } else if ((int)sub.dataTouched.size() >= kRansomUserFiles) {
        // ★★★ 2026-10-01 新增档：勒索批量破坏用户数据（探针 hook 面补齐后才有此数据）
        //   放在 score 判定**之前**，因为它比分数更硬 —— 分数是权重堆出来的，
        //   这条是"直接观测到 20+ 个既有用户文档被覆写/删除"这一事实本身。
        sub.verdict = "malicious";
        sub.verdictStrong = true;          // 直接观测到的事实，高置信
        if (sub.score < kScoreHigh) sub.score = kScoreHigh;
        const int nData = (int)sub.dataTouched.size();
        sub.summary = "沙箱内观察到对 " + std::to_string(nData) +
                      " 个用户数据文件的批量改写/删除（勒索加密特征；探针捕获覆写 " +
                      std::to_string(sub.probeWrite) + " 次、删除 " +
                      std::to_string(sub.probeDel) + " 次）。示例：" +
                      sub.dataTouched[0];
    } else if (scoreOnlyUnattributed && sub.score >= kScoreHigh) {
        // ★ 分数够高，但**无法归属**到样本行为 → 降为 suspicious 并明示（不判恶意）
        sub.verdict = "suspicious";
        if (sub.score < kScoreSus) sub.score = kScoreSus;
        sub.summary = "沙箱目录内出现 " + std::to_string(nFiles) + " 个落地物（累计 " +
                      std::to_string(sub.score) + " 分），但**探针在目标样本进程内零观测**"
                      "（文件/进程/注册表/网络行为均为 0）—— 无法把这些落地物归属到样本，"
                      "高度疑似沙箱环境自建或运行时自生文件。**不判恶意**（避免误杀），"
                      "请人工确认。";
    } else if (sub.score >= kScoreHigh) {
        sub.verdict = "malicious";
        // ★ 纯分数推定**不是**高置信（可能来自无法归属的噪声）→ 不入本地恶意库
        sub.verdictStrong = false;
        sub.summary = "沙箱内落出 " + std::to_string(nFiles) + " 个文件（可执行 " +
                      std::to_string(nExec) + " 个），行为特征累计 " + std::to_string(sub.score) +
                      " 分" + regNote + "，达恶意阈值（未命中病毒库，系行为推定）";
    } else if (highReg > 0 && (nExec > 0 || sub.netC2)) {
        // ★ 持久化 + 行为（落地或 C2）= 铁证组合 → 恶意
        sub.verdict = "malicious";
        sub.verdictStrong = true;          // 组合铁证，高置信
        if (sub.score < 130) sub.score = 130;
        sub.summary = "沙箱观察到注册表持久化与" + std::string(sub.netC2 ? "外部 C2 连接" : "落地可执行") +
                      "的组合行为，达恶意阈值（未命中病毒库，系行为推定）";
    } else if (sub.score >= kScoreSus || sub.netC2) {
        // ★ 网络外联单独 = 强可疑（C2 信标形态），但不杀
        sub.verdict = "suspicious";
        if (sub.score < kScoreSus) sub.score = kScoreSus;
        std::string netNote = sub.netC2 ? ("；网络：观察到 " + std::to_string(sub.netConns.size()) +
                                          " 个外部连接（疑似 C2 信标）") : "";
        sub.summary = "沙箱内落出 " + std::to_string(nFiles) + " 个文件（可执行 " +
                      std::to_string(nExec) + " 个），累计 " + std::to_string(sub.score) +
                      " 分" + regNote + netNote + "，建议人工确认";
    } else {
        sub.verdict = "clean";
        // ===================================================================
        //  ★★ 观测窗口文案必须报**实测值**，不能报计划值（2026-09-27 修）
        // ===================================================================
        //  旧实现写的是「观察 <wait> 秒内未观察到…」，而 wait 是**计划**时长。
        //  但下面的送检循环是 `if (w != WAIT_TIMEOUT) break;` —— 样本自己退了
        //  就立刻跳出。实测一个 1 秒就退出的样本，计划窗口 90 秒，实际只看了
        //  1~3 秒，报告却声称"观察了 90 秒"。
        //
        //  ★ 这属于**报告在撒谎**，而且是最容易骗过审阅者的一种：数字看起来
        //    具体、专业、有说服力，读者不会去质疑"你真的看了 90 秒吗"。
        //    对"延迟几分钟才发作"的样本，把 3 秒观察写成 90 秒观察，
        //    等于把**零覆盖**包装成**接近全覆盖** —— 这正是本模块最危险的
        //    一类错误（假阴性）。
        //    项目已有同型纪律：不信返回码只看回读事实（service.cpp
        //    ChangeServiceConfig2）、日志丢行不得当成"代码没跑"。
        // ===================================================================
        std::string win = "观察 " + std::to_string(sub.elapsedSec) +
                          " 秒内未观察到落地/持久化行为";
        if (!dryrun && sub.elapsedSec + 5 < wait) {
            // ★ 差 5 秒以上才提示：避免"等了 89 秒 / 计划 90 秒"这种
            //   正常抖动被写成告警，把真问题淹掉。
            win += "（★ 样本在 " + std::to_string(sub.elapsedSec) +
                   " 秒后即自行退出，实际观察窗口**短于计划的 " + std::to_string(wait) +
                   " 秒**。这是正常现象，但意味着观察时长不足 —— "
                   "对「延迟几分钟才发作」的样本不构成任何保证）";
        }
        // ★ 这句话必须留着：沙箱"没看到"不等于"没有"。
        sub.summary = win + regNote + "。注意：这不等于安全 —— 样本可能检测到沙箱而休眠、"
                      "延迟触发，或依赖特定环境才会发作";
    }

    // ★ 阶段二：把探针自报情况并入结论（覆盖缺口必须明示，不得静默成"干净"）
    //   ★ 2026-10-01 语义修正后三分支：probeLoaded 现在专指"**目标样本**跑起来了"。
    if (!cfg.probeDll64.empty()) {
        if (sub.probeLoaded) {
            sub.summary += "；探针确认目标进程执行，捕获行为 " + std::to_string(sub.probeEvents) +
                           " 条（文件 " + std::to_string(sub.probeFile) + " / 进程 " +
                           std::to_string(sub.probeProcess) + " / 注册表 " +
                           std::to_string(sub.probeReg) + " / 网络 " + std::to_string(sub.probeNet) + "）";
        } else if (sub.probeOtherLoaded) {
            sub.summary += "；★探针注入生效但**未覆盖到目标样本进程**（只有非目标进程写出 beacon，"
                           "如 Start.exe / 沙箱辅助进程）—— 常见于 32 位样本未被 64 位探针覆盖、"
                           "或注入被样本反制，观察存在覆盖缺口";
        } else {
            sub.summary += "；★探针注入未生效（沙箱内无任何进程写出 beacon），阶段二行为视角缺失，"
                           "本次结论仅来自快照 diff，不构成全覆盖";
        }
    }

    // ★ 2026-10-01：驻留观察期结论并入摘要（主进程退出后 box 内还发生了什么）
    //   计分纪律：残留进程**本身不定罪**（正常安装器也会留子进程）；
    //   但"退出后仍在继续外联"是 C2 驻留的强形态 —— 该信号已通过 netC2 通道计入结论，
    //   这里只在摘要里把事实说清楚，供人工复核。
    if (sub.residentSec > 0) {
        if (sub.residentProcs > 0 || sub.residentNewFiles > 0 || sub.residentOutbound) {
            std::string rn = "；★主进程退出后继续驻留观察 " + std::to_string(sub.residentSec) +
                             " 秒：残留进程峰值 " + std::to_string(sub.residentProcs) + " 个";
            if (!sub.residentExe.empty()) {
                rn += "（";
                for (size_t i = 0; i < sub.residentExe.size(); i++) {
                    if (i) rn += "、";
                    rn += sub.residentExe[i];
                }
                rn += "）";
            }
            if (sub.residentNewFiles > 0)
                rn += "，退出后二次落地 " + std::to_string(sub.residentNewFiles) + " 个文件";
            if (sub.residentOutbound)
                rn += "，★退出后仍在建立外部连接（驻留 C2 形态）";
            sub.summary += rn;
        } else {
            sub.summary += "；主进程退出后继续驻留观察 " + std::to_string(sub.residentSec) +
                           " 秒，box 内未再有残留进程/落地/外联";
        }
    }

    LogDbg("[sandbox] 结论：" + sub.verdict + " score=" + std::to_string(sub.score) +
           " 文件物=" + std::to_string(nFiles) +
           " 可执行=" + std::to_string(nExec) +
           " 注册表高危=" + std::to_string(highReg) +
           " 注册表自建=" + std::to_string(susReg) +
           " hashHit=" + std::string(anyHash ? "1" : "0") +
           " 驻留进程峰值=" + std::to_string(sub.residentProcs) +
           " 退出后外联=" + std::string(sub.residentOutbound ? "1" : "0") +
           " 用时=" + std::to_string(sub.elapsedSec) + "s");

    // ---- ⑧ 销毁一次性 box（无论结论如何，都要销毁）----
    if (!dryrun) {
        std::string dmsg;
        const bool gone = DestroyBox(cfg, box, &dmsg);
        sub.cleanup = dmsg + (gone ? "" : "（已记入待回收清单，下轮重试）");
        if (!gone) GcAdd(box);
    } else {
        sub.cleanup = "dryrun：未建箱，无需销毁";
    }
    return true;
}

// ---------------------------------------------------------------------------
//  临时解压目录的清理
// ---------------------------------------------------------------------------
// ★ 安全闸门：只删**本模块自己算出来**的 %TEMP%\SilverFoxSandbox\ 下的子目录。
//   解压出来的很可能是恶意文件，必须及时抹掉；但"删目录"这个动作本身危险，
//   所以三条同时满足才动手：
//     (a) 路径里含 "\silverfoxsandbox\"
//     (b) 不含 ".."（防拼接逃逸）
//     (c) 长度 > 该前缀长度（不是前缀本身）
//   宁可漏删（临时目录里多留一份），也绝不越界删用户目录。
static bool SafeRemovePayloadDir(const std::string& dir) {
    const std::string low = LowerAscii(dir);
    if (low.size() < 24) return false;
    if (low.find("\\silverfoxsandbox\\") == std::string::npos) return false;
    if (low.find("..") != std::string::npos) return false;
    const std::wstring w = U2W(dir);
    RemoveTreeW(w, 0);
    const bool gone = !PathExistsW(w);
    if (!gone) LogDbg("[sandbox] ★临时解压目录未能完全删除：" + dir +
                      "（残留的是解压出的文件，下次送检前会重试清理）");
    return gone;
}

// ---------------------------------------------------------------------------
//  主流程（调度层）
// ---------------------------------------------------------------------------
// ★★ 本层的存在理由：**压缩包不能直接送进沙箱**。
//   沙箱能观察的只有"进程跑起来之后干了什么"，而压缩包不是可执行体 ——
//   把它交给沙箱，它既不会自解压也不会执行任何东西，于是什么行为都不会发生。
//   如果据此报 clean，那是**假阴性**：不是"包里的东西没问题"，而是
//   **观察根本不适用**。用户会以为"沙箱验过了"，这是本模块最危险的一种错误。
//
//   所以：
//     · 可执行体（exe/dll/脚本…）→ 直接送沙箱（原路径）
//     · 归档（zip/rar/7z/…）    → 7z 解压出真实载荷 → 载荷**逐个**送沙箱
//     · 解压成功但包内没有可执行载荷 → verdict = not_applicable（★ 不是 clean）
//     · 解压失败               → verdict = error（★ 覆盖缺口，绝不能报 clean）
//
//   每个载荷各跑一轮独立的一次性 box（同一 box 跑多个样本会互相污染 diff）。
// ★★ 统一出卡口径（2026-10-01 **二次修正** · 银泊决策）—— **一律出卡**。
//
//   背景（银泊 10-01 23:00 报「沙箱分析的结果卡不显示，评分」）：
//   上一版把 error / not_applicable 判为「对用户无可操作信息」→ 只写日志不出卡。
//   实测代价（当天 guard.log 统计 124 次送检）：
//     clean 85 / **error 29（23%）** / malicious 7 / suspicious 3
//   —— 接近**每 4 次送检就有 1 次**，用户点完送检、看着进度卡走完，然后**什么都没有**。
//   银泊的判断：**「没告诉我」比「多一张卡」更糟** → 改为一律出卡。
//
//   为什么现在出卡是**安全**的（上一版担心的事都已解决）：
//     · **语义不再混淆**：toast.cpp 的 verdict 白名单已修正（error 不再被降级成
//       suspicious），index.html 也已分四档 —— 恶意(红)/可疑(黄)/干净(绿)/
//       **未能分析·不适用(灰)**，且灰色档标题刻意**不带"判定"二字**。
//       所以 error 出卡 = 灰色「沙箱未能完成分析」，**不会**被读成"这文件可疑"。
//     · **不摆假数字**：灰色档 `noScore` 收起**整条评分**（进度条+标签+数字），
//       不会出现"没分析过却写着评分 0"这种自相矛盾（原实现留了条空灰条，已于
//       同批修正为整条隐藏）。
//
//   ⚠️ 日志仍必须留痕 —— 出卡是给用户看的，日志是给排查用的，两者不能互相替代。
//      尤其 error 是**覆盖缺口**（沙箱没分析成），若不单独记一行，
//      「引擎没跑」与「跑了但没好结果」在日志里会混在一起。
static void NotifyIfActionable(const std::string& path, const std::string& verdict,
                               int score, const std::string& summary,
                               const std::string& errToken = std::string(),
                               int errLeftSec = 0) {
    // ★ 副本送检时结果卡必须挂**原件路径**（用户认得的那个）；日志仍留副本路径（证据）。
    NotifySandboxResult(DisplayPath(path), verdict, score, summary, errToken, errLeftSec);
    if (verdict != "malicious" && verdict != "suspicious" && verdict != "clean") {
        LogDbg("[sandbox] 已出「无结论」灰卡（verdict=" + verdict +
               "，不摆评分，属覆盖缺口而非判定）→ " + path);
    }
}

bool Scan(const std::string& path, bool dryrun, int waitSec, Report& out) {
    out = Report();
    out.file   = path;
    out.when   = NowStr();
    out.dryrun = dryrun;

    Config cfg;
    if (!Detect(cfg, false)) {
        out.verdict = "error";
        out.err     = "沙箱不可用：" + cfg.note;
        { std::lock_guard<std::mutex> lk(g_mtx); g_last = out; g_vError++; }
        // ★ 必须传 "error"：这里是"沙箱不可用"，不是"文件可疑"。
        //   旧版传 "suspicious" → 界面出琥珀色「可疑程序」卡 = 纯误报。
        //   但**不弹卡**：error 的决策卡由消费循环统一出（那里才有令牌与原件路径），
        //   详见 Scan 出口处 ⑤ 播报的注释（同一文件弹两张卡、路径还不一样）。
        return false;
    }
    if (cfg.sandboxUserRoot.empty()) {
        out.verdict = "error";
        out.err     = "无法确定沙箱根目录（C:\\Sandbox 下无可用用户目录，请确认 Sandboxie 已创建过 box）";
        { std::lock_guard<std::mutex> lk(g_mtx); g_last = out; g_vError++; }
        return false;   // 不弹卡：error 卡统一由消费循环出（带令牌与原件路径）
    }

    // 轮初回收：上一轮销毁失败的 box（只做一次，不随载荷数重复）
    if (!dryrun) GcSweep(cfg);

    // ---- ⓪ 决定送检清单 ----
    std::vector<Target> victims;
    std::string archTmpDir;

    if (IsArchivePath(path) && !dryrun) {
        // 解压到 %TEMP%\SilverFoxSandbox\<唯一名>（每个 box 一个唯一子目录）
        wchar_t tb[MAX_PATH] = { 0 };
        std::string tmpBase = (GetTempPathW(MAX_PATH, tb) > 0) ? W2U(tb) : std::string("C:\\Windows\\Temp\\");
        if (!tmpBase.empty() && tmpBase.back() != '\\') tmpBase.push_back('\\');
        archTmpDir = tmpBase + "SilverFoxSandbox\\p" + MakeBoxName();

        LogDbg("[sandbox] 输入是归档，先解压出真实载荷：" + path + " → " + archTmpDir);
        int    nFiles = 0;
        bool   trunc  = false;
        std::string aerr;
        if (!ArchiveToTargets(path, archTmpDir, &victims, &nFiles, &trunc, &aerr)) {
            // ★ 解压失败 = 覆盖缺口。绝不能继续往下走成 clean。
            out.verdict = "error";
            out.err     = "压缩包解压失败：" + aerr +
                          "。未能取得包内载荷，无法做行为观察 —— 本次结果"
                          "【不具参考价值】（不代表干净）。";
            SafeRemovePayloadDir(archTmpDir);
            { std::lock_guard<std::mutex> lk(g_mtx); g_last = out; g_vError++; }
            LogDbg("[sandbox] " + out.err);
            return false;   // 不弹卡：error 卡统一由消费循环出（带令牌与原件路径）
        }
        out.archExtracted = nFiles;
        out.archScanned   = (int)victims.size();
        out.archTruncated = trunc;

        if (victims.empty()) {
            // ★★ 解压成功、但包内确实没有可执行载荷。
            //    这是 not_applicable —— **不是 clean**。"沙箱无法观察这个包"
            //    与"这个包没问题"是两件完全不同的事，绝不能混为一谈。
            out.verdict = "not_applicable";
            out.score   = 0;
            out.summary = "压缩包已解压出 " + std::to_string(nFiles) +
                          " 个文件，但包内没有可执行载荷（exe/dll/脚本），"
                          "沙箱无法对它做行为观察。★ 注意：这一条**不是\"安全\"的结论**，"
                          "只是沙箱这类行为分析不适用于它 —— 静态结论保持不变。";
            out.cleanup = "未建箱（无可送检载荷）";
            SafeRemovePayloadDir(archTmpDir);
            { std::lock_guard<std::mutex> lk(g_mtx); g_last = out; g_vError++; }
            LogDbg("[sandbox] not_applicable：" + out.summary);
            NotifyIfActionable(path, "not_applicable", 0, out.summary);
            return true;
        }
    } else {
        Target t;
        t.path  = path;
        t.label = "";
        victims.push_back(t);
        if (dryrun) out.archExtracted = 0;
    }
    out.victims = victims;

    // ---- ① 载荷逐个送检 ----
    if (victims.size() > 1) {
        LogDbg("[sandbox] 本轮共 " + std::to_string(victims.size()) +
               " 个载荷需逐个送检（每个各建一个一次性 box）");
    }

    std::vector<Report> subs;
    for (size_t i = 0; i < victims.size(); ++i) {
        if (sf::IsStopRequested()) {
            LogDbg("[sandbox] 收到停止信号，剩余载荷不再送检");
            break;
        }
        Report sub;
        ScanOne(cfg, victims[i].path, victims[i].label, dryrun, waitSec, sub);
        sub.victims.clear();          // 载荷清单由外层统一持有，避免逐份重复
        subs.push_back(sub);
    }

    if (subs.empty()) {
        out.verdict = "error";
        out.err     = "未执行任何送检（服务正在停止）";
        { std::lock_guard<std::mutex> lk(g_mtx); g_last = out; g_vError++; }
        if (!archTmpDir.empty()) SafeRemovePayloadDir(archTmpDir);
        return false;
    }

    // ---- ② 聚合 ----
    // verdict 优先级：malicious > suspicious > error > clean > not_applicable
    //   error 排在 clean 之前是刻意的：只要有任何一轮**没观察成功**，
    //   整体就不能给"干净"的安心感 —— 那是覆盖率缺口，不是结论。
    int  bestScore = 0;
    bool anyMal = false, anySus = false, anyErr = false, anyClean = false, anyNA = false;
    for (size_t i = 0; i < subs.size(); ++i) {
        const Report& s = subs[i];
        if (s.score > bestScore) bestScore = s.score;
        if      (s.verdict == "malicious")      anyMal = true;
        else if (s.verdict == "suspicious")     anySus = true;
        else if (s.verdict == "error")          anyErr = true;
        else if (s.verdict == "clean")          anyClean = true;
        else if (s.verdict == "not_applicable") anyNA = true;
        for (auto a : s.artifacts) {
            a.src = victims[i].label;          // 标明证据来自哪个载荷
            out.artifacts.push_back(a);
        }
        // ★ 只要**任一**载荷是病毒库命中得出恶意结论，整体就算库命中：
        //   处置层据此走"确凿"卡片（字节同一性）而不是"可疑"卡片。
        if (s.hashHit) out.hashHit = true;
        // ★ 高置信标志同样取"任一载荷高置信即整体高置信"（供处置层决定是否入库）
        if (s.verdictStrong) out.verdictStrong = true;
        // 汇总 box 生命周期
        if (!s.box.empty()) {
            if (!out.box.empty()) out.box += ",";
            out.box += s.box;
        }
        if (!s.cleanup.empty()) {
            if (!out.cleanup.empty()) out.cleanup += " | ";
            out.cleanup += s.cleanup;
        }
        out.elapsedSec += s.elapsedSec;
        // ★ 阶段二：合并各载荷的探针自报
        if (s.probeLoaded)      out.probeLoaded      = true;
        if (s.probeOtherLoaded) out.probeOtherLoaded = true;
        if (s.probeTargetRan)   out.probeTargetRan   = true;
        out.probeFile    += s.probeFile;
        out.probeProcess += s.probeProcess;
        out.probeReg     += s.probeReg;
        out.probeNet     += s.probeNet;
        out.probeEvents  += s.probeEvents;
        if (out.probeDetail.size() < 4000) {
            if (!out.probeDetail.empty()) out.probeDetail += "\n";
            out.probeDetail += s.probeDetail;
        }
    }
    out.score = bestScore;

    if      (anyMal)   out.verdict = "malicious";
    else if (anySus)   out.verdict = "suspicious";
    else if (anyErr)   out.verdict = "error";
    else if (anyClean) out.verdict = "clean";
    else               out.verdict = "not_applicable";

    // ---- ★ 调试模式：沙箱结论留证（本轮挖矿/漏报排障最缺的一环）----
    //  为什么单独埋这里：沙箱这条链有**四层**可能断（送检门槛 / 箱内起不来 /
    //  探针 beacon 归属 / 病毒库点查），而四层最终都只汇成 verdict 一个字符串。
    //  只看 verdict 无法区分「样本确实干净」与「样本压根没在箱里跑起来」——
    //  上一轮 0xC0000135 就是后者，却因为 verdict=error 而一度被当成反沙箱逃逸。
    //  所以这里把**每一层的分项**都写下来：载荷数、四个探针位、耗时、是否库命中。
    //  ★ 只写日志，不参与判定。
    //
    //  ★ **无条件**写（不设开关），但**按档位裁剪**——这是唯一的量级控制：
    //    每轮送检只有几行，与"每进程一行的 [judge]"同量级，不构成日志压力。
    //    真正的量级风险在"每个样本逐个打一行载荷明细"上（压缩包动辄几十个载荷），
    //    所以逐载荷那行只在**非 clean** 时打：clean 的载荷没有任何可查价值。
    {
        std::string one = "载荷=" + std::to_string(subs.size()) +
            " 探针[已加载=" + (out.probeLoaded ? "1" : "0") +
            " 他进程加载=" + (out.probeOtherLoaded ? "1" : "0") +
            " 目标进程运行=" + (out.probeTargetRan ? "1" : "0") + "]" +
            " 事件[文件=" + std::to_string(out.probeFile) +
            " 进程=" + std::to_string(out.probeProcess) +
            " 注册表=" + std::to_string(out.probeReg) +
            " 网络=" + std::to_string(out.probeNet) + "]" +
            " 得分=" + std::to_string(out.score) +
            " 耗时=" + std::to_string(out.elapsedSec) + "s";

        // ★ 汇总行始终打（这是判定链的落点：四个探针位 + verdict 一起看才有用）
        LogDbg("[sandbox] 汇总 " + one + " → " + out.verdict);

        if (out.verdict != "clean") {
            // ⚠️ 循环上界必须用 subs.size()，**不能**用 victims.size()：
            //    上面那个 for 收到停止信号会 break ⇒ subs 可能比 victims 短
            //    （服务正在停止时）。按 victims.size() 索引 subs 就是越界读 ——
            //    而越界读在 release 下往往"看起来正常"，只会偶发打印乱内容。
            for (size_t i = 0; i < subs.size(); ++i) {
                LogDbg("[sandbox]   载荷 " + victims[i].label + " → " + subs[i].verdict +
                       " 得分=" + std::to_string(subs[i].score));
            }
            if (subs.size() < victims.size()) {
                LogDbg("[sandbox]   ★ 覆盖缺口：共 " + std::to_string(victims.size()) +
                       " 个载荷，只分析了 " + std::to_string(subs.size()) +
                       " 个（收到停止信号）");
            }
        }
    }

    // ---- ③ 汇总摘要 ----
    const bool multi = (subs.size() > 1);
    std::ostringstream os;
    if (multi) {
        os << "压缩包解压出 " << out.archExtracted << " 个文件，对其中的 "
           << subs.size() << " 个可执行载荷逐个做了行为分析：";
        size_t shown = 0;
        for (size_t i = 0; i < subs.size() && shown < 3; ++i, ++shown) {
            os << (i ? "；" : "") << victims[i].label << " → " << subs[i].verdict;
            if (subs[i].score > 0) os << "(" << subs[i].score << "分)";
        }
        if (subs.size() > shown) os << "；另有 " << (subs.size() - shown) << " 个";
        if (out.archTruncated)
            os << "。★ 载荷数量已达上限被截断，**未覆盖包内全部载荷**，这是覆盖缺口";
        // 先列出各载荷的结论，再补最严重那一条的细节
        std::string worst = subs[0].summary;
        for (auto& s : subs) {
            if (s.verdict == "malicious")   { worst = s.summary; break; }
            if (s.verdict == "suspicious")  worst = s.summary;
            else if (s.verdict == "error" && worst.empty()) worst = s.err;
        }
        if (!worst.empty()) os << "。最严重的一项：" << worst;
    } else {
        os << subs[0].summary;
        if (!subs[0].err.empty()) os << " " << subs[0].err;
    }
    out.summary = os.str();
    if (out.verdict == "error" && out.err.empty()) {
        for (auto& s : subs) if (!s.err.empty()) { out.err = s.err; break; }
    }

    // ---- ④ 清理临时解压目录（★ 解压出来的可能正是恶意文件，必须抹掉）----
    if (!archTmpDir.empty()) {
        const bool gone = SafeRemovePayloadDir(archTmpDir);
        if (!gone) out.cleanup += " | ★临时解压目录未清干净";
    }

    LogDbg("[sandbox] 汇总结论：" + out.verdict + " score=" + std::to_string(out.score) +
           " 载荷=" + std::to_string(subs.size()) +
           " 解压文件=" + std::to_string(out.archExtracted) +
           " 证据=" + std::to_string(out.artifacts.size()) +
           " 用时=" + std::to_string(out.elapsedSec) + "s");

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_last = out;
        g_runs++; g_artSum += out.artifacts.size();
        if      (out.verdict == "malicious")      g_vMal++;
        else if (out.verdict == "suspicious")     g_vSus++;
        else if (out.verdict == "clean")          g_vClean++;
        else                                      g_vError++;
    }

    // ---- ⑤ 播报 ----
    //   ★ 只有 malicious/suspicious/clean/not_applicable 出卡；**error 不在这里出**。
    //
    //   【为什么 error 要在这里压住 —— 2026-10-03 真样本轮实测】
    //     error 的处置需要**令牌**（用户点「删掉/不删除」要凭它授权），
    //     而令牌是在**消费循环**里、路径还原成原件之后才生成的。
    //     所以 error 必然由消费循环出那张**决策卡**。
    //     若这里也出，就会对同一文件弹两张卡：
    //       21:45:36.858 灰卡 → 路径=副本 holds\hSFx67xdhy01\OBWOcH.exe
    //       21:45:37.111 决策卡 → 路径=原件 C:\msys64\...\OBWOcH.exe
    //     两张卡**路径还不一样**，用户会以为是两个文件被拦了，
    //     而其中一张还没有按钮（无令牌）⇒ 看起来像"有个按钮点了没反应"。
    //   ⇒ error 一律不在此出；此注释原本就写着"error 仅留档"，代码没照做。
    //
    // ★★ 2026-10-04：not_applicable 也**不在此出** ——
    //   此处 path 是**副本**（holds\hSFx…\xxx.dll），用户看到的是内部临时目录。
    //   原件路径在消费循环里才还原（OrigOfCopy），所以那张卡由消费循环出。
    //   判据用 `path` 是不是副本路径来分，而不是看 verdict ——
    //   因为"落卡时用户认得哪个路径"才是决定因素。
    {
        std::string origPath;
        const bool isCopy = OrigOfCopy(path, &origPath);
        if (out.verdict != "error" && !(isCopy && out.verdict == "not_applicable"))
            NotifyIfActionable(path, out.verdict, out.score, out.summary);
    }
    return true;
}

// ---------------------------------------------------------------------------
//  ★★ 异步送检队列（契约与设计理由见 sandbox.h）
// ---------------------------------------------------------------------------
namespace {

const size_t kQueueCap = 16;    // 队列上限（沙箱是独占资源，排太多毫无意义）
const size_t kDedupCap = 512;   // 去重集合上限（超了整体清空，粗糙但够用）

// ★★ 自动送检的滚动限流（2026-09-27 新增）—— 见 sandbox.h 的说明
//   为什么队列上限（kQueueCap）**不足以**兜住这件事：
//     packscan 队列上限 64，单件成本几秒 → 最坏 64×5s ≈ 5 分钟。
//     本模块队列上限 16，单件成本 30~90 秒（还要建箱 + 销毁箱 + 磁盘 churn）
//     → 最坏 16×90s = **连续 24 分钟重活**，在一台办公笔记本上足以让机器
//     明显卡顿。成本量级差约两个数量级，所以"照抄 packscan 的队列上限"
//     并不是等效的防护 —— 必须再加一道**时间维度**的闸门。
//   人工送检（dedup=false）**不受此限**：用户显式点击，用户自己承担。
const size_t kAutoPerHour = 12;                 // 自动送检每小时上限
std::deque<unsigned long long> g_autoStamps;    // 自动送检时间戳（GetTickCount64 毫秒）

std::mutex              g_qmtx;
std::condition_variable g_qcv;

struct Job {
    std::string path;
    bool        dryrun;
    int         waitSec;
};
std::deque<Job>        g_queue;
std::set<std::string>  g_dedup;          // 已入队过的路径（小写）
ReportSink             g_sink = nullptr;

// ★ 用 atomic：消费者线程写、管道线程（sandboxstat）读，不共用一把锁。
std::atomic<unsigned long long> g_qQueued{0};
std::atomic<unsigned long long> g_qDone{0};
std::atomic<unsigned long long> g_qDropped{0};
std::atomic<unsigned long long> g_qThrottled{0};   // 因限流未入队数（★ 必须可见）

// ★★ 按「触发原因」分类计数（2026-10-01）
//   为什么光有日志行还不够：guard.log 会滚动，事后想回答"新引擎到底跑过没有"
//   只能翻历史日志（还可能已被截断）。有了计数器，`sandboxstat` 随时能给出
//   「左腿命中 N 次 / 其他原因 M 次」，两条腿的覆盖情况**可长期观测**。
std::atomic<unsigned long long> g_whyLv{0};       // 原因以"左腿"开头的入队数
std::atomic<unsigned long long> g_whyOther{0};    // 带原因但非左腿的入队数（新引擎等）

// 滚动窗口检查 + 登记。返回 false = 本小时配额已满，调用方应放弃入队。
// 调用方必须已持有 g_qmtx。
static bool AutoQuotaTake() {
    const unsigned long long now = GetTickCount64();
    const unsigned long long win = 3600ULL * 1000ULL;   // 1 小时
    while (!g_autoStamps.empty() && (now - g_autoStamps.front()) > win)
        g_autoStamps.pop_front();
    if (g_autoStamps.size() >= kAutoPerHour) return false;
    g_autoStamps.push_back(now);
    return true;
}

}  // namespace

void EnqueueScan(const std::string& path, bool dryrun, int waitSec, bool dedup,
                 const char* why) {
    if (path.empty()) return;

    // ---- ① 去重 + 限流（语义与既有完全一致，只提前到"复制"之前）----
    //   ★ 必须先判、再复制：为一个注定被去重/限流挡掉的送检白复制一份文件
    //     （高抖动样本每秒都能触发落地事件）是纯浪费，还会污染 holds 目录。
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (dedup) {
            // ★ 限流闸门放在去重之前还是之后？
            //   放在**去重之后**：同一个文件反复触发时，第二次起就被去重挡掉，
            //   根本不该消耗配额 —— 否则一个反复抖动的文件就能把小时配额吃光，
            //   真正的新样本反而送不进去。
            if (g_dedup.size() >= kDedupCap) g_dedup.clear();
            // ★ 去重的意义：样本自身会反复触发落地事件，指纹级抖动就能把
            //   队列刷满。这不是"省性能"，是**防止把沙箱当一次性耗材烧掉**。
            if (!g_dedup.insert(LowerAscii(path)).second) return;

            if (!AutoQuotaTake()) {
                g_qThrottled.fetch_add(1);
                LogDbg("[sandbox] ★自动送检已达限流上限（每小时 " +
                       std::to_string(kAutoPerHour) + " 次），本次未送检：" + path +
                       "（这是**覆盖缺口**：该样本没有被动态分析，静态结论保持不变）");
                return;
            }
        }
    }

    // ---- ② ★ 封锁原件 + 造副本（不持 g_qmtx：这是磁盘 I/O，别把消费者堵住）----
    //   注意去重键仍是**原件路径**（上面已登记）—— 若拿副本路径去去重，每次都不同，
    //   去重就彻底失效了。
    //   失败**不阻断送检**：「分析」比「封锁」重要，本次退回直接送原件（只是不封锁）。
    std::string submit = path;
    if (!dryrun) {
        std::string holdWhy;
        if (!MakeHold(path, &submit, &holdWhy)) {
            g_holdFail.fetch_add(1);
            LogDbg("[sandbox] 本次未封锁原件（" +
                   (holdWhy.empty() ? std::string("不适用") : holdWhy) +
                   "），仍直接送检原件：" + path);
        }
    }

    // ---- ③ 入队 ----
    std::string evicted;
    size_t depth = 0;
    {
        std::lock_guard<std::mutex> lk(g_qmtx);
        if (g_queue.size() >= kQueueCap) {
            // 满了丢最旧（保新不保全，同 packscan）：新落地的样本更可能
            // 是当前攻击链的一环，旧样本早已过期。
            evicted = g_queue.front().path;
            g_queue.pop_front();
            g_qDropped.fetch_add(1);
        }
        Job j;
        j.path    = submit;
        j.dryrun  = dryrun;
        j.waitSec = waitSec;
        g_queue.push_back(j);
        g_qQueued.fetch_add(1);
        depth = g_queue.size();
    }
    // ★★ 被挤掉的那个若正持有封锁，必须在这里解掉 ——
    //   否则它的原件会被**永久锁死**：锁的持有者是我们，用户既跑不了也删不掉
    //   （不共享读 ⇒ 连复制都读不出去），这是比"不封锁"更坏的结果。
    if (!evicted.empty()) DropHold(evicted, "队列满被挤出");
    g_qcv.notify_one();
    // ★★ 打印触发原因：让「左腿 lv>=1」与「右腿 unsignedSusp」在日志里可分辨。
    //   在改动之前这两者打印完全相同 → 新引擎是否被触发过无法验证（半通故障）。
    const char* whyStr = (why && *why) ? why : "-";
    if (why && strncmp(why, "左腿", strlen("左腿")) == 0) g_whyLv.fetch_add(1);
    else if (why && *why != '\0')                          g_whyOther.fetch_add(1);
    LogDbg("[sandbox] 送检入队：" + submit +
           (submit == path ? std::string() : std::string("（★原件已封锁，改送副本）")) +
           "（dryrun=" + std::string(dryrun ? "1" : "0") +
           "，去重=" + std::string(dedup ? "1" : "0") +
           "，队列=" + std::to_string(depth) +
           "，原因=" + whyStr + "）");
}

void SetSink(ReportSink sink) { g_sink = sink; }

int QueueDepth() {
    std::lock_guard<std::mutex> lk(g_qmtx);
    return (int)g_queue.size();
}

std::string QueueStatsJson() {
    std::lock_guard<std::mutex> lk(g_qmtx);
    std::string j = "{";
    j += "\"depth\":"     + std::to_string(g_queue.size());
    j += ",\"queued\":"    + std::to_string(g_qQueued.load());
    j += ",\"done\":"      + std::to_string(g_qDone.load());
    j += ",\"dropped\":"   + std::to_string(g_qDropped.load());
    j += ",\"throttled\":" + std::to_string(g_qThrottled.load());
    j += ",\"dedup\":"     + std::to_string(g_dedup.size());
    // 当前滚动窗口内已用掉的自动送检配额（界面可据此显示"本小时还能送几份"）
    j += ",\"autoPerHour\":"  + std::to_string(kAutoPerHour);
    j += ",\"autoInWindow\":" + std::to_string(g_autoStamps.size());
    // ★ 按触发原因分列（用于验证"新送沙箱引擎"是否真的被执行过）
    j += ",\"whyLv\":"    + std::to_string(g_whyLv.load());
    j += ",\"whyOther\":" + std::to_string(g_whyOther.load());
    // ★★ 送检封锁（preview4）：锁定成功/失败累计 + 当前仍被锁定的件数。
    //   为什么必须可见：封锁是**用户感知得到**的行为（双击会报错），
    //   若只留在日志里，事后无法回答"现在到底锁着几个文件"。
    j += ",\"lockOk\":"     + std::to_string(g_holdOk.load());
    j += ",\"lockFail\":"   + std::to_string(g_holdFail.load());
    j += ",\"lockActive\":" + std::to_string(g_holdActive.load());
    j += "}";
    return j;
}

void ConsumePendingLoop() {
    LogDbg("[sandbox] 送检队列消费线程已启动");
    // ★ 启动清残留：上次进程被强杀时留下的副本（句柄已随进程消亡，文件还在）
    GcHoldsDir();
    for (;;) {
        if (sf::IsStopRequested()) break;

        // ★ 回收已到期的「沙箱无结论」封锁（verdict=error 走的那条，见 ScheduleHoldRelease）。
        //   放在取任务之前：循环本身是 1 秒轮询，扫一张极小的表开销可忽略，
        //   顺带保证「即使之后没有新任务入队，到期封锁也一定会被回收」。
        ReapExpiredErrHolds();

        Job job;
        {
            std::unique_lock<std::mutex> lk(g_qmtx);
            if (g_queue.empty()) {
                // 1 秒超时：既能及时响应停止信号，也不忙等
                g_qcv.wait_for(lk, std::chrono::seconds(1));
                if (g_queue.empty()) continue;
            }
            job = g_queue.front();
            g_queue.pop_front();
        }

        Report rep;
        try {
            // ★ 注意 Scan 内部自己会调 NotifySandboxResult 推界面卡片 ——
            //   这里不重复播报，只负责把报告交给服务层做**处置层面的**判断。
            Scan(job.path, job.dryrun, job.waitSec, rep);
        } catch (...) {
            // 分析过程抛异常不能杀掉消费线程（后面排队的样本还要跑）。
            rep = Report();
            rep.file    = job.path;
            rep.verdict = "error";
            rep.err     = "沙箱分析过程抛出异常（已捕获，消费线程继续运行）";
            rep.when    = NowStr();
            LogDbg("[sandbox] ★送检异常（已捕获）：" + job.path);
        }
        g_qDone.fetch_add(1);

        // ---- ★★ 送检封锁收尾：还原路径 + 解封锁 + 删副本 ----
        //  ★ 为什么必须在 g_sink **之前**：
        //    ① sink 里会 QuarantineLanded(rep.file)，那一步要用**原件路径**；
        //    ② 隔离走 rename —— 实测"锁定期间也能改名"，但先解锁更干净，
        //       否则句柄还挂在一个已被搬走的文件上。
        //  ★ 结论**不分档位**都要收尾：error / not_applicable / clean 同样必须解锁 ——
        //    否则一次"没结论"就把用户文件**永久锁死**（不共享读 ⇒ 用户连复制都读不
        //    出去），那比不封锁糟糕得多。
        //  ★ 删副本是用户明确要求的："送检完得出结论后，要把我们复制的文件给删掉"。
        // ★ 封锁补偿要用的原件路径（下面这个作用域结束时仍要可见）
        std::string heldOrig;
        {
            std::string origPath;
            if (OrigOfCopy(job.path, &origPath)) {
                // 报告里凡出现副本路径的地方，一律还原成**原件路径**
                if (LowerAscii(rep.file) == LowerAscii(job.path)) rep.file = origPath;
                for (auto& t : rep.victims)
                    if (LowerAscii(t.path) == LowerAscii(job.path)) t.path = origPath;
                for (std::string* s : { &rep.summary, &rep.err }) {
                    for (size_t p = s->find(job.path); p != std::string::npos;
                         p = s->find(job.path, p + origPath.size()))
                        s->replace(p, job.path.size(), origPath);
                }
                // ★★ 2026-10-03 修正（本轮真样本轮实测出的反直觉缺陷）：
                //   原实现在这里**无条件** DropHold —— 也就是「沙箱无论测出什么，
                //   都把原件解锁放行」。于是 verdict=error（= 沙箱根本没测出任何东西，
                //   `targetRan=0`）也照样解锁，文件立刻恢复可执行。
                //
                //   实证（VM 12:30:07）：样本 exitCode=0xC0000135、探针 targetRan=0、
                //   verdict=error ⇒ 日志「送检未在沙箱中生效」⇒ 12:30:07 解锁 ⇒
                //   此后 8 分钟文件完全自由，用户双击即执行，而行为判定给 0 分。
                //   **沙箱失效反而成了放行理由**，这是设计上的倒挂。
                //
                //   改法：error = 「我们不知道」，不等于「它没事」。
                //   继续保持封锁 + 明确告知用户，请手动处理（删除或右键查杀）。
                //   解除时机改由下方补偿逻辑之外的一条显式路径承担：仅 clean/suspicious
                //   才解锁；malicious 走隔离（句柄随之释放）；not_applicable 视同 clean。
                const bool keepLocked = (rep.verdict == "error");
                if (keepLocked) {
                    // 维持封锁 + **登记用户决策**（银泊裁定，取代旧「30 分钟后自动放行」）。
                    // 旧行为的病根：锁着必然滑向放行，而放行等于裸奔（用户双击即执行，
                    // 行为判定多半 0 分）。新行为把处置权交回用户 + 30 秒后自动删除。
                    //
                    // ★ 登记必须在 MakeHold 成功**之后**（此刻我们确实持着原件句柄），
                    //   否则会出现「还没锁上就可决策」的窗口。
                    const std::string tok = errhold::Add(origPath, job.path,
                                                         rep.err.empty() ? "沙箱未测出任何结论"
                                                                         : rep.err,
                                                         kErrDecisionSeconds);
                    LogDbg("[sandbox] ★★ verdict=error（沙箱未测出任何结论）⇒ **维持封锁，"
                           "处置权交回用户**："
                           + origPath + "（令牌 " + (tok.empty() ? std::string("无·只能等超时")
                                                                : tok.substr(0, 6) + "…") +
                           "，" + std::to_string(kErrDecisionSeconds) +
                           " 秒内未决策则**自动删除**（删除前先隔离留底））");
                    // ★ 出卡必须带令牌与倒计时，否则用户点不了、也看不到"会自己删"。
                    //   这里补发一张决策卡（前面 Scan 内部已发过灰色结果卡，
                    //   但那张没有按钮、没有令牌 —— 刻意**不**改那张，
                    //   避免同一文件弹两张卡把用户搞懵）。
                    if (!tok.empty()) {
                        // ★ 刻意**不调 g_sink**：sink 是服务层处置入口，而它对
                        //   `!mal` 的档位会 ObserveAdd(600) —— 那等于把一个
                        //   "我们什么都没测出来"的文件登记成放行后监控对象，
                        //   语义完全错位（它是被**锁着**的，不该在监控名单里）。
                        //   这里只发界面卡，让用户做决定；真正的登记由
                        //   errdecide 的 release 分支按银泊裁定做（ObserveAdd 3600）。
                        std::string sum = rep.summary;
                        sum += "；★该文件现被隔离保护，"
                               "请在 " + std::to_string(kErrDecisionSeconds) +
                               " 秒内选择处理方式；**不做选择将自动删除**"
                               "（删除前会先留底到隔离区，可找回）";
                        NotifyIfActionable(origPath, "error", 0, sum,
                                           tok, (int)kErrDecisionSeconds);
                    }
                } else {
                    DropHold(job.path, "送检已出结论");
                    // ★★ 2026-10-04（VM 实测）：not_applicable 的卡在**副本上下文**出，
                    //   于是挂的是 `C:\ProgramData\SilverFoxGuard\holds\hSFx66y16e02\SkinBtn.dll`
                    //   —— 用户看到的是一个**他从没见过的内部临时目录**，
                    //   既不知道自己在哪、也没法去处置（那个目录下一轮就被 GC）。
                    //   实测一次装包解出 5 个 DLL ⇒ 连弹 5 张这种卡，纯噪音。
                    //   ⇒ 在这里（原件路径已还原、且已解锁）**补一张原件路径的**，
                    //     并把 Scan 里那张副本卡降级为不弹。
                    //   ⚠️ 只补 not_applicable：malicious/suspicious/clean 走的是
                    //     「本来就想让用户知道结论」的路径，而它们的卡在别处也会出，
                    //     在这里补会造成双卡。
                    if (rep.verdict == "not_applicable")
                        NotifyIfActionable(rep.file, rep.verdict, 0, rep.summary);
                }
                heldOrig = origPath;
                if (keepLocked) heldOrig.clear();   // 不参与下面的「封锁补偿」
            }
        }

        // ---- ★★★ 封锁补偿（2026-10-03，银泊裁定）：把"被我们挡住的那次启动"补回去 ----
        //   只在真的封锁过（heldOrig 非空）时才有意义 —— 没封锁就没有副作用要补偿。
        //   必须在 DropHold **之后**：句柄不放开，我们自己启动它同样会被 ERROR 32 拒。
        //   结果写进 rep.summary，让结果卡如实告诉用户"我们替他补跑了"，绝不静默。
        if (!heldOrig.empty() && !job.dryrun) {
            std::string cwhy;
            if (TryCompensateLaunch(heldOrig, rep.verdict, &cwhy)) {
                rep.summary += "；★本次送检曾**临时封锁**该文件（本机一度无法启动），"
                               "判定安全后已**按原意自动重新启动**。";
            } else {
                LogDbg("[sandbox] 封锁补偿未执行（" + cwhy + "）：" + heldOrig);
            }
        }

        // ===================================================================
        //  ★★ 结果出口 —— 这条链此前是断的（2026-09-27 补）
        // ===================================================================
        //  在补上这个 sink 之前：报告只经 NotifySandboxResult 推给界面卡片，
        //  服务层的判定链（g_result findings / trace 行为链 / 隔离）**完全
        //  看不到它**。于是会出现一种最典型的事故形态：
        //      卡片告诉用户"这是恶意样本"，而那个文件仍然躺在磁盘上
        //      可以双击运行 —— 判定发生了，处置没发生，两边都以为对方在做。
        //  （同型先例：packscan 的 level>=2 若不回调 OnPackHit，压缩包
        //    被扫出高危也只是一个数字，落不了地。）
        //
        //  ⚠️ 调用 sink 时**不持有 g_qmtx**（上面 pop 后已出作用域）——
        //     否则 sink 里一旦调用 QueueDepth()/QueueStatsJson() 就自锁。
        // ===================================================================
        if (g_sink) {
            try {
                g_sink(rep);
            } catch (...) {
                LogDbg("[sandbox] 送检结果回调异常（已捕获）：" + job.path);
            }
        }
    }
    // ★ 服务停止：把还挂着的封锁全部释放 —— 否则在我们退出前，用户那些文件
    //   一直是"跑不了也删不掉"的状态（句柄随进程退出才会消失）。
    ReleaseAllHolds("服务停止");
    LogDbg("[sandbox] 送检队列消费线程已退出（累计入队 " +
           std::to_string(g_qQueued.load()) + " / 完成 " +
           std::to_string(g_qDone.load()) + " / 丢弃 " +
           std::to_string(g_qDropped.load()) + "）");
}

// ---------------------------------------------------------------------------
//  JSON 输出
// ---------------------------------------------------------------------------
std::string ConfigJson() {
    Config c;
    Detect(c, false);
    std::string j = "{";
    j += "\"ready\":" + std::string(c.ready ? "true" : "false");
    j += ",\"box\":"      + JsonString(c.box);
    j += ",\"startExe\":" + JsonString(c.startExe);
    j += ",\"sbieIni\":"  + JsonString(c.sbieIni);
    j += ",\"root\":"     + JsonString(c.root);
    j += ",\"driveRoot\":" + JsonString(c.driveRoot);
    j += ",\"userRoot\":" + JsonString(c.sandboxUserRoot);
    j += ",\"mode\":\"disposable\"";        // 一次性沙箱模式（每轮新建 + 销毁）
    j += ",\"note\":"     + JsonString(c.note);
    j += "}";
    return j;
}

std::string StatsJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::string j = "{";
    j += "\"runs\":"  + std::to_string(g_runs);
    j += ",\"mal\":"  + std::to_string(g_vMal);
    j += ",\"sus\":"  + std::to_string(g_vSus);
    j += ",\"clean\":" + std::to_string(g_vClean);
    j += ",\"error\":" + std::to_string(g_vError);
    j += ",\"artifacts\":" + std::to_string(g_artSum);
    // ★ 一次性沙箱的可观测性：建了多少箱、有多少销毁失败留下了残留
    //   后者应长期为 0；不为 0 就说明 SbieSvc 有句柄泄漏或权限问题。
    j += ",\"boxMade\":"  + std::to_string(g_boxMade);
    j += ",\"boxLeft\":"  + std::to_string(g_boxLeft);
    j += ",\"gcPending\":" + std::to_string((long long)0);   // 占位，见 sandboxstat 的 gc 字段
    j += "}";
    return j;
}

std::string LastReportJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
    const Report& r = g_last;
    std::string j = "{";
    j += "\"file\":"    + JsonString(r.file);
    j += ",\"verdict\":" + JsonString(r.verdict);
    j += ",\"score\":"   + std::to_string(r.score);
    j += ",\"summary\":" + JsonString(r.summary);
    j += ",\"err\":"     + JsonString(r.err);
    j += ",\"dryrun\":"  + std::string(r.dryrun ? "true" : "false");
    j += ",\"hashHit\":" + std::string(r.hashHit ? "true" : "false");
    j += ",\"verdictStrong\":" + std::string(r.verdictStrong ? "true" : "false");
    j += ",\"elapsed\":" + std::to_string(r.elapsedSec);
    j += ",\"when\":"    + JsonString(r.when);
    j += ",\"box\":"     + JsonString(r.box);
    j += ",\"cleanup\":" + JsonString(r.cleanup);
    // ★ 阶段二：探针自报字段（结构字段，GUI 直接读，不解析 summary 文案）
    j += ",\"probeLoaded\":"      + std::string(r.probeLoaded ? "true" : "false");
    j += ",\"probeOtherLoaded\":" + std::string(r.probeOtherLoaded ? "true" : "false");
    j += ",\"probeTargetRan\":"   + std::string(r.probeTargetRan ? "true" : "false");
    j += ",\"probeFile\":"      + std::to_string(r.probeFile);
    j += ",\"probeProcess\":"   + std::to_string(r.probeProcess);
    j += ",\"probeReg\":"       + std::to_string(r.probeReg);
    j += ",\"probeNet\":"       + std::to_string(r.probeNet);
    j += ",\"probeEvents\":"    + std::to_string(r.probeEvents);
    j += ",\"probeDetail\":"    + JsonString(r.probeDetail);
    // ★ 2026-09-30：沙箱网络外联（此前**漏序列化** → GUI 看不到网络证据，只有结论文字提到）
    j += ",\"netC2\":" + std::string(r.netC2 ? "true" : "false");
    j += ",\"netConns\":[";
    for (size_t i = 0; i < r.netConns.size(); i++) {
        if (i) j += ",";
        j += JsonString(r.netConns[i]);
    }
    j += "]";
    // ★ 2026-10-01：驻留观察期（主进程退出后 box 内的残留活动，详见 sandbox.h）
    j += ",\"residentSec\":"      + std::to_string(r.residentSec);
    j += ",\"residentProcs\":"    + std::to_string(r.residentProcs);
    j += ",\"residentPids\":"     + std::to_string(r.residentPids);
    j += ",\"residentNewFiles\":" + std::to_string(r.residentNewFiles);
    j += ",\"residentOutbound\":" + std::string(r.residentOutbound ? "true" : "false");
    j += ",\"residentExe\":[";
    for (size_t i = 0; i < r.residentExe.size(); i++) {
        if (i) j += ",";
        j += JsonString(r.residentExe[i]);
    }
    j += "]";
    // ★ 压缩包解压送检（2026-09-27）：让界面能看出"这次验的到底是什么"。
    //   否则"送检了 zip、报告说 clean"会被误读成"zip 本身验过了没问题"。
    j += ",\"archExtracted\":" + std::to_string(r.archExtracted);
    j += ",\"archScanned\":"   + std::to_string(r.archScanned);
    j += ",\"archTruncated\":" + std::string(r.archTruncated ? "true" : "false");
    j += ",\"victims\":[";
    for (size_t i = 0; i < r.victims.size(); i++) {
        if (i) j += ",";
        j += "{\"path\":"  + JsonString(r.victims[i].path);
        j += ",\"label\":" + JsonString(r.victims[i].label) + "}";
    }
    j += "]";
    j += ",\"artifacts\":[";
    for (size_t i = 0; i < r.artifacts.size(); i++) {
        if (i) j += ",";
        j += "{\"rel\":"   + JsonString(r.artifacts[i].rel);
        j += ",\"size\":"  + std::to_string(r.artifacts[i].size);
        j += ",\"action\":" + JsonString(r.artifacts[i].action);
        j += ",\"tree\":"  + JsonString(r.artifacts[i].tree);
        j += ",\"src\":"   + JsonString(r.artifacts[i].src);
        j += ",\"score\":" + std::to_string(r.artifacts[i].score);
        j += ",\"why\":"   + JsonString(r.artifacts[i].why) + "}";
    }
    j += "]}";
    return j;
}

const Report& LastReport() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_last;
}

}  // namespace sandbox
}  // namespace sf
