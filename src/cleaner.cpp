// cleaner.cpp — 可疑文件清除（强制项）：最高权限删除 + 解除占用 + 载荷 DLL 连坐 + 进度落盘
//
// 权限来源：本代码运行在 LocalSystem 服务进程内，等价于「最高权限」——
//   * 可结束任意会话（含用户桌面会话）中的任意进程；
//   * 可删除普通用户无权限删除的文件（含隐藏+系统属性的文件）；
//   * 全程不触发 UAC（UAC 只约束交互式提权，服务本就在最高权限上下文中）。
//
// 三段式流程（配合弹窗进度条）：
//   ① locate：先直接删；删不掉（=被占用）的进入待处理，并记录「占用进程」及其加载的【非系统 DLL】。
//      银狐常以「宿主 EXE + 同目录恶意 DLL」形态存活，且 DLL 会被重新释放/下载，故必须连坐删除。
//   ② kill  ：强制结束全部占用进程（含用户会话里的样本进程）。
//   ③ delete：逐个删除（含新发现的载荷 DLL）。仍删不掉的登记为「重启后删除」，保证下次开机不再存活。
// 删除一律走 \\?\ 前缀的长路径 API：既能绕过 MAX_PATH 限制，也能正确处理「结尾空格/点」的畸形文件名
// （这类名字用普通 Win32 路径永远打不开，是银狐的经典藏文件手法）。
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <aclapi.h>
#include <sddl.h>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include <unordered_map>
#include <filesystem>

namespace fs = std::filesystem;

#include "cleaner.h"
#include "common.h"
#include "scanner.h"
#include "sideload.h"   // 白加黑（DLL 侧加载）检测，2026-09-22

#pragma comment(lib, "psapi.lib")

namespace sf {

// ---------------------------------------------------------------------------
//  进度文件（服务写 / 用户会话里的弹窗读）
// ---------------------------------------------------------------------------
static std::wstring ProgressPathW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\clean_progress.txt";
}

void WriteCleanProgress(const std::string& phase, int done, int total, const std::string& current) {
    std::string s = "phase=" + phase + " done=" + std::to_string(done) +
                    " total=" + std::to_string(total) + " current=" + current;
    HANDLE h = CreateFileW(ProgressPathW().c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    DWORD w = 0;
    WriteFile(h, s.data(), (DWORD)s.size(), &w, nullptr);
    CloseHandle(h);
}

bool ReadCleanProgress(std::string& phase, int& done, int& total, std::string& current) {
    phase.clear(); done = 0; total = 0; current.clear();
    HANDLE h = CreateFileW(ProgressPathW().c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    char buf[1200] = {0}; DWORD n = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &n, nullptr);
    CloseHandle(h);
    if (!n) return false;
    std::string s(buf, n);
    auto num = [&s](const char* key) -> int {
        size_t p = s.find(key);
        if (p == std::string::npos) return 0;
        p += strlen(key);
        int v = 0;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') { v = v * 10 + (s[p] - '0'); ++p; }
        return v;
    };
    done  = num("done=");
    total = num("total=");
    size_t pp = s.find("phase=");
    if (pp != std::string::npos) {
        size_t e = s.find(' ', pp);
        phase = s.substr(pp + 6, (e == std::string::npos ? s.size() : e) - (pp + 6));
    }
    size_t cp = s.find("current=");
    if (cp != std::string::npos) current = s.substr(cp + 8);
    return true;
}

void ClearCleanProgress() { DeleteFileW(ProgressPathW().c_str()); }

// ---------------------------------------------------------------------------
//  路径与自保
// ---------------------------------------------------------------------------
static std::wstring A2W(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

// 转成 \\?\ 形式：绕过 MAX_PATH，且按字面处理「结尾空格/点」的畸形名字
static std::wstring LongPathW(const std::string& ansiPath) {
    std::wstring w = A2W(ansiPath);
    if (w.empty()) return w;
    if (w.rfind(L"\\\\?\\", 0) == 0) return w;
    return L"\\\\?\\" + w;
}

// 自保：绝不删除我方程序自身的文件
static bool IsSelfPath(const std::string& path) {
    std::string l = to_lower(path);
    if (ci_contains(l, "silverfoxenvscan")) return true;
    if (ci_contains(l, "silverfox-guard"))  return true;
    if (ci_contains(l, "silverfoxguard"))   return true;
    std::string me = to_lower(GetExePath());
    return (!me.empty() && l == me);
}

// 用户可写位置（投放载荷的典型位置）：AppData / Temp / ProgramData / 公共目录 / 桌面下载 / 中文目录
static bool IsUserWritableLocation(const std::string& pathLower) {
    if (ci_contains(pathLower, "\\appdata\\"))     return true;
    if (ci_contains(pathLower, "\\temp\\"))        return true;
    if (ci_contains(pathLower, "\\programdata\\")) return true;
    if (ci_contains(pathLower, "\\users\\public")) return true;
    if (ci_contains(pathLower, "\\desktop\\"))     return true;
    if (ci_contains(pathLower, "\\downloads\\"))   return true;
    if (ci_contains(pathLower, "\\$recycle.bin\\"))return true;
    for (unsigned char c : pathLower) if (c >= 0x80) return true;   // 中文等非 ASCII 目录
    return false;
}

// ---------------------------------------------------------------------------
//  占用检测 / 强制结束 / 载荷模块收集
// ---------------------------------------------------------------------------
static std::string LowerA(const std::string& s) { return to_lower(s); }

struct HolderProc {
    DWORD pid = 0;
    std::string name;
    HANDLE handle = nullptr;   // 已打开的进程句柄（调用方负责 CloseHandle）
};

// 系统主机进程名单：这些进程被杀会造成系统级副作用（lsass 蓝屏、explorer 桌面消失、
// winlogon 登录失效、svchost 服务中断），【任何清除路径都不得结束它们】。
// 载荷 DLL 即使被注入进这些进程，也只能"删文件"（硬删/重启登记），宿主进程保留。
static const char* kProtectedHostNames[] = {
    "svchost.exe", "explorer.exe", "winlogon.exe", "lsass.exe", "csrss.exe",
    "services.exe", "wininit.exe", "dwm.exe", "spoolsv.exe", "sihost.exe",
    "taskhostw.exe", "runtimebroker.exe", "searchhost.exe", "shell experience host.exe",
    "fontdrvhost.exe", "smss.exe", "conhost.exe", "audiodg.exe",
};

// 进程名是否属于【受保护系统主机】（大小写不敏感，不含扩展名差异）
static bool IsProtectedHostProc(const std::string& nameLower) {
    for (const char* hn : kProtectedHostNames)
        if (nameLower == hn) return true;
    return false;
}

// 该进程是否「正在运行某文件」或「已把该文件作为模块加载」（DLL 被占用的情形）
static bool ProcessUsesFile(HANDLE hProc, const std::string& targetLower) {
    char img[MAX_PATH * 2] = {0};
    DWORD n = (DWORD)sizeof(img) - 1;
    if (QueryFullProcessImageNameA(hProc, 0, img, &n) && n) {
        if (LowerA(std::string(img)) == targetLower) return true;
    }
    HMODULE mods[512]; DWORD need = 0;
    if (EnumProcessModulesEx(hProc, mods, sizeof(mods), &need, LIST_MODULES_ALL)) {
        DWORD cnt = need / sizeof(HMODULE);
        if (cnt > 512) cnt = 512;
        for (DWORD i = 0; i < cnt; ++i) {
            char mp[MAX_PATH * 2] = {0};
            if (GetModuleFileNameExA(hProc, mods[i], mp, sizeof(mp)) && mp[0]) {
                if (LowerA(std::string(mp)) == targetLower) return true;
            }
        }
    }
    return false;
}

// 找出占用目标文件的进程（打开句柄返回给调用方，稍后统一结束）
static std::vector<HolderProc> FindHolders(const std::string& target) {
    std::vector<HolderProc> out;
    const std::string tl = LowerA(target);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
    const DWORD self = GetCurrentProcessId();
    if (Process32First(snap, &pe)) {
        do {
            const DWORD pid = pe.th32ProcessID;
            if (pid == 0 || pid == 4 || pid == self) continue;   // Idle / System / 自己
            if (IsProtectedHostProc(to_lower(std::string(pe.szExeFile)))) continue;   // 系统主机进程绝不杀（注入 DLL 走删文件/延迟路径）
            // 同一进程可能已记录（多个目标共用），避免重复
            bool dup = false;
            for (const auto& h : out) if (h.pid == pid) { dup = true; break; }
            if (dup) continue;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                                    FALSE, pid);
            if (!hp) continue;
            if (ProcessUsesFile(hp, tl)) {
                HolderProc h; h.pid = pid; h.name = pe.szExeFile; h.handle = hp;
                out.push_back(h);
            } else {
                CloseHandle(hp);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);

    // 兜底：精确路径/模块匹配无果时，按【可执行文件基名】匹配（大小写不敏感）——
    // 目标文件可能被改名/短路径/相对引用，进程映像名与目标文件名相同即为占用者。
    // 仅当精确匹配为空时启用，避免误杀同名合法进程（有精确持证时以精确为准）。
    if (out.empty() && !tl.empty()) {
        std::string baseL = tl; size_t p = tl.find_last_of("/\\");
        if (p != std::string::npos) baseL = tl.substr(p + 1);
        if (!baseL.empty()) {
            HANDLE snap2 = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap2 != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe2{}; pe2.dwSize = sizeof(pe2);
                if (Process32First(snap2, &pe2)) {
                    do {
                        if (to_lower(pe2.szExeFile) != baseL) continue;
                        if (IsProtectedHostProc(to_lower(std::string(pe2.szExeFile)))) continue;   // 兜底同样不杀主机进程
                        if (pe2.th32ProcessID == 0 || pe2.th32ProcessID == 4 || pe2.th32ProcessID == self) continue;
                        bool dup = false;
                        for (const auto& h : out) if (h.pid == pe2.th32ProcessID) { dup = true; break; }
                        if (dup) continue;
                        HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                                                FALSE, pe2.th32ProcessID);
                        if (!hp) continue;
                        HolderProc h; h.pid = pe2.th32ProcessID; h.name = pe2.szExeFile; h.handle = hp;
                        out.push_back(h);
                    } while (Process32Next(snap2, &pe2));
                }
                CloseHandle(snap2);
            }
        }
    }
    return out;
}

// 收集进程加载的「非系统」模块：排除 Windows 目录，只保留落在用户可写位置的模块——
// 这些就是样本自带/释放的载荷 DLL（银狐赖以运行的模块），进程被杀后必须一并删除。
static std::vector<std::string> PayloadModulesOf(HANDLE hProc) {
    std::vector<std::string> out;
    HMODULE mods[512]; DWORD need = 0;
    if (!EnumProcessModulesEx(hProc, mods, sizeof(mods), &need, LIST_MODULES_ALL)) return out;
    DWORD cnt = need / sizeof(HMODULE);
    if (cnt > 512) cnt = 512;
    for (DWORD i = 0; i < cnt; ++i) {
        char mp[MAX_PATH * 2] = {0};
        if (!GetModuleFileNameExA(hProc, mods[i], mp, sizeof(mp)) || !mp[0]) continue;
        std::string m = mp;
        std::string lm = LowerA(m);
        if (ci_contains(lm, "\\windows\\")) continue;      // 系统目录里的正规模块
        if (IsSelfPath(m)) continue;                        // 自保
        if (!IsUserWritableLocation(lm)) continue;          // 只收用户可写位置的（载荷典型位置）
        out.push_back(m);
    }
    return out;
}

// ---------------------------------------------------------------------------
//  删除
// ---------------------------------------------------------------------------
static bool TryDeleteOnce(const std::string& path) {
    SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);          // 清只读/隐藏/系统属性
    SetFileAttributesW(LongPathW(path).c_str(), FILE_ATTRIBUTE_NORMAL);
    if (DeleteFileW(LongPathW(path).c_str())) return true;
    if (RemoveDirectoryW(LongPathW(path).c_str())) return true;        // 目录型目标
    return false;
}

CleanReport CleanFiles(const std::vector<std::string>& targetsIn) {
    CleanReport rep;
    ClearCleanProgress();

    // 去重 + 去空
    std::vector<std::string> targets;
    for (const auto& t : targetsIn) if (!t.empty()) targets.push_back(t);
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    rep.requested = (int)targets.size();

    std::vector<std::string> pending;          // 待删除目标（含后续发现的载荷 DLL）
    std::vector<std::string> pendingReason;    // 与 pending 一一对应的说明前缀
    std::vector<HolderProc> holders;

    // ---- 阶段 1：locate（直接删；删不掉的找出占用进程与载荷 DLL）----
    WriteCleanProgress("locate", 0, rep.requested, "");
    for (size_t i = 0; i < targets.size(); ++i) {
        const std::string& t = targets[i];
        WriteCleanProgress("locate", (int)i, rep.requested, t);
        CleanItemResult it; it.path = t;

        if (IsSelfPath(t)) {
            it.action = "skipped"; it.reason = "自保排除：我方程序文件";
            ++rep.skipped; rep.items.push_back(it); continue;
        }
        if (GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) {
            it.action = "deleted"; it.reason = "文件已不存在";
            ++rep.deleted; rep.items.push_back(it); continue;
        }
        if (TryDeleteOnce(t)) {
            it.action = "deleted";
            ++rep.deleted; rep.items.push_back(it); continue;
        }
        // 被占用 → 进入待处理，并记录占用进程
        pending.push_back(t);
        pendingReason.push_back("");
        auto hs = FindHolders(t);
        for (auto& h : hs) {
            bool dup = false;
            for (const auto& e : holders) if (e.pid == h.pid) { dup = true; break; }
            if (dup) { CloseHandle(h.handle); continue; }
            holders.push_back(h);
        }
    }

    // ---- 阶段 1.5：把「占用进程加载的非系统 DLL」也纳入待删除（银狐释放的载荷模块）----
    for (const auto& h : holders) {
        for (const auto& m : PayloadModulesOf(h.handle)) {
            bool dup = false;
            for (const auto& p : pending) if (to_lower(p) == to_lower(m)) { dup = true; break; }
            for (const auto& t : targets) if (to_lower(t) == to_lower(m)) { dup = true; break; }
            if (dup) continue;
            pending.push_back(m);
            pendingReason.push_back("［由被结束进程加载的载荷 DLL］");
            ++rep.extraDlls;
        }
    }

    // ---- 阶段 2：kill（强制结束全部占用进程）----
    if (!holders.empty()) {
        WriteCleanProgress("kill", 0, (int)holders.size(), "");
        for (size_t i = 0; i < holders.size(); ++i) {
            WriteCleanProgress("kill", (int)i, (int)holders.size(), holders[i].name);
            if (TerminateProcess(holders[i].handle, 1)) {
                ++rep.killed;
                rep.killedNames.push_back(holders[i].name);
            }
            CloseHandle(holders[i].handle);
            holders[i].handle = nullptr;
        }
        WriteCleanProgress("kill", (int)holders.size(), (int)holders.size(), "");
        Sleep(400);   // 给内核释放文件句柄留出时间
    } else {
        for (auto& h : holders) if (h.handle) CloseHandle(h.handle);
    }

    // ---- 阶段 3：delete（逐个删除；含新发现的载荷 DLL）----
    WriteCleanProgress("delete", 0, (int)pending.size(), "");
    for (size_t i = 0; i < pending.size(); ++i) {
        const std::string& p = pending[i];
        WriteCleanProgress("delete", (int)i, (int)pending.size(), p);
        CleanItemResult it; it.path = p;
        if (IsSelfPath(p)) {
            it.action = "skipped"; it.reason = "自保排除：我方程序文件";
            ++rep.skipped; rep.items.push_back(it); continue;
        }
        // 重试 3 次（进程刚被杀时句柄可能尚未完全释放）
        bool ok = false;
        for (int r = 0; r < 3 && !ok; ++r) {
            ok = TryDeleteOnce(p);
            if (!ok) Sleep(250);
        }
        if (!ok && GetFileAttributesA(p.c_str()) == INVALID_FILE_ATTRIBUTES) ok = true;   // 已被别的流程删掉

        if (ok) {
            it.action = "deleted";
            it.reason = pendingReason[i];
            ++rep.deleted;
        } else if (MoveFileExA(p.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
            it.action = "deferred";
            it.reason = pendingReason[i] +
                (rep.killed ? "文件仍被占用，已登记重启后自动删除" : "文件被占用，已登记重启后自动删除");
            ++rep.deferred;
        } else {
            // MoveFileEx 失败（常见于 \\?\ 长路径/畸形名）→ 手动写注册表兜底，保证重启后立即清除
            std::wstring ntPath = L"\\??\\" + A2W(p);
            if (!ntPath.empty() && ntPath != L"\\??\\") {
                HKEY hk = nullptr;
                if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                                  L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                                  0, KEY_READ | KEY_WRITE, &hk) == ERROR_SUCCESS) {
                    DWORD type = 0, sz = 0;
                    std::vector<wchar_t> buf;
                    if (RegQueryValueExW(hk, L"PendingFileRenameOperations", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS && sz > 0) {
                        buf.resize(sz / sizeof(wchar_t) + 2, 0);
                        RegQueryValueExW(hk, L"PendingFileRenameOperations", nullptr, &type,
                                         (LPBYTE)buf.data(), &sz);
                    }
                    if (!buf.empty() && buf.back() != 0) buf.push_back(0);
                    for (wchar_t c : ntPath) buf.push_back(c);
                    buf.push_back(0);
                    buf.push_back(0);
                    RegSetValueExW(hk, L"PendingFileRenameOperations", 0, REG_MULTI_SZ,
                                   (LPBYTE)buf.data(), (DWORD)(buf.size() * sizeof(wchar_t)));
                    RegCloseKey(hk);
                    it.action = "deferred";
                    it.reason = pendingReason[i] + "已登记重启后自动删除（注册表兜底）";
                    ++rep.deferred;
                } else {
                    it.action = "failed";
                    it.reason = pendingReason[i] + "删除失败（错误码 " + std::to_string(GetLastError()) +
                                "），可能受系统保护或为受信任目录";
                    ++rep.failed;
                }
            } else {
                it.action = "failed";
                it.reason = pendingReason[i] + "删除失败（错误码 " + std::to_string(GetLastError()) +
                            "），可能受系统保护或为受信任目录";
                ++rep.failed;
            }
        }
        rep.items.push_back(it);
    }

    // ---- 阶段 4：防复活复查（银狐常留守护线程/子进程，主载荷被删后几秒内重新写回）----
    // 等内核充分释放后，对「本次已删成」的目标逐一复查：若又冒出来 → 二次硬删；
    // 二次删除仍失败 → 该条目改为 failed（提示未能根除，交给高级清除接管）。
    if (!targets.empty()) {
        WriteCleanProgress("recheck", 0, (int)targets.size(), "");
        Sleep(2000);
        for (size_t i = 0; i < targets.size(); ++i) {
            const std::string& t = targets[i];
            WriteCleanProgress("recheck", (int)i, (int)targets.size(), t);
            if (GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) continue;   // 已无 → 无需复查
            CleanItemResult* prev = nullptr;
            for (auto& it : rep.items) if (it.path == t) { prev = &it; break; }
            if (!prev || prev->action != "deleted") continue;   // 只复查「已删成」的（failed/deferred 另有通道）
            if (TryDeleteOnce(t)) {
                prev->reason += "；防复活复查发现重新生成，已二次删除";
            } else if (GetFileAttributesA(t.c_str()) != INVALID_FILE_ATTRIBUTES) {
                prev->action = "failed";
                prev->reason += "；防复活复查发现重新生成且二次删除失败（疑有守护进程，请用「高级清除」）";
                ++rep.failed; --rep.deleted;
            }
        }
        WriteCleanProgress("done", (int)pending.size(), (int)pending.size(), "");
    }
    return rep;
}

// ---------------------------------------------------------------------------
//  高级清除（卡巴式「Advanced Disinfection」思路的本地化子集，无内核驱动）
//  普通清除的兜底手段有限：只杀「完整路径精确匹配」的占用进程、只删带普通 AC L
//  的「可删文件」。真正的银狐会用改名/短路径/子进程复活/收紧删除权限来对抗，
//  普通流程删不掉的，就交给这里：
//   遏制 KillHard —— 按 exe 基名匹配全部实例 + 子进程树，多轮快照强杀；
//   硬删 DeleteHard —— 清属性 → 解 DACL(Everyone:F) → 严格重试 →
//                      NtSetInformationFile POSIX 延迟删除 → 重启登记。
// ---------------------------------------------------------------------------

// 高级硬删除：比普通 TryDeleteOnce 更狠的删除原语，逐级兜底：
//   ① 清全部文件属性（只读/隐藏/系统/压缩标记等）；
//   ② 解除 DACL：把删除权限放开给 Everyone（破“被收走删除权限”的自我保护）；
//   ③ 严格重试 DeleteFile（含 \\?\ 长路径）；
//   ④ 仍失败且有 DELETE 权限句柄 → NtSetInformationFile(FileDispositionInformationEx,
//      POSIX 语义) 请求内核在引用计数降到 0 后删除（能解“句柄占用但共享删除”的场景）；
//   ⑤ 都不行 → 登记重启后由系统删除（MOVEFILE_DELAY_UNTIL_REBOOT）。
// 返回 true 表示文件已删除/已登记删除；false 表示彻底失败。

static std::string BaseN(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

static std::string DirN(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(0, s);
}

// 短随机名判定（与 scanner.cpp 同规则）：5~9 位字母数字、字母数字混合、含数字穿插
// ★ 2026-09-20 修正：原实现只剥离 4 字符后缀（.exe/.dll/.sys/...），导致
//   3 字符扩展名的随机名脚本（.ps1 / .py / .scr / .bat）因「基名+后缀」整体超长
//   而被判否 —— 但 CollectDerivatives 的扩展名白名单里明明收了它们，
//   结果是「枚举到但清不掉」。现按「取最后一个点之后为后缀」统一处理，
//   并把后缀白名单与 CollectDerivatives 对齐。
static bool ShortRand(const std::string& fname) {
    std::string s = fname;
    size_t dot = s.rfind('.');
    if (dot != std::string::npos && dot > 0 && s.size() - dot <= 5) {
        static const char* kStrip[] = {".exe", ".dll", ".sys", ".dat", ".tmp", ".bin",
                                       ".js", ".vbs", ".ps1", ".py", ".scr", ".bat", ".cmd"};
        std::string ext = to_lower(s.substr(dot));
        for (const char* e : kStrip) if (ext == e) { s = s.substr(0, dot); break; }
    }
    size_t n = s.size();
    if (n < 5 || n > 9) return false;
    bool hasDigit = false, hasAlpha = false;
    for (char c : s) {
        if (isdigit((unsigned char)c)) hasDigit = true;
        else if (isalpha((unsigned char)c)) hasAlpha = true;
        else return false;
    }
    if (!hasDigit || !hasAlpha) return false;
    for (size_t i = 0; i + 2 < n; ++i) if (isdigit((unsigned char)s[i])) return true;
    return false;
}

// ---------------------------------------------------------------------------
//  ★ 绝不清理路径白名单（2026-09-20 新增）—— 衍生物清除的最后一道保险
//
//  为什么必须存在：衍生物的判据是「短随机名 + 可执行扩展名」，扫描范围包含
//  ProgramData / Temp / Downloads / Users\Public。**游戏反作弊恰好符合这个画像**：
//    · EasyAntiCheat   → C:\ProgramData\EasyAntiCheat\ 下释放随机名组件
//    · BattlEye        → C:\Program Files (x86)\Common Files\BattlEye\ <目录>
//    · ACE / 腾讯反作弊 → C:\Program Files\AntiCheatExpert\ <目录>
//    · Vanguard(无畏契约) → C:\Program Files\Riot Vanguard\ <目录>
//
//  ⚠️ 上面几行的**行尾不能以反斜杠结尾** —— MSVC 的行拼接在注释里同样生效，
//     写成 `...BattlEye\` 会把下一行注释接上来一起被注释掉，
//     连带后面的注释块结构全乱（铁律 41 同族）。
//  这些目录一旦被按名字扫掉，后果是「游戏起不来」——用户会立刻卸载我们，
//  比漏报一个银狐严重得多。故此处采用**目录级白名单硬拦截**，
//  命中即跳过，不进入任何删除流程（连枚举结果都不给）。
//
//  白名单维度（任一命中即保护）：
//    ① 系统目录：\Windows\、\System32\、\SysWOW64\、\WinSxS\、\$Recycle.Bin 除外
//    ② 程序安装目录：\Program Files\、\Program Files (x86)\ —— 正常软件都装这里，
//       反作弊也大量安装在这里；银狐从不用这些位置释放载荷（写不进去），
//       所以整体排除不会有检测损失
//    ③ 反作弊 / 游戏平台专用目录（关键词匹配，覆盖国内外主流）
//    ④ 我方程序自身目录（自保，已有 IsSelfPath 兜底，这里再做一层）
//    ⑤ 用户自定义信任目录（由 service.cpp 写入全局列表）
// ---------------------------------------------------------------------------
static std::vector<std::string> g_userTrustDirs;   // 小写、带前后分隔符的安全目录
static std::mutex              g_trustMtx;

// 供 service.cpp 登记用户信任目录（如「这是我自己写的程序目录，别动」）
void AddNeverCleanDir(const std::string& dir) {
    if (dir.size() < 4) return;
    std::string d = to_lower(dir);
    for (auto& c : d) if (c == '/') c = '\\';
    if (d.back() != '\\') d += '\\';
    std::lock_guard<std::mutex> lk(g_trustMtx);
    for (const auto& e : g_userTrustDirs) if (e == d) return;
    g_userTrustDirs.push_back(d);
    LogDbg("[clean-safe] 已登记信任目录: " + d);
}

bool IsNeverCleanPath(const std::string& path) {
    if (path.empty()) return true;                 // 空路径绝不处理
    std::string lp = to_lower(path);
    for (auto& c : lp) if (c == '/') c = '\\';

    // ① 系统目录（注意 \$recycle.bin 是清理目标，不能进白名单）
    static const char* kSysDirs[] = {
        "\\windows\\", "\\winsxs\\", "\\system volume information\\",
        "\\$windows.~bt\\", "\\$windows.~ws\\",
    };
    for (const char* d : kSysDirs) if (lp.find(d) != std::string::npos) return true;

    // ② 程序安装目录：银狐无法向这里释放载荷（缺写权限），故整体保护，
    //    同时天然覆盖装在 Program Files 下的反作弊 / 游戏平台。
    //    ⚠️ 例外：若路径**同时**位于用户可写的高发区（见下），说明是畸形路径，不豁免。
    if (lp.find("\\program files\\") != std::string::npos ||
        lp.find("\\program files (x86)\\") != std::string::npos) {
        if (lp.find("\\appdata\\") == std::string::npos &&
            lp.find("\\temp\\") == std::string::npos) return true;
    }

    // ③ 反作弊 / 游戏平台专用目录（关键词，覆盖国内外主流反作弊）
    //    这些目录可能不在 Program Files 下（如 EAC 用 ProgramData、BattlEye 用 ProgramData），
    //    必须单独列出，否则就是误删现场。
    static const char* kAntiCheatDirs[] = {
        // 国际反作弊
        "\\easyanticheat", "\\easy anti-cheat", "\\battleye", "\\riot vanguard",
        "\\vgk", "\\vanguard", "\\equ8", "\\xigncode", "\\nprotect",
        "\\fairfight", "\\faceit", "\\esea", "\\punkbuster", "\\gameguard",
        "\\denuvo", "\\arbiter", "\\mhyprot", "\\anti-cheat", "\\anticheat",
        // 国内反作弊 / 平台
        "\\anticheatexpert", "\\ace-guard", "\\ace\\", "\\tenprotect",
        "\\tenio", "\\tencent\\tp", "\\sguard", "\\腾讯游戏", "\\tp3helper",
        "\\netease", "\\易盾", "\\yuanqi", "\\antiprotect",
        // 游戏平台
        "\\steamapps\\", "\\steam\\", "\\epic games\\", "\\ubisoft", "\\origin",
        "\\ea games\\", "\\battle.net\\", "\\blizzard", "\\gog galaxy\\",
        "\\riot games\\", "\\wegame", "\\warframe", "\\rockstar",
    };
    for (const char* d : kAntiCheatDirs) if (lp.find(d) != std::string::npos) return true;

    // ④ 我方程序自身目录
    if (IsSelfPath(path)) return true;

    // ⑤ 用户自定义信任目录
    {
        std::lock_guard<std::mutex> lk(g_trustMtx);
        for (const auto& d : g_userTrustDirs) if (lp.rfind(d, 0) == 0) return true;
    }
    return false;
}

// 衍生物收集：不仅收【目标同目录】的随机名载荷，还扫【跨目录高发区】——
// 银狐常在 %TEMP%、AppData\Roaming、Users\Public、各盘 Downloads、ProgramData 里
// 释放多份副本/伴生 DLL，只清样本所在目录会漏（重启后副本可再拉起）。
// 仅收「随机名 + 可执行/脚本/加载类」文件，绝不碰正常命名的用户文件。
static void CollectDerivatives(const std::vector<std::string>& targets, std::vector<std::string>& out) {
    std::set<std::string> seen;
    for (const auto& t : targets) seen.insert(to_lower(t));
    auto isDeriv = [&](const std::string& p) -> bool {
        std::string lp = to_lower(p);
        if (IsNeverCleanPath(p)) return false;   // ★ 白名单硬拦截（反作弊/系统/Program Files）
        if (IsSelfPath(p)) return false;
        if (seen.count(lp)) return false;
        std::string base = BaseN(lp);
        static const char* derExts[] = {".exe", ".dll", ".sys", ".bin", ".dat",
                                        ".tmp", ".js", ".vbs", ".ps1", ".py", ".scr"};
        bool exeLike = false;
        for (const char* e : derExts) if (ci_ends_with(base, e)) { exeLike = true; break; }
        if (!exeLike) return false;
        return ShortRand(base);
    };
    // 扫描指定目录（maxDepth：0=仅顶层，1=顶层+一层子目录）
    auto scanDir = [&](const std::string& dir, int maxDepth) {
        std::error_code ec;
        if (!fs::exists(dir, ec)) return;
        try {
            for (auto it = fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); ++it) {
                if (it.depth() > maxDepth) { it.disable_recursion_pending(); continue; }
                std::error_code e2;
                if (!it->is_regular_file(e2)) continue;
                std::string p = it->path().string();
                if (isDeriv(p)) { out.push_back(p); seen.insert(to_lower(p)); }
            }
        } catch (...) {}
    };
    // ① 目标同目录
    for (const auto& t : targets) {
        std::string d = DirN(t);
        if (!d.empty()) scanDir(d, 0);
    }

    // ①b ★ 白加黑：从每个 PE 目标的导入表找同目录的恶意侧加载 DLL（2026-09-22）
    //
    //  为什么单列一步：上面 isDeriv 的判据是 ShortRand（短随机名），
    //  而侧加载 DLL 的**名字是正常的**（version.dll / libcurl.dll / sqlite3.dll）——
    //  它们永远不会命中随机名判据，于是整个白加黑形态在清除链上是空白的。
    //  唯一能发现它们的入口是读宿主 exe 的导入表：它声明了"我会加载哪些 DLL"。
    //
    //  ⚠️ 只在**实时处置链**（本函数）走这一步，不进全盘扫描的逐文件路径 ——
    //     sideload::Find 内部会做 WinVerifyTrust 签名校验，逐文件调用开销会累积。
    //     这里每个样本只跑一次，且只有"同目录真的存在该 DLL"时才验签，开销可忽略。
    for (const auto& t : targets) {
        std::string tl = to_lower(t);
        bool peLike = ci_ends_with(tl, ".exe") || ci_ends_with(tl, ".dll") || ci_ends_with(tl, ".sys");
        if (!peLike) continue;                    // 非 PE 没有导入表，跳过
        std::vector<sf::sideload::Finding> fs = sf::sideload::Find(t);
        for (const auto& f : fs) {
            if (f.level < 1) continue;            // 档 0 = 不报（sideload 内部已过滤，双保险）
            if (IsNeverCleanPath(f.dllPath)) continue;   // 反作弊/系统/Program Files 硬拦截
            if (IsSelfPath(f.dllPath)) continue;
            std::string lp = to_lower(f.dllPath);
            if (seen.count(lp)) continue;         // 已被 scanDir 收过则不重复
            out.push_back(f.dllPath);
            seen.insert(lp);
            LogDbg("[sideload] 纳入清除清单 level=" + std::to_string(f.level) +
                   "：" + f.dllPath + " host=" + f.hostExe);
        }
    }
    // ② 跨目录高发区（所有固定盘）
    DWORD drives = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (!(drives & (1 << (c - 'A')))) continue;
        std::string root = std::string(1, c) + ":\\";
        if (GetDriveTypeA(root.c_str()) != DRIVE_FIXED) continue;
        // Users\<user>\ 下的 Temp / Roaming（用户级衍生物高发区）
        std::error_code uec;
        std::string users = root + "Users";
        if (fs::exists(users, uec)) {
            try {
                for (auto u = fs::directory_iterator(users, uec); u != fs::directory_iterator(); ++u) {
                    std::error_code ue2;
                    if (!u->is_directory(ue2)) continue;
                    std::string udir = u->path().string();
                    scanDir(udir + "\\AppData\\Local\\Temp", 1);
                    scanDir(udir + "\\AppData\\Roaming", 1);
                    scanDir(udir + "\\Downloads", 1);
                }
            } catch (...) {}
        }
        // ProgramData / Users\Public（公共区衍生物）
        scanDir(root + "ProgramData", 1);
        scanDir(root + "Users\\Public", 1);
    }
}

// 激活指定特权（SeTakeOwnershipPrivilege 等）。服务以 LocalSystem 运行，默认持有但需显式启用。
static void EnablePrivilege(const char* name) {
    HANDLE hTok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) return;
    LUID luid;
    if (LookupPrivilegeValueA(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hTok, FALSE, &tp, 0, nullptr, nullptr);
    }
    CloseHandle(hTok);
}

// 夺取所有权：把自己（SYSTEM SID S-1-5-18）设为文件所有者。拥有者隐含 WRITE_DAC，
// 之后才能把被恶意收死的 ACL（只给别的 SID / 移除继承）改回 Everyone 可删。
static void TakeOwnershipToSystem(const std::string& path) {
    EnablePrivilege("SeTakeOwnershipPrivilege");
    PSID sysSid = nullptr;
    if (!ConvertStringSidToSidW(L"S-1-5-18", &sysSid)) return;
    SetNamedSecurityInfoW((LPWSTR)LongPathW(path).c_str(), SE_FILE_OBJECT,
                          OWNER_SECURITY_INFORMATION, sysSid, nullptr, nullptr, nullptr);
    LocalFree(sysSid);
}

static bool DeleteHard(const std::string& path) {
    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return true;   // 已不存在

    // ① 清属性（普通删除只清到 NORMAL；这里把隐藏/系统/只读/压缩类标记全清）
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(path.c_str(), FILE_ATTRIBUTE_NORMAL);
        SetFileAttributesW(LongPathW(path).c_str(), FILE_ATTRIBUTE_NORMAL);
    }

    // ② 夺权 + 解 DACL：先把 OWNER 夺到 SYSTEM（应对「ACL 只给别的 SID + 移除继承」的自保护），
    //    再把 DACL 放开给 Everyone 完全控制。夺权失败不影响后续（直接 Set DACL 也试一次）。
    TakeOwnershipToSystem(path);
    PSECURITY_DESCRIPTOR psd = nullptr;
    if (ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;FA;;;WD)", SDDL_REVISION_1, &psd, nullptr)) {
        BOOL present = FALSE, defaulted = FALSE; PACL dacl = nullptr;
        if (GetSecurityDescriptorDacl(psd, &present, &dacl, &defaulted) && present && dacl) {
            SetNamedSecurityInfoW((LPWSTR)LongPathW(path).c_str(), SE_FILE_OBJECT,
                                  DACL_SECURITY_INFORMATION, nullptr, nullptr, dacl, nullptr);
        }
        LocalFree(psd);
    }

    // ③ 严格重试（普通只试 3 次，这里 6 次 × 400ms，给进程句柄释放留足时间）
    for (int r = 0; r < 6; ++r) {
        if (TryDeleteOnce(path)) return true;
        if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
        Sleep(400);
    }

    // ④ POSIX 语义延迟删除：拿到 DELETE 权限句柄后让内核在句柄引用耗尽时删。
    //    对「未映射为代码页 + 允许共享删除」的锁文件有效（可执行映像被内存映射时仍受保护，走⑤）。
    {
        HANDLE h = CreateFileW(LongPathW(path).c_str(), DELETE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            typedef LONG(WINAPI* pNtSetInfo)(HANDLE, PVOID, PVOID, ULONG, ULONG);
            static pNtSetInfo NtSetInformationFile = (pNtSetInfo)GetProcAddress(
                GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile");
            if (NtSetInformationFile) {
                struct FILE_DISPOSITION_INFO_EX { BOOLEAN DeleteFile; ULONG Flags; };
                struct IO_STATUS_BLOCK_LOCAL { void* Pointer; ULONG_PTR Information; };
                const ULONG FileDispositionInformationEx = 64;
                const ULONG FILE_DISPOSITION_POSIX_SEMANTICS = 0x02;
                IO_STATUS_BLOCK_LOCAL io{};
                FILE_DISPOSITION_INFO_EX info{};
                info.DeleteFile = TRUE;
                info.Flags = FILE_DISPOSITION_POSIX_SEMANTICS;
                if (NtSetInformationFile(h, &io, &info, (ULONG)sizeof(info),
                                         FileDispositionInformationEx) == 0) {
                    CloseHandle(h);
                    Sleep(300);
                    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
                }
            }
            CloseHandle(h);
        }
    }

    // ⑤ 重启登记兜底（与普通流程一致）。
    //    必须用【普通路径】而非 \\?\ 长路径前缀：Session Manager 在系统启动早期读取
    //    PendingFileRenameOperations 时只认 \??\ 或盘符路径，\\?\ 是 Win32 层概念，写进去
    //    重启后解析失败 → 文件不会被删。MoveFileEx 失败时再手动写注册表（\??\ 格式）兜底，
    //    保证「登记了重启删除」就一定会在重启后立即被系统清除，无需等扫描/服务介入。
    if (GetFileAttributesA(path.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
    {
        std::wstring plain = A2W(path);   // 普通 ANSI→宽路径（无 \\?\ 前缀）
        if (!plain.empty() && MoveFileExW(plain.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) return true;
    }
    // 手动写注册表兜底：HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations
    // 格式为 REG_MULTI_SZ：成对出现 [源路径, ""]，空目标 = 删除。
    {
        std::wstring ntPath = L"\\??\\" + A2W(path);   // Session Manager 实际解析的 NT 格式
        if (!ntPath.empty() && ntPath != L"\\??\\") {
            HKEY hk = nullptr;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                              L"SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                              0, KEY_READ | KEY_WRITE, &hk) == ERROR_SUCCESS) {
                DWORD type = 0, sz = 0;
                std::vector<wchar_t> buf;
                if (RegQueryValueExW(hk, L"PendingFileRenameOperations", nullptr, &type, nullptr, &sz) == ERROR_SUCCESS && sz > 0) {
                    buf.resize(sz / sizeof(wchar_t) + 2, 0);
                    RegQueryValueExW(hk, L"PendingFileRenameOperations", nullptr, &type,
                                     (LPBYTE)buf.data(), &sz);
                }
                // 追加成对条目 [ntPath, L""]（REG_MULTI_SZ 以双 \0 结尾）
                if (!buf.empty() && buf.back() != 0) buf.push_back(0);
                for (wchar_t c : ntPath) buf.push_back(c);
                buf.push_back(0);   // 空目标 = 删除
                buf.push_back(0);   // 双 \0 结尾
                RegSetValueExW(hk, L"PendingFileRenameOperations", 0, REG_MULTI_SZ,
                               (LPBYTE)buf.data(), (DWORD)(buf.size() * sizeof(wchar_t)));
                RegCloseKey(hk);
                return true;
            }
        }
    }
    return false;
}

// 遏制强杀：按「可执行文件基名」匹配全部存活实例，连同其子进程树一并结束。
// 多轮快照（普通清除只基于精确路径找一次占用者，且不处理子进程复活）。
// 杀进程前先枚举其加载的【非系统载荷模块】（PayloadModulesOf：排除 \windows\ 系统 DLL、
// 排除自保文件、只收用户可写位置的 DLL）输出到 outMods——这些就是样本实际调用的衍生物，
// 进程死后必须一并删除，否则宿主被杀、DLL 还在（副本可再拉起）。
// 返回被杀进程总数；selfPid 轨道排除自身（本服务）。
static int KillHardByName(const std::string& targetPath, std::vector<std::string>* outMods = nullptr) {
    std::string baseL = to_lower(BaseN(targetPath));
    if (baseL.empty()) return 0;
    std::set<DWORD> killed;
    const DWORD self = GetCurrentProcessId();

    // 2 轮快照 + 杀：第一轮可能漏掉刚拉起的复活进程，第二轮收敛
    for (int round = 0; round < 2; ++round) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) break;
        std::unordered_map<DWORD, DWORD> parent;          // pid -> 父 pid
        std::vector<DWORD> matched;                        // 同名实例
        PROCESSENTRY32 pe{}; pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                parent[pe.th32ProcessID] = pe.th32ParentProcessID;
                if (pe.th32ProcessID == self || pe.th32ProcessID == 0 || pe.th32ProcessID == 4) continue;
                if (to_lower(std::string(pe.szExeFile)) == baseL) matched.push_back(pe.th32ProcessID);
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
        // 扩展：把每个同名实例的【子进程树】一并加入（银狐常由母进程拉起子载荷）
        std::vector<DWORD> todo = matched;
        for (size_t i = 0; i < todo.size(); ++i) {
            for (auto& kv : parent) {
                if (kv.second == todo[i]) todo.push_back(kv.first);
            }
        }
        for (DWORD p : todo) {
            if (killed.count(p)) continue;
            killed.insert(p);
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE,
                                   FALSE, p);
            if (h) {
                if (outMods) {
                    auto mods = PayloadModulesOf(h);   // 非系统载荷模块（样本调用的衍生物）
                    for (auto& m : mods) outMods->push_back(m);
                }
                TerminateProcess(h, 1);
                CloseHandle(h);
            }
        }
        Sleep(300);
    }
    return (int)killed.size();
}

// 高级清除主入口：输入普通清除后仍失败的清单，逐一「遏制 → 硬删」；
// 并扩展收集【同目录衍生物】（同批释放的随机名载荷）一并遏制+硬删，防止样本被重启/重新拉起。
// ---------------------------------------------------------------------------
//  P4 清除加强：ADS 流级清除 + 持久化锚点清除
// ---------------------------------------------------------------------------

// 宽→窄路径（日志用；cleaner.cpp 内部仅有 A2W，补一个反向）
static std::string W2A(const wchar_t* w) {
    if (!w || !w[0]) return std::string();
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s; if (n > 1) { s.resize(n - 1); WideCharToMultiByte(CP_ACP, 0, w, -1, &s[0], n, nullptr, nullptr); }
    return s;
}

// ADS 流级清除：银狐借 NTFS 备用数据流藏载荷（主文件伪装正常），此时只删流不动主文件。
// 仅删「可疑具名流」，Zone.Identifier/Encryptable/Smartlocker/Win32App 等系统或软件私有流保留。
// 返回删除的流数量。
static int CleanAdsOf(const std::string& path) {
    std::wstring wpath = A2W(path);
    if (wpath.empty()) return 0;
    int removed = 0;
    WIN32_FIND_STREAM_DATA fsd{};
    HANDLE h = FindFirstStreamW(wpath.c_str(), FindStreamInfoStandard, &fsd, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        std::wstring ln = fsd.cStreamName;
        while (!ln.empty() && ln[0] == L':') ln.erase(ln.begin());
        size_t tail = ln.find(L":$data");
        if (tail != std::wstring::npos) ln = ln.substr(0, tail);
        if (ln.empty() || ln == L"$data") continue;
        std::wstring ll = ln;
        for (auto& c : ll) if (c >= L'A' && c <= L'Z') c = (wchar_t)(c - L'A' + L'a');
        if (ll.find(L"zone.identifier") != std::wstring::npos) continue;
        if (ll.find(L"encryptable") != std::wstring::npos) continue;
        if (ll.find(L"smartlocker") != std::wstring::npos) continue;
        if (ll.find(L"win32app") != std::wstring::npos) continue;
        if (ll.find(L"oecustomproperty") != std::wstring::npos) continue;
        if (ll.find(L"summaryinformation") != std::wstring::npos) continue;
        std::wstring adsFull = wpath + L":" + ln;
        if (DeleteFileW(adsFull.c_str())) ++removed;
    } while (FindNextStreamW(h, &fsd));
    FindClose(h);
    return removed;
}

// 注册表 Run/RunOnce 值清理：值数据包含样本路径（小写比对）则删除该值
static void EraseRunEntry(HKEY root, const char* subkey, const std::vector<std::string>& lows) {
    HKEY hk;
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return;
    DWORD nVals = 0, maxName = 256, maxData = 4096;
    RegQueryInfoKeyA(hk, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &nVals, &maxName, &maxData, nullptr, nullptr);
    for (DWORD i = 0; i < nVals; ++i) {
        std::vector<char> vn(maxName + 1); std::vector<char> vd(maxData + 1);
        DWORD vnS = (DWORD)vn.size(), vdS = (DWORD)vd.size(), type = 0;
        if (RegEnumValueA(hk, i, vn.data(), &vnS, nullptr, &type, (LPBYTE)vd.data(), &vdS) != ERROR_SUCCESS) continue;
        std::string dl = LowerA(std::string(vd.data()));
        for (const auto& low : lows) {
            if (!low.empty() && dl.find(low) != std::string::npos) {
                RegDeleteValueA(hk, vn.data());
                LogDbg("[clean-persist] Run 值删除: " + std::string(subkey) + "[" + vn.data() + "] = " + vd.data());
                break;
            }
        }
    }
    RegCloseKey(hk);
}

// Startup 文件夹：解析 .lnk 目标，指向样本则整条删除
static void EraseStartupLinks(const std::vector<std::string>& lows, const std::wstring& dir) {
    std::error_code ec;
    try {
        for (auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
             it != fs::directory_iterator(); ++it) {
            std::error_code e2;
            if (!it->is_regular_file(e2)) continue;
            std::wstring p = it->path().wstring();
            if (p.size() < 5 || _wcsicmp(p.substr(p.size() - 4).c_str(), L".lnk") != 0) continue;
            IShellLinkW* sl = nullptr;
            if (FAILED(CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&sl)) || !sl) continue;
            IPersistFile* pf = nullptr;
            if (SUCCEEDED(sl->QueryInterface(IID_IPersistFile, (void**)&pf)) && pf) {
                if (SUCCEEDED(pf->Load(p.c_str(), STGM_READ))) {
                    wchar_t target[MAX_PATH * 2] = {0};
                    if (SUCCEEDED(sl->GetPath(target, MAX_PATH * 2, nullptr, SLGP_RAWPATH)) && target[0]) {
                        std::string tl = LowerA(W2A(target));
                        for (const auto& low : lows) {
                            if (!low.empty() && tl.find(low) != std::string::npos) {
                                _wremove(p.c_str());
                                LogDbg("[clean-persist] Startup .lnk 删除: " + W2A(p.c_str()));
                                break;
                            }
                        }
                    }
                }
                pf->Release();
            }
            sl->Release();
        }
    } catch (...) {}
}

// Windows 服务清理：ImagePath 指向样本 → 停止服务并删除服务键
static void DeleteServicePersistence(const std::vector<std::string>& lows) {
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ | KEY_WRITE | KEY_WOW64_64KEY, &hk) != ERROR_SUCCESS) return;
    DWORD idx = 0; char name[128];
    for (;;) {
        DWORD nl = sizeof(name);
        if (RegEnumKeyExA(hk, idx, name, &nl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        ++idx;
        HKEY sk;
        if (RegOpenKeyExA(hk, name, 0, KEY_READ | KEY_WOW64_64KEY, &sk) != ERROR_SUCCESS) continue;
        char img[MAX_PATH * 2] = {0}; DWORD imgs = sizeof(img); DWORD itype = 0;
        bool match = false;
        if (RegQueryValueExA(sk, "ImagePath", nullptr, &itype, (LPBYTE)img, &imgs) == ERROR_SUCCESS && img[0]) {
            std::string il = LowerA(std::string(img));
            for (const auto& low : lows) if (!low.empty() && il.find(low) != std::string::npos) { match = true; break; }
        }
        RegCloseKey(sk);
        if (!match) continue;
        // 停止该服务（避免删键时被 SCM 拒绝 / 复活）
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (scm) {
            SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_STOP | DELETE);
            if (svc) {
                SERVICE_STATUS ss{};
                ControlService(svc, SERVICE_CONTROL_STOP, &ss);
                DeleteService(svc);
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
        }
        // 兜底：直接删注册表服务键（若 OpenService 失败）
        RegDeleteTreeA(hk, name);
        LogDbg("[clean-persist] 服务删除: " + std::string(name) + " (" + img + ")");
    }
    RegCloseKey(hk);
}

// 入口：对全部样本路径清除持久化锚点（每次高级清除收尾调用）
static void CleanPersistenceFor(const std::vector<std::string>& targets) {
    std::vector<std::string> lows;
    for (const auto& t : targets) {
        std::string p = t;
        size_t q = p.find('"');
        if (q != std::string::npos) {
            size_t q2 = p.find('"', q + 1);
            p = p.substr(q + 1, q2 == std::string::npos ? std::string::npos : q2 - q - 1);
        } else {
            size_t sp = p.find(' ');
            if (sp != std::string::npos) p = p.substr(0, sp);
        }
        std::string l = LowerA(p);
        if (l.size() > 3) lows.push_back(l);
    }
    if (lows.empty()) return;
    // ① Run / RunOnce：HKCU + HKLM
    EraseRunEntry(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", lows);
    EraseRunEntry(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", lows);
    EraseRunEntry(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", lows);
    EraseRunEntry(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce", lows);
    // ② 服务
    DeleteServicePersistence(lows);
    // ③ Startup 快捷方式（当前用户 + 公共）
    {
        wchar_t p[MAX_PATH] = {0};
        if (SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, 0, p) == S_OK && p[0]) EraseStartupLinks(lows, p);
        if (SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, 0, p) == S_OK && p[0]) EraseStartupLinks(lows, p);
    }
}

CleanReport AdvancedCleanFiles(const std::vector<std::string>& targetsIn) {
    CleanReport rep;
    // 去重 + 去空
    std::vector<std::string> targets;
    for (const auto& t : targetsIn) if (!t.empty()) targets.push_back(t);
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    // 扩展：同目录随机名衍生物（银狐整批释放，删主样本不够）
    std::vector<std::string> deriv;
    CollectDerivatives(targets, deriv);
    for (const auto& d : deriv) targets.push_back(d);
    std::sort(targets.begin(), targets.end());
    targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
    rep.requested = (int)targets.size();

    // 高级清除时，进程是动态的：遏制杀进程前枚举其加载的【非系统载荷模块】，
    // 运行中发现的新衍生物（样本实际调用的 DLL）追加进待删清单一并硬删。
    std::set<std::string> advSeen;
    for (const auto& t : targets) advSeen.insert(to_lower(t));

    for (size_t i = 0; i < targets.size(); ++i) {
        const std::string& t = targets[i];
        WriteCleanProgress("advkill", (int)i, (int)targets.size(), t);
        CleanItemResult it; it.path = t;
        if (IsSelfPath(t)) { it.action = "skipped"; it.reason = "自保排除：我方程序文件"; ++rep.skipped; rep.items.push_back(it); continue; }
        if (GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) { it.action = "deleted"; ++rep.deleted; rep.items.push_back(it); continue; }

        // ① 遏制：按基名 2 轮快照强杀（含子进程树）；先枚举进程调用的非系统载荷模块
        std::vector<std::string> liveMods;
        int killed = KillHardByName(t, &liveMods);
        if (killed > 0) rep.killed += killed;
        // 把运行期发现的载荷模块并入 targets（进程被杀、宿主已删，模块不能留）
        for (const auto& m : liveMods) {
            if (IsSelfPath(m)) continue;
            if (!advSeen.insert(to_lower(m)).second) continue;
            targets.push_back(m);
            WriteCleanProgress("advkill", (int)targets.size() - 1, (int)targets.size(), m);
        }

        // ② 硬删：清属性 → 解 ACL → 严格重试 → POSIX 删除 → 重启登记
        WriteCleanProgress("delete", (int)i, (int)targets.size(), t);
        if (DeleteHard(t)) {
            it.action = "deleted";
            it.reason = killed > 0 ? "高级清除：已强制结束 " + std::to_string(killed) + " 个进程并删除"
                                   : "高级清除：已解除权限并删除";
            ++rep.deleted;
        } else if (GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) {
            it.action = "deleted";   // 期间被别的流程删掉
            ++rep.deleted;
        } else {
            it.action = "failed";
            it.reason = "高级清除仍失败（错误码 " + std::to_string(GetLastError()) + "）";
            ++rep.failed;
        }
        rep.items.push_back(it);
    }
    // 收尾 ①：ADS 流级清除（主文件删不掉/合法宿主时，流里的载荷单独拔除）
    for (const auto& t : targets) {
        if (IsSelfPath(t)) continue;
        if (GetFileAttributesA(t.c_str()) == INVALID_FILE_ATTRIBUTES) continue;
        int rm = CleanAdsOf(t);
        if (rm > 0) LogDbg("[clean-ads] " + std::to_string(rm) + " stream(s) removed from " + t);
    }
    // 收尾 ②：持久化锚点清除（Run/服务/Startup，防下次开机复活）
    CleanPersistenceFor(targets);
    WriteCleanProgress("done", (int)targets.size(), (int)targets.size(), "");
    return rep;
}

// ---------------------------------------------------------------------------
//  ★ 衍生物定点清除（2026-09-20 新增）——实时拦截联动专用
//
//  触发场景（三条实时路径）：
//    · WmiSink：进程被判高危并已 TerminateProcess → 清它释放/召唤出来的伴生文件
//    · LandedAlertWatch：落地载荷已隔离 → 清同批落地的其它副本
//    · RegRunWatch：可疑自启动项已移除 → 清它指向的载荷本体
//
//  与 AdvancedCleanFiles 的差别（刻意做得更保守）：
//    · 不杀进程（调用方已处置；此处只处理文件，避免实时路径里再掀进程树）
//    · 有文件数上限（默认 24），防止实时路径被海量枚举拖住
//    · 全程白名单（IsNeverCleanPath）+ 自保 + 目标去重
//    · 单文件失败就跳过，不升级为「重启登记删除」——重启登记是重武器，
//      实时路径里误登记一个正常文件的后果是用户下次开机发现文件没了且无从追溯
//
//  删除策略：先 TryDeleteOnce（轻量，能删掉就用它）；删不掉说明被占用，
//            此时**不硬删**（硬删会解 ACL + 夺权，风险面大），只跳过并记原因。
//            真正的顽固文件留给用户显式点「一键清除 / 高级清除」去处理。
//            这样实时路径永远是「安全可撤销」的，不会自作主张扩大破坏面。
// ---------------------------------------------------------------------------
int SweepDerivatives(const std::vector<std::string>& seedPaths,
                     CleanReport* outReport, bool dryRun) {
    const size_t kMaxFiles = 24;   // 实时路径硬上限
    int removed = 0;

    if (seedPaths.empty()) return 0;

    // 种子路径净化：只保留非空、非白名单、非自保的
    std::vector<std::string> seeds;
    for (const auto& s : seedPaths) {
        if (s.empty()) continue;
        if (IsNeverCleanPath(s) || IsSelfPath(s)) continue;
        seeds.push_back(s);
    }
    if (seeds.empty()) return 0;

    // 收集衍生物（CollectDerivatives 内部已做白名单 + 自保 + 去重）
    std::vector<std::string> deriv;
    try { CollectDerivatives(seeds, deriv); } catch (...) { return 0; }
    if (deriv.empty()) return 0;

    // 再兜一层上限（CollectDerivatives 可能一次收很多）
    std::vector<std::string> todo;
    for (const auto& d : deriv) {
        if (todo.size() >= kMaxFiles) break;
        if (IsNeverCleanPath(d) || IsSelfPath(d)) continue;   // 双保险
        todo.push_back(d);
    }
    if (todo.empty()) return 0;

    CleanReport rep;
    rep.requested = (int)todo.size();

    for (const auto& p : todo) {
        CleanItemResult it; it.path = p;
        if (dryRun) {
            it.action = "skipped";
            it.reason = "干跑模式：仅枚举，未删除";
            ++rep.skipped;
            rep.items.push_back(it);
            continue;
        }
        if (GetFileAttributesA(p.c_str()) == INVALID_FILE_ATTRIBUTES) {
            it.action = "deleted";
            it.reason = "衍生物已不存在";
            ++rep.deleted; ++removed;
            rep.items.push_back(it);
            continue;
        }
        if (TryDeleteOnce(p)) {
            it.action = "deleted";
            it.reason = "已清除衍生物（同批释放的随机名载荷）";
            ++rep.deleted; ++removed;
            rep.items.push_back(it);
            LogDbg("[deriv] 已清除衍生物: " + p);
            continue;
        }
        // 被占用 → 实时路径**不硬删**（避免解 ACL / 夺权扩大破坏面），跳过等用户显式清除
        it.action = "failed";
        it.reason = "文件被占用，已跳过（如需强制清除请在主界面点「一键清除」）";
        ++rep.failed;
        rep.items.push_back(it);
        LogDbg("[deriv] 衍生物删除失败（被占用，跳过）: " + p);
    }

    if (outReport) *outReport = rep;
    if (removed > 0)
        LogDbg("[deriv] 本轮衍生物清除完成：requested=" + std::to_string(rep.requested) +
               " deleted=" + std::to_string(rep.deleted) +
               " failed=" + std::to_string(rep.failed));
    return removed;
}

// 是否属于「可清除的强样本类」：只清理乱码（随机名）文件、双后缀诱饵、已知路径/标记样本，
// 以及扫描器连坐发现的自带 DLL（同目录载荷）。旁证类（ADS/超隐藏的属性旁证）绝不进清除队列——
// 那可能是用户自建软件（OneMail.exe 等）或正常软件私有流，删了就是事故。
static bool IsCleanTarget(const Finding& f) {
    if (f.category != "文件" || f.path.empty()) return false;
    static const char* cleanTitles[] = {
        "发现双后缀诱饵文件", "发现银狐可疑文件路径", "发现随机名可执行文件",
        "发现银狐标记文件", "发现超隐藏文件（隐藏+系统属性）",
        "发现随机名驱动文件", "发现随机名 DLL 模块", "发现畸形文件名（结尾空格/点）",
        "发现同目录 DLL 载荷",                       // 扫描器已判定的自带/连坐 DLL
    };
    for (const char* t : cleanTitles) if (f.title == t) return true;
    return false;   // ADS 旁证 / 超隐藏旁证 / 系统同名 DLL 侧加载（剪映等正常软件自带）→ 不删
}

// 进程类强样本也应整体清除：结束进程 + 删除可执行文件本体（f.path 已在扫描时存为完整路径）。
// 只收「恶意载荷名 / 双后缀 / 随机名落盘」这类不可辩驳的；「合法程序被利用做 DLL 侧加载」的
// 宿主 EXE 是合法软件，只删其 path 指向的恶意 DLL，绝不删宿主进程。
static bool IsCleanProcTarget(const Finding& f) {
    if (f.category != "进程" || f.path.empty()) return false;
    static const char* killTitles[] = {
        "发现已知银狐木马进程", "进程为双后缀诱饵程序",
        "随机名进程位于可疑落地目录", "可写目录下存在随机名可执行文件",
        "合法程序被利用进行 DLL 侧加载",            // path 即恶意 DLL 全路径，删 DLL 不删宿主
        "系统主机进程被注入可疑 DLL",              // path 即被注入的 DLL 全路径：只删 DLL，宿主受保护不杀
    };
    for (const char* t : killTitles) if (f.title == t) return true;
    return false;   // 「进程路径含银狐可疑片段」不足以单独判删，避免误删含同名片段的合法程序
}

std::vector<std::string> CollectCleanTargets() {
    std::vector<std::string> out;
    {
        std::lock_guard<std::mutex> lk(g_resultMutex);
        for (const auto& f : g_result.findings) {
            if (IsCleanTarget(f) || IsCleanProcTarget(f)) out.push_back(f.path);
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

}  // namespace sf
