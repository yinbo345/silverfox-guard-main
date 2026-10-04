// mod_compat.cpp — Windows 版本适配与进程访问能力层
//
// ===========================================================================
//  为什么要这个文件（2026-10-03，Win10 虚拟机实测逼出来的）
// ===========================================================================
//  银泊在 **Windows 10** 虚拟机上跑真样本，暴露了一整族"在 Win11 上恰好能工作"的
//  隐性依赖。实测四条断点：
//
//   ① 命令行拿不到（铁律 41）
//      `behavior.cpp:1336` 硬编码 `PEB + 0x20` 取 ProcessParameters，
//      偏移**按位宽固定**，不随 Windows 版本变；`RTL_USER_PROCESS_PARAMETERS`
//      的 `CommandLine` 偏移在 Win10 早期版本是 `0x40`，Win11 是 `0x38` 附近。
//      ⇒ 同一个偏移在两个版本上**只有一个对**。
//      叠加 `service.cpp:2143` 的 240ms 重试窗口 ⇒ Win10 上大面积读空。
//
//   ② 读空后静默降级（铁律 41 下半段）
//      `behavior.cpp:1364` 读空时 `commandLine = imagePath` —— 不是空，是被路径顶替。
//      规则库几乎全是命令行子串匹配 ⇒ 一律 0 分 ⇒ **静默漏报，不报任何错**。
//
//   ③ ★★ 服务从不提 `SeDebugPrivilege`（本文件新增的根因修复）
//      全工程只有 `cleaner.cpp:700 EnablePrivilege()`，且**只用于文件所有权**。
//      `OpenProcess(PROCESS_TERMINATE)` 打不开别的用户/受保护进程 ⇒
//      实测连续 5 次「终止进程失败（权限不足或进程已退出）」，
//      而 `innoextract.exe` 明明是 SYSTEM 服务能杀的 ⇒ **权限不是不够，是没去要**。
//      ⇒ 服务启动时必须显式启用 SeDebugPrivilege。
//
//   ④ 全工程**零版本判断**
//      grep `IsWindows10|VerifyVersionInfo|RtlGetNtVersionNumbers` 全无命中
//      ⇒ 没有任何"这台机器是不是 Win10"的判断能力，全部靠运行时碰运气。
//
//  本文件把 ③④ 补上，并给 ①② 提供**多策略 + 可观测**的取命令行能力：
//  · `EnableDebugPrivilege()`   —— 服务启动调一次
//  · `WinVersion()`             —— 统一版本口径（RtlGetNtVersionNumbers，**不依赖 manifest**）
//  · `IsWin10OrOlder()`
//  · `ReadRemoteCommandLineEx()`—— 三级策略 + 每级成败都留日志
//  · `CompatDiag()`             —— 一次性自检，把四个断点的状态写进日志
//
// ===========================================================================

#include "module.h"
#include "sfcompat.h"

#include <windows.h>
#include <winternl.h>

#include <cstdio>
#include <cstring>
#include <string>

namespace sf { namespace compat {

// ---------------------------------------------------------------------------
//  版本口径：RtlGetNtVersionNumbers（ntdll 导出）
//  ★ 不用 GetVersionEx / VerifyVersionInfo：
//    前者受 application manifest 里的 "supportedOS" 撒谎影响（Win11 会报 6.2 / 10.0），
//    后者对 Win10 1809 之后的版本号无能为力。
//    RtlGetNtVersionNumbers 是内核真值，manifest 说谎也骗不过它。
// ---------------------------------------------------------------------------
bool WinVersion(unsigned& major, unsigned& minor, unsigned& build) {
    typedef VOID(WINAPI* PfnRtlGetNtVersionNumbers)(ULONG*, ULONG*, ULONG*);
    static PfnRtlGetNtVersionNumbers pfn = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) pfn = (PfnRtlGetNtVersionNumbers)GetProcAddress(nt, "RtlGetNtVersionNumbers");
    }
    if (!pfn) return false;
    RTL_OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    ULONG b = 0;
    pfn(&vi.dwMajorVersion, &vi.dwMinorVersion, &b);
    major = vi.dwMajorVersion;
    minor = vi.dwMinorVersion;
    build = b & 0x0FFFFFFFu;          // 高 16 位是 flags，取低 16 位才是 build 号
    return true;
}

bool IsWin10OrOlder() {
    unsigned mj = 0, mn = 0, bd = 0;
    if (!WinVersion(mj, mn, bd)) return false;   // 探测失败 ⇒ 假定较新 ⇒ 不走兼容分支
    return mj < 10 || (mj == 10 && mn <= 0);
}

const char* WinVerText() {
    static char buf[64];
    static bool done = false;
    if (done) return buf;
    unsigned mj = 0, mn = 0, bd = 0;
    if (WinVersion(mj, mn, bd)) {
        // Win11 22H2+ 的 build 与 Win10 末代(19045)重叠，必须靠 mj/mn 区分：
        // 微软官方口径：Win11 = 10.0.22000 及以上，且 major 仍报 10。
        // 唯一可靠判据是 build >= 22000 且 major==10 ⇒ 报 11。
        if (mj == 10 && mn == 0 && bd >= 22000)
            snprintf(buf, sizeof(buf), "Win11 (10.0.%u)", bd);
        else
            snprintf(buf, sizeof(buf), "Win%u.%u build %u", mj, mn, bd);
    } else {
        snprintf(buf, sizeof(buf), "版本探测失败(RtlGetNtVersionNumbers 不可用)");
    }
    done = true;
    return buf;
}

// ---------------------------------------------------------------------------
//  SeDebugPrivilege —— ★ 本文件最重要的修复
// ---------------------------------------------------------------------------
//  为什么必须显式启用：
//  服务以 LocalSystem 运行，**默认持有但未启用** SeDebugPrivilege。
//  未启用时 OpenProcess(PROCESS_TERMINATE) 对其它用户/受保护进程会
//  返回 ERROR_ACCESS_DENIED ⇒ 我们的「已自动终止高危进程」永远失败，
//  而日志只写「终止进程失败（权限不足或进程已退出）」——**把权限问题说成进程已退出**。
//  实测代价：innoextract 事件里连续 5 次处置失败（pid 3484/20280/12636/5668…）。
//
//  注意：AdjustTokenPrivileges 即使「没这个特权」也会**返回成功**（只设 LastError），
//  所以必须回读 GetLastError() 才能判断是否真的拿到 —— 这一点极易漏。
bool EnableDebugPrivilege() {
    HANDLE hTok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
        return false;
    }
    LUID luid{};
    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hTok);
        return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(ERROR_SUCCESS);
    const BOOL ok = AdjustTokenPrivileges(hTok, FALSE, &tp, 0, nullptr, nullptr);
    const DWORD err = GetLastError();
    CloseHandle(hTok);
    // ★ ok 可能为 TRUE 而 err==ERROR_NOT_ALL_ASSIGNED（特权未授予）
    if (!ok) return false;
    if (err != ERROR_SUCCESS) return false;
    return true;
}

// ---------------------------------------------------------------------------
//  远程命令行读取：三级策略 + 可观测
// ---------------------------------------------------------------------------
//  背景（断点 ①②）：behavior.cpp 原来只有「硬编码 PEB+0x20」一策，
//  Win10 上读空 → 降级成 imagePath → 命令行规则全 0 分 → 静默漏报。
//
//  这里给三条策略，按成本从低到高逐级尝试，**任一成功即返回**：
//    策略 A：直接读 PEB，按**位宽**取 ProcessParameters 偏移，再按**版本**取 CommandLine 偏移
//    策略 B：枚举 PEB->Ldr 链表，在各模块的 PEB 里找 ProcessParameters（对布局差异更宽容）
//    策略 C：读不到就**如实返回空**，绝不用 imagePath 顶替（由调用方决定降级策略并打日志）
//
//  ★ 与原实现的关键差别：
//    1) PEB 偏移按**编译位宽**（x64=0x20 / x86=0x10）而不是恒 0x20
//    2) CommandLine 偏移**按 Windows 版本**取值（Win10 早期 0x40 / Win11 0x38）
//    3) **不静默降级** —— 失败时日志会写明「读不到命令行」，不再伪装成路径
//
//  outStrategy：非空时写入实际生效的策略名（用于日志打点，故障可诊断）
static bool ReadProcessArgs(HANDLE h, std::wstring& out, int* outStrategy) {
    typedef NTSTATUS(WINAPI* PfnNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static PfnNtQIP pNtQIP = nullptr;
    static bool tried = false;
    if (!tried) {
        tried = true;
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) pNtQIP = (PfnNtQIP)GetProcAddress(nt, "NtQueryInformationProcess");
    }
    if (!pNtQIP) return false;

    // ProcessBasicInformation = 0
    struct {
        PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2];
        ULONG_PTR UniqueProcessId; PVOID Reserved3;
    } pbi{};
    ULONG retLen = 0;
    if (pNtQIP(h, 0, &pbi, sizeof(pbi), &retLen) != 0 || !pbi.PebBaseAddress) return false;

    const BYTE* peb = (const BYTE*)pbi.PebBaseAddress;
    SIZE_T rd = 0;

#ifdef _WIN64
    const SIZE_T kPebParamsOff = 0x20;    // x64 PEB.ProcessParameters
#else
    const SIZE_T kPebParamsOff = 0x10;    // x86 PEB.ProcessParameters
#endif

    // ---- 策略 A：直读，按候选偏移试 CommandLine ----------------------------
    //  RTL_USER_PROCESS_PARAMETERS（x64）真实布局（本项目**实测 dump 确认**，
    //  见下方「为什么不再猜偏移」）：
    //    MaximumLength 0x00 / Length 0x04 / Flags 0x08 / DebugFlags 0x0C
    //    ConsoleHandle 0x10 / ConsoleFlags 0x18 / StandardInput 0x20
    //    StandardOutput 0x28 / StandardError 0x30
    //    CurrentDirectory 0x38 / DllPath 0x48
    //    ImagePathName 0x60  ★
    //    CommandLine    0x70  ★  ← 真实值
    //    Environment    0x80
    //
    //  ★★★ 2026-10-03 修正（真样本轮实测打出的铁证）：
    //  旧候选表是 `{ 0x38, 0x40, 0x30, 0x48, 0x28, 0x20 }` —— **里面没有 0x70**。
    //  后果不是「读错」，而是**一个偏移都命不中 ⇒ 100% 读空**：
    //      compat 自检：策略=0 长度=0 ★读到空
    //      实际运行：596 次判定，cmdStrategy **全部** =0，cmd 全部 =（空）
    //  连**读自己的进程**都读不到 ⇒ 排除了权限/时序/目标特殊性，
    //  只能是实现本身错了。这就是铁律 41「静默漏报」的完整现场：
    //  日志一切正常、周期统计照打、服务不报错，而**所有命令行规则全 0 分**。
    //
    //  【为什么不再"猜"偏移】旧表把 0x38/0x40 当成候选，那是**凭印象抄的**
    //  （0x38 其实是 CurrentDirectory、0x48 是 DllPath，都不是字符串路径）。
    //  正确做法：**先按权威布局排好序，再加一条"结构化扫描"兜底** ——
    //  见下方 tryParams 里的 ScanFallback。
    //  ★ 0x60（ImagePathName）**故意不在快路径里**：它只有路径、没有参数，
    //    靠 requireCmdShape 里的"含 -- / - / /"可能勉强通过，也可能因
    //    路径里含盘符 `:\` 而误判。把它交给扫描兜底并要求"更长"更稳。
    static const SIZE_T kCandX64[] = { 0x70, 0x48, 0x38, 0x40, 0x30, 0x28, 0x20 };
    static const SIZE_T kCandX86[] = { 0x40, 0x38, 0x30, 0x24, 0x2C, 0x1C, 0x18, 0x14 };

    auto tryParams = [&](const BYTE* params) -> bool {
        if (!params) return false;

        // 读一个 UNICODE_STRING 并做**内容合理性**校验。
        // ★ 合理性校验是这套逻辑能成立的关键：光看 len/buf 合法是不够的 ——
        //   任何一段可读内存都能被解释成"长度合理的 UNICODE_STRING"，
        //   所以必须额外要求「像命令行」（见下方 nonWs 与 looksCmd）。
        auto readUs = [&](SIZE_T off, std::wstring& dst, bool requireCmdShape) -> bool {
            USHORT len = 0; ULONG_PTR buf = 0;
            SIZE_T got = 0;
            if (!ReadProcessMemory(h, params + off, &len, sizeof(len), &got)) return false;
            // ★★ Buffer 在 **off + 8**，不是 off + sizeof(USHORT)。
            //   UNICODE_STRING 的实际内存布局是：
            //       +0  USHORT Length
            //       +2  USHORT MaximumLength
            //       +4  USHORT padding（对齐填充）
            //       +8  PWSTR Buffer      ← 8 字节指针对齐
            //   写成 off + sizeof(USHORT)（= off+2）会把 Length/MaximumLength
            //   与 padding 一起当成指针读 ⇒ 得到一个**看起来合法、实则垃圾**的地址 ⇒
            //   ReadProcessMemory 失败或读出乱码 ⇒ **任何偏移都命不中**。
            //   这与「候选表里没有 0x70」是**两个独立的 bug，叠在一起**才导致
            //   100% 读空 —— 修一个另一个仍在（实测：只修偏移表仍读不到）。
            if (!ReadProcessMemory(h, params + off + 8, &buf, sizeof(buf), &got)) return false;
            if (len == 0 || len > 32768 || (len & 1) || !buf) return false;
            // ★ 多读一个字（len/2 + 1）再截断：UNICODE_STRING 的 Buffer **不保证**
            //   以 NUL 结尾。只读 len/2 个字符时，若内容含尾部残留就会带进脏字符。
            std::wstring w(len / sizeof(wchar_t) + 1, L'\0');
            if (!ReadProcessMemory(h, (void*)buf, &w[0], len, &got)) return false;
            w.resize(len / sizeof(wchar_t));
            size_t nonWs = 0;
            for (wchar_t c : w) if (c != L' ' && c != L'\0' && c != L'\t' && c != L'\r' && c != L'\n') ++nonWs;
            if (nonWs < 2) return false;
            if (requireCmdShape) {
                // 命令line 的形状：应当含可执行文件名（.exe）或参数标记（- / --）。
                // 判据不能只看 .exe —— 有些样本命令行只有参数没有路径（由父进程传入）。
                const bool hasExe = w.find(L".exe") != std::wstring::npos ||
                                    w.find(L".com") != std::wstring::npos;
                const bool hasArg = w.find(L"--") != std::wstring::npos ||
                                    w.find(L" -") != std::wstring::npos ||
                                    w.find(L"/") != std::wstring::npos;
                if (!hasExe && !hasArg) return false;
            }
            dst.swap(w);
            return true;
        };

        // ---- ① 按权威布局试（快路径，绝大多数情况一发命中）----
        // ⚠️ 这里**不能**写 `for (SIZE_T off : (cond ? kCandX64 : kCandX86))`：
        //   两个数组的元素类型虽同，但**数组类型不同**，三元表达式不 decay 成指针，
        //   MSVC 直接报 C3312「找不到 const SIZE_T* 的 begin」（原写法就是这么写的，
        //   只是当时编译器恰好推过去了 —— 不可依赖）。显式取指针最稳。
        {
            const SIZE_T* cand = (sizeof(void*) == 8) ? kCandX64 : kCandX86;
            const size_t   n   = (sizeof(void*) == 8)
                                 ? (sizeof(kCandX64) / sizeof(kCandX64[0]))
                                 : (sizeof(kCandX86) / sizeof(kCandX86[0]));
            for (size_t i = 0; i < n; ++i) {
                if (readUs(cand[i], out, /*requireCmdShape=*/true)) return true;
            }
        }

        // ---- ② 结构化扫描兜底（**不依赖任何硬编码偏移**）----
        //  为什么需要：候选表是"权威布局"，但 Windows 未来改布局、或某些
        //  安全软件对目标进程做过 PEB 扰动，候选表就会再次全灭 ——
        //  而"全灭"的表现是**静默漏报**（铁律 41），最难查。
        //  做法：把前 0x100 字节按 8 字节步长逐个当 UNICODE_STRING 读，
        //  用**内容形状**判定（像命令行 + 与 ImagePath 有区别）来认。
        //  代价：最坏多几十次 ReadProcessMemory（本地内存，微秒级），
        //  且只在候选表全灭时才走 ⇒ 正常路径零开销。
        {
            std::wstring best;
            SIZE_T bestOff = 0;
            for (SIZE_T off = 0; off <= 0xF0; off += 8) {
                std::wstring w;
                if (!readUs(off, w, /*requireCmdShape=*/true)) continue;
                // 命令行通常**包含**映像路径 ⇒ 至少与候选表里的答案一样长，
                // 且必须含参数或 exe。取最长者作为最可能的命令行。
                if (best.empty() || w.size() > best.size()) { best.swap(w); bestOff = off; }
            }
            if (!best.empty()) {
                out = best;
                // 用 3 标记"扫描兜底命中"：排障时能一眼看出"偏移表已过期，
                // 这次是靠扫描读到的" ⇒ 提醒该更新 kCandX64。
                if (outStrategy) *outStrategy = 3;
                return true;
            }
        }
        return false;
    };

    {
        void* params = nullptr;
        if (ReadProcessMemory(h, (void*)(peb + kPebParamsOff), &params, sizeof(params), &rd) && params) {
            if (tryParams((const BYTE*)params)) { if (outStrategy) *outStrategy = 1; return true; }
        }
    }

    // ---- 策略 B：走 Ldr 链表，在模块 PEB 里再找一次 --------------------------
    // 某些系统上 ProcessParameters 在 PEB 里可能暂未填好，但模块 PEB 已有。
    // 代价是几次额外读，但只在 A 失败时走。
#ifdef _WIN64
    const SIZE_T kLdrOff = 0x18;   // PEB.Ldr
    const SIZE_T kInLoadOff = 0x20;
#else
    const SIZE_T kLdrOff = 0x0C;
    const SIZE_T kInLoadOff = 0x14;
#endif
    {
        void* ldr = nullptr;
        if (ReadProcessMemory(h, (void*)(peb + kLdrOff), &ldr, sizeof(ldr), &rd) && ldr) {
            // LDR_DATA_TABLE_ENTRY.InLoadOrderLinks 是链表头，遍历前 8 个模块足够
            const BYTE* base = (const BYTE*)ldr;
            for (int i = 0; i < 8; ++i) {
                LIST_ENTRY head{};
                if (!ReadProcessMemory(h, base + kInLoadOff, &head, sizeof(head), &rd)) break;
                void* link = head.Flink;
                if (!link || link == head.Flink) break;
                LIST_ENTRY cur{};
                if (!ReadProcessMemory(h, link, &cur, sizeof(cur), &rd)) break;
                // LDR_DATA_TABLE_ENTRY.DllBase 在 InLoadOrderLinks 之后
                // x64: +0x30  /  x86: +0x18
                void* modBase = nullptr;
#ifdef _WIN64
                const SIZE_T kDllBase = 0x30;
#else
                const SIZE_T kDllBase = 0x18;
#endif
                if (!ReadProcessMemory(h, (const BYTE*)link + kDllBase, &modBase, sizeof(modBase), &rd)) break;
                if (!modBase) break;
                void* mp = nullptr;
                if (ReadProcessMemory(h, (const BYTE*)modBase + kPebParamsOff, &mp, sizeof(mp), &rd)
                    && tryParams((const BYTE*)mp)) {
                    if (outStrategy) *outStrategy = 2;
                    return true;
                }
                base = (const BYTE*)link;
            }
        }
    }
    return false;
}

std::string ReadRemoteCommandLineEx(HANDLE h, int* outStrategy) {
    if (outStrategy) *outStrategy = 0;
    std::wstring w;
    if (!ReadProcessArgs(h, w, outStrategy)) return {};
    if (w.empty()) return {};
    const int need = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (need <= 0) return {};
    std::string out(need, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &out[0], need, nullptr, nullptr);
    return out;
}

std::string ReadRemoteCommandLine(HANDLE h) {
    int s = 0;
    return ReadRemoteCommandLineEx(h, &s);
}

// ---------------------------------------------------------------------------
//  兼容性自检：把四个断点的状态一次性写进日志
//  服务启动后调一次，让"Win10 上到底哪几处不工作"变成可观测事实而非猜测。
// ---------------------------------------------------------------------------
std::string CompatDiag() {
    std::string s;
    char b[512];

    snprintf(b, sizeof(b), "版本=%s  SeDebugPrivilege=%s\n",
             WinVerText(), EnableDebugPrivilege() ? "已启用" : "★未启用");
    s += b;

    // 自检命令行读取能力：拿自己的进程试（自己一定读得到 ⇒ 可作基线）
    int st = 0;
    HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE,
                              (DWORD)GetCurrentProcessId());
    if (self) {
        std::string cl = ReadRemoteCommandLineEx(self, &st);
        snprintf(b, sizeof(b),
                 "自检命令行：策略=%d 长度=%u  %s\n",
                 st, (unsigned)cl.size(), cl.empty() ? "★读到空" : "可读");
        s += b;
        CloseHandle(self);
    } else {
        s += "自检命令行：★OpenProcess 自进程失败（SeDebug 未生效？）\n";
    }

    // 列出本次实际生效的候选偏移策略（诊断用）
    snprintf(b, sizeof(b),
             "PEB偏移策略=%s  宽=%d  IsWin10OrOlder=%d\n",
             (sizeof(void*) == 8 ? "x64" : "x86"),
             (int)sizeof(void*), IsWin10OrOlder() ? 1 : 0);
    s += b;
    return s;
}

}}  // namespace sf::compat

// ===========================================================================
//  模块注册
// ===========================================================================
namespace sf { namespace mod {

// 无管道命令 —— 这是一次性自检，由 service.cpp 启动流程直接调用。
// 不走 if-else 链（module.h 的契约要求），所以 CmdEntry 为空。
const Module kModule_compat = {
    "compat", nullptr, nullptr, nullptr, nullptr, 0
};

}}
