// crashlog.cpp — 崩溃留证实现（契约见 crashlog.h）
//
//  实现只有三件事，刻意保持极简：
//   ① 装 SetUnhandledExceptionFilter；
//   ② 崩溃时把异常事实 + guard.log 尾部写成一个 txt；
//   ③ 启动时若发现上次的 crash-*.txt，打一行日志。
//
//  ★ 全部 POD / 定长缓冲，函数体内不出现任何需要栈展开的对象 ——
//     MSVC C2712：含 __try 的函数不能展开 C++ 对象。崩溃时 CRT 状态不可信，
//     所以连 std::string 都不用（连文件名拼接都是手写 wchar 数组）。
#include "crashlog.h"

#include <windows.h>
#include <shlobj.h>

#include "common.h"   // LogDbg（只在非崩溃路径用）

namespace sf {
namespace crashlog {

namespace {

// 崩溃文件名（模块作用域，Install 时算一次；崩溃路径只读它 ⇒ 无需再算）
wchar_t g_lastPath[MAX_PATH] = {0};

void CrashDirW(wchar_t* out, size_t cap) {
    wchar_t p[MAX_PATH] = {0};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p) == S_OK)
        _snwprintf_s(out, cap, _TRUNCATE, L"%s\\SilverFoxGuard\\crash", p);
    else
        _snwprintf_s(out, cap, _TRUNCATE, L"%s\\SilverFoxGuard\\crash", L"C:\\ProgramData");
    CreateDirectoryW(out, nullptr);
}

// 读 guard.log 尾部若干 KB 追加进崩溃文件。
// guard.log 是 UTF-16LE，这里**原样按字节拷贝**（不做转码）——
// 目的只是"崩溃前最后发生了什么"，保留原始字节比保证可读性更重要
// （此刻任何解析代码都可能因崩溃现场而不稳定）。
void AppendLogTail(HANDLE h) {
    // 与 CrashDirW 同口径：优先 CSIDL，取不到才退回 C:\ProgramData。
    wchar_t log[MAX_PATH];
    wchar_t base[MAX_PATH] = {0};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, base) == S_OK)
        _snwprintf_s(log, MAX_PATH, _TRUNCATE, L"%s\\SilverFoxGuard\\guard.log", base);
    else
        wcscpy_s(log, L"C:\\ProgramData\\SilverFoxGuard\\guard.log");

    HANDLE lg = CreateFileW(log, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (lg == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER li{};
    if (!GetFileSizeEx(lg, &li) || li.QuadPart <= 0) { CloseHandle(lg); return; }

    // 取尾部 8KB（固定量，避免大日志被整个读进内存）
    const DWORD want = 8192;
    const DWORD tail = (li.QuadPart > (LONGLONG)want) ? want : (DWORD)li.QuadPart;
    LARGE_INTEGER from{}; from.QuadPart = li.QuadPart - tail;
    if (!SetFilePointerEx(lg, from, nullptr, FILE_BEGIN)) { CloseHandle(lg); return; }

    BYTE buf[8192];
    DWORD rd = 0;
    if (ReadFile(lg, buf, tail, &rd, nullptr) && rd > 0) {
        const wchar_t* sep = L"\r\n---- guard.log 尾部（崩溃前最后发生的事）----\r\n";
        DWORD wn = 0;
        WriteFile(h, sep, (DWORD)(wcslen(sep) * sizeof(wchar_t)), &wn, nullptr);
        WriteFile(h, buf, rd, &wn, nullptr);
        WriteFile(h, L"\r\n---- 尾部结束 ----\r\n", (DWORD)(wcslen(L"---- 尾部结束 ----\r\n") * sizeof(wchar_t)), &wn, nullptr);
    }
    CloseHandle(lg);
}

// ★ 本函数是 SEH 回调：**禁止任何需要栈展开的对象**（C2712）。全 POD。
LONG WINAPI CrashFilter(EXCEPTION_POINTERS* ep) {
    wchar_t dir[MAX_PATH];
    CrashDirW(dir, MAX_PATH);

    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t cp[MAX_PATH];
    _snwprintf_s(cp, MAX_PATH, _TRUNCATE, L"%s\\crash-%04d%02d%02d_%02d%02d%02d_%lu.txt",
                 dir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                 (unsigned long)GetCurrentProcessId());

    HANDLE h = CreateFileW(cp, GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        wchar_t mod[MAX_PATH] = {0};
        GetModuleFileNameW(nullptr, mod, MAX_PATH);

        wchar_t head[1024];
        _snwprintf_s(head, 1024, _TRUNCATE,
                     L"崩溃时刻 %04d-%02d-%02d %02d:%02d:%02d.%03d  pid=%lu  tid=%lu\r\n"
                     L"PE 映像 %ls\r\n",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                     st.wMilliseconds, (unsigned long)GetCurrentProcessId(),
                     (unsigned long)GetCurrentThreadId(), mod);
        DWORD wn = 0;
        WriteFile(h, head, (DWORD)(wcslen(head) * sizeof(wchar_t)), &wn, nullptr);

        if (ep && ep->ExceptionRecord) {
            wchar_t eb[256];
            _snwprintf_s(eb, 256, _TRUNCATE,
                         L"异常码 0x%08X  地址 %p  标志 0x%08X\r\n",
                         (unsigned)ep->ExceptionRecord->ExceptionCode,
                         (void*)ep->ExceptionRecord->ExceptionAddress,
                         (unsigned)ep->ExceptionRecord->ExceptionFlags);
            WriteFile(h, eb, (DWORD)(wcslen(eb) * sizeof(wchar_t)), &wn, nullptr);
            if (ep->ExceptionRecord->NumberParameters <= 4) {
                for (UINT i = 0; i < ep->ExceptionRecord->NumberParameters; i++) {
                    wchar_t pb[64];
                    _snwprintf_s(pb, 64, _TRUNCATE, L"  参数[%u] = %p\r\n", i,
                                 (void*)ep->ExceptionRecord->ExceptionInformation[i]);
                    WriteFile(h, pb, (DWORD)(wcslen(pb) * sizeof(wchar_t)), &wn, nullptr);
                }
            }
        }
        AppendLogTail(h);
        CloseHandle(h);
    }
    // 交回系统，让 SCM 的失败策略照常重启（不自己重启，避免与自保逻辑打架）
    return EXCEPTION_CONTINUE_SEARCH;
}

}  // namespace

void Install() {
    wchar_t dir[MAX_PATH];
    CrashDirW(dir, MAX_PATH);

    // 找上次的崩溃文件（不删：连续崩多次时那几份就是唯一线索）
    wchar_t pat[MAX_PATH];
    _snwprintf_s(pat, MAX_PATH, _TRUNCATE, L"%s\\crash-*.txt", dir);
    WIN32_FIND_DATAW fd{};
    HANDLE hf = FindFirstFileW(pat, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        // 取最近一次（显式比较时间：FindFirstFile 的顺序跨卷/文件系统不可靠）
        ULONGLONG bt = 0;
        do {
            ULONGLONG t = ((ULONGLONG)fd.ftLastWriteTime.dwHighDateTime << 32)
                        | fd.ftLastWriteTime.dwLowDateTime;
            if (t > bt) { bt = t; _snwprintf_s(g_lastPath, MAX_PATH, _TRUNCATE,
                                               L"%s\\%ls", dir, fd.cFileName); }
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }

    SetUnhandledExceptionFilter(CrashFilter);

    if (g_lastPath[0]) {
        char w[MAX_PATH * 2];
        WideCharToMultiByte(CP_UTF8, 0, g_lastPath, -1, w, (int)sizeof(w), nullptr, nullptr);
        LogDbg(std::string("[crash] 检测到上次崩溃遗留：") + w +
               "（异常码与崩溃前日志尾部见该文件）");
    }
}

}  // namespace crashlog
}  // namespace sf
