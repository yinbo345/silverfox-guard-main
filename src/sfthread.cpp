// sfthread.cpp — 工作线程双层兜底实现（契约见 sfthread.h）
//
// 本文件是原 service.cpp 内 static ThreadBodyCxx / RunThreadGuard 的公共化搬迁，
// 实现逐字保留（包括 C2712 相关的注意事项），仅函数名与可见性变化。
#include "sfthread.h"

#include <windows.h>
#include <cstdio>
#include <exception>
#include <string>

#include "common.h"    // LogDbg / LogDbgC

namespace sf {

// ---------------------------------------------------------------------------
// 内层：捕获 C++ 异常（此函数体内禁止出现 __try）
// ---------------------------------------------------------------------------
static void ThreadBodyCxx(const char* name, void (*fn)()) {
    try {
        fn();
    } catch (const std::exception& e) {
        LogDbg(std::string("[fatal] 线程 ") + name + " 抛出 C++ 异常: " + e.what() +
               "（已捕获，服务继续运行）");
    } catch (...) {
        LogDbg(std::string("[fatal] 线程 ") + name + " 抛出未知 C++ 异常（已捕获，服务继续运行）");
    }
}

// ---------------------------------------------------------------------------
// 外层：捕获 SEH。注意本函数内**不得声明任何需要析构的对象**，
// 否则 MSVC 报 C2712「无法在需要对象展开的函数中使用 __try」。
// ---------------------------------------------------------------------------
void RunThreadGuarded(const char* name, void (*fn)()) {
    DWORD sehCode = 0;
    char buf[160];   // 栈上定长缓冲：POD，不触发对象展开
    __try {
        ThreadBodyCxx(name, fn);
    } __except (sehCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        // 这里只能用 LogDbgC（纯 C）—— LogDbg 的 std::string 参数会在调用点
        // 构造临时对象，直接触发 C2712。
        snprintf(buf, sizeof(buf),
                 "[fatal] 线程 %s 触发结构化异常 0x%08X（已捕获，服务继续运行）",
                 name, (unsigned)sehCode);
        LogDbgC(buf);
    }
}

}  // namespace sf
