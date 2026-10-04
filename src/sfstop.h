// sfstop.h — 服务停止信号的统一契约
//
// 【为什么要有这个文件】
// 拆分巨型文件（见 docs/refactor-roadmap.md）时最大的阻力不是代码量，而是
// 「隐式约定」：谁拥有 g_stopEvent、谁能 Set、各线程该怎么退。这些约定过去
// 只存在于 service.cpp 的 2796 行里，子模块（bootguard / rollback / etw）
// 各自用 SetStopEvent(void*) 存了一份句柄 —— 包括 etw.cpp 里那份**私有的**
// 第二套 CreateEventW，意味着服务停止时 ETW 线程走的是另一条退出路径。
//
// 本文件把「停止信号」定义成唯一契约：service.cpp 拥有并驱动，其余模块只读。
//
// 【线程退出范式 —— 全项目统一，勿自创】
//     while (!sf::IsStopRequested()) {
//         if (WaitForSingleObject(sf::StopHandle(), 5000) != WAIT_TIMEOUT) break;
//         ...
//     }
// 或需要等多个句柄时，把 StopHandle() 放进句柄数组一起 WaitForMultipleObjects。
//
// ⚠️ 命名沿用 service.h 的既有 API（RequestStop / IsStopRequested），
//    本文件**不重复声明**它们，只补一个此前缺失的 StopHandle()。
//    这样存量调用点（service.cpp 内部 20+ 处 g_stop / g_stopEvent 用法）
//    无需一次性改写，新模块则统一走这两个函数。
//
// ⚠️ 本文件不含任何状态定义：真正的 g_stopEvent / g_stop 仍在 service.cpp 定义
//    （它们必须随 SERVICE_STATUS 生命周期走），这里通过访问器暴露唯一视图。
#pragma once

#include "service.h"   // RequestStop() / IsStopRequested()

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#endif

namespace sf {

// 停止事件句柄（可等待对象）。**可能为空** —— 例如脱离服务环境跑的回归程序、
// 或 nmhost 进程未创建该事件时。调用方必须先判空再 WaitForSingleObject：
//
//     HANDLE h = sf::StopHandle();
//     if (h && WaitForSingleObject(h, 5000) != WAIT_TIMEOUT) break;
//
// 刻意保留这种宽松语义，是为了让同一份线程代码既能跑在服务里，
// 也能被单测/回归程序复用（后者不建事件，靠 IsStopRequested() 轮询退出）。
HANDLE StopHandle();

}  // namespace sf
