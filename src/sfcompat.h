// sfcompat.h — Windows 版本适配与进程访问能力层（契约）
//
// 配套 mod_compat.cpp。设计约束：
//   · **只声明、不实现**（实现全在 mod_compat.cpp）
//   · 纯能力声明，不含任何判定逻辑，便于其它模块独立 include
//   · 命名统一 sf::compat:: 命名空间
#ifndef SFCOMPAT_H
#define SFCOMPAT_H

#include <string>

namespace sf { namespace compat {

// 统一版本口径。RtlGetNtVersionNumbers 拿内核真值，**不受 manifest 撒谎影响**
// （GetVersionEx 在 Win11 上会因 manifest 报 6.2，必须弃用）。
// 失败返回 false（调用方应假定"较新"，不贸然走兼容分支）。
bool WinVersion(unsigned& major, unsigned& minor, unsigned& build);

// 人类可读版本串，如 "Win11 (10.0.26200)" / "Win10.0 build 19045" / "版本探测失败"。
const char* WinVerText();

// Win10 及更早（含 10.0）。Win11 的 major 仍报 10，**必须靠 build>=22000 区分**。
bool IsWin10OrOlder();

// ★ 启用 SeDebugPrivilege。服务以 SYSTEM 运行但默认**未启用**该特权，
//   导致 OpenProcess(PROCESS_TERMINATE) 对受保护进程失败 ——
//   而日志会把权限不足写成"进程已退出"，掩盖真因。
//   ★ 必须回读 GetLastError：AdjustTokenPrivileges 在特权未授予时仍返回 TRUE。
//   返回 true 表示**确实拿到**该特权。应在服务启动早期调用一次。
bool EnableDebugPrivilege();

// 多策略读取远程进程命令行。
//   outStrategy（可选）回填实际生效的策略：0=失败 1=直读 PEB 2=走 Ldr 链表兜底。
//   ★ 与旧实现的关键差别：读不到时**返回空，不拿 imagePath 顶替**，
//     由调用方显式降级并打日志（旧实现在 behavior.cpp:1364 静默顶替 ⇒ 静默漏报）。
std::string ReadRemoteCommandLineEx(void* h, int* outStrategy);

// 便捷包装（不关心策略时用）。
std::string ReadRemoteCommandLine(void* h);

// 一次性兼容性自检，把「这台机器上哪几处不工作」变成可观测事实。
std::string CompatDiag();

}}  // namespace sf::compat

#endif  // SFCOMPAT_H
