// common.h — 银狐主防程序共享基础模块
// 被 service（守护/服务）与 nmhost（原生消息宿主）两个可执行文件共用。
#pragma once
#include <string>

// ⚠️ 本头文件的接口里用了 HANDLE（见下方 WriteFramed / ReadFramed），
//    所以必须自带 windows.h —— 否则任何"先 include common.h、后 include
//    windows.h"的编译单元都会报 `common.h(38): error C2065: HANDLE 未声明的
//    标识符`，而错误指向本文件，极易被误判成"common.h 被改坏了"。
//    （2026-09-22 真实踩坑：sfthread.cpp 因此编不过。）
//    若调用方已定义 WIN32_LEAN_AND_MEAN，windows.h 会遵从该宏，行为不变。
#ifdef _WIN32
#  include <windows.h>
#endif

// 扫描结果结构定义（被 BuildResultJson 使用）
#include "scanner.h"

namespace sf {

// ---- 常量 ----
extern const wchar_t* SVC_NAME;        // Windows 服务名
extern const wchar_t* SVC_DISPLAY;     // 服务显示名
extern const wchar_t* PIPE_NAME;       // 命名管道 \\.\pipe\SilverFoxGuard
extern const char*    NM_HOST_NAME;    // Native Messaging 宿主名 com.silverfox.guard

// ---- 路径 ----
std::string GetExePath();              // 当前模块完整路径（ANSI）
std::string DirName(const std::string& path);
std::string BaseName(const std::string& path);
bool FileExists(const std::string& path);

// ---- 哈希 ----
std::string Sha256File(const std::string& path);
std::string Sha256Bytes(const void* data, size_t len);

// ---- JSON ----
std::string JsonEscape(const std::string& s);     // 转义 \ " 等
std::string JsonString(const std::string& s);     // 带引号、已转义的 JSON 字符串
// ★ 2026-10-02 新增：JsonEscape 的**逆运算**（还原 \\ \" \/ \n \r \t \b \f \uXXXX）。
//   为什么必须单独提供：本工程的 JSON 解析一律是"字符串查找式"的极简实现，早期调用方
//   （service.cpp 的落地告警消费线程）直接把两个引号之间的**原文**当路径用 —— 于是生产者
//   写出的 "C:\\WINDOWS\\system32\\cmd.exe" 里的双反斜杠被原样带进了路径。
//   后果不是"打不开文件"（Win32 会自动折叠重复分隔符，复制副本/算哈希照常成功），
//   而是**前缀比较类判定静默失效** —— 见 scanner.cpp HasCatalogSignature 的
//   %SystemRoot% 前缀检查：`c:\\windows` 与 `c:\windows` 第 3 个字符就不等 → 判"不在
//   Windows 目录下" → 微软正版系统组件被判「无可信签名」。凡是"从 JSON 取字符串"的
//   地方都必须过一遍本函数，不能拿 find 出来的原文直接用。
std::string JsonUnescape(const std::string& s);
// 极简字段提取：从 {"key":"value"} 中取出 key 对应的字符串值
std::string JsonGetString(const std::string& json, const std::string& key);
// 取出 key 对应的【数字】值（BuildResultJson 输出裸数字，故不能对 JsonGetString 的结果用 atoi）
int JsonGetInt(const std::string& json, const std::string& key);
// ★ 64 位版（2026-09-25）：JsonGetInt 内部虽然用 long long 累加，但末尾 `return (int)(...)`
//   会按 32 位截断 —— Unix 毫秒时间戳（约 1.76e12）、超 2GB 的文件字节数（如 3e9）、
//   百年老文件的年龄秒数（约 3.1e9）全部超 int32，经 JsonGetInt 取回来就是垃圾值。
//   凡是要传时间戳 / 文件大小 / 长年龄的字段一律用本函数。
//   JsonGetInt 保持原样：既有调用方（score/level/count/on/…）全部期望 int，不能改返回类型。
long long JsonGetInt64(const std::string& json, const std::string& key);
// 把扫描结果序列化为 JSON（供管道 / 原生消息传输）
std::string BuildResultJson(const ScanResult& r);

// ---- 命名管道帧（4 字节小端长度前缀 + 负载）----
bool WriteFramed(HANDLE h, const std::string& msg);
bool ReadFramed(HANDLE h, std::string& out);

// ---- 自保 ----
// 自身完整性校验：比对本程序与安装时记录的 SHA-256；无基线（未安装）返回 true
bool VerifySelfIntegrity(std::string& outCurrentHash);
bool StoreHash(const std::string& hash);          // 安装 / 服务自身调用，写受保护注册表
std::string ReadStoredHash();
// 文件 ACL 加固：仅 SYSTEM/Admins 可写，普通用户只读+执行
bool HardenFileAcl(const std::string& path);

// ---- 系统通知 ----
// 环境异常时向交互式桌面用户发送系统消息（服务位于 Session 0，需跨会话推送）。
// 内部按状态切换去重：仅当状态较上次变化时弹一次，避免反复刷屏。
//   status = "infected"  → 高危告警（疑似中银狐）
//   status = "warning"   → 风险预警（存在可疑迹象）
//   status = "normal"    → 仅在由异常恢复时弹一次「已恢复正常」
//
// 后三个参数供「勒索回滚」场景使用（普通扫描告警留空即可）：
//   risk       = "high"    → 引擎已自动处置，卡片渲染「撤销我的处理」
//                "suspect" → 仅拦截未动手，卡片渲染「还原文件」询问按钮
//   undoToken  = 撤销凭据；非空时卡片会把 token 回传给服务调用 rollbackundo
//   rolledBack = 本次是否真的发生过覆盖写（false 则不显示撤销入口）
void NotifyAnomaly(const std::string& status, int score,
                   const std::string& risk = std::string(),
                   const std::string& undoToken = std::string(),
                   bool rolledBack = false);

// 沙箱动态分析弹窗（Electron 卡片，由服务跨会话拉起）：
//   NotifySandboxProgress —— 进度卡「可疑文件正在送进沙箱检测，预计还剩 N 秒」（带倒计时）。
//   NotifySandboxResult   —— 结果卡（verdict = malicious / suspicious / clean，附行为摘要）。
//   file 由调用方传 UTF-8 路径；内部做 URL 编码后拼入 Electron 载荷，JS 侧 decodeURIComponent 还原。
//   etaSec / score 越界会被钳制（eta 1~600s；score 0~200；verdict 非三枚举值按 suspicious 降级）。
void NotifySandboxProgress(const std::string& file, int etaSec);
// errToken / errLeftSec：★ 无结论（verdict=error）时的**用户决策凭据**（2026-10-03）。
//   非空 ⇒ 卡片渲染「删掉 / 不删除」两个按钮 + 倒计时，用户的选择经
//   管道命令 errdecide + 该令牌下达；errLeftSec 秒内无人决策则自动删除。
//   默认空 = 不带决策区（clean/malicious/suspicious/not_applicable 都不需要）。
//   ⚠️ 令牌只由服务端生成、只认自己发出去的那一批；前端拿到的路径**不可**用于删除。
void NotifySandboxResult(const std::string& file, const std::string& verdict,
                         int score, const std::string& summary,
                         const std::string& errToken = std::string(),
                         int errLeftSec = 0);

// ---- 维护模式（临时停止守护）----
//
// 【解决什么问题】
//   主防有三层"守护自保"，导致用户/AI **无法正常停掉它做调试**：
//     ① 服务被删 → 服务内 GuardThread 每 30 分钟 EnsureServiceRegistered() 重建；
//     ② 服务被停 → SCM 的 failure actions 拉起；
//     ③ 服务停/删后 → 浏览器拉起 NM 宿主时 SelfHealService() 自愈重启（最凶的一条）。
//   实战后果：想临时停服排障，只能"把安装目录整个删掉"——而这会把同目录下的
//   沙箱（Sandboxie）等服务一起带走，代价过大。
//
// 【安全模型 —— 为什么不是"用户写个文件就能关掉自保"】
//   标记文件 C:\ProgramData\SilverFoxGuard\maint.flag 的 ACL 由服务端(SYSTEM)设置：
//   SYSTEM/Administrators 完全控制，Everyone **只读**。所以普通权限的恶意程序
//   写不进、也删不掉这个文件 —— 它无法"自己关掉自保"。
//   开启动作只能经管道命令 cmd=maint 触发，且服务端用 GetNamedPipeClientProcessId
//   校验调用方映像必须是【安装目录下的 SilverFoxGUI.exe】（该目录 ACL 已由
//   HardenFileAcl 加固为仅 SYSTEM/Admin 可写）→ 第三方程序无法冒充 GUI。
//   ⚠️ 因此**调试命令行不能开启维护模式**（--maint=on 不实现），这是刻意的。
//   另加 TTL 兜底：标记带过期时间，超时自动失效，避免忘了关导致长期无防护。
bool MaintenanceActive();                  // 标记存在且未过期？
bool EnterMaintenance(int ttlMinutes);     // 写标记（仅服务端鉴权通过后调用）
bool ExitMaintenance();                    // 删标记（需 SYSTEM/Admin 权限）
std::string MaintenanceInfoJson();         // {"on":1,"left":<秒>,"expire":<unix>}

// 调试日志（写 C:\ProgramData\SilverFoxGuard\guard.log，VM 也可访问）。
// 用于回捞弹窗 / 扫描链路在真实环境中的执行证据。
void LogDbg(const std::string& msg);

// 纯 C 版日志：签名只有 POD 参数，供 __except 块内使用。
// MSVC 不允许在 __try 所在函数里展开 C++ 对象（C2712），而 LogDbg 的
// std::string 参数会在调用点构造临时对象 —— 所以 SEH 处理块里必须用这个。
void LogDbgC(const char* msg);

// 在用户桌面会话渲染右下角 WebView2 通知（由服务跨会话拉起 --toast 模式调用）。
// 自带固定版本 WebView2 运行时（exe 同级 WebView2Runtime 目录），不依赖系统 Edge。
// 后三个参数为勒索回滚场景附加：risk（"high"/"suspect"）、undoToken、rolledBack。
int RunToast(const std::string& status, int score,
             const std::string& risk = std::string(),
             const std::string& undoToken = std::string(),
             bool rolledBack = false);

// 预热模式：在扫描进行期间提前创建 WebView2 环境（省去扫描完成后弹窗的冷启动 5~8 秒）。
// 预热完成后轮询结果文件，读到「正常」则静默退出不留进程；读到「异常」则原地渲染对应状态并显示。
int RunPrewarm();
int RunScanProgress();
int RunProbeToast(const std::wstring& fileW);   // 右键自定义查杀：连服务管道判定并渲染右下角卡片

// ---- Native Messaging 宿主注册表 ----
// 写清单 JSON 文件，返回其路径
bool WriteNmManifest(const std::string& hostExePath,
                     const std::string& extIdChrome,
                     const std::string& extIdEdge,
                     std::string& outManifestPath);
// 在 Chrome + Edge 的 NativeMessagingHosts 下写入指向清单的注册表项
bool RegisterNmHost(const std::string& manifestPath,
                    const std::string& extIdChrome,
                    const std::string& extIdEdge);
bool UnregisterNmHost();

// 记录 / 读取已配置的本机扩展 ID（供双击重装复用，避免丢失 allowed_origins）
bool SaveExtIds(const std::string& chrome, const std::string& edge);
bool ReadSavedExtIds(std::string& outChrome, std::string& outEdge);

// 受保护的配置根键（HKLM\SOFTWARE\SilverFoxGuard，安装时以管理员写入）
extern const char* CFG_ROOT;

// 读安装器写入的安装目录（HKLM\SOFTWARE\SilverFoxGuard\InstallDir）。
// ★ 进程外组件（shell 扩展等）**只能**靠它定位主程序 —— 不要按 %ProgramFiles%
//   之类约定猜路径：用户可以把 $INSTDIR 指到任意盘，猜路径会静默失效
//   （菜单出现、点击没反应）。读不到返回空串，调用方必须判空。
std::wstring ReadInstallDir();

}  // namespace sf
