// cleaner.h — 可疑文件清除（强制项）
// 运行在 LocalSystem 服务进程内，因此天然具备「最高权限」：
// 可结束任意会话/任意用户的进程、删除用户无权限删除的文件，**无需 UAC 提权**。
#pragma once
#include <string>
#include <vector>

namespace sf {

// 单个目标的清除结果
struct CleanItemResult {
    std::string path;    // 目标文件路径
    std::string action;  // deleted（已删除）/ deferred（已登记重启后删除）/ failed（失败）/ skipped（自保排除）
    std::string reason;  // 说明：被杀进程名 / 失败原因等
};

// 一次清除任务的汇总
struct CleanReport {
    int requested = 0;         // 请求清除的目标数（不含运行期新发现的载荷 DLL）
    int deleted   = 0;         // 已成功删除
    int deferred  = 0;         // 仍被占用，已登记重启后由系统删除（MOVEFILE_DELAY_UNTIL_REBOOT）
    int failed    = 0;         // 彻底失败
    int skipped   = 0;         // 自保排除（我方程序文件）
    int killed    = 0;         // 为解除占用而强制结束的进程数
    int extraDlls = 0;         // 运行期从被结束进程里发现的额外载荷 DLL（银狐释放的模块）
    std::vector<std::string> killedNames;   // 被结束的进程名
    std::vector<CleanItemResult> items;
};

// 以最高权限清除指定文件集合：
//   ① 清属性后直接删除；
//   ② 删除失败（多半是文件被占用/正在运行）→ 找出占用它的进程（镜像路径或已加载模块命中）→ 强杀 → 重试删除；
//      重试两轮，兼顾进程退出后句柄延迟释放的情况；
//   ③ 仍失败 → MoveFileEx(MOVEFILE_DELAY_UNTIL_REBOOT) 登记重启后删除，保证下次开机不再存活。
// 我方自身程序文件一律跳过（自保），避免把杀软自己删掉。
// 过程中每处理一个目标都会把进度写入进度文件（供用户会话里的弹窗渲染进度条）。
CleanReport CleanFiles(const std::vector<std::string>& targets);

// 高级清除（卡巴斯基「Advanced Disinfection」思路的本地化子集，无内核驱动）：
// 给「普通清除 ③ 仍失败」的顽固目标兜底——
//   遏制：按【可执行文件基名】匹配全部存活实例 + 其子进程树，多轮快照强杀（防“杀一个又拉一个”）；
//   硬删：清全部文件属性 → 解除 DACL（Everyone 完全控制，破“删除权限被收紧”的自我保护）→
//         严格重试删除 → NtSetInformationFile 以 POSIX 语义延迟删除（绕过“句柄未释放但仍可删”）→
//         最后 MoveFileEx 重启登记兜底。
CleanReport AdvancedCleanFiles(const std::vector<std::string>& targets);

// 收集「当前扫描结果」中可清除的文件目标（category=="文件" 且 path 非空），已去重。
std::vector<std::string> CollectCleanTargets();

// ---------------------------------------------------------------------------
//  衍生物定点清除（2026-09-20 新增）——供实时拦截三条路径联动调用
//
//  与 CleanFiles / AdvancedCleanFiles 的区别：
//    · 只清「种子样本的衍生物」（同目录 + 高发区的短随机名载荷），不碰用户正常文件；
//    · **不杀种子进程**（种子进程由调用方负责终止），只清它释放/拉起的伴生文件；
//    · 强制执行路径白名单（见下），任何落在白名单目录里的文件一律不动；
//    · 文件数有硬上限，避免实时路径被扫盘拖慢。
//
//  为什么必须带白名单：衍生物判据是「短随机名 + 可执行扩展名」，在 Temp/Downloads/
//  ProgramData/Users\Public 里按名字扫。而**游戏反作弊**（EasyAntiCheat / BattlEye /
//  ACE / Vanguard / Riot Vanguard 等）恰好会把随机名组件释放到 ProgramData、
//  Temp 这些目录 —— 不加白名单就是实打实的误删事故（毁游戏 = 用户直接卸载我们）。
//
//  参数 seedPaths   ：种子样本路径（被判高危的文件 / 被终止进程的映像路径）。
//  参数 outReport   ：可选，回填本次清除的统计与明细（供弹窗文案与历史记录）。
//  参数 dryRun      ：true = 只枚举不删除（用于先验证误删面，默认 false）。
//  返回实际删除（含登记重启删除）的文件数。
// ---------------------------------------------------------------------------
int SweepDerivatives(const std::vector<std::string>& seedPaths,
                     CleanReport* outReport = nullptr,
                     bool dryRun = false);

// 判断一个路径是否落在「绝不清理」的白名单内（反作弊、游戏平台、系统目录、我方程序、
// 以及用户在配置里登记的信任目录）。暴露出来供 service.cpp 与测试脚本共用。
bool IsNeverCleanPath(const std::string& path);

// 登记一条用户信任目录（该目录及其子目录下的文件永不进入任何清除流程）。
// 供扩展端「信任区」/ 配置项调用；内部自动小写化并补尾部反斜杠。
void AddNeverCleanDir(const std::string& dir);

// ---- 清除进度（服务写 / 弹窗读）----
// 弹窗运行在用户桌面会话，拿不到服务内存里的进度，故经
// %ProgramData%\SilverFoxGuard\clean_progress.txt 传递，格式：
//     phase=<locate|kill|delete|done> done=<已完成数> total=<总数> current=<当前目标路径>
void WriteCleanProgress(const std::string& phase, int done, int total, const std::string& current);
bool ReadCleanProgress(std::string& phase, int& done, int& total, std::string& current);
void ClearCleanProgress();

}  // namespace sf
