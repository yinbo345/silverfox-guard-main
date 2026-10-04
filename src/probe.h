// probe.h — 银狐主防单文件启发式查杀引擎（独立于全盘扫描链路）
#pragma once
#include <string>
#include <vector>   // ImportedDlls 的输出参数

namespace sf {

// 单文件启发式判定：返回 JSON
// {"level":0|1|2,"score":n,"type":"PE|NSIS|INNO|ZIP|OTHER",
//  "title":"...","hits":[{"sev":0|1|2|3,"name":"...","desc":"..."},...]}
// level: 0=正常 1=可疑 2=危险
// 全程离线、不运行样本、不做整文件字符串泛匹配。
std::string ScanTargetFile(const std::string& path);

// 读取 PE 的导入 DLL 名（小写、去重）。
// 用途：DLL 劫持/侧加载（"白加黑"）检测 —— 由导入表得知"这个 exe 会加载哪些 DLL"，
//       再去它所在目录看是否存在可被劫持的同名文件。
// 返回 false = 非 PE 或解析失败 —— 调用方**不得**据此判定任何东西（宁可漏报不可误报）。
bool ImportedDlls(const std::string& path, std::vector<std::string>& out);

// ---------------------------------------------------------------------------
//  LooksLikeInstallerExe：判断「这个 .exe 其实是自解压安装器」（2026-10-03 新增）
// ---------------------------------------------------------------------------
//  场景：`packscan::IsArchiveExt()` 只认归档**扩展名**（zip/rar/7z/…），
//        而银狐本体是「PE 头 + 内嵌 Inno/NSIS 载荷」的 .exe ⇒ 永远进不了 packscan 队列，
//        只能靠单文件静态判定，**看不见包内真实载荷**。
//        本函数让分流判据从「扩展名像不像归档」改成「**外层魔数是不是安装器**」。
//  判据：只扫两条魔数 —— "Inno Setup Setup Data (" / "NullsoftInst"；
//        **只看 .exe/.com/.scr**（其他扩展名直接返回 false，省一次文件扫描）。
//  ★ 返回 false = 交回原路径，**绝不误分流**。
//  ★ 任何异常都吞掉返回 false —— 它在实时轮询路径上，不能因判据失败影响主链。
bool LooksLikeInstallerExe(const std::string& path);

// ---------------------------------------------------------------------------
//  归档解压（供沙箱模块复用）
// ---------------------------------------------------------------------------
// 定位：**把压缩包里的真实文件解压到磁盘**，不是"解包分析"。
// 场景：沙箱要观察的是**行为**，压缩包本身不是可执行体（送进去什么都不发生），
//       所以必须先解压出里面的真实载荷（exe/dll/脚本），再逐个送进沙箱运行。
//
// 与 ScanTargetFile 的关系：ScanTargetFile 内部也会解包，但那是**静态**判定
// （列条目 + 看名字/内容特征），不产生可直接运行的文件。两者不互相替代。
//
// 返回 false 时：解压失败（加密/损坏/私有变体）或 7z 不可用。
//   ★ 调用方**不得**把"解压失败"当成"包内没有恶意文件" —— 那是覆盖缺口。
std::string Find7z();                                              // 空串 = 未找到 7z.exe
bool ExtractArchiveTo(const std::string& archivePathUtf8,
                      const std::string& destDirUtf8);             // 7z x -y -aos 到目录

}  // namespace sf