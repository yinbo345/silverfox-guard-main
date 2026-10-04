// sfutils.h — 共享路径 / 字符串工具的唯一出口
//
// 【为什么要有这个文件】
// BaseName / DirName / FileExists / JsonEscape / JsonString 这些函数
// 已在 common.h 声明、common.cpp 实现（2026-09-22 核对确认），但 service.cpp /
// rollback.cpp / trace.cpp 里仍各自散落了同类小函数（约 14 处），语义略有差异
// （大小写处理、尾部分隔符、空路径返回 "\\" 还是 ""），导致「同一个路径」
// 在不同模块里判等失败 —— 历史上回滚引擎误判文件已变更，根因即在此。
//
// 本文件不重复声明已有函数，只补齐**缺失且被多处需要**的那几个，
// 并作为「新代码该用哪一套」的明确指引。
//
// 【新代码请统一 include 本文件】而不是零散地 include common.h 里那几个函数 ——
// 目的是把「路径比较必须大小写不敏感」这类规则收敛到一个地方。
#pragma once
#include <string>

namespace sf {

// ---- 以下函数实现见 common.cpp（此处仅作契约汇总，便于新模块一处 include）----
// std::string DirName(const std::string& path);
// std::string BaseName(const std::string& path);
// bool        FileExists(const std::string& path);
// std::string JsonEscape(const std::string& s);
// std::string JsonString(const std::string& s);

// ---- 本文件补齐的工具 ----

// 小写扩展名（含点，例 ".exe"）。无扩展名或纯点文件返回空串。
// ⚠️ 不能用 BaseName 之后手工找点：形如 "C:\a.b\file" 会把目录里的点算进去，
//    本函数只取最后一段分隔符之后的第一个点，规避该坑。
std::string ExtLower(const std::string& path);

// 归一化路径：统一分隔符为 '\'、去掉结尾多余分隔符、不去大小写。
// 用于「同一文件的不同写法」归并（NT 路径 → 盘符路径的转换不在此处，
// 见 etw.cpp 的 NormalizeImagePath，那是另一件事）。
std::string NormPath(const std::string& path);

// 大小写不敏感判等（Windows 路径语义）。空串与空串相等，空串与非空不等。
bool PathEqualsCi(const std::string& a, const std::string& b);

// 路径 a 是否位于目录 dir 之下（大小写不敏感，按路径分量比较，不做子串匹配）。
// 例：IsUnderDir("C:\\Windows\\Temp\\x.exe", "C:\\Windows\\Temp") == true
//     IsUnderDir("C:\\Windows\\TempX\\x.exe","C:\\Windows\\Temp") == false
bool IsUnderDir(const std::string& path, const std::string& dir);

// 本地时间串，格式固定为 "YYYY-MM-DD HH:MM:SS"。
// ⚠️ 全项目只应有这一个时间戳格式：历史上弹窗卡片、日志、扫描结果各写了一套
//    （有的带毫秒、有的用 '-' 分隔日期），导致前端解析时不得不同时兼容三种。
std::string NowStr();

}  // namespace sf
