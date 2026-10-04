// iowatch.cpp — 文件系统 / 注册表写操作采集层实现
//
// 线程范式照 etwproc.cpp / netwatch.cpp（**勿自创**）：
//   会话随机名 → 一个会话订阅两个 provider → OpenTrace 实时消费
//   → ETW 回调只解析+入队（绝不磁盘 I/O）→ 独立消费线程出队 → 过滤 → 外发
//
// 与 etwproc.cpp 的差异（其余一一对应）：
//   · 一个会话订**两个** provider（Kernel-File + Kernel-Registry），回调按 ProviderId 分流；
//   · 字段名**不硬编码**，先读事件自带属性表拿真实名字/真实类型再取值（见下）；
//   · 回调里多一层「消费侧过滤」，因为这两路事件量比进程创建高一到两个量级。
//
// ===========================================================================
//  ★★ 为什么字段名要从事件里读，而不是像 etwproc 那样写死在代码里
// ===========================================================================
//  etwproc.cpp 曾把 Kernel-Process id=1 的字段写成 NewProcessId / ProcessId /
//  ImageFileName，而 manifest 里的真实名字是 ProcessID / ParentProcessID /
//  ImageName（"ID" 全大写，且根本没有 ImageFileName）。
//  TdhGetProperty 按属性名查找**区分大小写** → 全部取不到 → 2026-09-23 实测
//  「TDH 100% 解析失败、parseFail=recv、实时防护完全静默」，最后靠固定偏移
//  解析（ParseByOffset）兜底才没彻底瞎掉。
//
//  本模块换一种做法，让这类事故在结构上不可能发生：
//    ① 事件到达时先调 TdhGetEventInformation 取该 (EID,Version) 的**完整属性表**
//       （名字 + 声明的 InType），缓存起来（每对组合只取一次）；
//    ② 想取某个字段时，拿候选名去属性表里**大小写不敏感**匹配，匹配到就用
//       **属性表里的原始名字**去调 TdhGetProperty；
//    ③ 解码方式也不猜：属性表里声明的 InType == TDH_INTYPE_UNICODESTRING
//       就按 UTF-16LE 解，== TDH_INTYPE_ANSISTRING 就按 ANSI 解。
//  这样即使某天微软改名、或装了别的语言版本的 manifest，采集也不会静默失效。
//
//  属性表首见时会把「EID + 真实属性名」写进日志（中文串，便于 grep 取证）。
// ===========================================================================
#include "iowatch.h"

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>

#include <atomic>
#include <cctype>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "common.h"    // LogDbg
#include "sfstop.h"

#pragma comment(lib, "tdh.lib")

namespace sf {
namespace iowatch {

// ---------------------------------------------------------------------------
//  单调时钟毫秒（与 netwatch / etwproc 同口径，逐字一致 —— 跨模块时间戳必须同口径）
// ---------------------------------------------------------------------------
static uint64_t NowMsSteady() {
    static LARGE_INTEGER freq = [] {
        LARGE_INTEGER f{}; QueryPerformanceFrequency(&f); return f;
    }();
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    if (freq.QuadPart <= 0) return GetTickCount64();
    return (uint64_t)((double)c.QuadPart * 1000.0 / (double)freq.QuadPart);
}

// ---------------------------------------------------------------------------
//  Provider / keyword / 事件 ID 常量
//  全部来自本机实测：keyword 位来自 `logman query providers <名>`，
//  事件 ID 与字段名来自 `Get-WinEvent -ListProvider <名>` 的 manifest 模板。
//  导出留档：docs/etw-schema-dump.txt
// ---------------------------------------------------------------------------

// Microsoft-Windows-Kernel-File {EDD08927-9CC4-4E65-B970-C2560FB5C289}
static const GUID kKernelFile =
    { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };

// Microsoft-Windows-Kernel-Registry {70EB4F03-C1DE-4F73-A051-33D13D5413BD}
static const GUID kKernelRegistry =
    { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };

// Kernel-File keyword 位
static const ULONGLONG kKwFileName = 0x10;   // KERNEL_FILE_KEYWORD_FILENAME
static const ULONGLONG kKwFileIo   = 0x20;   // 每次读写都发 → 刻意不订（量级炸弹）
static const ULONGLONG kKwOpEnd    = 0x40;
static const ULONGLONG kKwCreate   = 0x80;   // EID 12（唯一带 CreateOptions 的）
static const ULONGLONG kKwRead     = 0x100;  // 不订
static const ULONGLONG kKwWrite    = 0x200;  // 不订
static const ULONGLONG kKwDelete   = 0x400;  // EID 26 删除路径
static const ULONGLONG kKwRename   = 0x800;  // EID 27/28 改名路径
static const ULONGLONG kKwNewFile  = 0x1000; // EID 30 新建文件

// ★ 生产掩码 0x1C90 = FILENAME | CREATE | DELETE_PATH | RENAME_SETLINK_PATH | CREATE_NEW_FILE
//   刻意不含 FILEIO(0x20) / READ(0x100) / WRITE(0x200)：那是"每次读写一条"，
//   日常机器上轻易上万条/秒，而勒索检测靠"建→改→删"的组合模式即可。
//   ★ 降级路径（若 fileprobe 实测频率 > 5000 条/秒，按序砍）：
//       第一步 砍 CREATE(0x80) → 0x1C10（少掉 EID 12，也就放弃 CreateOptions 覆盖写信号）
//       第二步 砍 FILENAME(0x10) → 0x1C80（少掉 EID 10/11，放弃"名字建立/移除"通知）
//     裁到哪一档由 docs 里记的实测频率决定，不凭感觉。
//   ★ 2026-10-02 补充：第一步「砍 CREATE(0x80)」的**代价已大幅下降** ——
//     EID 12 自今日起只做遥测（Kind::Opened），不再驱动落地链，砍掉它只丢
//     「覆盖写」这一路行为信号，不会再影响任何告警/送检。若频率压不住，可以放心砍。
static const ULONGLONG kFileKeyword = kKwFileName | kKwCreate | kKwDelete | kKwRename | kKwNewFile;

// Kernel-Registry keyword 位 + 生产掩码 0x5340
//   SetInformationKey(0x40) | SetValueKey(0x100) | DeleteValueKey(0x200)
//   | CreateKey(0x1000) | DeleteKey(0x4000)
//   不含 QueryValueKey(0x400) / EnumerateKey(0x800) / OpenKey(0x2000) —— 全是读路径噪声。
static const ULONGLONG kRegKeyword = 0x40 | 0x100 | 0x200 | 0x1000 | 0x4000;

// 事件 ID
static const USHORT kEvFileNameCreate = 10;   // 文件名建立（kw=FILENAME，带完整 FileName）
static const USHORT kEvFileNameDelete = 11;   // 文件名移除
static const USHORT kEvFileCreate     = 12;   // ★「打开/创建」——归 Kind::Opened，**绝不是落地事件**
static const USHORT kEvFileDeletePath = 26;   // 删除路径
static const USHORT kEvFileRenameA    = 27;   // 改名路径
static const USHORT kEvFileRenameB    = 28;   // 改名路径
static const USHORT kEvFileNewFile    = 30;   // 新建文件
static const USHORT kEvRegCreateKey   = 1;
static const USHORT kEvRegDeleteKey   = 3;
static const USHORT kEvRegSetValue    = 5;
static const USHORT kEvRegDeleteValue = 6;
static const USHORT kEvRegSetInfo     = 11;

// 字段名候选（大小写不敏感匹配；属性表里的原始名优先）
static const char* kCandFileName[] = { "FileName", "FilePath", "Name" };
static const char* kCandKeyName[]  = { "KeyName", "BaseName" };
static const char* kCandBaseName[] = { "BaseName" };
static const char* kCandRelName[]  = { "RelativeName" };
static const char* kCandValueName[]= { "ValueName" };
static const char* kCandInfoClass[]= { "InfoClass" };
static const char* kCandCreateOpt[]= { "CreateOptions" };

// ---------------------------------------------------------------------------
//  全局状态
// ---------------------------------------------------------------------------
static std::atomic<bool>  g_running{ false };
static std::atomic<bool>  g_stop{ false };

static TRACEHANDLE        g_session = 0;
static TRACEHANDLE        g_trace   = 0;
static std::thread        g_thread;
static std::thread        g_consumer;
static IoSink             g_sink = nullptr;
static std::string        g_sessionName;

static std::atomic<uint64_t> g_receivedFile{ 0 };
static std::atomic<uint64_t> g_receivedReg{ 0 };
static std::atomic<uint64_t> g_delivered{ 0 };
static std::atomic<uint64_t> g_dropped{ 0 };
static std::atomic<uint64_t> g_parseFail{ 0 };
static std::atomic<uint64_t> g_noPath{ 0 };     // EID 12/30 等「manifest 本就没有路径字段」的事件
static std::atomic<uint64_t> g_filteredSelf{ 0 };
static std::atomic<uint64_t> g_filteredNoise{ 0 };
static std::atomic<uint64_t> g_deduped{ 0 };
static std::atomic<uint64_t> g_lastEventMs{ 0 };
static std::atomic<uint64_t> g_startMs{ 0 };   // 本次 Start 的时刻（IsHealthy 启动宽限期用）

// 队列容量：文件事件比进程事件密得多，4096 会频繁丢；
// ★ 2026-10-02（#617）：修好 FindProp 后注册表事件会真正涌入（EID 1/3/5/6/11），
//   8192 在高频写盘/装软件时易被冲满 → 提到 16384（约 2.4MB 常驻，可接受）。
static const size_t kQueueCap = 16384;

// IsHealthy 的启动宽限期：进程刚起、还没等到第一条事件时算"待机健康"；
// 超过此窗口仍零事件 = 采集面哑火（见 IsHealthy 的"哑巴兜底"修正）。
static const uint64_t kStartupGraceMs = 60000;
static std::mutex          g_qMtx;
static std::deque<IoEvent> g_queue;
static HANDLE              g_qEvent = nullptr;

// 最近事件环形缓冲（诊断用，供 iowatchq 命令回捞）
static std::mutex          g_recentMtx;
static std::deque<IoEvent> g_recent;

// 已 dump 属性表的 (EID,Version) 对数上限（防日志刷屏）
static std::atomic<int> g_schemaLogBudget{ 32 };

// ★★ 2026-10-02（铁律 35）：会话名由「随机后缀」改回**固定名**。
//   理由与 etwproc.cpp 完全一致：随机名让每次重建都换新名 ⇒ 残留只增不减
//   （实测 iowatch 51 个名 / 只退出 49）⇒ 累积撞 1450 后内核 provider 订阅表劣化
//   ⇒ "会话建得起来、事件一条不来"（一活三死、跨进程存活、唯 OS 重启可清）。
//   固定名后：重建即覆盖同一会话，残留无处累积；配合 PurgeStaleSession() + 183 有限重试。
static const char* kSessionName = "SilverFoxGuardIo";

static std::string MakeSessionName() {
    return std::string(kSessionName);
}

// 清理"同名残留会话"（ControlTraceW 第一参数传 0；4201=本就没有同名会话，正常）。
static void PurgeStaleSession() {
    if (g_sessionName.empty()) return;
    std::vector<BYTE> props(1024, 0);
    EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
    p->Wnode.BufferSize = (ULONG)props.size();
    p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ControlTraceW(0, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
    if (st == ERROR_SUCCESS) {
        LogDbg("[iowatch] 已清理同名残留会话（" + g_sessionName + "）");
    }
}

// ---------------------------------------------------------------------------
//  ★ 属性表缓存：名字 + 声明的 InType
//  回调由 ProcessTrace 单线程串行调用 → 本缓存**无需加锁**（勿加，加了是白付锁开销）
// ---------------------------------------------------------------------------
struct PropInfo {
    std::string    name;    // 属性名（UTF-8，日志/匹配用）
    std::wstring   wname;   // ★ 属性名 UTF-16 原文 —— TdhGetProperty 的
                            //   PROPERTY_DATA_DESCRIPTOR.PropertyName 要求
                            //   **null-terminated Unicode**（微软文档原文）。
                            //   2026-09-26 实锤：此前把缓冲当 ANSI 读，名字全部
                            //   截成首字母（字段表日志 [I F I C C S F] 即铁证），
                            //   FindProp 永远失配 → parseFail=全部、delivered=0。
    std::string    lower;   // 小写 UTF-8，用于大小写不敏感匹配
    USHORT         inType = 0;
};

struct SchemaSlot {
    uint32_t               key    = 0xFFFFFFFF;   // (version<<16)|eid
    bool                   ready  = false;
    bool                   failed = false;
    std::vector<PropInfo>  props;
};

static const int  kSchemaSlots = 512;
static SchemaSlot g_schema[kSchemaSlots];

// 属性表建立失败的限流采样日志（每 10 秒最多 1 条，带 EID+错误码定位问题）
static void SchemaFailLog(USHORT eid, USHORT ver, DWORD rc) {
    static std::atomic<ULONGLONG> s_last{ 0 };
    const ULONGLONG now = NowMsSteady();
    ULONGLONG prev = s_last.load();
    if (now - prev > 10000 && s_last.compare_exchange_strong(prev, now)) {
        LogDbg("[iowatch] ⚠ 属性表建立失败（采样）EID=" + std::to_string((unsigned)eid) +
               " ver=" + std::to_string((unsigned)ver) + " TdhRc=" + std::to_string((unsigned long)rc));
    }
}

static SchemaSlot* GetSchemaSlot(USHORT eid, USHORT ver, PEVENT_RECORD ev, bool reg) {
    // ★ 2026-09-26 探针实锤的根因修复：key 必须含 provider 位。
    //   本会话同时订 Kernel-File + Kernel-Registry，两边 EID 空间重叠（例如
    //   注册表 KcbRundown 也是 12），同 (eid,ver) 会互相污染字段表缓存：
    //   文件事件命中注册表字段表 → 里面没有 FileName → parseFail=全部。
    //   探针 probe_etw.cpp 只订一个 provider → 永不踩坑 → 提取必成功。
    uint32_t key = ((uint32_t)ver << 16) | (uint32_t)eid;
    if (reg) key |= 0x80000000u;
    int idx = (int)(key % (uint32_t)kSchemaSlots);
    for (int probe = 0; probe < 8; ++probe) {
        SchemaSlot& s = g_schema[(idx + probe) % kSchemaSlots];
        if (s.key == key) return &s;
        if (s.key == 0xFFFFFFFF) {
            // 空位 → 就地载入
            s.key = key;
            ULONG sz = 0;
            DWORD tRc = TdhGetEventInformation(ev, 0, nullptr, nullptr, &sz);
            if (tRc != ERROR_INSUFFICIENT_BUFFER || sz == 0) {
                s.failed = true; s.ready = true;
                SchemaFailLog(eid, ver, tRc);
                return &s;
            }
            std::vector<BYTE> buf(sz);
            TRACE_EVENT_INFO* info = (TRACE_EVENT_INFO*)buf.data();
            tRc = TdhGetEventInformation(ev, 0, nullptr, info, &sz);
            if (tRc != ERROR_SUCCESS) {
                s.failed = true; s.ready = true;
                SchemaFailLog(eid, ver, tRc);
                return &s;
            }
            const ULONG top = info->TopLevelPropertyCount;
            for (ULONG i = 0; i < top; ++i) {
                const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
                if (p.NameOffset == 0) continue;
                PropInfo pi;
                // ★ 属性名在缓冲里是 null-terminated **UTF-16**（微软文档：
                //   EVENT_PROPERTY_INFO.NameOffset / PROPERTY_DATA_DESCRIPTOR.
                //   PropertyName 均要求 Unicode）。按 ANSI 读会截成首字母。
                {
                    const wchar_t* wn = (const wchar_t*)((const BYTE*)info + p.NameOffset);
                    int n8 = WideCharToMultiByte(CP_UTF8, 0, wn, -1,
                                                 nullptr, 0, nullptr, nullptr);
                    if (n8 > 1) {
                        pi.name.resize(n8 - 1);
                        WideCharToMultiByte(CP_UTF8, 0, wn, -1, &pi.name[0], n8,
                                            nullptr, nullptr);
                    }
                    pi.wname = wn;      // UTF-16 原文留给 TdhGetProperty
                }
                pi.lower = pi.name;
                for (char& c : pi.lower) c = (char)tolower((unsigned char)c);
                // 只对「非结构体」属性取 InType（结构体类型的 union 成员不是 InType）
                pi.inType = p.nonStructType.InType;
                s.props.push_back(pi);
            }
            s.ready = true;

            // 首见该 (eid,version) → 打一行中文日志（取证锚点：查串不查函数名）
            if (g_schemaLogBudget.fetch_sub(1) > 0) {
                std::string names;
                for (const PropInfo& pi : s.props) { names += pi.name; names += ' '; }
                LogDbg(std::string("[iowatch] 事件字段表 来源=") + (reg ? "注册表" : "文件") +
                       " EID=" + std::to_string((unsigned)eid) +
                       " 版本=" + std::to_string((unsigned)ver) +
                       " 属性=[" + names + "]");
            }
            return &s;
        }
    }
    return nullptr;   // 槽位塞满（512 种 EID/版本组合，实际远用不到）
}

// 在属性表里找候选名（大小写不敏感），返回属性表里的**原始名**
// ★ 2026-10-02（#616，P1 修复）：原实现 `if (p.lower == cands[i])` 恒为假 ——
//   p.lower 已转成全小写（如 "filename"），而候选是全驼峰（"FileName"），
//   std::string 逐字节比较 ⇒ 永远不相等 ⇒ 注册表事件**一条都出不来**、
//   文件 EID 10/30 路径全丢、InfoClass/CreateOptions 恒 0。
//   此前被 EID=12 固定偏移兜底（FallbackEid12Path）掩盖，delivered>0 看似正常。
//   改用 _stricmp 做真正的大小写不敏感比较。
static const PropInfo* FindProp(const SchemaSlot* s, const char* const* cands, size_t n) {
    if (!s || s->failed) return nullptr;
    for (const PropInfo& p : s->props) {
        for (size_t i = 0; i < n; ++i) {
            if (_stricmp(p.lower.c_str(), cands[i]) == 0) return &p;
        }
    }
    return nullptr;
}

// 按属性表里的真实名字取值（字符串）。解码方式由 manifest 声明的 InType 决定。
// rcOut（可选）：诊断采样用。0=成功；1=字段为空指针/类型不符；
//               2=Size失败（值为 TdhGetPropertySize 的 rc）；3=超长；
//               4=Get失败（值为 TdhGetProperty 的 rc）；5=编码转换失败。
static bool GetPropStr(PEVENT_RECORD ev, const PropInfo* pi, std::string* out,
                       DWORD* rcOut = nullptr) {
    if (!pi || !out) { if (rcOut) *rcOut = 1; return false; }
    // ★ PropertyName 必须是 UTF-16（微软文档原文 "null-terminated Unicode
    //   string"）—— 传 UTF-16 原文（wname），见 PropInfo 处的取证注释。
    PROPERTY_DATA_DESCRIPTOR pd{};
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)pi->wname.c_str();
    pd.ArrayIndex   = ULONG_MAX;

    ULONG size = 0;
    DWORD szRc = TdhGetPropertySize(ev, 0, nullptr, 1, &pd, &size);
    if (szRc != ERROR_SUCCESS) { if (rcOut) *rcOut = 2 * 100000 + szRc; return false; }
    if (size == 0) { out->clear(); if (rcOut) *rcOut = 0; return true; }   // 空串也算取到了
    if (size > 8192) { if (rcOut) *rcOut = 3; return false; }              // 异常超长，防御
    std::vector<BYTE> raw(size);
    DWORD gRc = TdhGetProperty(ev, 0, nullptr, 1, &pd, size, raw.data());
    if (gRc != ERROR_SUCCESS) { if (rcOut) *rcOut = 4 * 100000 + gRc; return false; }

    out->clear();
    if (pi->inType == TDH_INTYPE_UNICODESTRING) {
        int wlen = (int)(size / 2);
        const wchar_t* w = (const wchar_t*)raw.data();
        while (wlen > 0 && w[wlen - 1] == L'\0') --wlen;
        if (wlen <= 0) { if (rcOut) *rcOut = 0; return true; }
        int n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, nullptr, 0, nullptr, nullptr);
        if (n <= 0) { if (rcOut) *rcOut = 5; return false; }
        out->resize(n);
        WideCharToMultiByte(CP_UTF8, 0, w, wlen, &(*out)[0], n, nullptr, nullptr);
        if (rcOut) *rcOut = 0;
        return true;
    }
    if (pi->inType == TDH_INTYPE_ANSISTRING) {
        std::string s((const char*)raw.data(), size);
        while (!s.empty() && s.back() == '\0') s.pop_back();
        *out = s;
        if (rcOut) *rcOut = 0;
        return true;
    }
    // 其它类型（指针/整数等）当字符串取没有意义
    if (rcOut) *rcOut = 1;
    return false;
}

// 按属性表里的真实名字取值（32 位整数）
static bool GetPropU32(PEVENT_RECORD ev, const PropInfo* pi, uint32_t* out) {
    if (!pi || !out) return false;
    PROPERTY_DATA_DESCRIPTOR pd{};
    pd.PropertyName = (ULONGLONG)(ULONG_PTR)pi->wname.c_str();   // UTF-16，见 GetPropStr
    pd.ArrayIndex   = ULONG_MAX;
    uint32_t v = 0;
    if (TdhGetProperty(ev, 0, nullptr, 1, &pd, sizeof(v), (PBYTE)&v) != ERROR_SUCCESS) return false;
    *out = v;
    return true;
}

// 便捷包装：直接按候选名取字符串
static bool GetStrBy(PEVENT_RECORD ev, const SchemaSlot* s,
                     const char* const* cands, size_t n, std::string* out) {
    return GetPropStr(ev, FindProp(s, cands, n), out);
}

// ---------------------------------------------------------------------------
//  ★ TDH 兜底：EID 12（Create）ver 1 的固定偏移路径提取（x64）
//  探针 probe_etw.cpp 2026-09-26 hex 实锤布局：
//    FileObject(8) + 第二指针(8) + Irp(4) + CreateOptions(4)
//    + CreateAttributes(4) + ShareAccess(4) = 32B，其后为 null 结尾 UTF-16 路径。
//  内容校验（'\\' 设备路径或 'X:' 盘符）防止偏移错位时拿到垃圾。
// ---------------------------------------------------------------------------
static bool FallbackEid12Path(PEVENT_RECORD ev, std::string* out) {
    if (!ev || !ev->UserData) return false;
    if (ev->EventHeader.EventDescriptor.Id != 12) return false;
    if (ev->EventHeader.EventDescriptor.Version != 1) return false;
    if (ev->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) return false;   // x86 事件不兜
    if (ev->UserDataLength < 36) return false;
    const BYTE* p = (const BYTE*)ev->UserData;
    const wchar_t* w = (const wchar_t*)(const void*)(p + 32);
    const size_t maxw = (ev->UserDataLength - 32) / 2;
    // 内容校验：必须是 NT 路径形态
    if (!(w[0] == L'\\' || (w[0] >= L'A' && w[0] <= L'Z' && w[1] == L':'))) return false;
    size_t n = 0;
    while (n < maxw && w[n] != L'\0') ++n;
    if (n == 0 || n >= 1024) return false;      // 过长视为异常，防御
    int n8 = WideCharToMultiByte(CP_UTF8, 0, w, (int)n, nullptr, 0, nullptr, nullptr);
    if (n8 <= 1) return false;
    out->resize((size_t)n8 - 1);
    WideCharToMultiByte(CP_UTF8, 0, w, (int)n, &(*out)[0], n8, nullptr, nullptr);
    return true;
}

// ---------------------------------------------------------------------------
//  路径归一化
// ---------------------------------------------------------------------------
static std::mutex g_driveMtx;
static bool       g_driveReady = false;
static std::vector<std::pair<std::string, std::string>> g_driveMap;   // 设备前缀 → 盘符

static void EnsureDriveMap() {
    std::lock_guard<std::mutex> lk(g_driveMtx);
    if (g_driveReady) return;
    g_driveReady = true;
    const DWORD drives = GetLogicalDrives();
    for (char c = 'A'; c <= 'Z'; ++c) {
        if (!(drives & (1u << (c - 'A')))) continue;
        char dev[8] = { c, ':', 0 };
        char target[MAX_PATH * 2] = { 0 };
        if (QueryDosDeviceA(dev, target, (DWORD)sizeof(target)) && target[0]) {
            g_driveMap.emplace_back(std::string(target), std::string(dev));
        }
    }
    // \SystemRoot → 系统目录（内核路径里很常见）
    char winDir[MAX_PATH] = { 0 };
    if (GetWindowsDirectoryA(winDir, MAX_PATH)) {
        g_driveMap.emplace_back("\\SystemRoot", std::string(winDir));
        g_driveMap.emplace_back("\\??\\" + std::string(winDir), std::string(winDir));
    }
}

std::string NormalizeFilePath(const std::string& kernelPath) {
    if (kernelPath.empty()) return std::string();
    EnsureDriveMap();

    std::string s = kernelPath;
    // \??\C:\... → C:\...
    if (s.rfind("\\??\\", 0) == 0) s = s.substr(4);

    std::lock_guard<std::mutex> lk(g_driveMtx);
    for (const auto& kv : g_driveMap) {
        const std::string& from = kv.first;
        if (s.size() < from.size()) continue;
        if (_strnicmp(s.c_str(), from.c_str(), from.size()) != 0) continue;
        // 前缀之后必须是路径分隔符或字符串结束（防止 \Device\HarddiskVolume1 误配 Volume10）
        if (s.size() > from.size() && s[from.size()] != '\\') continue;
        s = kv.second + s.substr(from.size());
        break;
    }
    return s;
}

std::string NormalizeRegPath(const std::string& kernelPath) {
    if (kernelPath.empty()) return std::string();
    std::string s = kernelPath;
    static const char* kRegRoot = "\\REGISTRY\\";
    if (s.rfind(kRegRoot, 0) != 0) return s;        // 不是内核注册表路径，原样返回
    std::string rest = s.substr(strlen(kRegRoot));
    if (rest.rfind("MACHINE\\", 0) == 0 || rest == "MACHINE")
        return "HKLM\\" + rest.substr(strlen("MACHINE\\"));
    if (rest.rfind("USER\\", 0) == 0 || rest == "USER")
        return "HKU\\" + rest.substr(strlen("USER\\"));
    return "HK" + rest;
}

// ---------------------------------------------------------------------------
//  事件语义分类
// ---------------------------------------------------------------------------
static void Classify(PEVENT_RECORD ev, IoEvent& e) {
    const USHORT eid = e.eid;
    if (e.registry) {
        switch (eid) {
            case kEvRegCreateKey:   e.kind = Kind::Created; e.kindSrc = KindSrc::ByEid; return;
            case kEvRegSetValue:    e.kind = Kind::Created; e.kindSrc = KindSrc::ByEid; return;
            case kEvRegSetInfo:     e.kind = Kind::Created; e.kindSrc = KindSrc::ByEid; return;
            case kEvRegDeleteKey:   e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByEid; return;
            case kEvRegDeleteValue: e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByEid; return;
            default: break;
        }
        // 未登记的注册表事件：按 keyword 兜底（不静默丢弃）
        const ULONGLONG kw = ev->EventHeader.EventDescriptor.Keyword;
        if (kw & 0x1000 || kw & 0x100) { e.kind = Kind::Created; e.kindSrc = KindSrc::ByKeyword; }
        else if (kw & 0x4000 || kw & 0x200) { e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByKeyword; }
        return;
    }

    switch (eid) {
        case kEvFileNewFile:    e.kind = Kind::Created; e.kindSrc = KindSrc::ByEid; return;
        // ★★★ 2026-10-02 误报事故修复（本行是触发器，务必不要再改回 Created）
        //   EID 12 的语义是**「打开 / 创建」**（参数含 CreateOptions，见本文件顶部
        //   字段表）—— 它对每一次 CreateFile 都发，包括纯粹读一下、枚举目录内容、
        //   杀软扫描、编译器读自己的产物。把它归成 Created 就等于宣布「打开 =
        //   新建」，于是 service.cpp 的落地哨兵（判据 kind==Created）会把**全系统
        //   每一次文件打开**当成「新文件落盘」→ 送检 → 锁原件。
        //   2026-10-02 实测被锁：cmd.exe / conhost.exe / sc.exe / powershell.exe /
        //   dsregcmd.exe / msra.exe / TieringEngineService.exe / refsdedupsvc.exe
        //   （微软正版组件，仅被打开）、银泊桌面 OneMail.exe / OneMail_Manager.exe、
        //   PortableGit grep.exe（均为数月前的存量文件）。
        //   成因确认后自问过一句：为什么不干脆从掩码里砍掉 CREATE(0x80)？
        //   因为 CreateOptions 是**覆盖写**的唯一信号（勒索画像要用），砍掉丢能力。
        //   正解是保留订阅、改语义：Opened 照旧进遥测与环形缓冲，只是不进落地链。
        case kEvFileCreate:     e.kind = Kind::Opened;  e.kindSrc = KindSrc::ByEid; return;
        case kEvFileDeletePath: e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByEid; return;
        case kEvFileRenameA:
        case kEvFileRenameB:    e.kind = Kind::Renamed; e.kindSrc = KindSrc::ByEid; return;
        // ★★★ 2026-10-02 误报事故修复（第二处触发器，与上面 EID 12 同源，务必不要再改回 Created）
        //   【旧注释是错的，已删】原文写「新建文件发 10，删除发 11，改名则成对出现」——
        //   把 EID 10 理解成了"新建文件"。真实语义是 **NameCreate：把一个名字关联到
        //   文件对象（FILE_OBJECT）**，发生在**每一次 CreateFile 调用**上，无论这次
        //   调用最终是「打开一个已存在的文件」还是「新建一个文件」。
        //   微软文档原话：NameCreate —— "A file name was created"（名字被建立），
        //   而非 "A new file was created"。后者是 **EID 30 CreateNewFile**。
        //   ⇒ EID 10 与 EID 12 是**同一次打开操作的前后两拍**（先 10 关联名字、后 12
        //     完成创建/打开），把任意一拍当成"落地"都等于宣布「打开 = 新建」。
        //
        //   【事故现场】本机 2026-10-02 17:42，服务刚启动，一批**数月前就存在**的
        //   系统/UWP 组件仅仅被系统自身**读了一下**（SearchProtocolHost 做索引、
        //   Defender 扫描、CompatTelRunner 遥测），就被判「落地初筛命中（1级）」：
        //     · C:\Program Files\WindowsApps\Microsoft.Paint_*\PaintApp\mspaint.exe
        //     · C:\Program Files\WindowsApps\Microsoft.WindowsStore_*\store.exe
        //     · C:\Program Files\WindowsApps\Microsoft.GetHelp_*\GetHelp.exe
        //     · C:\Windows\System32\regsvr32.exe / CxUIUSvc64.exe
        //   其中 WindowsApps 一族还会一路走到"送检"（它们**没有嵌入签名、也不在
        //   .cat 里** —— UWP 走 MSIX 包级签名，我们的签名判定另有第三条路补，见
        //   scanner.cpp 的 HasAppxPackageSignature）。
        //
        //   【为什么不担心漏掉真正的落地】"新建文件"有**三条独立**的证据链覆盖：
        //     ① EID 30 CreateNewFile（硬依据）；② keyword NewFile(0x1000)；
        //     ③ ReadDirectoryChangesW 的 FILE_ACTION_ADDED（rollback 那条腿）。
        //   三条都不依赖 EID 10，故把它归 Opened 不会丢任何一次真实落地。
        //   保留 kindSrc=ByNameNotify，让下游仍能看出这条是"名字通知"级依据。
        case kEvFileNameCreate: e.kind = Kind::Opened;  e.kindSrc = KindSrc::ByNameNotify; return;
        case kEvFileNameDelete: e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByNameNotify; return;
        default: break;
    }
    const ULONGLONG kw = ev->EventHeader.EventDescriptor.Keyword;
    if (kw & kKwNewFile)                          { e.kind = Kind::Created; e.kindSrc = KindSrc::ByKeyword; }
    else if (kw & kKwRename)                      { e.kind = Kind::Renamed; e.kindSrc = KindSrc::ByKeyword; }
    else if (kw & kKwDelete)                      { e.kind = Kind::Deleted; e.kindSrc = KindSrc::ByKeyword; }
    // ★ 2026-10-02：CREATE(0x80) 与 FILENAME(0x10) 兜底**都只能是 Opened**。
    //   FILENAME 单独出现不能作为落地依据的理由，见上面 EID 10 那段的完整说明
    //   （NameCreate 在每一次打开时都会发）。旧代码把 FILENAME 兜底归 Created 是
    //   误报的第二入口；旧注释还声称"CREATE 必须放在 FILENAME 之后判"——那是在
    //   两者语义不同时的约束，现已统一为 Opened，顺序不再有影响。
    //   ⚠️ 唯一必须保持的优先级：**NewFile 排在最先**，否则带 NewFile keyword 的
    //      真落地会被后面任何一个分支抢先归类而丢掉。
    else if (kw & kKwCreate)                      { e.kind = Kind::Opened;  e.kindSrc = KindSrc::ByKeyword; }
    else if (kw & kKwFileName)                    { e.kind = Kind::Opened;  e.kindSrc = KindSrc::ByKeyword; }
}

// ---------------------------------------------------------------------------
//  ETW 回调：只做「按属性表取名取值 + 入队」，绝不磁盘 I/O / 长锁
// ---------------------------------------------------------------------------
static VOID WINAPI OnEventRecord(PEVENT_RECORD ev) {
    if (!ev || !ev->UserData) return;
    if (!g_running.load(std::memory_order_relaxed)) return;

    const GUID& prov = ev->EventHeader.ProviderId;
    const bool isFile = (memcmp(&prov, &kKernelFile, sizeof(GUID)) == 0);
    const bool isReg  = (memcmp(&prov, &kKernelRegistry, sizeof(GUID)) == 0);
    if (!isFile && !isReg) return;

    if (isFile) g_receivedFile.fetch_add(1, std::memory_order_relaxed);
    else        g_receivedReg.fetch_add(1, std::memory_order_relaxed);

    const USHORT eid = ev->EventHeader.EventDescriptor.Id;
    const USHORT ver = ev->EventHeader.EventDescriptor.Version;

    SchemaSlot* slot = GetSchemaSlot(eid, ver, ev, isReg);
    if (!slot || slot->failed) {
        g_parseFail.fetch_add(1, std::memory_order_relaxed);
        return;
    }

    IoEvent e;
    e.eid       = eid;
    e.registry  = isReg;
    // ★ 事件体里**没有** ProcessId（只有 Irp/FileObject/FileKey/IssuingThreadId），
    //   发起进程只能取事件头 —— 内核在发起线程上下文里记日志，事件头带的就是它。
    e.pid       = (unsigned long)ev->EventHeader.ProcessId;
    e.tid       = (unsigned long)ev->EventHeader.ThreadId;
    e.atMs      = NowMsSteady();

    Classify(ev, e);

    // ---- 取路径 ----
    std::string raw;
    if (isReg) {
        if (eid == kEvRegCreateKey) {
            // 建键事件给的是 BaseName + RelativeName 两段，需要拼接
            std::string base, rel;
            GetStrBy(ev, slot, kCandBaseName, 1, &base);
            GetStrBy(ev, slot, kCandRelName, 1, &rel);
            raw = base;
            if (!rel.empty()) {
                if (!raw.empty() && raw.back() != '\\') raw += '\\';
                raw += rel;
            }
        } else {
            GetStrBy(ev, slot, kCandKeyName, 2, &raw);
        }
        std::string val;
        if (GetStrBy(ev, slot, kCandValueName, 1, &val)) e.valueName = val;
    } else {
        const PropInfo* fp = FindProp(slot, kCandFileName, 3);
        GetPropStr(ev, fp, &raw);
        if (raw.empty() && FallbackEid12Path(ev, &raw)) {
            // TDH 主路失败 → EID12 固定偏移兜底成功（探针 hex 实锤布局，
            // 2026-09-26）。raw 非空后由下方统一放行。
        }
    }

    // 路径取不到 → 记录失败计数 + 限流采样日志（带 EID，便于定位是哪类事件失败）。
    // ★ 2026-09-26 二次勘误：EID 12/30 的字段表实测**都有 FileName**（此前误判
    //   为「无路径事件」分流进 noPathField，导致 20 万条创建事件被跳过、
    //   delivered 恒 0）。路径字段真正缺失的事件待实测确认后再登记到此。
    // ★ 2026-09-26 三次增强：失败时把「失败步骤+rc+字段表+事件头标志」全部带出，
    //   一轮日志定根因（此前只打 EID/ver，四轮盲改都是猜）。
    if (raw.empty()) {
        g_parseFail.fetch_add(1, std::memory_order_relaxed);
        static std::atomic<ULONGLONG> s_lastFailLog{ 0 };
        const ULONGLONG nowF = NowMsSteady();
        ULONGLONG prevF = s_lastFailLog.load();
        if (nowF - prevF > 10000 &&
            s_lastFailLog.compare_exchange_strong(prevF, nowF)) {
            char fb[24];
            snprintf(fb, sizeof(fb), "%08llx",
                     (unsigned long long)ev->EventHeader.Flags);
            std::string detail;
            if (isReg) {
                detail = "来源=注册表";
            } else {
                const PropInfo* fp = FindProp(slot, kCandFileName, 3);
                if (!fp) {
                    detail = "来源=文件 步骤=字段未命中 props=[";
                    for (const PropInfo& q : slot->props) { detail += q.name; detail += ' '; }
                    detail += "]";
                } else {
                    DWORD rc = 0;
                    std::string tmp;
                    GetPropStr(ev, fp, &tmp, &rc);
                    detail = "来源=文件 步骤码=" + std::to_string((unsigned)rc) +
                             " inType=" + std::to_string((unsigned)fp->inType);
                }
            }
            LogDbg("[iowatch] ⚠ 路径提取失败（parseFail 采样）EID=" +
                   std::to_string((unsigned)eid) + " ver=" + std::to_string((unsigned)ver) +
                   " " + detail + " flags=0x" + fb);
        }
        return;
    }
    e.rawPath = raw;
    e.path    = isReg ? NormalizeRegPath(raw) : NormalizeFilePath(raw);

    // 补充字段（取不到就是 0，不影响主流程）
    uint32_t tmp = 0;
    if (GetPropU32(ev, FindProp(slot, kCandInfoClass, 1), &tmp)) e.infoClass = (int)tmp;
    if (!isReg && GetPropU32(ev, FindProp(slot, kCandCreateOpt, 1), &tmp)) e.createOptions = (int)tmp;

    g_lastEventMs.store(e.atMs, std::memory_order_relaxed);

    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        if (g_queue.size() >= kQueueCap) {
            g_queue.pop_front();          // 满了丢最旧（保新不保全）
            g_dropped.fetch_add(1, std::memory_order_relaxed);
        }
        g_queue.push_back(std::move(e));
    }
    if (g_qEvent) SetEvent(g_qEvent);
}

// ---------------------------------------------------------------------------
//  消费侧过滤
// ---------------------------------------------------------------------------

// 高噪路径：**只排除明确不可能藏恶意代码的位置**，每一条都要能说出为什么。
//  宁可多采一点，也不靠"排除目录"来省事 —— 排除目录是最容易造成漏报的偷懒手法。
static const char* kNoiseMarks[] = {
    // 浏览器磁盘缓存：每次加载网页都产生成百上千个文件，恶意软件不会藏在这里
    // （HTTP 缓存内容由浏览器校验和解释，不是可执行载体）
    "\\Cache\\Cache_Data\\",
    "\\Code Cache\\",
    "\\GPUCache\\",
    "\\Service Worker\\CacheStorage\\",
    // 系统自身的高频日志/回滚点（与本产品无关，且量大）
    "\\Windows\\Prefetch\\",
    "\\Windows\\Logs\\",
    "\\Windows\\SoftwareDistribution\\",
    "\\Windows\\ServiceProfiles\\",
    "\\Windows\\System32\\LogFiles\\",
    // 本产品自己的目录：隔离区索引/日志/快照会被自己反复读写 → 防"自噬"刷屏
    "\\ProgramData\\SilverFoxGuard\\",
};

static bool IsNoisePath(const std::string& p) {
    if (p.empty()) return true;
    for (const char* m : kNoiseMarks) {
        if (p.find(m) != std::string::npos) return true;
    }
    return false;
}

// 短窗口去重：同一 (进程, 动作, 路径) 在 kDedupMs 内只留一条。
// 这一招是这两路事件能进生产的关键 —— 浏览器与开发工具会把同一路径反复创建。
static const uint64_t kDedupMs   = 2000;
static const size_t   kDedupCap  = 8192;
static std::unordered_map<std::string, uint64_t> g_dedup;

static bool DedupDrop(const IoEvent& e, uint64_t now) {
    std::string key = std::to_string(e.pid);
    key += '\x1f';
    key += std::to_string((int)e.kind);
    key += '\x1f';
    key += e.path;
    key += '\x1f';
    key += e.valueName;
    auto it = g_dedup.find(key);
    if (it != g_dedup.end() && now - it->second <= kDedupMs) {
        it->second = now;
        return true;                       // 窗口内重复 → 丢
    }
    if (g_dedup.size() >= kDedupCap) {
        // 简单策略：整体清空。去重表只是"省流量"的优化，清空只会短暂多采一点，
        // 不会漏采 —— 这与"宁可多采"的原则一致。
        g_dedup.clear();
    }
    g_dedup[key] = now;
    return false;
}

// 进程名缓存（消费线程内使用）：pid → 映像名，TTL 30 秒，避免每条事件都开句柄
static const uint64_t kProcNameTtlMs = 30000;
static const size_t   kProcNameCap   = 512;
static std::unordered_map<unsigned long, std::pair<std::string, uint64_t>> g_procNames;

static const std::string& ProcNameOf(unsigned long pid, uint64_t now) {
    static const std::string kEmpty;
    auto it = g_procNames.find(pid);
    if (it != g_procNames.end() && now - it->second.second <= kProcNameTtlMs) return it->second.first;

    std::string nm;
    HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (hp) {
        wchar_t buf[MAX_PATH * 2] = { 0 };
        DWORD sz = (DWORD)(sizeof(buf) / sizeof(buf[0]));
        if (QueryFullProcessImageNameW(hp, 0, buf, &sz) && sz > 0) {
            int n = WideCharToMultiByte(CP_UTF8, 0, buf, (int)sz, nullptr, 0, nullptr, nullptr);
            if (n > 0) { nm.resize(n); WideCharToMultiByte(CP_UTF8, 0, buf, (int)sz, &nm[0], n, nullptr, nullptr); }
        }
        CloseHandle(hp);
    }
    if (g_procNames.size() >= kProcNameCap) g_procNames.clear();
    auto& slot = g_procNames[pid];
    slot.first  = nm;
    slot.second = now;
    return g_procNames[pid].first;
}

// ---------------------------------------------------------------------------
//  消费线程：出队 → 过滤 → 补进程名 → 外发 + 记环形缓冲
// ---------------------------------------------------------------------------
static void ConsumeLoop() {
    std::vector<IoEvent> batch;
    batch.reserve(64);
    const unsigned long selfPid = GetCurrentProcessId();

    while (!g_stop.load()) {
        batch.clear();
        {
            std::lock_guard<std::mutex> lk(g_qMtx);
            while (!g_queue.empty() && batch.size() < 64) {
                batch.push_back(std::move(g_queue.front()));
                g_queue.pop_front();
            }
        }
        if (batch.empty()) {
            if (g_qEvent) WaitForSingleObject(g_qEvent, 200);
            else Sleep(20);
            continue;
        }

        for (IoEvent& e : batch) {
            // ① 无发起进程（会话0基础设施/内核线程）→ 无从归因，丢
            if (e.pid == 0) { g_filteredNoise.fetch_add(1, std::memory_order_relaxed); continue; }
            // ② 本进程自己：我们自己写日志/隔离区/快照 → 不采（防自噬刷屏）
            if (e.pid == selfPid) { g_filteredSelf.fetch_add(1, std::memory_order_relaxed); continue; }
            // ③ PID 4（System）：系统缓存刷盘、内核 hive 写 → 量极大且无归因价值
            if (e.pid == 4) { g_filteredNoise.fetch_add(1, std::memory_order_relaxed); continue; }
            // ④ 高噪路径
            if (IsNoisePath(e.path)) { g_filteredNoise.fetch_add(1, std::memory_order_relaxed); continue; }
            // ⑤ 短窗口去重
            if (DedupDrop(e, e.atMs)) { g_deduped.fetch_add(1, std::memory_order_relaxed); continue; }

            e.procName = ProcNameOf(e.pid, e.atMs);

            {
                std::lock_guard<std::mutex> lk(g_recentMtx);
                g_recent.push_back(e);
                while (g_recent.size() > kRecentCap) g_recent.pop_front();
            }

            if (g_sink) {
                g_sink(e);
                g_delivered.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    // 退出前把去重表/进程名表清掉：服务长时间运行 + 频繁重启会话时避免常驻膨胀
    g_dedup.clear();
    g_procNames.clear();
}

// ---------------------------------------------------------------------------
//  启动 / 停止
// ---------------------------------------------------------------------------
static void ReleaseHandles() {
    if (g_qEvent) { CloseHandle(g_qEvent); g_qEvent = nullptr; }
    {
        std::lock_guard<std::mutex> lk(g_qMtx);
        g_queue.clear();
    }
}

bool Start(IoSink sink) {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return true;   // 幂等

    g_sink        = sink;
    g_stop.store(false);
    g_startMs.store(NowMsSteady());       // IsHealthy 启动宽限期起点
    g_sessionName = MakeSessionName();
    g_qEvent      = CreateEventW(nullptr, FALSE, FALSE, nullptr);   // 自动重置

    // [1] 创建会话
    //  ★ 固定名 ⇒ 先清同名残留；清完仍可能因内核尚未回收而 183 ⇒ 有限重试（≤3 次，每次等 200ms）。
    //    ⚠️ 重试硬上限：无限重试 = 卡死启动路径。
    std::wstring wname(g_sessionName.begin(), g_sessionName.end());
    ULONG st = ERROR_SUCCESS;
    bool  started = false;
    for (int attempt = 1; attempt <= 3; ++attempt) {
        PurgeStaleSession();
        if (attempt > 1) Sleep(200);

        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize    = (ULONG)props.size();
        p->Wnode.Flags         = WNODE_FLAG_TRACED_GUID;
        p->Wnode.ClientContext = 1;                // 1 = QPC 时间戳
        p->BufferSize          = 64;               // KB
        p->MinimumBuffers      = 64;               // 文件事件密 → 起步缓冲给大些
        p->MaximumBuffers      = 256;
        p->LogFileMode         = EVENT_TRACE_REAL_TIME_MODE;
        p->FlushTimer          = 1;
        p->LoggerNameOffset    = sizeof(EVENT_TRACE_PROPERTIES);

        st = StartTraceW(&g_session, wname.c_str(), p);
        if (st == ERROR_SUCCESS) { started = true; break; }
        g_session = 0;
        if (st == ERROR_ALREADY_EXISTS) {
            LogDbg("[iowatch] StartTraceW 撞同名会话（183，第 " + std::to_string(attempt) +
                   "/3 次），清理后重试");
            continue;
        }
        break;
    }
    if (!started) {
        LogDbg("[iowatch] StartTraceW 失败，错误码 " + std::to_string(st) +
               "（5=权限不足 183=会话名冲突 1450=会话数上限）→ 本模块无 WMI 兜底，降级为不可用");
        g_running.store(false);
        ReleaseHandles();
        return false;
    }

    // [2] 订阅 Kernel-File
    st = EnableTraceEx2(g_session, &kKernelFile, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, kFileKeyword, 0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        LogDbg("[iowatch] 订阅 Kernel-File 失败，错误码 " + std::to_string(st) +
               " keyword=0x1C90 → 降级为不可用");
        g_running.store(false);
        Stop();
        return false;
    }

    // [3] 订阅 Kernel-Registry（同一会话，第二个 provider）
    st = EnableTraceEx2(g_session, &kKernelRegistry, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                        TRACE_LEVEL_INFORMATION, kRegKeyword, 0, 0, nullptr);
    if (st != ERROR_SUCCESS) {
        // 注册表订阅失败不致命：文件那一路仍可用，记日志继续。
        LogDbg("[iowatch] 订阅 Kernel-Registry 失败，错误码 " + std::to_string(st) +
               " keyword=0x5340 → 仅保留文件事件采集");
    }

    // [4] 打开实时消费
    EVENT_TRACE_LOGFILEW lf{};
    lf.LoggerName          = (LPWSTR)wname.c_str();
    lf.ProcessTraceMode    = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    lf.EventRecordCallback = OnEventRecord;

    g_trace = OpenTraceW(&lf);
    if (g_trace == INVALID_PROCESSTRACE_HANDLE) {
        LogDbg("[iowatch] OpenTraceW 失败，错误码 " + std::to_string(GetLastError()) +
               " → 降级为不可用");
        g_running.store(false);
        Stop();
        return false;
    }

    // [5] ProcessTrace 阻塞 → 独立线程；消费另起一个
    g_thread   = std::thread([] { ProcessTrace(&g_trace, 1, nullptr, nullptr); });
    g_consumer = std::thread(ConsumeLoop);

    LogDbg("[iowatch] 文件与注册表事件采集已启动（ETW），会话名 " + g_sessionName +
           "，provider=Kernel-File(kw=0x1C90)+Kernel-Registry(kw=0x5340)");
    return true;
}

void Stop() {
    g_running.store(false);
    g_stop.store(true);
    if (g_qEvent) SetEvent(g_qEvent);

    // ★ 顺序不能反：先 CloseTrace 让阻塞中的 ProcessTrace 返回，再 join
    if (g_trace && g_trace != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_trace);
        g_trace = 0;
    }
    if (g_thread.joinable())   g_thread.join();
    if (g_consumer.joinable()) g_consumer.join();

    if (g_session) {
        // ★ 2026-10-02：显式 DISABLE_PROVIDER（本模块两个 provider 都要关）。
        //   旧实现只有 ENABLE、无 DISABLE，注销仅靠 STOP 的隐式副作用 ——
        //   STOP 失败 / 崩溃时内核侧留下"已订阅但无人消费"的记录，随残留累积。
        EnableTraceEx2(g_session, &kKernelFile,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, kFileKeyword, 0, 0, nullptr);
        EnableTraceEx2(g_session, &kKernelRegistry,
                       EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                       TRACE_LEVEL_INFORMATION, kRegKeyword, 0, 0, nullptr);
        std::vector<BYTE> props(1024, 0);
        EVENT_TRACE_PROPERTIES* p = (EVENT_TRACE_PROPERTIES*)props.data();
        p->Wnode.BufferSize = (ULONG)props.size();
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        std::wstring wname(g_sessionName.begin(), g_sessionName.end());
        ControlTraceW(g_session, wname.c_str(), p, EVENT_TRACE_CONTROL_STOP);
        g_session = 0;
    }
    ReleaseHandles();
    g_sink = nullptr;
}

bool IsRunning() { return g_running.load(); }

Stats GetStats() {
    Stats s;
    s.receivedFile  = g_receivedFile.load();
    s.receivedReg   = g_receivedReg.load();
    s.delivered     = g_delivered.load();
    s.dropped       = g_dropped.load();
    s.parseFail     = g_parseFail.load();
    s.noPathField   = g_noPath.load();
    s.filteredSelf  = g_filteredSelf.load();
    s.filteredNoise = g_filteredNoise.load();
    s.deduped       = g_deduped.load();
    s.lastEventMs   = g_lastEventMs.load();
    return s;
}

bool IsHealthy(uint64_t silentMs) {
    if (!g_running.load()) return false;
    uint64_t last  = g_lastEventMs.load();
    uint64_t start = g_startMs.load();
    if (last == 0) {
        // ★ 2026-10-02（#617，铁律 24「哑巴兜底」修正）：原实现 `if (last==0) return true;`
        //   ⇒ **从未收到过任何事件 = 健康** ⇒ 采集面彻底哑火时 0 告警，故障被掩盖。
        //   改为只给启动宽限期内算"待机健康"，超窗仍零事件即判不健康。
        return (NowMsSteady() - start) <= kStartupGraceMs;
    }
    return (NowMsSteady() - last) <= silentMs;
}

std::string SessionName() { return g_sessionName; }

std::vector<IoEvent> Recent(size_t maxCount) {
    std::lock_guard<std::mutex> lk(g_recentMtx);
    std::vector<IoEvent> out;
    size_t n = g_recent.size() < maxCount ? g_recent.size() : maxCount;
    out.reserve(n);
    // 取最新的 n 条（deque 尾是最新），输出按时间正序
    for (size_t i = g_recent.size() - n; i < g_recent.size(); ++i) out.push_back(g_recent[i]);
    return out;
}

void ClearRecent() {
    std::lock_guard<std::mutex> lk(g_recentMtx);
    g_recent.clear();
}

}  // namespace iowatch
}  // namespace sf
