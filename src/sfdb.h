// sfdb.h — 自研 SQL 子集数据库引擎（银狐主防内置存储层）
//
// ===========================================================================
//  为什么自己写，而不是用现成的
// ===========================================================================
//  银泊的指示很明确：**不要用微软的方案（ESE / esent.dll），自己写 SQL**。
//  这个决定在本项目语境下是合理的，理由有三条（也顺手记下代价）：
//
//  ① 体积与依赖：ESE 虽随系统附带，但要 `esent.dll` + 一段不算短的
//     Jet API 样板（JetCreateInstance → JetCreateDatabase → JetBeginSession →
//     JetCreateTableColumnIndex…）。自研版是**纯 Win32 文件 API**，
//     零第三方、零系统组件依赖，静态单文件 /MT 编译目标不受影响。
//  ② 数据形态其实很窄：本产品要落盘的「B 类可变事务数据」只有
//     回滚快照元数据、隔离区索引、清理历史、白名单/黑名单、少量状态单值。
//     它们共同点是「列少、行数万级、查询简单、写入低频」——
//     不需要事务隔离级别、不需要多用户并发、不需要 B+ 树页管理。
//  ③ 可审查性：安全产品里每一行代码都要能解释。自研引擎的磁盘格式
//     只有 8 条帧类型、一个 CRC、一个长度前缀，出问题能拿十六进制直接看懂；
//     而 ESE 的 .edb 页结构出问题时只能靠微软文档。
//
//  代价（必须承认）：没有 ACID 多语句事务、没有并发读写、没有 SQL 优化器。
//  所以**不要**把它用在「A 类只读点查」场景 —— 那类数据（云端哈希库）
//  走 mmap 有序二进制（见 hashdb.h），比任何数据库都快一个数量级。
//
// ===========================================================================
//  磁盘格式（追加日志式，日志即数据文件）
// ===========================================================================
//  整个 DB = 一个文件，内容是**顺序追加的定长头 + 变长负载帧**：
//
//      ┌──────────── 16 字节帧头 ────────────┐┌──── 负载 ────┐
//      │ magic(4) │kind(1)│flg(1)│pad(2)│len(4)│crc(4)│  len 字节  │
//      └──────────────────────────────────────┘└──────────────┘
//
//  · magic 固定 'FDB1'（0x31424446）—— 防止误把别的文件当 DB 打开并写坏。
//  · kind  = 帧类型，见 impl::FrameKind（建表/建索引/插入/更新/删除/落表/检查点）。
//  · len   = 负载字节数，硬上限 16MB（超过一律判为损坏，绝不 malloc 巨块）。
//  · crc   = 负载的 CRC32（IEEE 802.3 多项式）。**头自身不参与 CRC**，
//            这样头写坏时能靠 magic + len 的合理性先兜一层。
//
//  ★ 本引擎的「WAL」与「数据文件」是**同一个文件**（log-structured）。
//    每次写操作 = 追加一帧。帧写完（含可选 FlushFileBuffers）即持久。
//    没有「先写 WAL 再改页」的两段式 —— 也就没有「WAL 写了但页没落」的不一致窗口。
//
//  ★ 崩溃恢复 = 从前向后重放，遇到第一个不完整/CRC 错的帧就**截断**
//    （SetEndOfFile）到该帧起点。四种残缺形态全覆盖：
//      ① 头不足 16 字节           → 尾部半帧
//      ② len > 16MB 或 magic 错   → 头写坏 / 被别的数据污染
//      ③ 负载读不满 len           → 负载半写
//      ④ CRC 与负载不匹配         → 负载写坏
//    代价是「最后一条记录」可能丢，但**永远不会**出现「文件结构损坏打不开」。
//    对隔离区索引这类数据，丢最后一条远比整库打不开好。
//
//  ★ 删除是**墓碑**（Row::dead = true），不是原地抹除 —— 追加式存储没法原地改。
//    墓碑长期累积会让文件变大，用 Compact() 重写：新文件只写活行，
//    写完 MoveFileEx 原子替换。中途崩溃 → 原文件完好无损。
//
// ===========================================================================
//  支持的 SQL 子集（刻意窄，够用即可）
// ===========================================================================
//      CREATE TABLE [IF NOT EXISTS] t (c1 TEXT PRIMARY KEY, c2 INT, ...)
//      CREATE [UNIQUE] INDEX name ON t (col)
//      DROP TABLE [IF EXISTS] t
//      INSERT INTO t (c1, c2) VALUES ('a', 1), ('b', 2)
//      INSERT INTO t VALUES ('a', 1)              -- 位置对应全部列
//      SELECT * | c1, c2 | COUNT(*) FROM t
//             [WHERE expr] [ORDER BY c1 [ASC|DESC], ...] [LIMIT n [OFFSET m]]
//      UPDATE t SET c1 = v1 [, c2 = v2 ...] [WHERE expr]
//      DELETE FROM t [WHERE expr]
//
//      expr := and (OR and)*
//      and  := unit (AND unit)*
//      unit := [NOT] ( '(' expr ')' | col OP value | value OP col )
//      OP   := = | == | != | <> | < | <= | > | >= | LIKE | NOT LIKE
//
//  · 类型只有 TEXT 与 INT(64 位)。够覆盖路径/时间戳/大小/状态码。
//  · 一个表最多 1 个主键（可无）。主键即默认唯一索引。
//  · 列名/表名大小写不敏感；标识符不支持下划线以外的怪字符（本产品用不到）。
//
//  ★ 比较语义（**刻意偏离标准 SQL，请先看这里再写查询**）：
//    · 字符串比较**大小写不敏感**（Windows 路径语义，与 sf::PathEqualsCi 一致）。
//      原因是本引擎的主要用途是匹配路径 / 状态名，写成 'C:\Temp\a.exe'
//      与 'c:\temp\A.EXE' 判不同会天天踩坑。
//    · LIKE 同理大小写不敏感，`%` 匹配任意串、`_` 匹配单字符。
//    · INT 与 TEXT 比较时，若 TEXT 能整体解析为十进制整数则按数值比，否则按文本比。
//    · ORDER BY 用同一套比较规则。
//
// ===========================================================================
//  线程安全
// ===========================================================================
//  Database 的所有公开方法内部持互斥量，可被多个工作线程同时调用
//  （扫描线程写历史、管道线程读隔离区，是本产品的真实并发形态）。
//  但**不要**在回调里嵌套调用本库（没有可重入设计）。
//
// ===========================================================================
//  编码 / 路径
// ===========================================================================
//  · Open() 接受 **UTF-8** 路径。内部走 MultiByteToWideChar(CP_UTF8) → *W API。
//    ⚠️ 这是本项目的铁律之一：中文用户名（C:\Users\银泊\…）下若用 *A API，
//    GetFileAttributesA 会按 ANSI 解释 UTF-8 字节 → 静默失败且无日志。
//  · 列值里的字符串按**原样字节**存取（不转码）。调用方给 UTF-8 就存 UTF-8。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace sf {
namespace sfdb {

// ===========================================================================
//  值
// ===========================================================================
//  三态：Null（缺省/未提供）/ Int / Text。
//  Null 只在「读出来但该列不存在」这类边界场景出现，正常读写不会产生。
struct Value {
    enum Type : unsigned char {
        Null = 0,
        Int  = 1,
        Text = 2,
    };

    Type        type = Null;
    long long   i    = 0;
    std::string s;

    Value() = default;

    static Value OfInt(long long v) {
        Value x;
        x.type = Int;
        x.i    = v;
        return x;
    }
    static Value OfText(const std::string& v) {
        Value x;
        x.type = Text;
        x.s    = v;
        return x;
    }

    bool IsNull() const { return type == Null; }

    // Null → ""；Int → 十进制；Text → 原文
    std::string ToText() const;

    // Null → def；Text → 若能整体解析为十进制则返回该值，否则 def
    long long ToInt(long long def = 0) const;

    // 相等 / 序比较，规则见文件头「比较语义」
    static int Compare(const Value& a, const Value& b);  // <0 / 0 / >0
    static bool Like(const std::string& text, const std::string& pattern);
};

// ===========================================================================
//  结果集
// ===========================================================================
struct ResultSet {
    bool        isQuery   = false;  // true = SELECT（有列与行）；false = 改动语句
    std::string statement;          // 语句类型，如 "select" / "insert"
    long long   affected  = 0;      // 改动语句影响的行数
    std::vector<std::string>           columns;  // 列名（SELECT 才有）
    std::vector<std::vector<Value> >   rows;     // 每行按 columns 顺序
};

// ===========================================================================
//  统计（供 dbstat 命令 / 诊断用）
// ===========================================================================
struct TableStat {
    std::string name;
    long long   rows      = 0;   // 含墓碑
    long long   live      = 0;   // 活行
    long long   dead      = 0;   // 墓碑
    int         columns   = 0;
    int         indexes   = 0;   // 含主键？不，仅二级索引
    bool        hasPk     = false;
};

struct Stats {
    std::string path;             // UTF-8
    bool        open      = false;
    long long   fileBytes = 0;    // 当前文件字节数
    long long   frames    = 0;    // 已重放+新追加的帧数
    long long   appends   = 0;    // 本进程写入的帧数
    long long   compacts  = 0;    // 本进程压缩次数
    long long   recovered = 0;    // 打开时因损坏而截断的字节数（0 = 干净）
    bool        dirty     = false;// 墓碑是否需要压缩（dead > live/4）
    std::vector<TableStat> tables;
};

// ===========================================================================
//  Database
// ===========================================================================
class Database {
public:
    Database();
    ~Database();

    Database(const Database&)            = delete;
    Database& operator=(const Database&) = delete;

    // 打开（不存在则创建）。pathUtf8 是 UTF-8 编码的完整文件路径。
    // 父目录不存在会自动创建。失败返回 false，原因见 LastError()。
    bool Open(const std::string& pathUtf8);

    // 关闭并刷盘。可重复调用。
    void Close();

    bool IsOpen() const;

    // 最近一次失败的原因（中文，可直接进日志）
    std::string LastError() const;

    // 执行一条 SQL。outs 为各语句的结果（按顺序）。
    // 任一条语句失败即**停止后续**（前面的已生效，本引擎无多语句事务），
    // 返回 false。调用方可用 MultiStatement 判断是否需要回滚。
    bool Exec(const std::string& sql, std::vector<ResultSet>& outs);

    // 便利版：只跑一条语句
    bool ExecOne(const std::string& sql, ResultSet& out);

    // 压缩：重写日志，丢弃墓碑与历史 UPDATE 帧。
    // 中途崩溃 → 原文件完好（新内容写在 .tmp，最后原子替换）。
    bool Compact();

    // 是否每次写入都 FlushFileBuffers。
    //   默认 true（安全产品宁可慢一点也不能丢索引）；
    //   批量迁移（如把 17000 个 .meta 灌进表）时可临时关掉，
    //   迁移完手动 Sync() 一次，能快 1~2 个数量级。
    void SetSyncOnWrite(bool on);
    bool Sync();                 // 手动刷盘

    Stats GetStats() const;

    // ---- 便捷查询（内部拼 SQL，失败返回 false 并置 LastError）----
    // 取单个标量（SELECT <expr> FROM t WHERE ... LIMIT 1）
    bool QueryText(const std::string& sql, std::string& out);
    bool QueryInt(const std::string& sql, long long& out);

    // 表是否存在
    bool TableExists(const std::string& table) const;

    // 行数（活行；table 为空则统计全部表之和）
    long long CountRows(const std::string& table) const;

    // 转义一个字面串，返回带单引号的 SQL 字面量（供上层拼 SQL）
    // 例：Quote("O'Brien") → 'O''Brien'
    static std::string Quote(const std::string& raw);

private:
    struct Impl;
    Impl* p_;
};

}  // namespace sfdb
}  // namespace sf
