// sfdb_impl.h — sfdb 引擎的内部结构（**不是公共接口，仅供 sfdb.cpp / sfdb_sql.cpp 使用**）
//
// ===========================================================================
//  为什么拆成两个 .cpp 还要一个内部头
// ===========================================================================
//  sfdb 的实现有两块性质完全不同的代码：
//    · 存储层（sfdb.cpp）    —— 文件帧编解码、CRC、崩溃恢复、重放、压缩
//    · 查询层（sfdb_sql.cpp）—— 词法、语法、求值、执行分派
//  两者放一个文件会变成 2000+ 行的巨型文件，且以后改 SQL 语法要动存储代码。
//  拆开之后，两边通过本头里的 impl::Store 对话：查询层只调 Store 的
//  语义化方法（CreateTable/Insert/UpdateByPk/DeleteByPk），**完全不碰文件格式**。
//  这是本产品一贯的分层原则（主干不做业务判断，同理：查询层不做落盘）。
//
//  ⚠️ 本头文件**不进 build.sh 的公开契约**，任何外部模块都不应 include 它。
//     外部一律只用 sfdb.h。
#pragma once

#include "sfdb.h"

#include <windows.h>

#include <string>
#include <unordered_map>
#include <vector>

namespace sf {
namespace sfdb {
namespace impl {

// ===========================================================================
//  帧类型
// ===========================================================================
//  只有 8 种，全部定长头 + 变长负载。加新帧类型时**只能往后追加编号**，
//  已有编号的含义永不改变（否则旧文件重放会静默错乱）。
enum FrameKind : unsigned char {
    kFrameHeader      = 1,  // 文件头：格式版本 + 引擎标识
    kFrameCreateTable = 2,
    kFrameCreateIndex = 3,
    kFrameDropTable   = 4,
    kFrameInsert      = 5,
    kFrameUpdate      = 6,  // 负载携带**全部列的新值**（含主键），按主键原地替换
    kFrameDelete      = 7,  // 负载携带主键值 → 打墓碑
    kFrameCheckpoint  = 8,  // 诊断用：记录压缩点/帧计数，重放时忽略
};

// 帧头魔数 'FDB1'（文件里字节序为 46 44 42 31）
const uint32_t kMagic = 0x31424446u;

// 单帧负载上限。超过一律判损坏 —— 绝不为了"能读"去 malloc 一个巨块，
// 那等于把「文件损坏」升级成「服务 OOM」。
const uint32_t kMaxPayload = 16u * 1024u * 1024u;

// 单条语句最多影响的行数（防止 `DELETE FROM t` 不写 WHERE 把库清空）
const long long kMaxAffectedPerStmt = 200000;

#pragma pack(push, 1)
struct FrameHead {
    uint32_t magic;
    uint8_t  kind;
    uint8_t  flags;    // 保留（恒 0）
    uint16_t pad;      // 保留（恒 0）
    uint32_t len;
    uint32_t crc;
};
#pragma pack(pop)

static_assert(sizeof(FrameHead) == 16, "帧头必须是 16 字节（定长，便于崩溃时定位）");

// ===========================================================================
//  表结构
// ===========================================================================
struct Col {
    std::string  name;
    Value::Type  type = Value::Text;
    bool         isPk = false;
};

struct Row {
    std::vector<Value> cells;
    bool               dead = false;   // 墓碑：DELETE 只置位，不物理删除
};

// 二级索引：列值 → 行下标列表（列值可重复，故是 list 不是单个）
struct Index {
    std::string name;
    int         col     = -1;
    bool        unique  = false;  // 声明为 UNIQUE → 插入/更新时强制查重
    std::unordered_map<std::string, std::vector<size_t> > map;
};

struct Table {
    std::string        name;
    std::vector<Col>   cols;
    int                pk = -1;         // 主键列下标，-1 = 无主键
    std::vector<Row>   rows;            // 顺序 = 插入顺序（含墓碑）
    std::unordered_map<std::string, size_t> pkMap;  // 主键值 → rows 下标
    std::vector<Index> idx;

    // 列名查下标（大小写不敏感）。找不到返回 -1。
    int FindCol(const std::string& n) const;

    long long LiveCount() const;
    long long DeadCount() const;
};

// 索引键：Text 转小写（与比较语义一致），Int 转十进制串。
std::string KeyOf(const Value& v);

// ===========================================================================
//  Store —— 存储层（实现在 sfdb.cpp）
// ===========================================================================
//  查询层拿到的唯一句柄。方法名即语义，调用者不需要知道帧的存在。
//  所有方法都会**先校验后落盘**：校验不过则一个字节都不写。
struct Store {
    std::string path;                     // UTF-8
    HANDLE      hFile = INVALID_HANDLE_VALUE;

    std::vector<Table> tables;

    long long fileBytes = 0;
    long long frames    = 0;
    long long appends   = 0;
    long long compacts  = 0;
    long long recovered = 0;              // 打开时截断掉的字节数

    bool        syncOnWrite = true;
    bool        open        = false;
    std::string err;

    // ---- 打开 / 关闭 ----
    bool OpenFile(const std::string& pathUtf8);
    void CloseFile();
    void SetErr(const std::string& e) { err = e; }

    // ---- 查找 ----
    Table*       Find(const std::string& name);
    const Table* Find(const std::string& name) const;

    // ---- 变更（内部自动：校验 → 追加帧 → 应用内存）----
    bool CreateTable(const std::string& name, const std::vector<Col>& cols, bool ifNotExists);
    bool CreateIndex(const std::string& table, const std::string& indexName,
                     const std::string& col, bool unique, bool ifNotExists);
    bool DropTable(const std::string& name, bool ifExists);
    // 插入一行（cells 必须已按表列顺序对齐，缺列由查询层补 Null）
    bool Insert(const std::string& table, const std::vector<Value>& cells);
    // 按**旧主键值** key 定位行，整行替换为 newCells。
    // ⚠️ 参数必须同时给旧主键：SET 有可能改主键列本身
    //    （`UPDATE t SET id = 'x' WHERE id = 'y'`），若只给新值就无法定位旧行，
    //    这个 bug 在 2026-09-25 的验证程序里被专门测出来了。
    //    帧里同时记录旧主键，重放时才能复现「主键搬家」。
    bool UpdateByPk(const std::string& table, const Value& key, const std::vector<Value>& newCells);
    bool DeleteByPk(const std::string& table, const Value& pkValue);

    // ---- 帧 I/O ----
    bool AppendFrame(FrameKind kind, const std::string& payload);
    bool Sync();
    bool Compact();

    // ---- 重放 ----
    // 参数是**宽字符**路径：重放要反复 SetFilePointerEx/SetEndOfFile，
    // 直接传已转好的宽路径，避免在热路径上重复做 UTF-8 转换。
    bool Replay(const std::wstring& wpath);

    // ---- 索引维护（查询层插入/删除后由 Store 内部调用）----
    void IndexAdd(Table& t, size_t rowIdx);
    void IndexRemove(Table& t, size_t rowIdx);
    void RebuildIndexes(Table& t);
};

// ===========================================================================
//  负载编解码（实现在 sfdb.cpp，查询层也要用）
// ===========================================================================
class Writer {
public:
    std::string buf;

    void U8(uint8_t v);
    void U32(uint32_t v);
    void I64(long long v);
    void Str(const std::string& s);
    void Value_(const Value& v);       // 名字带下划线避免与类型 Value 撞名
};

class Reader {
public:
    Reader(const char* p, size_t n) : p_(p), n_(n) {}

    bool U8(uint8_t& v);
    bool U32(uint32_t& v);
    bool I64(long long& v);
    bool Str(std::string& v);
    bool Value_(Value& v);

    bool Ok() const { return !bad_; }     // 全程无越界 = true
    size_t Used() const { return off_; }

private:
    const char* p_;
    size_t      n_;
    size_t      off_ = 0;
    bool        bad_ = false;
};

// 编/解一行（cells 数量 + 每格值）
void WriteCells(Writer& w, const std::vector<Value>& cells);
bool ReadCells(Reader& r, std::vector<Value>& cells);

uint32_t Crc32(const void* data, size_t len);

// UTF-8 → 宽字符（本文件的铁律：所有 *W 调用前必须经过它）
std::wstring Utf8ToWide(const std::string& s);

// ===========================================================================
//  查询层入口（实现在 sfdb_sql.cpp）
// ===========================================================================
//  跑完 sql 里的全部语句，结果按序压进 outs。任一语句失败返回 false 并置 store.err。
bool SqlRunAll(Store& store, const std::string& sql, std::vector<ResultSet>& outs);

}  // namespace impl
}  // namespace sfdb
}  // namespace sf
