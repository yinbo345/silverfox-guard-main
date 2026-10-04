// sfschema.cpp — 库结构 SQL + SQL 护栏的实现（详见 sfschema.h 的说明）
#include "sfschema.h"

#include <cctype>

namespace sf {
namespace sfschema {

// ===========================================================================
//  库结构
// ===========================================================================
//  每条后面的注释写的是「这张表替代了什么」，便于以后判断能不能删。
const char* const kSql =
    // 架构版本（k → v）。版本号本身由调用方先查后插，不在这里 INSERT。
    "CREATE TABLE IF NOT EXISTS schema_version (k TEXT PRIMARY KEY, v TEXT);"

    // 隔离区索引。替代 quarantine\index.tsv（一行一条、要全读进内存）。
    // 换成表之后：按 state 筛"还关着哪些"、按 at 排序看"最近隔离了什么"
    // 都是一次索引查，而不是把整个文件读进内存再线性扫。
    // ★ 隔离 ≠ 删除：state 从 quarantined 变 restored 就还原，行的身份保留。
    "CREATE TABLE IF NOT EXISTS quarantine ("
    "  id TEXT PRIMARY KEY,"
    "  origin TEXT,"
    "  stored TEXT,"
    "  at INT,"
    "  bytes INT,"
    "  reason TEXT,"
    "  state TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_quar_state ON quarantine (state);"

    // 回滚快照元数据。.snap 本体（C 类大二进制，单文件最大 160MB）继续留
    // 文件系统，表里只放路径 —— 把 160MB 的 blob 写进日志式库会让压缩
    // 变成"每压缩一次重写 160MB"的灾难。
    "CREATE TABLE IF NOT EXISTS rollback_snap ("
    "  path TEXT PRIMARY KEY,"
    "  snap TEXT,"
    "  size INT,"
    "  at INT,"
    "  hits INT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_snap_at ON rollback_snap (at);"

    // 衍生物清理的执行台账
    "CREATE TABLE IF NOT EXISTS clean_history ("
    "  id TEXT PRIMARY KEY,"
    "  at INT,"
    "  seed TEXT,"
    "  path TEXT,"
    "  tag TEXT,"
    "  bytes INT,"
    "  result TEXT"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_clean_at ON clean_history (at);"

    // ★ 信任区。银泊语义：信任 ≠ 放行 —— 只豁免**身份类**判据
    // （随机名 / 签名 / 路径），行为类判据照常跑。
    // 所以这张表存的是"哪些身份可信"，而不是"哪些东西别管"。
    "CREATE TABLE IF NOT EXISTS allowlist ("
    "  key TEXT PRIMARY KEY,"
    "  kind TEXT,"
    "  value TEXT,"
    "  note TEXT,"
    "  at INT"
    ");"

    // 通用单值（扫描进度、上次全盘时间、云库版本号……）
    "CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT, at INT);"

    // AI 引擎「影子模式」的观察台账：先攒真机样本，再决定是否让 AI 参与判定。
    // 这是"不拿用户机器做实验"的做法 —— 推理照跑、结论只记录、判定仍由规则引擎定。
    //
    // ★ 2026-09-25 加 cmd / label 两列（架构版本 1 → 2）
    //   两列的来历不同，都是"当时不加、以后要花大代价"的类型：
    //
    //   · cmd（完整命令行）—— 只为**人工复盘**。训练其实不需要它：
    //     命令行信息已经全部进了 feat（组 3 的 12 维）。但没有它，
    //     银泊看到一条"为什么误报"的样本时无法还原现场，只能对着
    //     一堆归一化到 [0,1] 的数字猜 —— 而复盘能力正是攒语料的意义所在。
    //
    //   · label（真值标注）—— 这是**训练标签**，不是特征。
    //     影子模式在用户机器上自动采集，它**不可能知道**进程是不是真恶意，
    //     所以自动采集的行 label 一律留空；恶意样本在虚拟机里跑完之后
    //     用 `aiobmark` 按时间窗批量打标。
    //     没有这一列，数据集里"什么叫恶意"就只能靠"规则引擎说过它有罪"来定义，
    //     而规则引擎自己就是被评判的对象 —— 那是循环论证，训出来的模型
    //     上限就是"模仿规则引擎"，毫无意义。
    //
    // ⚠️ 为什么敢直接加列而不做迁移：这张表此前**从来没有任何写入方**
    //    （全项目唯一的 INSERT 是 schema_version），生产环境里 guard.sfdb
    //    尚不存在。现在加列的成本是零，等有了数据再改就要写迁移。
    //    版本号随之抬到 2（EnsureSchema 只报不改，见 mod_sfdb.cpp）。
    "CREATE TABLE IF NOT EXISTS ai_observe ("
    "  id TEXT PRIMARY KEY,"       // 事件毫秒 + "-" + pid + "-" + 投递序号（见 aiobserve.h 的 seq）
    "  at INT,"                     // 事件 Unix 毫秒
    "  proc TEXT,"                  // 映像文件名
    "  path TEXT,"                  // 映像完整路径
    "  cmd TEXT,"                   // ★ 完整命令行（人工复盘用；训练用 feat 即可）
    "  score INT,"                  // 现有规则引擎分数（对照基准）
    "  verdict TEXT,"               // 现有规则引擎结论："clean"/"suspect"/"blocked"[:tag]
    "  aiscore INT,"                // ★ AI 分数 0~100；-1 = 当时没有装载模型
    "  label TEXT,"                 // ★ 真值标注：'' = 未标注 / 'benign' / 'malware'
    "  tags TEXT,"                  // ★ 行为标签真值：'' = 未标注 / 'none' = 确认无行为 / 'b64,iex'
    "  feat TEXT"                   // 特征向量（紧凑文本，便于导出做离线训练）
    ");"
    "CREATE INDEX IF NOT EXISTS idx_aiob_at ON ai_observe (at);"
    "CREATE INDEX IF NOT EXISTS idx_aiob_label ON ai_observe (label);";

// 架构版本。
//  ★ 1 → 2（2026-09-25）：ai_observe 增加 cmd / label 两列。
//    与 sfschema.h 的约定不同，这一次**刻意没有写迁移分支**，理由是
//    v1 从未在任何机器上落过地：ai_observe 一直没有任何写入方，
//    生产环境的 guard.sfdb 也还不存在（本轮才首次能建库）。
//    所以 v2 是"首个真实版本"，不存在需要迁移的 v1 数据。
//  ★ 2 → 3（2026-09-25，同日稍晚）：ai_observe 增加 tags 一列。
//    同样**不写迁移分支**，理由与上面完全一致、且这次是**抢在部署前**做的：
//    截至此刻，全世界的 guard.sfdb 仍然一个都不存在（银泊还没跑过第五轮部署包），
//    所以 v3 同样是"首个真实版本"，不存在需要迁移的 v2 数据。
//
//    ★★ 为什么必须抢在这一刻加：标签列是多头模型**第二个头唯一的监督目标**
//    （label 只能训恶意分那一头）。一旦银泊先部署了 v2 的包、机器上落了 v2 的库，
//    再加这一列就必须写真正的迁移分支了 —— 而 EnsureSchema 是**只报不改**的
//    （见 mod_sfdb.cpp）：版本不一致时它只记一行日志、照常继续跑，
//    于是老库缺少 tags 列 → INSERT 里多出来的那一列直接让**每一次样本写入都失败**，
//    表现成 aiobstat 上 writeFail 一路涨的"假故障"。
//    ⚠️ 从那以后（真用户机器上有了样本数据）再改表结构，就必须有迁移分支了。
const char* const kVersion = "3";

// 列探针 —— 说明见 sfschema.h。按名字列出 ai_observe 的全部列，
// 少一列或多一列都会与 CREATE TABLE 对不上；老库缺列时这条会直接失败。
// 用 LIMIT 1 而不是全表扫描：只为验证"这些列都认得"，不为取数据（表可能几十万行）。
const char* const kProbeSql =
    "SELECT id, at, proc, path, cmd, score, verdict, aiscore, label, tags, feat "
    "FROM ai_observe LIMIT 1";

// ===========================================================================
//  SQL 护栏实现
// ===========================================================================
static bool IsWordStart(char c) {
    return std::isalpha((unsigned char)c) != 0 || c == '_';
}
static bool IsWordChar(char c) {
    return std::isalnum((unsigned char)c) != 0 || c == '_';
}

bool ScanSqlShape(const std::string& sql, SqlShape& out, std::string& err) {
    out = SqlShape();
    err.clear();

    size_t i = 0;
    const size_t n = sql.size();
    bool inStr = false, inLine = false, inBlock = false;
    bool curHas = false;   // 当前语句是否已见到实质内容

    while (i < n) {
        char c = sql[i];

        if (inLine) {                       // -- 行注释，到行尾
            if (c == '\n') inLine = false;
            ++i; continue;
        }
        if (inBlock) {                      // /* 块注释 */
            if (c == '*' && i + 1 < n && sql[i + 1] == '/') { inBlock = false; i += 2; }
            else ++i;
            continue;
        }
        if (inStr) {                        // '字符串'；'' 表示一个单引号
            if (c == '\'') {
                if (i + 1 < n && sql[i + 1] == '\'') { i += 2; continue; }
                inStr = false;
            }
            ++i; continue;
        }

        if (c == '-' && i + 1 < n && sql[i + 1] == '-') { inLine = true;  i += 2; continue; }
        if (c == '/' && i + 1 < n && sql[i + 1] == '*') { inBlock = true; i += 2; continue; }
        if (c == '\'') { inStr = true; curHas = true; ++i; continue; }

        if (c == ';') {
            if (curHas) { ++out.stmts; curHas = false; }
            ++i; continue;
        }
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }

        if (IsWordStart(c)) {
            size_t j = i;
            while (j < n && IsWordChar(sql[j])) ++j;
            std::string w = sql.substr(i, j - i);
            for (size_t k = 0; k < w.size(); ++k)
                w[k] = (char)std::toupper((unsigned char)w[k]);

            if (out.stmts == 0) {           // 只在第一条语句里记录形状
                if (out.firstKw.empty()) out.firstKw = w;
                else if (w == "WHERE")   out.hasWhere = true;
            }
            curHas = true;
            i = j;
            continue;
        }

        // 数字 / 括号 / 运算符。语句的**第一个**实质字符必须是字母 ——
        // 否则连关键字都没有，没必要喂给引擎。
        if (!curHas) {
            err = "语句必须以关键字开头（只支持 SELECT / INSERT / UPDATE / "
                  "DELETE / CREATE / DROP）";
            return false;
        }
        curHas = true;
        ++i;
    }

    if (inStr)   { err = "字符串常量未闭合（缺少结尾单引号）"; return false; }
    if (inBlock) { err = "块注释未闭合（缺少 */）"; return false; }
    if (curHas)  ++out.stmts;

    if (out.stmts == 0) { err = "没有可执行的语句"; return false; }
    return true;
}

Tier TierOf(const std::string& kwUpper) {
    if (kwUpper == "SELECT") return kTierRead;
    if (kwUpper == "INSERT" || kwUpper == "UPDATE" || kwUpper == "CREATE")
        return kTierWrite;
    if (kwUpper == "DELETE" || kwUpper == "DROP") return kTierUnsafe;
    return kTierUnknown;
}

}  // namespace sfschema
}  // namespace sf
