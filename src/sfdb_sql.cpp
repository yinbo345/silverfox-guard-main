// sfdb_sql.cpp — 自研 SQL 子集数据库：**查询层**
//
// ===========================================================================
//  本文件的职责边界
// ===========================================================================
//  词法 → 语法 → 求值 → 调 Store 的语义化方法。
//  **不碰文件格式、不碰帧、不碰索引结构** —— 那三样全在 sfdb.cpp。
//  这条边界让「以后想加个 GROUP BY」只需要动本文件，不必重新理解磁盘布局。
//
// ===========================================================================
//  ★★ 核心设计：解析与执行必须分成两趟（这里踩过一个大坑）
// ===========================================================================
//  第一版是「边解析边执行」，结果在验证程序里炸出一条很危险的路径：
//
//      UPDATE t SET v = v + 1000 WHERE id = 'k1'
//
//  本引擎不支持算术表达式（刻意的，见下）。旧实现在读到 `v` 后就把
//  `v` 当成字符串常量、以为 SET 结束，接着没看到 WHERE 就当作
//  **无条件更新全表**，500 行全被改掉；之后才在「语句结尾多余的词元」上报错。
//  结果是：调用方收到"失败"，但数据已经被改了 —— 一半成功一半失败，
//  而且是**静默的全表覆盖**。对隔离区元数据这类数据，等于灾难。
//
//  所以现在严格两趟：
//      ① ParseStatement：**纯函数**，只往 Statement 计划里填东西，一个字节都不写；
//      ② 整条语句（含结尾的 `;`）都合法之后，ExecuteStatement 才动数据。
//  语法错、词法错、多余词元 —— 全部在写入之前暴露。
//
//  ⚠️ 仍然没有的能力（必须在文档与注释里说清，不要指望）：
//      · 多语句事务（`a; b;` 中 b 失败时 a 已生效，无法回滚）
//      · 多行 INSERT 的原子性（逐行落盘；但**批内冲突会预先校验**，
//        所以"写了一半才发现主键撞了"不会发生）
//      · 表达式 / 函数 / 子查询 / JOIN / GROUP BY
//
// ===========================================================================
//  字符串字面量里反斜杠**不是转义符**
// ===========================================================================
//  这是刻意的选择，且与主流实现一致（SQLite / SQL Server / PostgreSQL 标准模式）：
//      INSERT INTO t VALUES ('C:\Temp\a.exe')      -- 反斜杠原样保留
//      SELECT * FROM t WHERE path LIKE '%\Temp\%'  -- 不需要写双反斜杠
//  只有单引号需要转义（写两遍：`''`）。
//  反例（MySQL 默认）把 `\` 当转义符，会让人习惯性写 `'C:\\Temp\\a.exe'`，
//  在本引擎里那就变成"含双反斜杠的路径"，永远匹配不上——这个差异很坑，
//  所以特意在验证程序里放了一条断言把它钉住。
#include "sfdb_impl.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <unordered_set>
#include <utility>

namespace sf {
namespace sfdb {
namespace impl {

// ===========================================================================
//  词法
// ===========================================================================
namespace {

enum class Tk {
    End = 0,
    Ident,   // 标识符 / 关键字（关键字判定在语法层做，见 EqCi）
    Str,     // 字符串字面量（已解转义）
    Num,     // 十进制整数
    Punct,   // 标点 / 运算符（单或双字符，见 Token::s）
};

struct Token {
    Tk          k = Tk::End;
    std::string s;
    long long   n  = 0;
    size_t      at = 0;   // 原文偏移，仅用于报错
};

bool EqCi(const std::string& a, const char* b) {
    return a.size() == strlen(b) && _stricmp(a.c_str(), b) == 0;
}

bool IsIdentStart(unsigned char c) {
    // 允许 >=0x80 的字节，这样中文表名/列名/值也能用
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80;
}

bool IsIdentChar(unsigned char c) {
    return IsIdentStart(c) || (c >= '0' && c <= '9') || c == '$';
}

bool Tokenize(const std::string& src, std::vector<Token>& out, std::string& err) {
    out.clear();
    size_t i = 0, n = src.size();

    while (i < n) {
        unsigned char c = (unsigned char)src[i];

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { ++i; continue; }

        // 注释：-- 到行尾；/* ... */
        if (c == '-' && i + 1 < n && src[i + 1] == '-') {
            while (i < n && src[i] != '\n') ++i;
            continue;
        }
        if (c == '/' && i + 1 < n && src[i + 1] == '*') {
            size_t end = src.find("*/", i + 2);
            if (end == std::string::npos) { err = "块注释未闭合（/* 缺少 */）"; return false; }
            i = end + 2;
            continue;
        }

        Token t;
        t.at = i;

        // 字符串字面量：单引号，'' 表示一个单引号；反斜杠**不转义**（见文件头说明）
        if (c == '\'') {
            ++i;
            std::string v;
            bool closed = false;
            while (i < n) {
                if (src[i] == '\'') {
                    if (i + 1 < n && src[i + 1] == '\'') { v.push_back('\''); i += 2; continue; }
                    ++i;
                    closed = true;
                    break;
                }
                v.push_back(src[i++]);
            }
            if (!closed) { err = "字符串字面量未闭合（缺少收尾的 '）"; return false; }
            t.k = Tk::Str;
            t.s = v;
            out.push_back(t);
            continue;
        }

        if (c >= '0' && c <= '9') {
            long long v = 0;
            while (i < n && src[i] >= '0' && src[i] <= '9') { v = v * 10 + (src[i] - '0'); ++i; }
            t.k = Tk::Num;
            t.n = v;
            t.s = std::to_string(v);
            out.push_back(t);
            continue;
        }

        if (IsIdentStart(c)) {
            size_t s = i;
            while (i < n && IsIdentChar((unsigned char)src[i])) ++i;
            t.k = Tk::Ident;
            t.s = src.substr(s, i - s);
            out.push_back(t);
            continue;
        }

        // 双字符运算符优先（<= >= != <> ==）
        if (i + 1 < n) {
            char a = src[i], b = src[i + 1];
            if ((a == '<' && (b == '=' || b == '>')) || (a == '>' && b == '=') ||
                (a == '!' && b == '=') || (a == '=' && b == '=')) {
                t.k = Tk::Punct;
                t.s = std::string() + a + b;
                if (t.s == "<>") t.s = "!=";   // 归一化：<> 与 != 同义
                i += 2;
                out.push_back(t);
                continue;
            }
        }

        // 单字符标点（显式白名单：避免把中文标点当运算符）
        if (src[i] != '\0' &&
            (strchr("(),;*", src[i]) != nullptr || src[i] == '=' || src[i] == '<' ||
             src[i] == '>' || src[i] == '+' || src[i] == '-' || src[i] == '/')) {
            t.k = Tk::Punct;
            t.s = std::string(1, src[i]);
            ++i;
            out.push_back(t);
            continue;
        }

        err = std::string("无法识别的字符 '") + src[i] + "'（位置 " + std::to_string(i) + "）";
        return false;
    }

    Token e;
    e.k  = Tk::End;
    e.at = n;
    out.push_back(e);
    return true;
}

// ===========================================================================
//  表达式 AST
// ===========================================================================
struct Expr;
typedef std::shared_ptr<Expr> ExprP;

struct Expr {
    enum Kind { And, Or, Not, Cmp } kind = Cmp;

    // kind == Cmp 时有效
    std::string colName;      // 解析期：列名（大小写不敏感地查）
    int         colIdx = -1;  // 执行期：ResolveExpr 填好的列下标
    std::string op;           // "=" "!=" "<" "<=" ">" ">=" "like" "notlike"
    Value       val;          // 右操作数（常量）

    ExprP a, b;
};

ExprP MkBin(Expr::Kind k, ExprP a, ExprP b) {
    ExprP e(new Expr());
    e->kind = k;
    e->a = a;
    e->b = b;
    return e;
}

// 执行期把列名解析成下标。解析失败的表达式**不会被求值**。
bool ResolveExpr(Expr& e, const Table& t, std::string& err) {
    if (e.kind == Expr::Cmp) {
        int ci = t.FindCol(e.colName);
        if (ci < 0) { err = "列不存在：" + e.colName; return false; }
        e.colIdx = ci;
        return true;
    }
    if (e.a && !ResolveExpr(*e.a, t, err)) return false;
    if (e.b && !ResolveExpr(*e.b, t, err)) return false;
    return true;
}

// 求值：只读内存，绝不落盘
bool EvalExpr(const Expr& e, const Row& r) {
    switch (e.kind) {
        case Expr::And: return EvalExpr(*e.a, r) && EvalExpr(*e.b, r);
        case Expr::Or:  return EvalExpr(*e.a, r) || EvalExpr(*e.b, r);
        case Expr::Not: return !EvalExpr(*e.a, r);
        case Expr::Cmp: {
            Value l;
            if (e.colIdx >= 0 && e.colIdx < (int)r.cells.size()) l = r.cells[e.colIdx];
            if (e.op == "like")    return Value::Like(l.ToText(), e.val.ToText());
            if (e.op == "notlike") return !Value::Like(l.ToText(), e.val.ToText());
            int c = Value::Compare(l, e.val);
            if (e.op == "=")  return c == 0;
            if (e.op == "!=") return c != 0;
            if (e.op == "<")  return c < 0;
            if (e.op == "<=") return c <= 0;
            if (e.op == ">")  return c > 0;
            if (e.op == ">=") return c >= 0;
            return false;
        }
    }
    return false;
}

// ===========================================================================
//  语句计划（纯数据，不含任何副作用）
// ===========================================================================
struct SortKey {
    std::string name;   // 解析期记名字，执行期解析成下标
    int         col  = -1;
    bool        desc = false;
};

struct SetItem {
    std::string name;
    Value       val;
};

enum class StmtOp {
    None = 0,
    CreateTable,
    CreateIndex,
    DropTable,
    Insert,
    Select,
    Update,
    Delete,
};

struct Statement {
    StmtOp      op = StmtOp::None;
    std::string table;
    bool        ifNotExists = false;   // CREATE ... IF NOT EXISTS
    bool        ifExists    = false;   // DROP TABLE IF EXISTS

    // CreateTable
    std::vector<Col> newCols;

    // CreateIndex
    std::string indexName;
    std::string indexCol;
    bool        unique = false;

    // Insert
    std::vector<std::string>         insertCols;   // 空 = 位置对应全部列
    std::vector<std::vector<Value> > tuples;

    // Update
    std::vector<SetItem> sets;

    // Select
    bool                 countStar = false;
    std::vector<std::string> selNames;    // 空 = SELECT *
    std::vector<SortKey> sortKeys;
    long long            limit  = -1;
    long long            offset = 0;

    // Select / Update / Delete
    ExprP where;
};

// ===========================================================================
//  语法（纯解析，不执行）
// ===========================================================================
struct Parser {
    const std::vector<Token>& toks;
    Store&                    st;     // 只用于查表定义（解析列名），**不用于写**
    size_t                    i = 0;
    std::string               err;

    Parser(const std::vector<Token>& t, Store& s) : toks(t), st(s) {}

    const Token& Peek(size_t k = 0) const {
        size_t j = i + k;
        return (j < toks.size()) ? toks[j] : toks.back();
    }
    bool AtEnd() const { return Peek().k == Tk::End; }

    void Fail(const std::string& m) {
        if (err.empty()) err = m + "（位置 " + std::to_string(Peek().at) + "）";
    }

    bool AcceptKw(const char* kw) {
        if (Peek().k == Tk::Ident && EqCi(Peek().s, kw)) { ++i; return true; }
        return false;
    }
    bool AcceptPunct(const char* p) {
        if (Peek().k == Tk::Punct && Peek().s == p) { ++i; return true; }
        return false;
    }
    bool ExpectPunct(const char* p) {
        if (AcceptPunct(p)) return true;
        Fail(std::string("期望 '") + p + "'");
        return false;
    }
    // 取一个标识符。关键字也允许当名字用（本产品的表里确实有叫 state 的列）
    bool Ident(std::string& out) {
        if (Peek().k != Tk::Ident) { Fail("期望标识符"); return false; }
        out = Peek().s;
        ++i;
        return true;
    }

    // 是否是算术/拼接运算符 —— 用来把「不支持表达式」报成精确错误，
    // 而不是让它退化成"语句结尾多余词元"这种看不懂的提示。
    bool AtArithOp() const {
        if (Peek().k != Tk::Punct) return false;
        const std::string& s = Peek().s;
        return s == "+" || s == "-" || s == "*" || s == "/";
    }

    // 解析一个值。strict=true 时拒绝后面紧跟算术运算符（即拒绝表达式）
    bool ParseValue(Value& out, bool strict) {
        if (Peek().k == Tk::Punct && Peek().s == "-") {
            ++i;
            if (Peek().k != Tk::Num) { Fail("负号后面必须是数字"); return false; }
            out = Value::OfInt(-Peek().n);
            ++i;
            return true;
        }
        if (AcceptPunct("+")) { /* 允许 +12 */ }

        if (Peek().k == Tk::Num)      { out = Value::OfInt(Peek().n);  ++i; }
        else if (Peek().k == Tk::Str) { out = Value::OfText(Peek().s); ++i; }
        else if (Peek().k == Tk::Ident) {
            // 裸标识符当字符串（如 state = pending）。宽松一点，但只吃一个词，
            // 不会把后面的关键字/运算符一起吞掉。
            out = Value::OfText(Peek().s);
            ++i;
        } else {
            Fail("期望一个值（数字或字符串常量）");
            return false;
        }

        if (strict && AtArithOp()) {
            Fail("本引擎不支持表达式运算（只接受常量值）。"
                 "若确实要写算术结果，请在调用方算好后作为参数传入");
            return false;
        }
        return true;
    }

    // ---- 条件表达式 ----
    // ★ 整条链都要带 `const Table&`：条件里出现的列名必须**在解析期**就校验存在性。
    //   若拖到执行期，`DELETE FROM t WHERE typo_col = 1` 会先被当成"没有匹配行"静默成功，
    //   而真正的意图（清空全表）和执行结果难以区分 —— 这类"看起来成功"的错必须掐死在解析层。
    ExprP ParseOr(const Table& t) {
        ExprP a = ParseAnd(t);
        if (!a) return ExprP();
        while (AcceptKw("OR")) {
            ExprP b = ParseAnd(t);
            if (!b) return ExprP();
            a = MkBin(Expr::Or, a, b);
        }
        return a;
    }

    ExprP ParseAnd(const Table& t) {
        ExprP a = ParseUnit(t);
        if (!a) return ExprP();
        while (AcceptKw("AND")) {
            ExprP b = ParseUnit(t);
            if (!b) return ExprP();
            a = MkBin(Expr::And, a, b);
        }
        return a;
    }

    ExprP ParseUnit(const Table& t) {
        if (AcceptKw("NOT")) {
            ExprP inner = ParseUnit(t);
            if (!inner) return ExprP();
            ExprP e(new Expr());
            e->kind = Expr::Not;
            e->a    = inner;
            return e;
        }
        if (AcceptPunct("(")) {
            ExprP inner = ParseOr(t);
            if (!inner) return ExprP();
            if (!ExpectPunct(")")) return ExprP();
            return inner;
        }
        return ParseCmp(t);
    }

    bool ReadOp(std::string& op, bool& isLike) {
        isLike = false;
        if (Peek().k != Tk::Punct && Peek().k != Tk::Ident) { Fail("期望比较运算符"); return false; }

        // col NOT LIKE 'x' —— 与布尔义的 NOT (col LIKE 'x') 等价
        if (Peek().k == Tk::Ident && EqCi(Peek().s, "NOT")) {
            ++i;
            if (!AcceptKw("LIKE")) { Fail("NOT 后面只支持 LIKE"); return false; }
            op = "notlike";
            isLike = true;
            return true;
        }
        if (AcceptKw("LIKE")) { op = "like"; isLike = true; return true; }

        if (Peek().k == Tk::Punct) {
            const std::string& s = Peek().s;
            if (s == "=" || s == "!=" || s == "<" || s == "<=" || s == ">" || s == ">=") {
                op = s;
                ++i;
                return true;
            }
        }
        Fail("期望比较运算符（= != < <= > >= LIKE）");
        return false;
    }

    // 归一化：列永远在左。`5 < a` 翻成 `a > 5`，求值阶段就只需一套逻辑。
    ExprP ParseCmp(const Table& t) {
        ExprP e(new Expr());
        e->kind = Expr::Cmp;

        if (Peek().k == Tk::Ident) {
            std::string name = Peek().s;
            ++i;
            if (t.FindCol(name) < 0) { Fail("列不存在：" + name); return ExprP(); }

            std::string op;
            bool isLike = false;
            if (!ReadOp(op, isLike)) return ExprP();
            Value v;
            if (!ParseValue(v, true)) return ExprP();

            e->colName = name;
            e->op      = op;
            e->val     = v;
            return e;
        }

        // 常量在左：读常量 → 读运算符 → 读列 → 翻转运算符
        Value v;
        if (!ParseValue(v, true)) return ExprP();
        std::string op;
        bool isLike = false;
        if (!ReadOp(op, isLike)) return ExprP();
        if (isLike) { Fail("LIKE 左侧必须是列名"); return ExprP(); }
        if (Peek().k != Tk::Ident) { Fail("期望列名"); return ExprP(); }
        std::string name = Peek().s;
        ++i;
        if (t.FindCol(name) < 0) { Fail("列不存在：" + name); return ExprP(); }

        std::string flipped;
        if (op == "<")       flipped = ">";
        else if (op == "<=") flipped = ">=";
        else if (op == ">")  flipped = "<";
        else if (op == ">=") flipped = "<=";
        else                 flipped = op;   // = 与 != 自反

        e->colName = name;
        e->op      = flipped;
        e->val     = v;
        return e;
    }

    // ---- 语句 ----
    bool ParseStatement(Statement& out);
};

// ===========================================================================
//  语法实现
// ===========================================================================
bool Parser::ParseStatement(Statement& out) {
    // ---------------------------------------------------------------- SELECT
    if (AcceptKw("SELECT")) {
        out.op = StmtOp::Select;

        if (AcceptPunct("*")) {
            // 全部列，执行期按表定义填
        } else if (Peek().k == Tk::Ident && EqCi(Peek().s, "COUNT")) {
            ++i;
            if (!ExpectPunct("(") || !ExpectPunct("*") || !ExpectPunct(")")) return false;
            out.countStar = true;
        } else {
            while (true) {
                std::string c;
                if (!Ident(c)) return false;
                out.selNames.push_back(c);
                if (!AcceptPunct(",")) break;
            }
        }

        if (!AcceptKw("FROM")) { Fail("SELECT 后面缺少 FROM"); return false; }
        if (!Ident(out.table)) return false;
        Table* tp = st.Find(out.table);
        if (!tp) { Fail("表不存在：" + out.table); return false; }
        const Table& t = *tp;

        // 提前校验选中的列名（避免执行期才发现写错列）
        for (size_t k = 0; k < out.selNames.size(); ++k) {
            if (t.FindCol(out.selNames[k]) < 0) { Fail("列不存在：" + out.selNames[k]); return false; }
        }

        if (AcceptKw("WHERE")) {
            out.where = ParseOr(t);
            if (!out.where) return false;
        }

        if (AcceptKw("ORDER")) {
            if (!AcceptKw("BY")) { Fail("ORDER 后面缺少 BY"); return false; }
            while (true) {
                SortKey k;
                if (!Ident(k.name)) return false;
                if (t.FindCol(k.name) < 0) { Fail("ORDER BY 的列不存在：" + k.name); return false; }
                if (AcceptKw("DESC"))      k.desc = true;
                else                       AcceptKw("ASC");
                out.sortKeys.push_back(k);
                if (!AcceptPunct(",")) break;
            }
        }

        if (AcceptKw("LIMIT")) {
            if (Peek().k != Tk::Num) { Fail("LIMIT 后面必须是数字"); return false; }
            out.limit = Peek().n;
            ++i;
            if (AcceptKw("OFFSET")) {
                if (Peek().k != Tk::Num) { Fail("OFFSET 后面必须是数字"); return false; }
                out.offset = Peek().n;
                ++i;
            }
        }
        return true;
    }

    // --------------------------------------------------------- CREATE ...
    if (AcceptKw("CREATE")) {
        if (AcceptKw("UNIQUE")) out.unique = true;

        if (AcceptKw("TABLE")) {
            out.op = StmtOp::CreateTable;
            if (AcceptKw("IF")) {
                if (!AcceptKw("NOT") || !AcceptKw("EXISTS")) { Fail("IF NOT EXISTS 写法不完整"); return false; }
                out.ifNotExists = true;
            }
            if (!Ident(out.table)) return false;
            if (!ExpectPunct("(")) return false;

            while (true) {
                Col c;
                if (!Ident(c.name)) return false;

                std::string ty;
                if (!Ident(ty)) return false;
                if (EqCi(ty, "INT") || EqCi(ty, "INTEGER") || EqCi(ty, "BIGINT")) {
                    c.type = Value::Int;
                } else if (EqCi(ty, "TEXT") || EqCi(ty, "VARCHAR") || EqCi(ty, "CHAR") ||
                           EqCi(ty, "STRING") || EqCi(ty, "BOOL")) {
                    c.type = Value::Text;
                    if (AcceptPunct("(")) {   // 吃掉 VARCHAR(n) 的长度参数
                        if (Peek().k != Tk::Num) { Fail("长度参数必须是数字"); return false; }
                        ++i;
                        if (!ExpectPunct(")")) return false;
                    }
                } else {
                    Fail("不支持的类型：" + ty + "（本引擎只有 TEXT / INT）");
                    return false;
                }

                // 列级约束。NOT NULL / UNIQUE / DEFAULT 本引擎不做强制，
                // 但**必须吃掉**，否则会被当成下一个列名，语法立刻错位。
                while (true) {
                    if (AcceptKw("PRIMARY")) {
                        if (!AcceptKw("KEY")) { Fail("PRIMARY 后面缺少 KEY"); return false; }
                        c.isPk = true;
                        continue;
                    }
                    if (AcceptKw("NOT")) {
                        if (!AcceptKw("NULL")) { Fail("NOT 后面缺少 NULL"); return false; }
                        continue;
                    }
                    if (AcceptKw("UNIQUE")) continue;
                    if (AcceptKw("DEFAULT")) {
                        Value dummy;
                        if (!ParseValue(dummy, false)) return false;
                        continue;
                    }
                    break;
                }

                out.newCols.push_back(c);
                if (AcceptPunct(",")) continue;
                break;
            }
            if (!ExpectPunct(")")) return false;
            return true;
        }

        if (AcceptKw("INDEX")) {
            out.op = StmtOp::CreateIndex;
            if (AcceptKw("IF")) {
                if (!AcceptKw("NOT") || !AcceptKw("EXISTS")) { Fail("IF NOT EXISTS 写法不完整"); return false; }
                out.ifNotExists = true;
            }
            if (!Ident(out.indexName)) return false;
            if (!AcceptKw("ON")) { Fail("CREATE INDEX 缺少 ON"); return false; }
            if (!Ident(out.table)) return false;
            if (!ExpectPunct("(")) return false;
            if (!Ident(out.indexCol)) return false;
            if (!ExpectPunct(")")) return false;
            return true;
        }

        Fail("CREATE 后面只支持 TABLE / [UNIQUE] INDEX");
        return false;
    }

    // ------------------------------------------------------------- DROP TABLE
    if (AcceptKw("DROP")) {
        if (!AcceptKw("TABLE")) { Fail("DROP 后面只支持 TABLE"); return false; }
        out.op = StmtOp::DropTable;
        if (AcceptKw("IF")) {
            if (!AcceptKw("EXISTS")) { Fail("IF 后面缺少 EXISTS"); return false; }
            out.ifExists = true;
        }
        if (!Ident(out.table)) return false;
        return true;
    }

    // ----------------------------------------------------------------- INSERT
    if (AcceptKw("INSERT")) {
        out.op = StmtOp::Insert;
        if (!AcceptKw("INTO")) { Fail("INSERT 后面缺少 INTO"); return false; }
        if (!Ident(out.table)) return false;
        Table* tp = st.Find(out.table);
        if (!tp) { Fail("表不存在：" + out.table); return false; }
        const Table& t = *tp;

        if (AcceptPunct("(")) {
            while (true) {
                std::string c;
                if (!Ident(c)) return false;
                if (t.FindCol(c) < 0) { Fail("列不存在：" + c); return false; }
                out.insertCols.push_back(c);
                if (!AcceptPunct(",")) break;
            }
            if (!ExpectPunct(")")) return false;
        }

        if (!AcceptKw("VALUES")) { Fail("INSERT 缺少 VALUES"); return false; }

        while (true) {
            if (!ExpectPunct("(")) return false;
            std::vector<Value> vals;
            while (true) {
                Value v;
                if (!ParseValue(v, true)) return false;
                vals.push_back(v);
                if (!AcceptPunct(",")) break;
            }
            if (!ExpectPunct(")")) return false;
            out.tuples.push_back(vals);
            if (!AcceptPunct(",")) break;   // 支持 VALUES (...), (...), (...)
        }
        return true;
    }

    // ----------------------------------------------------------------- UPDATE
    if (AcceptKw("UPDATE")) {
        out.op = StmtOp::Update;
        if (!Ident(out.table)) return false;
        Table* tp = st.Find(out.table);
        if (!tp) { Fail("表不存在：" + out.table); return false; }
        const Table& t = *tp;
        if (t.pk < 0) { Fail("UPDATE 需要表有主键（本引擎按主键定位行）"); return false; }

        if (!AcceptKw("SET")) { Fail("UPDATE 缺少 SET"); return false; }
        while (true) {
            SetItem si;
            if (!Ident(si.name)) return false;
            if (t.FindCol(si.name) < 0) { Fail("列不存在：" + si.name); return false; }
            if (!ExpectPunct("=")) return false;
            if (!ParseValue(si.val, true)) return false;
            out.sets.push_back(si);
            if (!AcceptPunct(",")) break;
        }

        if (AcceptKw("WHERE")) {
            out.where = ParseOr(t);
            if (!out.where) return false;
        }
        return true;
    }

    // ----------------------------------------------------------------- DELETE
    if (AcceptKw("DELETE")) {
        out.op = StmtOp::Delete;
        if (!AcceptKw("FROM")) { Fail("DELETE 后面缺少 FROM"); return false; }
        if (!Ident(out.table)) return false;
        Table* tp = st.Find(out.table);
        if (!tp) { Fail("表不存在：" + out.table); return false; }
        const Table& t = *tp;
        if (t.pk < 0) { Fail("DELETE 需要表有主键（本引擎按主键打墓碑）"); return false; }

        if (AcceptKw("WHERE")) {
            out.where = ParseOr(t);
            if (!out.where) return false;
        }
        return true;
    }

    Fail("无法识别的语句（本引擎支持 CREATE / DROP / INSERT / SELECT / UPDATE / DELETE）");
    return false;
}

// ===========================================================================
//  执行（只有在整条语句**完全**合法之后才会走到这里）
// ===========================================================================
void CollectRows(const Table& t, const ExprP& where, std::vector<size_t>& out) {
    out.clear();
    for (size_t ri = 0; ri < t.rows.size(); ++ri) {
        if (t.rows[ri].dead) continue;
        if (!where || EvalExpr(*where, t.rows[ri])) out.push_back(ri);
    }
}

bool ExecuteSelect(Store& st, Statement& s, ResultSet& rs) {
    Table* tp = st.Find(s.table);
    if (!tp) { st.SetErr("表不存在：" + s.table); return false; }
    Table& t = *tp;

    std::vector<int>         cols;
    std::vector<std::string> names;

    if (s.countStar) {
        names.push_back("count");
    } else if (s.selNames.empty()) {
        for (size_t c = 0; c < t.cols.size(); ++c) {
            cols.push_back((int)c);
            names.push_back(t.cols[c].name);
        }
    } else {
        for (size_t c = 0; c < s.selNames.size(); ++c) {
            int ci = t.FindCol(s.selNames[c]);
            if (ci < 0) { st.SetErr("列不存在：" + s.selNames[c]); return false; }
            cols.push_back(ci);
            names.push_back(t.cols[ci].name);
        }
    }

    if (s.where) {
        std::string e;
        if (!ResolveExpr(*s.where, t, e)) { st.SetErr(e); return false; }
    }

    for (size_t k = 0; k < s.sortKeys.size(); ++k) {
        int ci = t.FindCol(s.sortKeys[k].name);
        if (ci < 0) { st.SetErr("ORDER BY 的列不存在：" + s.sortKeys[k].name); return false; }
        s.sortKeys[k].col = ci;
    }

    std::vector<size_t> idxs;
    CollectRows(t, s.where, idxs);

    if (!s.sortKeys.empty()) {
        std::stable_sort(idxs.begin(), idxs.end(), [&](size_t a, size_t b) {
            for (size_t k = 0; k < s.sortKeys.size(); ++k) {
                const SortKey& sk = s.sortKeys[k];
                int c = Value::Compare(t.rows[a].cells[sk.col], t.rows[b].cells[sk.col]);
                if (c != 0) return sk.desc ? (c > 0) : (c < 0);
            }
            return false;   // 相等 → stable_sort 保持插入顺序（结果确定，不随实现变）
        });
    }

    if (s.offset > 0) {
        if (s.offset >= (long long)idxs.size()) idxs.clear();
        else idxs.erase(idxs.begin(), idxs.begin() + (ptrdiff_t)s.offset);
    }
    if (s.limit >= 0 && (long long)idxs.size() > s.limit) idxs.resize((size_t)s.limit);

    rs.isQuery   = true;
    rs.statement = "select";
    rs.columns   = names;

    if (s.countStar) {
        std::vector<Value> row;
        row.push_back(Value::OfInt((long long)idxs.size()));
        rs.rows.push_back(row);
        return true;
    }

    rs.rows.reserve(idxs.size());
    for (size_t k = 0; k < idxs.size(); ++k) {
        const Row& r = t.rows[idxs[k]];
        std::vector<Value> row;
        row.reserve(cols.size());
        for (size_t c = 0; c < cols.size(); ++c) {
            if (cols[c] < (int)r.cells.size()) row.push_back(r.cells[cols[c]]);
            else                               row.push_back(Value());
        }
        rs.rows.push_back(row);
    }
    return true;
}

bool ExecuteInsert(Store& st, Statement& s, ResultSet& rs) {
    Table* tp = st.Find(s.table);
    if (!tp) { st.SetErr("表不存在：" + s.table); return false; }
    Table& t = *tp;

    // 1) 列映射
    std::vector<int> map;
    if (!s.insertCols.empty()) {
        for (size_t k = 0; k < s.insertCols.size(); ++k) {
            int ci = t.FindCol(s.insertCols[k]);
            if (ci < 0) { st.SetErr("列不存在：" + s.insertCols[k]); return false; }
            map.push_back(ci);
        }
    }

    // 2) 组装每行的完整 cells
    std::vector<std::vector<Value> > rows;
    rows.reserve(s.tuples.size());
    for (size_t k = 0; k < s.tuples.size(); ++k) {
        const std::vector<Value>& tup = s.tuples[k];
        if (map.empty()) {
            if (tup.size() != t.cols.size()) {
                st.SetErr("第 " + std::to_string(k + 1) + " 组值有 " + std::to_string(tup.size()) +
                          " 个，表 " + s.table + " 有 " + std::to_string(t.cols.size()) + " 列");
                return false;
            }
            rows.push_back(tup);
        } else {
            if (tup.size() != map.size()) {
                st.SetErr("第 " + std::to_string(k + 1) + " 组值的个数与列清单不一致");
                return false;
            }
            std::vector<Value> cells(t.cols.size());
            for (size_t j = 0; j < map.size(); ++j) cells[map[j]] = tup[j];
            rows.push_back(cells);
        }
    }

    // 3) ★ 全批判重（批内 + 批外）—— 必须在写第一行之前做完。
    //    否则「写了 3 行才发现第 4 行主键撞了」会留下半成品数据。
    if (t.pk >= 0) {
        std::unordered_set<std::string> seen;
        for (size_t k = 0; k < rows.size(); ++k) {
            const Value& pkv = rows[k][t.pk];
            if (pkv.IsNull()) { st.SetErr("主键列 " + t.cols[t.pk].name + " 不能为空"); return false; }
            std::string key = KeyOf(pkv);
            if (!seen.insert(key).second) { st.SetErr("批内主键重复：" + key); return false; }
            auto it = t.pkMap.find(key);
            if (it != t.pkMap.end() && it->second < t.rows.size() && !t.rows[it->second].dead) {
                st.SetErr("主键重复：" + key);
                return false;
            }
        }
    }
    for (size_t ix = 0; ix < t.idx.size(); ++ix) {
        Index& I = t.idx[ix];
        if (!I.unique || I.col < 0) continue;
        std::unordered_set<std::string> seen;
        for (size_t k = 0; k < rows.size(); ++k) {
            std::string key = KeyOf(rows[k][I.col]);
            if (!seen.insert(key).second) {
                st.SetErr("批内唯一索引 " + I.name + " 冲突：" + rows[k][I.col].ToText());
                return false;
            }
            auto it = I.map.find(key);
            if (it == I.map.end()) continue;
            for (size_t j = 0; j < it->second.size(); ++j) {
                size_t ri = it->second[j];
                if (ri < t.rows.size() && !t.rows[ri].dead) {
                    st.SetErr("唯一索引 " + I.name + " 冲突：" + rows[k][I.col].ToText());
                    return false;
                }
            }
        }
    }

    // 4) 逐行落盘
    for (size_t k = 0; k < rows.size(); ++k) {
        if (!st.Insert(s.table, rows[k])) return false;
    }
    rs.statement = "insert";
    rs.affected  = (long long)rows.size();
    return true;
}

bool ExecuteUpdate(Store& st, Statement& s, ResultSet& rs) {
    Table* tp = st.Find(s.table);
    if (!tp) { st.SetErr("表不存在：" + s.table); return false; }
    Table& t = *tp;
    if (t.pk < 0) { st.SetErr("UPDATE 需要表有主键"); return false; }

    std::vector<int>   setCols;
    std::vector<Value> setVals;
    for (size_t k = 0; k < s.sets.size(); ++k) {
        int ci = t.FindCol(s.sets[k].name);
        if (ci < 0) { st.SetErr("列不存在：" + s.sets[k].name); return false; }
        setCols.push_back(ci);
        setVals.push_back(s.sets[k].val);
    }

    if (s.where) {
        std::string e;
        if (!ResolveExpr(*s.where, t, e)) { st.SetErr(e); return false; }
    }

    std::vector<size_t> idxs;
    CollectRows(t, s.where, idxs);
    if ((long long)idxs.size() > kMaxAffectedPerStmt) {
        st.SetErr("UPDATE 将影响 " + std::to_string(idxs.size()) + " 行，超过上限 " +
                  std::to_string(kMaxAffectedPerStmt) + "，请补上 WHERE 条件");
        return false;
    }

    // 组装每条目标行的最终内容 + 记录旧主键（SET 可能改主键列）
    std::vector<std::vector<Value> > newRows;
    std::vector<Value>               oldKeys;
    std::unordered_set<size_t>       target(idxs.begin(), idxs.end());
    newRows.reserve(idxs.size());
    oldKeys.reserve(idxs.size());
    for (size_t k = 0; k < idxs.size(); ++k) {
        std::vector<Value> cells = t.rows[idxs[k]].cells;
        for (size_t j = 0; j < setCols.size(); ++j) cells[setCols[j]] = setVals[j];
        newRows.push_back(cells);
        oldKeys.push_back(t.rows[idxs[k]].cells[t.pk]);
    }

    // ★ 预校验：全批先查重，避免"改了 5 行才在第 6 行冲突"
    {
        std::unordered_set<std::string> seen;
        for (size_t k = 0; k < newRows.size(); ++k) {
            const Value& pkv = newRows[k][t.pk];
            if (pkv.IsNull()) { st.SetErr("主键不能为空"); return false; }
            std::string nk = KeyOf(pkv);
            if (!seen.insert(nk).second) { st.SetErr("更新后多行主键重复：" + nk); return false; }
            auto it = t.pkMap.find(nk);
            if (it != t.pkMap.end() && it->second < t.rows.size() && !t.rows[it->second].dead &&
                target.find(it->second) == target.end()) {
                st.SetErr("更新后主键与其它行冲突：" + nk);
                return false;
            }
        }
    }
    for (size_t ix = 0; ix < t.idx.size(); ++ix) {
        Index& I = t.idx[ix];
        if (!I.unique || I.col < 0) continue;
        std::unordered_set<std::string> seen;
        for (size_t k = 0; k < newRows.size(); ++k) {
            std::string key = KeyOf(newRows[k][I.col]);
            if (!seen.insert(key).second) {
                st.SetErr("更新后批内唯一索引 " + I.name + " 冲突：" + newRows[k][I.col].ToText());
                return false;
            }
            auto it = I.map.find(key);
            if (it == I.map.end()) continue;
            for (size_t j = 0; j < it->second.size(); ++j) {
                size_t ri = it->second[j];
                if (ri < t.rows.size() && !t.rows[ri].dead && target.find(ri) == target.end()) {
                    st.SetErr("更新后唯一索引 " + I.name + " 冲突：" + newRows[k][I.col].ToText());
                    return false;
                }
            }
        }
    }

    for (size_t k = 0; k < newRows.size(); ++k) {
        if (!st.UpdateByPk(s.table, oldKeys[k], newRows[k])) return false;
    }
    rs.statement = "update";
    rs.affected  = (long long)newRows.size();
    return true;
}

bool ExecuteDelete(Store& st, Statement& s, ResultSet& rs) {
    Table* tp = st.Find(s.table);
    if (!tp) { st.SetErr("表不存在：" + s.table); return false; }
    Table& t = *tp;
    if (t.pk < 0) { st.SetErr("DELETE 需要表有主键"); return false; }

    if (s.where) {
        std::string e;
        if (!ResolveExpr(*s.where, t, e)) { st.SetErr(e); return false; }
    }

    std::vector<size_t> idxs;
    CollectRows(t, s.where, idxs);
    if ((long long)idxs.size() > kMaxAffectedPerStmt) {
        st.SetErr("DELETE 将影响 " + std::to_string(idxs.size()) + " 行，超过上限 " +
                  std::to_string(kMaxAffectedPerStmt) + "，请补上 WHERE 条件");
        return false;
    }

    std::vector<Value> pks;
    pks.reserve(idxs.size());
    for (size_t k = 0; k < idxs.size(); ++k) pks.push_back(t.rows[idxs[k]].cells[t.pk]);

    long long affected = 0;
    for (size_t k = 0; k < pks.size(); ++k) {
        if (!st.DeleteByPk(s.table, pks[k])) {
            // 「已经不存在」不算错误（收集到落地之间不可能发生，但防御性处理）
            if (st.err.find("不存在") != std::string::npos) { st.err.clear(); continue; }
            return false;
        }
        ++affected;
    }
    rs.statement = "delete";
    rs.affected  = affected;
    return true;
}

bool ExecuteStatement(Store& st, Statement& s, ResultSet& rs) {
    switch (s.op) {
        case StmtOp::CreateTable:
            if (!st.CreateTable(s.table, s.newCols, s.ifNotExists)) return false;
            rs.statement = "create table";
            return true;

        case StmtOp::CreateIndex:
            if (!st.CreateIndex(s.table, s.indexName, s.indexCol, s.unique, s.ifNotExists)) return false;
            rs.statement = "create index";
            return true;

        case StmtOp::DropTable:
            if (!st.DropTable(s.table, s.ifExists)) return false;
            rs.statement = "drop table";
            return true;

        case StmtOp::Insert: return ExecuteInsert(st, s, rs);
        case StmtOp::Select: return ExecuteSelect(st, s, rs);
        case StmtOp::Update: return ExecuteUpdate(st, s, rs);
        case StmtOp::Delete: return ExecuteDelete(st, s, rs);
        default: break;
    }
    st.SetErr("内部错误：未知的语句类型");
    return false;
}

}  // namespace

// ===========================================================================
//  对外入口
// ===========================================================================
bool SqlRunAll(Store& store, const std::string& sql, std::vector<ResultSet>& outs) {
    outs.clear();

    std::vector<Token> toks;
    std::string lerr;
    if (!Tokenize(sql, toks, lerr)) {
        store.SetErr("SQL 词法错误：" + lerr);
        return false;
    }

    Parser p(toks, store);

    while (true) {
        while (p.AcceptPunct(";")) { /* 跳过空语句 / 多余分号 */ }
        if (p.AtEnd()) break;

        Statement plan;
        if (!p.ParseStatement(plan)) {
            // ⚠️ 不要把解析器自己的兜底文案盖掉 Store 已经写好的具体原因。
            //    第一版写成 store.SetErr(p.err)，结果「主键重复」这类
            //    来自 Store::Insert 的真实原因被替换成笼统的"SQL 语法错误"，
            //    排查时完全看不出问题在哪（2026-09-25 验证程序抓到）。
            if (!p.err.empty())      store.SetErr(p.err);
            else if (store.err.empty()) store.SetErr("SQL 语句解析失败");
            return false;
        }

        // ★ 整条语句必须干净收尾（只允许 ';' 或结束）。
        //   这一步在 ExecuteStatement **之前** —— 保证语法错的语句一个字节都不写。
        if (!p.AtEnd() && !p.AcceptPunct(";")) {
            store.SetErr("语句结尾有多余内容（位置 " + std::to_string(p.Peek().at) +
                         "，词元「" + p.Peek().s + "」）。语句未执行。");
            return false;
        }

        store.err.clear();
        ResultSet rs;
        if (!ExecuteStatement(store, plan, rs)) {
            // 执行失败同样保持「失败 = 无结果」的直觉
            if (store.err.empty()) store.SetErr("语句执行失败");
            return false;
        }
        outs.push_back(rs);
    }

    return true;
}

}  // namespace impl
}  // namespace sfdb
}  // namespace sf
