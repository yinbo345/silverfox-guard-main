// mod_sfdb.cpp — 分体：自研 SQL 子集数据库（sfdb）+ 云端哈希库（hashdb）的托管与管道命令
//
// ===========================================================================
//  定位：本分体是「本地存储」的唯一入口
// ===========================================================================
//  本产品有两类数据，访问画像完全不同，所以用两套引擎（分区原则见
//  docs/storage-architecture.md）：
//
//    A 类 · 只读点查 · 云端哈希库
//        问「这个 SHA-256 在不在库里」。几十万~上千万条、进程启动即用、
//        永不原地更新（云库是整体替换的）。→ hashdb（mmap 有序数组 + Bloom）
//
//    B 类 · 可变事务 · 隔离区 / 回滚快照元数据 / 清理历史 / 白名单 / 状态单值
//        要按条件筛、按时间排序、要增删改。→ sfdb（自研 SQL 子集）
//
//    C 类 · 大二进制（.snap 快照本体，单文件最大 160MB）
//        继续留在文件系统。数据库里只存**路径与元数据** ——
//        把 160MB 的 blob 塞进日志式数据库会让压缩变成一场灾难。
//
//  ★ 为什么自研 SQL 而不用微软 ESE（esent.dll）
//    银泊明确否决了微软方案。客观理由也支持这个决定：
//      · 体积与依赖：ESE 要拖一个独立 DLL，且版本受系统影响；
//        本产品坚持零第三方依赖、单 EXE 交付（/MT 静态链接）。
//      · 数据形态很窄：这里只有「按主键查/改 + 少量条件筛 + 排序」，
//        不需要外键、JOIN、事务隔离级别、游标。为 5% 的能力付 100% 的复杂度不值。
//      · 可审查性：日志式追加 + 16 字节帧头 + CRC32，
//        整个磁盘格式能在 10 分钟里读完并说清「最坏情况丢什么」。
//        ESE 的恢复语义牵扯日志/检查点/软恢复，出问题时无法自己定性。
//    自研的代价是「要自己保证崩溃安全」—— 这件事已经用
//    「重放遇坏帧即截断」+「Compact 先写 .tmp 再原子替换」两条兜住了。
//
// ===========================================================================
//  命令清单（GUI / 命令行 / 脚本都用同一套）
// ===========================================================================
//    dbstat     库健康与结构（文件大小/帧数/表清单/墓碑/脏标记/打开时的恢复字节数）
//    sql        执行一条 SQL。★ 默认只读，分级开关：
//                 （不带开关）       只允许 SELECT
//                 write:1            + INSERT / UPDATE / CREATE
//                 unsafe:1           + DELETE / DROP（不可逆；隐含 write）
//               多语句需要 multi:1。无 WHERE 的 UPDATE 需要 unsafe:1。
//    dbcompact  手动压缩（把墓碑与历史 UPDATE 帧真正清掉，释放磁盘）
//    hashstat   三本云库（恶意SHA-256 / 可信SHA-256 / 恶意imphash）的状态
//    hashq      查一个哈希：
//                 hash=<64 hex>            按 algo 指定的键空间查
//                 path=<文件路径>           自动算（algo 省略 = sha256）
//                 path=... algo=imphash     算导入表哈希并派生查询键
//    hashchain  ★ 「病毒库到底有没有在工作」的唯一判据。分三组给数：
//                 库装载（哪本开着、多少条）／判定链查询（查了几次、中几次、
//                 因库未装载跳了几次）／哈希计算（算了多少、缓存省了多少、
//                 因超限跳了多少、失败多少）。**三组必须分开看** ——
//                 混在一起就无法区分"没有恶意文件"与"库根本没装载"。
//                 reset:1 顺带清零统计。
//    hashreload 重新打开云库 —— 云端刚下发新库时用，不必重启服务
//
// ===========================================================================
//  ★ 为什么 Init 恒返回 true
// ===========================================================================
//  按主干契约，Init 返回 false 会让主干**跳过整个分体**，于是连 dbstat 都查不到，
//  库打不开时反而失去唯一的诊断手段（"我打不开库"和"没有库这个功能"是两回事）。
//  所以这里把「功能是否存在」与「功能是否健康」拆开：
//    命令永远注册；健康状态由 dbstat / hashstat 的 ok、err 字段如实汇报。
//  云库缺失更是**正常状态** —— 新装的机器还没有下发过库，不算故障。
#include "module.h"

#include "common.h"    // WriteFramed / JsonString / JsonGetString / JsonGetInt / LogDbg
#include "hashdb.h"
#include "hashshare.h" // ★ 哈希库的跨模块**只读查询**契约（本分体是唯一实现方）
#include "libsig.h"    // ★ 病毒库签名验签（ECDSA P-256）。装载前的最后一道闸门。
#include "pehash.h"    // 文件哈希 / imphash（命令与实时链共用同一套算法）
#include "sfdb.h"
#include "sfschema.h"  // 库结构 SQL + SQL 护栏（独立可测单元，见该文件头）
#include "sfdbshare.h" // ★ 跨模块取用入口（本分体是唯一登记方，见该文件头）

#include <atomic>      // 全局实例登记用（读方是 mod_ai 的观测线程，写入方是本分体）

#include <windows.h>
#include <shlobj.h>

#include <cctype>
#include <ctime>       // Unix 秒 → "YYYY-MM-DD HH:MM:SS UTC"（库的"发布日期"）
#include <memory>
#include <shared_mutex>
#include <string>
#include <vector>
#include <algorithm>     // std::sort（本地恶意库 txt 重写排序）
#include <unordered_set> // 本地恶意库内存集合（独立于云库）

namespace {

// ===========================================================================
//  路径与编码
// ===========================================================================
//  铁律：内部路径统一 UTF-8，所有文件 API 走 *W（见项目「UTF-8 路径铁律」：
//  GetFileAttributesA / CreateFileA 会按 ANSI 解释 UTF-8，在中文用户名下静默失败）。
std::wstring DataDirW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else
        dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);   // 已存在则失败，无害
    return dir;
}

std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s((size_t)n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

bool EnsureDirW(const std::wstring& dir) {
    if (dir.empty()) return false;
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    DWORD e = GetLastError();
    if (e == ERROR_ALREADY_EXISTS) return true;
    // 逐级创建（ProgramData 下的子目录可能整条链都不存在）
    size_t pos = dir.find_last_of(L"\\/");
    if (pos == std::wstring::npos || pos == 0) return false;
    if (!EnsureDirW(dir.substr(0, pos))) return false;
    return CreateDirectoryW(dir.c_str(), nullptr) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

std::string JoinUtf8(const std::wstring& dir, const wchar_t* leaf) {
    return WideToUtf8(dir + L"\\" + leaf);
}

// ===========================================================================
//  全局状态
// ===========================================================================
std::wstring g_dataDir;
std::string  g_dbPath;          // <data>\guard.sfdb
std::string  g_cloudDir;        // <data>\cloud
std::string  g_malPath;         // <cloud>\malicious.sfh      ← 键 = 整文件 SHA-256
std::string  g_truPath;         // <cloud>\trusted.sfh        ← 键 = 整文件 SHA-256
std::string  g_malImpPath;      // <cloud>\malicious_imp.sfh  ← 键 = pehash::ImphashKey()
std::string  g_malMd5Path;      // <cloud>\malicious_md5.sfh  ← 键 = pehash::Md5Key()
std::string  g_malSha1Path;     // <cloud>\malicious_sha1.sfh ← 键 = pehash::Sha1Key()

// ---- 本地恶意库（独立于云库，高危隔离自动入库；云库更新不触达）----
//  ★ 为什么必须独立：云库 malicious.sfh 是「整文件原子替换」+ ECDSA 签名，
//    任何写进它的本地数据，下次云库一更新立刻被覆盖，且本机无私钥重签。
//    所以本地学习到的恶意哈希必须落在**另一个目录（local\）的另一个文件（txt）**，
//    libupdate / hashreload 永远不碰它 → 云库更新不会冲掉本机积累。
//  规范存储 = local\local_malicious.txt（每行一个 SHA-256，小写，已排序去重）；
//  内存集合 g_localMalSet 是真值，txt 是持久化镜像（原子重写）。
std::string  g_localDirU8;                       // <data>\local
std::string  g_localMalTxt;                       // <local>\local_malicious.txt
std::shared_mutex g_localMalMtx;                  // 本地库读写锁（读多写极少）
std::unordered_set<std::string> g_localMalSet;    // SHA-256 小写十六进制集合
bool        g_localInited = false;

// 内存集合 → txt 原子重写（txt 是规范存储；云库更新永远不碰它）。
bool LocalMalTxtRewriteLocked() {
    std::vector<std::string> v(g_localMalSet.begin(), g_localMalSet.end());
    std::sort(v.begin(), v.end());
    const std::wstring tmp = Utf8ToWide(g_localMalTxt + ".tmp");
    const std::wstring dst = Utf8ToWide(g_localMalTxt);
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool ok = true;
    for (const auto& s : v) {
        std::string line = s + "\n";
        DWORD w = 0;
        if (!WriteFile(h, line.data(), (DWORD)line.size(), &w, nullptr) || w != (DWORD)line.size()) {
            ok = false; break;
        }
    }
    if (ok && !FlushFileBuffers(h)) ok = false;
    CloseHandle(h);
    if (!ok) { DeleteFileW(tmp.c_str()); return false; }
    if (!MoveFileExW(tmp.c_str(), dst.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(tmp.c_str()); return false;
    }
    return true;
}

// 启动初始化：建 local\ 目录 + 从 txt 装载集合。仅 InitSfdb 调一次。
void InitLocalLib() {
    std::wstring localW = g_dataDir + L"\\local";
    EnsureDirW(localW);
    g_localDirU8  = WideToUtf8(localW);
    g_localMalTxt = g_localDirU8 + "\\local_malicious.txt";
    {
        std::lock_guard<std::shared_mutex> lk(g_localMalMtx);
        g_localMalSet.clear();
        HANDLE h = CreateFileW(Utf8ToWide(g_localMalTxt).c_str(), GENERIC_READ, FILE_SHARE_READ,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER sz;
            if (GetFileSizeEx(h, &sz) && sz.QuadPart > 0 && sz.QuadPart < (1LL << 26)) {
                std::string buf((size_t)sz.QuadPart, '\0');
                DWORD rd = 0;
                if (ReadFile(h, &buf[0], (DWORD)sz.QuadPart, &rd, nullptr) && rd == (DWORD)sz.QuadPart) {
                    size_t i = 0;
                    while (i < buf.size()) {
                        size_t j = buf.find('\n', i);
                        if (j == std::string::npos) j = buf.size();
                        size_t end = j;
                        if (end > i && buf[end - 1] == '\r') --end;
                        if (end > i) {
                            std::string line = buf.substr(i, end - i);
                            if (line.size() == 64) {
                                bool okhex = true;
                                for (char c : line) if (!std::isxdigit((unsigned char)c)) { okhex = false; break; }
                                if (okhex) g_localMalSet.insert(line);
                            }
                        }
                        if (j == buf.size()) break;
                        i = j + 1;
                    }
                }
            }
            CloseHandle(h);
        }
    }
    g_localInited = true;
    sf::LogDbg(std::string("[localmal] 本地恶意库初始化完成：") + g_localMalTxt +
               " 已加载 " + std::to_string(g_localMalSet.size()) + " 条（独立于云库，更新不触达）");
}

// ★ 为什么 imphash 必须**另立一本库**而不是和 SHA-256 混在一起存
//   ------------------------------------------------------------------
//   hashdb 的键是"32 字节不透明值"，它自己不校验键是怎么来的
//   （hashdb.cpp:336 只硬校验 hashBytes == 32）。也就是说混存**能跑通**，
//   没有任何一行代码会报错 —— 这正是危险之处：
//      · 同一本库里混着两种语义的键，**看不出哪条是哪条**；
//      · 一次误操作（把 SHA-256 派生成了 imphash 键，或反过来）
//        会表现为"库建了一百万条，命中率却接近零"，且**不报任何错**；
//      · 反过来也成立：库里有一半键属于另一个键空间，等于凭空多出
//        几十万条**永远不可能被正确命中**的死条目。
//    另立一本库的代价只有一个文件句柄，换来的是"两个键空间物理隔离，
//    混用在结构上不可能"。区分方式由库头 tag 唯一确定。
//   ⚠️ 只有"恶意" imphash 库，**刻意没有"可信" imphash 库** —— 理由见
//      hashshare.h 关于「可信哈希不得用于放行」那一段：一个可信 imphash
//      会豁免**一整个 loader 家族**（同一编译器/同一打包器产出的程序
//      imphash 常常相同），那是比可信 SHA-256 危险得多的后门。

sf::sfdb::Database g_db;
bool               g_dbReady = false;
std::string        g_dbErr;     // 打开失败原因（供 dbstat 汇报）

// ---- 进程内实例登记（跨模块取用，契约见 sfdbshare.h）----
// ★ 为什么用 atomic 而不是裸指针：
//   写入方是 StartAll / StopAll（服务主线程），读方是 mod_ai 的观测线程 ——
//   两者虽有 module.cpp 的「Init 后才起线程 / 先 join 再 Stop」顺序兜底，
//   但**管道命令线程**（dbexec / sql）随时可能并发到这里读。
//   靠"时序恰好安全"是本项目吃过大亏的思路（构建比源文件早 4 秒那次的教训），
//   这里直接上 atomic：开销为零，且不再需要论证时序。
std::atomic<sf::sfdb::Database*> g_regDb{ nullptr };
std::atomic<bool>                g_regReady{ false };

// 云库：用 unique_ptr 承载，好处是 hashreload 能"先建好新的再换指针"，
// 而不是"先关掉旧的再打开新的"—— 后者中间有一段时间窗完全无库可查。
//
// ★ 因此这里**绝不能**把裸指针交给外部（如 service.cpp 的实时链）：
//   hashreload 会 reset 掉它们，外部手里的指针立刻悬垂。
//   跨模块访问一律走 hashshare.h 的**函数**接口，由本文件在锁内完成查询。
std::shared_mutex g_hlock;
std::unique_ptr<sf::hashdb::HashDb> g_mal;
std::unique_ptr<sf::hashdb::HashDb> g_tru;
std::unique_ptr<sf::hashdb::HashDb> g_malImp;
std::unique_ptr<sf::hashdb::HashDb> g_malMd5;
std::unique_ptr<sf::hashdb::HashDb> g_malSha1;

// ===========================================================================
//  ★★ 病毒库签名校验（四步线第 2 步）—— 挂在 LoadCloudLocked 之前
// ===========================================================================
//  为什么需要它：云库此前是**裸文件**。谁能往 cloud\ 目录里写，谁就决定本机
//  的判定结果 —— 把一条哈希从恶意库里删掉，本机立刻对那个样本视而不见，
//  而界面上写着"病毒库正常，N 条"。**没有任何运行时症状**。签名把库内容与
//  我们签发的私钥绑死（验签实现见 libsig.h）。
//
// ---------------------------------------------------------------------------
//  ★ 这里刻意做了三件"反直觉"的事，每一件都对应一种真实故障形态
// ---------------------------------------------------------------------------
//  ① **默认拒绝，不是默认放行**（fail-closed）。
//     "没有签名就放行"看似平滑，实际会让"忘了带签名的下发"与"一切正常"
//     长得一模一样。默认拒绝的代价是**立刻可见**的：库装不上、hashstat 明写
//     原因、日志里有明确一行。
//
//  ② **调试开关不放在 cloud 目录里**。
//     若开关是 cloud\allow-unsigned 这种文件，那么"能改库的人"顺手就能关掉
//     验签 —— 整套机制形同虚设。改成**服务进程的环境变量**：给服务设环境变量
//     需要管理员权限（服务由 SCM 启动，环境来自 HKLM），而具备那个权限的人
//     本来就已经拿到了这台机器。
//
//  ③ **每次跳过都记账 + 在 hashstat 里明写 BYPASSED**。
//     "绕过安全机制的那条路径"必须是一个**看得见的事实**，不能是安静的
//     特殊分支。否则某天在一台机器上排查"为什么库里有这条却报不出"，
//     会从"库错了"查到"签名错了"再查到"验签被关了"，白绕一大圈。
struct LibSigState {
    bool        checked  = false;  // 是否走过校验（库文件不存在时为 false）
    bool        ok       = false;  // 验签通过
    bool        bypassed = false;  // 因调试开关跳过（**必须显眼**）
    bool        loaded   = false;  // 最终是否成功装载
    bool        hashOk   = false;  // 是否算出了库文件 SHA-256
    std::string result;            // libsig::ResultText 的结论
    std::string detail;            // 一句话细节（出错时能直接定位）
    std::string sha256;            // 实际算出的库哈希（便于人工与云端比对）
};
constexpr int kLibCount = 5;
LibSigState g_sigState[kLibCount];

// 调试开关：**只认恰好 "1"**。
// 不认 "true"/"yes"/"on" —— 那些"我以为设了但其实没生效"的形态会让调试者
// 以为验签已经关掉，从而把"签名问题"排到晚得多的地方。
// 而如果反过来宽容接受多种写法，则会出现"某个第三方脚本设了 yes，某台机器
// 悄悄关着验签"这种更难发现的状态。只认一个值，然后把当前状态显示出来。
bool SigBypassEnabled() {
    static const bool v = [] {
        wchar_t buf[16] = {0};
        const DWORD n = GetEnvironmentVariableW(L"SFH_ALLOW_UNSIGNED_LIBS", buf,
                                                (DWORD)(sizeof(buf) / sizeof(buf[0])));
        if (n == 0 || n >= sizeof(buf) / sizeof(buf[0])) return false;
        return buf[0] == L'1' && buf[1] == L'\0';
    }();
    return v;
}

// ===========================================================================
//  ★ SQL 护栏与库结构 SQL 在 sfschema.h / sfschema.cpp
// ===========================================================================
//  刻意不在本文件里实现：那两样东西"写错了不会当场报错"（建表 SQL 只有
//  真跑才知道对不对；护栏失灵等于该拦的没拦，也不报错），所以必须能被
//  验证程序单独链接测试。放在本文件里就得把 common.h / scanner.h / 管道
//  那一整坨拖进测试程序 —— 抽取的完整理由见 sfschema.h 文件头。

// ===========================================================================
//  建表（幂等）+ 架构版本
// ===========================================================================
//  ★ 为什么版本号的写回要单独做「先查后插」而不是塞进建表 SQL：
//    建表 SQL 每次服务启动都会跑。只要里面有 INSERT，第二次启动就撞
//    schema_version 的主键重复 → 建表整体失败 → 库再也建不起来。
//    （这是写本轮代码时当场抓到的坑：SQL 看着完全合理，第二次启动才炸。）
bool EnsureSchema() {
    std::vector<sf::sfdb::ResultSet> outs;
    if (!g_db.Exec(sf::sfschema::kSql, outs)) {
        g_dbErr = "建表失败：" + g_db.LastError();
        sf::LogDbg("[sfdb] " + g_dbErr);
        return false;
    }

    // 版本号：没有就写，有就核对
    sf::sfdb::ResultSet rs;
    std::string cur;
    bool haveVer = g_db.QueryText(
        "SELECT v FROM schema_version WHERE k = 'schema'", cur) && !cur.empty();

    if (!haveVer) {
        std::string ins = std::string("INSERT INTO schema_version (k, v) VALUES ('schema', '") +
                          sf::sfschema::kVersion + "')";
        if (!g_db.ExecOne(ins, rs)) {
            g_dbErr = "写架构版本失败：" + g_db.LastError();
            sf::LogDbg("[sfdb] " + g_dbErr);
            return false;
        }
        sf::LogDbg(std::string("[sfdb] 初始化架构版本 schema=") + sf::sfschema::kVersion);
    } else if (cur != sf::sfschema::kVersion) {
        // ★ 只报不改。往老库上盲目跑迁移比不迁移更危险 ——
        //   迁移必须先看清楚老库实际形态（列是否已在、数据量多大）再决定怎么做。
        sf::LogDbg("[sfdb] ！！架构版本不一致：库=" + cur + " 程序=" +
                   sf::sfschema::kVersion + "。需要人工确认迁移方案后再动，本程序不自动迁移。");
    }

    // ★★ 列探针：把"库缺列"从静默故障变成启动即报错（理由见 sfschema.h）。
    //    放在版本检查**之后**：新库（刚建完）也照样探一次，顺带证明建表 SQL
    //    与探针 SQL 没写岔。失败一律让 sfdb 进入"不可用"状态 ——
    //    结构不对的库上，样本写入必然全失败，与其让 writeFail 一路涨
    //    装成"库坏了"，不如在启动那一刻就说清楚是**库结构比程序老**。
    {
        sf::sfdb::ResultSet rs;
        if (!g_db.ExecOne(sf::sfschema::kProbeSql, rs)) {
            g_dbErr = std::string("库结构与程序不符（很可能是旧架构的库，缺少新列）：") +
                      g_db.LastError() + " —— 需要人工确认迁移方案，本程序不自动迁移";
            sf::LogDbg("[sfdb] ！！" + g_dbErr);
            return false;
        }
    }
    return true;
}

// ===========================================================================
//  云库加载
// ===========================================================================
//  ★ 库不存在是**正常状态**（新装机还没下发过库），只记一行日志，不算故障。
//    但"文件在、却打不开"必须大声报出来 —— 那说明库被写坏了或下发了错的库，
//    静默跳过会让防护力度无声下降，这是最不能接受的失败形态。
void LoadCloudLocked() {
    g_mal.reset();
    g_tru.reset();
    g_malImp.reset();

    // ★ 标签里必须带**键空间**（SHA-256 / imphash），不能只写"恶意/可信"。
    //   否则启动日志里三本库有两本都叫"恶意"，出问题时无法判断是哪一本
    //   装载失败 —— 而这两本库的用途、造库工具、失效后果完全不同。
    struct Item { const char* path; const char* label; };
    Item items[5] = {
        { g_malPath.c_str(),    "恶意(sha256)"  },
        { g_truPath.c_str(),    "可信(sha256)"  },
        { g_malImpPath.c_str(), "恶意(imphash)" },
        { g_malMd5Path.c_str(), "恶意(md5)"    },
        { g_malSha1Path.c_str(),"恶意(sha1)"   },
    };
    std::unique_ptr<sf::hashdb::HashDb>* slots[5] = { &g_mal, &g_tru, &g_malImp, &g_malMd5, &g_malSha1 };

    for (int i = 0; i < kLibCount; ++i) g_sigState[i] = LibSigState();

    for (int i = 0; i < kLibCount; ++i) {
        std::wstring w = Utf8ToWide(items[i].path);
        DWORD attr = GetFileAttributesW(w.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) {
            sf::LogDbg(std::string("[hashdb] ") + items[i].label + "云库尚未下发（正常）：" +
                       items[i].path);
            continue;
        }

        // ===================================================================
        //  ★★ 装载前的最后一道闸门：签名校验（四步线第 2 步）
        // ===================================================================
        //  顺序是刻意的：**先算哈希，再验签，验签不过就绝不 Open**。
        //  · 哈希无论如何都要算 —— 验签的签名对象就是它（见 libsig.h 第 ① 条）。
        //  · "先 Open 再验签"是不行的：Open 会 mmap 整个文件并建立 Bloom，
        //    那一刻库已经进入"可被查询"的状态了，只是我们还没查而已。
        //    中间任何一次查询（hashreload 与实时链是并发的）都会用到未经验证的库。
        LibSigState& ss = g_sigState[i];
        ss.checked = true;
        bool mayLoad = false;

        if (SigBypassEnabled()) {
            ss.bypassed = true;
            ss.result   = "已跳过（调试开关）";
            ss.detail   = "环境变量 SFH_ALLOW_UNSIGNED_LIBS=1 生效，本次**未校验签名**";
            mayLoad     = true;
            sf::LogDbg(std::string("[libsig] ！！") + items[i].label +
                       "云库**跳过签名校验**（SFH_ALLOW_UNSIGNED_LIBS=1）—— 仅供调试，"
                       "生产环境必须去掉该环境变量。路径=" + items[i].path);
        } else {
            std::string sha;
            if (!sf::pehash::FileSha256(items[i].path, sha) || sha.empty()) {
                ss.result = "无法计算库文件哈希";
                ss.detail = "读不到库文件（不存在 / 无权限 / 被占用）—— 拒绝装载";
                sf::LogDbg(std::string("[libsig] ！！") + items[i].label +
                           "云库无法读取，拒绝装载：路径=" + items[i].path);
            } else {
                ss.sha256 = sha;
                std::string detail;
                const sf::libsig::Result r =
                    sf::libsig::VerifyLibFile(items[i].path,
                                              sf::libsig::SigPathFor(items[i].path),
                                              sha, detail);
                ss.result = sf::libsig::ResultText(r);
                ss.detail = detail;
                ss.hashOk = true;
                ss.ok     = (r == sf::libsig::kOk);
                mayLoad   = ss.ok;
                if (ss.ok) {
                    sf::LogDbg(std::string("[libsig] ") + items[i].label +
                               "云库签名有效：keyId=" + sf::libsig::BuiltinKeyIdsText() +
                               " sha256=" + sha.substr(0, 16) +
                               "… 签名文件=" + sf::libsig::SigPathFor(items[i].path));
                } else {
                    // ★ 拒装必须**大声**：这条日志的意思是"本机的判定能力因为
                    //   这个库被拒而下降了"。静默跳过会让防护力度无声下降，
                    //   是本项目最不能接受的失败形态。
                    sf::LogDbg(std::string("[libsig] ！！拒绝装载 ") + items[i].label +
                               "云库：" + detail + " 路径=" + items[i].path);
                    sf::LogDbg(std::string("[libsig]    处置建议：") +
                               sf::libsig::ResultHint(r));
                }
            }
        }

        if (!mayLoad) continue;   // ← fail-closed：库留在磁盘上，但不进入可用状态

        std::unique_ptr<sf::hashdb::HashDb> h(new sf::hashdb::HashDb());
        if (!h->Open(items[i].path)) {
            // ★ 库在但打不开 = 必须留痕的异常
            sf::LogDbg(std::string("[hashdb] ！！") + items[i].label +
                       "云库存在但无法打开：" + h->LastError() + " 路径=" + items[i].path);
            continue;
        }
        sf::hashdb::Stats st = h->GetStats();
        sf::LogDbg(std::string("[hashdb] ") + items[i].label + "云库已装载：" +
                   std::to_string(st.count) + " 条，" + std::to_string(st.fileBytes) +
                   " 字节，tag=" + st.tag);
        *slots[i] = std::move(h);
        ss.loaded = true;
    }
}

}  // namespace

// ===========================================================================
//  命令实现（与上面的状态/工具分开写，便于对照命令清单阅读）
// ===========================================================================
namespace {

std::string ValueToJson(const sf::sfdb::Value& v) {
    if (v.type == sf::sfdb::Value::Null) return "null";
    if (v.type == sf::sfdb::Value::Int)  return std::to_string(v.i);
    return sf::JsonString(v.ToText());
}

// ---------------------------------------------------------------- dbstat
bool CmdDbStat(HANDLE h, const std::string& /*req*/) {
    sf::sfdb::Stats s = g_dbReady ? g_db.GetStats() : sf::sfdb::Stats();

    std::string j = "{\"cmd\":\"dbstat\",\"ok\":true,\"data\":{";
    j += "\"ready\":"     + std::string(g_dbReady ? "true" : "false");
    j += ",\"path\":"     + sf::JsonString(g_dbPath);
    j += ",\"cloudDir\":" + sf::JsonString(g_cloudDir);
    j += ",\"engine\":\"sfdb-log-structured\"";
    j += ",\"fileBytes\":"+ std::to_string(s.fileBytes);
    j += ",\"frames\":"   + std::to_string(s.frames);
    j += ",\"appends\":"  + std::to_string(s.appends);
    j += ",\"compacts\":" + std::to_string(s.compacts);
    j += ",\"recovered\":"+ std::to_string(s.recovered);
    j += ",\"dirty\":"    + std::string(s.dirty ? "true" : "false");
    if (!g_dbErr.empty()) j += ",\"err\":" + sf::JsonString(g_dbErr);

    j += ",\"tables\":[";
    for (size_t i = 0; i < s.tables.size(); ++i) {
        const sf::sfdb::TableStat& t = s.tables[i];
        if (i) j += ',';
        j += "{\"name\":"    + sf::JsonString(t.name);
        j += ",\"rows\":"    + std::to_string(t.rows);
        j += ",\"live\":"    + std::to_string(t.live);
        j += ",\"dead\":"    + std::to_string(t.dead);
        j += ",\"columns\":" + std::to_string(t.columns);
        j += ",\"indexes\":" + std::to_string(t.indexes);
        j += ",\"hasPk\":"   + std::string(t.hasPk ? "true" : "false");
        j += '}';
    }
    j += "]}}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------- sql
bool CmdSql(HANDLE h, const std::string& req) {
    const std::string sql = sf::JsonGetString(req, "sql");
    const bool writeOk  = sf::JsonGetInt(req, "write")  != 0;
    const bool unsafeOk = sf::JsonGetInt(req, "unsafe") != 0;
    const bool multiOk  = sf::JsonGetInt(req, "multi")  != 0;
    int maxRows = sf::JsonGetInt(req, "maxRows");

    auto fail = [&](const std::string& why) {
        sf::WriteFramed(h, "{\"cmd\":\"sql\",\"ok\":false,\"err\":" + sf::JsonString(why) + "}");
        return true;
    };

    if (!g_dbReady) return fail("库未打开：" + g_dbErr);
    if (sql.empty()) return fail("缺少 sql 参数");

    sf::sfschema::SqlShape sh;
    std::string serr;
    if (!sf::sfschema::ScanSqlShape(sql, sh, serr)) return fail(serr);

    if (sh.stmts > 1 && !multiOk) {
        return fail("检测到 " + std::to_string(sh.stmts) +
                    " 条语句，默认只允许单条（要一次执行多条请加 multi:1）");
    }

    // 不认识的关键字：如实拒掉。**不要**让它走"不可逆操作需要 unsafe:1"
    // 那条提示 —— 把 "SELEKT" 报成"这是 DELETE/DROP"会把人往完全错的方向带。
    const std::string& kw = sh.firstKw;
    const sf::sfschema::Tier tier = sf::sfschema::TierOf(kw);
    if (tier == sf::sfschema::kTierUnknown)
        return fail("无法识别的语句，只支持 SELECT / INSERT / UPDATE / DELETE / "
                    "CREATE / DROP；实际首关键字=" + kw);

    // 三级护栏：默认只读 → write:1 → unsafe:1（不可逆）
    if (kw != "SELECT") {
        int need = (int)tier;                                   // 1 或 2
        int have = unsafeOk ? 2 : (writeOk ? 1 : 0);
        if (have < need) {
            const char* hint = (need >= 2)
                ? "这是不可逆操作（DELETE / DROP），需要 unsafe:1"
                : "这是写操作，需要 write:1";
            return fail("语句 " + kw + " 被只读护栏拒绝：" + hint);
        }
    }
    // 无 WHERE 的 UPDATE 等价于"改全表"，把它抬到不可逆一级。
    // 依据：本项目对「批量改动」的一贯立场 —— 影响面不可预知时必须显式确认。
    if (kw == "UPDATE" && !sh.hasWhere && !unsafeOk) {
        return fail("UPDATE 没有 WHERE（等于改全表），需要 unsafe:1 显式确认");
    }

    if (maxRows <= 0 || maxRows > 500) maxRows = 50;

    std::vector<sf::sfdb::ResultSet> outs;
    if (!g_db.Exec(sql, outs)) return fail(g_db.LastError());

    std::string j = "{\"cmd\":\"sql\",\"ok\":true,\"data\":{\"count\":" +
                    std::to_string(outs.size());
    j += ",\"results\":[";
    for (size_t r = 0; r < outs.size(); ++r) {
        const sf::sfdb::ResultSet& rs = outs[r];
        if (r) j += ',';
        j += "{\"isQuery\":" + std::string(rs.isQuery ? "true" : "false");
        if (!rs.statement.empty()) j += ",\"stmt\":" + sf::JsonString(rs.statement);
        j += ",\"affected\":" + std::to_string(rs.affected);
        if (rs.isQuery) {
            j += ",\"columns\":[";
            for (size_t c = 0; c < rs.columns.size(); ++c) {
                if (c) j += ',';
                j += sf::JsonString(rs.columns[c]);
            }
            j += "]";
            size_t shown = rs.rows.size();
            bool truncated = false;
            if (shown > (size_t)maxRows) { shown = (size_t)maxRows; truncated = true; }
            j += ",\"rowCount\":" + std::to_string(rs.rows.size());
            j += ",\"truncated\":" + std::string(truncated ? "true" : "false");
            j += ",\"rows\":[";
            for (size_t i = 0; i < shown; ++i) {
                if (i) j += ',';
                j += '[';
                for (size_t c = 0; c < rs.rows[i].size(); ++c) {
                    if (c) j += ',';
                    j += ValueToJson(rs.rows[i][c]);
                }
                j += ']';
            }
            j += "]";
        }
        j += '}';
    }
    j += "]}}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------- dbcompact
bool CmdDbCompact(HANDLE h, const std::string& /*req*/) {
    if (!g_dbReady)
        return (sf::WriteFramed(h, "{\"cmd\":\"dbcompact\",\"ok\":false,\"err\":\"库未打开\"}"), true);

    sf::sfdb::Stats before = g_db.GetStats();
    long long b0 = before.fileBytes, f0 = before.frames;

    if (!g_db.Compact())
        return (sf::WriteFramed(h, "{\"cmd\":\"dbcompact\",\"ok\":false,\"err\":" +
                                   sf::JsonString(g_db.LastError()) + "}"), true);

    sf::sfdb::Stats after = g_db.GetStats();
    std::string j = "{\"cmd\":\"dbcompact\",\"ok\":true,\"data\":{";
    j += "\"bytesBefore\":" + std::to_string(b0);
    j += ",\"bytesAfter\":"  + std::to_string(after.fileBytes);
    j += ",\"framesBefore\":"+ std::to_string(f0);
    j += ",\"framesAfter\":" + std::to_string(after.frames);
    j += "}}";
    sf::WriteFramed(h, j);
    sf::LogDbg("[sfdb] 手动压缩：" + std::to_string(b0) + " → " +
               std::to_string(after.fileBytes) + " 字节");
    return true;
}

// ---------------------------------------------------------------- hashstat
// Unix 秒 → "YYYY-MM-DD HH:MM:SS UTC"（库的"发布日期"给人看的形式）
//   · <= 0 → "未标注"（与"1970-01-01"区分开：后者看起来像真日期，会误导）
//   · ★ 一律按 **UTC** 解释。库的构造时间本来就是 UTC（写库时用 ::time），
//     若这里换成本地时间，同一个库在不同时区会显示成不同日期，
//     而云端下发/本地读取可能跨时区 —— 那会让"发布日期"变成一个不可复现的数字。
//   · gmtime_s 而不是 gmtime：后者返回静态缓冲，在多线程命令处理里会被踩。
static std::string FormatUnixUtc(long long unixSec) {
    if (unixSec <= 0) return std::string("未标注");
    const time_t t = (time_t)unixSec;
    struct tm tmv;
    if (gmtime_s(&tmv, &t) != 0) return std::string();
    char buf[32];
    if (strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tmv) == 0) return std::string();
    return std::string(buf) + " UTC";
}

std::string OneHashStat(const char* label, const std::string& path,
                        const sf::hashdb::HashDb* db, int sigIdx) {
    static const LibSigState kNoSig;   // 越界时的兜底（正常情况下不会用到）
    const LibSigState& ss = (sigIdx >= 0 && sigIdx < kLibCount) ? g_sigState[sigIdx] : kNoSig;

    std::string j = "{\"label\":" + sf::JsonString(label);
    j += ",\"path\":" + sf::JsonString(path);

    // ---- ★ 签名校验状态：**两个分支写同一组字段** ----
    //  理由同下面 libVersion 那条注释：缺字段时前端读到 undefined，
    //  界面上只表现为一块空白 —— 看起来不像 bug，所以更难发现。
    //  而且这一组的用途恰恰是"回答库为什么没装载"，缺了它就只能去 grep 日志。
    j += ",\"sigChecked\":"  + std::string(ss.checked ? "true" : "false");
    j += ",\"sigOk\":"       + std::string(ss.ok ? "true" : "false");
    j += ",\"sigBypassed\":" + std::string(ss.bypassed ? "true" : "false");
    j += ",\"sigResult\":"   + sf::JsonString(ss.result);
    j += ",\"sigDetail\":"   + sf::JsonString(ss.detail);
    j += ",\"libSha256\":"   + sf::JsonString(ss.sha256);
    j += ",\"loaded\":"      + std::string(ss.loaded ? "true" : "false");

    if (!db || !db->IsOpen()) {
        j += ",\"open\":false";
        j += ",\"err\":" + sf::JsonString(db ? db->LastError() : std::string("未下发"));
        // ★ 与 open:true 分支保持**同一组字段**。缺字段时前端读到 undefined，
        //   界面上只表现为一块空白 —— 看起来不像 bug，所以更难发现。
        //   这里给"没有库"的诚实表达：版本 0 / 文本空串（**不是** "未标注"，
        //   那表示"有库但没写版本"，是另一回事）。
        j += ",\"libVersion\":0";
        j += ",\"libVersionText\":\"\"";
        j += ",\"builtAtText\":\"\"";
        j += '}';
        return j;
    }
    sf::hashdb::Stats s = db->GetStats();
    j += ",\"open\":true";
    j += ",\"kind\":"       + std::to_string(s.kind);
    j += ",\"tag\":"        + sf::JsonString(s.tag);
    j += ",\"count\":"      + std::to_string(s.count);
    j += ",\"fileBytes\":"  + std::to_string(s.fileBytes);
    j += ",\"bloomBits\":"  + std::to_string(s.bloomBits);
    j += ",\"bloomK\":"     + std::to_string(s.bloomK);
    j += ",\"builtAtUnix\":"+ std::to_string(s.builtAtUnix);
    j += ",\"builtAtText\":" + sf::JsonString(FormatUnixUtc(s.builtAtUnix));
    // ★ 内容版本号与**格式**版本号是两回事（见 hashdb.h 文件头）：
    //   libVersionText 是给人看的（"1.2" / "未标注"），供 GUI 显示与将来判断"要不要更新"。
    j += ",\"libVersion\":"     + std::to_string(s.contentVersion);
    j += ",\"libVersionText\":" + sf::JsonString(s.contentVersionText);
    j += ",\"queries\":"    + std::to_string(s.queries);
    j += ",\"bloomMiss\":"  + std::to_string(s.bloomMiss);
    j += ",\"hits\":"       + std::to_string(s.hits);
    j += '}';
    return j;
}

// ★★ 三本库状态的**唯一**序列化入口。
//
// 在它出现之前，"libs" 数组的拼装被复制了三份（CmdHashStat、CmdHashReload、
// 以及新增的 InstallCloudLibs）。三份内容必须逐字一致 —— 而消费者（GUI /
// libstat）是**按字段名取值**的，少一处字段或错一个逗号的表现是前端某块空白，
// 看起来不像 bug，所以更难发现。
//
// ⚠️ 调用方**必须已持有 g_hlock**（本函数读 g_mal / g_tru / g_malImp）。
std::string LibsJsonLocked() {
    std::string j = "[";
    j += OneHashStat("恶意库(SHA-256)", g_malPath,    g_mal.get(),    0);
    j += ',';
    j += OneHashStat("可信库(SHA-256)", g_truPath,    g_tru.get(),    1);
    j += ',';
    j += OneHashStat("恶意库(imphash)", g_malImpPath, g_malImp.get(), 2);
    j += ',';
    j += OneHashStat("恶意库(MD5)", g_malMd5Path, g_malMd5.get(), 3);
    j += ',';
    j += OneHashStat("恶意库(SHA-1)", g_malSha1Path, g_malSha1.get(), 4);
    j += "]";
    return j;
}

bool CmdHashStat(HANDLE h, const std::string& /*req*/) {
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    std::string j = "{\"cmd\":\"hashstat\",\"ok\":true,\"data\":{";
    j += "\"subsystemReady\":" +
         std::string(sf::hashshare::IsHashSubsystemReady() ? "true" : "false");

    // ---- ★ 验签政策：这是 hashstat 里最该被一眼看到的一行 ----
    //  "这台机器现在到底在不在验签？"必须是**可查的**，而不是只能靠"我没设过
    //  那个环境变量"来推断。BYPASSED 写全大写是刻意的：它在任何日志/截图里
    //  都会跳出来。
    j += ",\"sigPolicy\":" + sf::JsonString(SigBypassEnabled() ? "BYPASSED" : "enforced");
    j += ",\"sigKeyCount\":" + std::to_string(sf::libsig::BuiltinKeyCount());
    j += ",\"sigKeys\":" + sf::JsonString(sf::libsig::BuiltinKeyIdsText());
    // 验签计数：把"被拒了几次"与"通过几次"分开报。
    // 一个 failed 数字分不清"第一次部署还没带签名"和"有东西一直在改库"。
    {
        const sf::libsig::Stats ls = sf::libsig::GetStats();
        j += ",\"sigStats\":{";
        j += "\"ok\":"           + std::to_string(ls.ok);
        j += ",\"noKey\":"       + std::to_string(ls.noKey);
        j += ",\"missing\":"     + std::to_string(ls.sigMissing);
        j += ",\"malformed\":"   + std::to_string(ls.sigMalformed);
        j += ",\"unknownKey\":"  + std::to_string(ls.unknownKey);
        j += ",\"hashMismatch\":"+ std::to_string(ls.hashMismatch);
        j += ",\"badSig\":"      + std::to_string(ls.badSig);
        j += ",\"ioFail\":"      + std::to_string(ls.ioFail);
        j += '}';
    }

    j += ",\"lookup\":{";
    sf::hashshare::LookupStats ls = sf::hashshare::GetLookupStats();
    j += "\"queries\":"     + std::to_string(ls.queries);
    j += ",\"hits\":"       + std::to_string(ls.hits);
    j += ",\"skippedNoDb\":" + std::to_string(ls.skippedNoDb);
    j += "},\"libs\":" + LibsJsonLocked() + "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------- hashq
bool CmdHashQ(HANDLE h, const std::string& req) {
    auto fail = [&](const std::string& why) {
        sf::WriteFramed(h, "{\"cmd\":\"hashq\",\"ok\":false,\"err\":" + sf::JsonString(why) + "}");
        return true;
    };

    std::string hex  = sf::JsonGetString(req, "hash");
    std::string path = sf::JsonGetString(req, "path");
    std::string algo = sf::JsonGetString(req, "algo");
    if (algo.empty()) algo = "sha256";
    if (algo != "sha256" && algo != "imphash" && algo != "md5" && algo != "sha1")
        return fail("algo 只能是 sha256 / imphash / md5 / sha1（收到：" + algo + "）");

    if (hex.empty() && path.empty()) return fail("需要 hash=<64 位十六进制> 或 path=<文件路径>");

    if (!hex.empty()) {
        // 统一成小写，避免大小写不同导致"明明在库里却查不到"
        for (size_t i = 0; i < hex.size(); ++i)
            hex[i] = (char)std::tolower((unsigned char)hex[i]);
        unsigned char tmp[32];
        if (!sf::hashdb::HashDb::HexToHash(hex, tmp))
            return fail("hash 参数必须是 64 个十六进制字符"
                        "（md5/sha1/imphash 请先经对应 Key 函数派生）");
    } else if (algo == "sha256") {
        // ★ 走 pehash::FileSha256（*W 文件 API），**不复用 common.cpp 的
        //   Sha256File** —— 后者用 std::ifstream(std::string)，中文路径下会
        //   静默算出错误的哈希（算不出内容 → 返回空串或错值，且不报错）。
        if (!sf::pehash::FileSha256(path, hex))
            return fail("无法计算文件哈希（文件不存在或无权限）：" + path);
    } else if (algo == "imphash") {
        // imphash 三态，必须分开报 —— 三者的处置完全不同：
        //   "不是 PE" = 正常（命令问了个非 PE 文件）；
        //   "无导入表" = 可能是加壳（**刻意不给结论**，见 pehash.cpp）；
        //   "打不开/超上限" = 环境问题。
        std::string impHex;
        if (!sf::pehash::Imphash(path, impHex)) {
            // 再问一次原因：只有"能算出文件哈希但算不出 imphash"才说明是
            // PE 结构问题，否则就是根本读不到文件。
            std::string probeSha;
            if (!sf::pehash::FileSha256(path, probeSha))
                return fail("无法读取文件（不存在 / 无权限 / 超 " +
                            std::to_string(sf::pehash::kImphashMaxBytes / (1024 * 1024)) +
                            "MB 上限）：" + path);
            return fail("无法得到 imphash（非 PE、无导入表或加壳抹掉了导入表）：" + path);
        }
        hex = sf::pehash::ImphashKey(impHex);
        if (hex.empty()) return fail("imphash 派生查询键失败（imphash=" + impHex + "）");
    } else if (algo == "md5") {
        std::string md5Hex;
        if (!sf::pehash::FileMd5(path, md5Hex))
            return fail("无法计算文件 MD5（文件不存在或无权限）：" + path);
        hex = sf::pehash::Md5Key(md5Hex);
        if (hex.empty()) return fail("MD5 派生查询键失败（md5=" + md5Hex + "）");
    } else if (algo == "sha1") {
        std::string sha1Hex;
        if (!sf::pehash::FileSha1(path, sha1Hex))
            return fail("无法计算文件 SHA-1（文件不存在或无权限）：" + path);
        hex = sf::pehash::Sha1Key(sha1Hex);
        if (hex.empty()) return fail("SHA-1 派生查询键失败（sha1=" + sha1Hex + "）");
    }

    bool malHit = false, truHit = false, localHit = false;
    {
        std::shared_lock<std::shared_mutex> lk(g_hlock);
        // ★ 按键空间选库。**不能同时查两本** —— 那等于让两个键空间混用，
        //   一次误命中会被当成"真命中"，且事后无法判断是哪本库给的结论。
        //   （只有 SHA-256 才有可信库；md5/sha1/imphash 均只查恶意库，
        //    理由同「可信哈希不得用于放行」那条纪律。）
        if (algo == "imphash") {
            if (g_malImp && g_malImp->IsOpen()) malHit = g_malImp->ContainsHash(hex);
        } else if (algo == "md5") {
            if (g_malMd5 && g_malMd5->IsOpen()) malHit = g_malMd5->ContainsHash(hex);
        } else if (algo == "sha1") {
            if (g_malSha1 && g_malSha1->IsOpen()) malHit = g_malSha1->ContainsHash(hex);
        } else {
            if (g_mal && g_mal->IsOpen()) malHit = g_mal->ContainsHash(hex);
            if (g_tru && g_tru->IsOpen()) truHit = g_tru->ContainsHash(hex);
            // ★ 本地恶意库叠加（仅 SHA-256；独立于云库）
            if (!malHit && sf::hashshare::HitLocalMaliciousSha256(hex)) { malHit = true; localHit = true; }
        }
    }

    // 结论优先级：恶意 > 可信 > 未知。
    // （同一个哈希同时出现在两本库里属于库构造事故，如实把两个都报出来，
    //   不要把哪个"看起来更好"当结论 —— 那是拿用户的机器赌库没错。）
    const char* verdict = malHit ? "malicious" : (truHit ? "trusted" : "unknown");

    std::string j = "{\"cmd\":\"hashq\",\"ok\":true,\"data\":{";
    j += "\"algo\":"     + sf::JsonString(algo);
    j += ",\"hash\":"    + sf::JsonString(hex);   // 实际用于查询的键（imphash 时是派生键）
    j += ",\"found\":"   + std::string((malHit || truHit) ? "true" : "false");
    j += ",\"malicious\":"+ std::string(malHit ? "true" : "false");
    j += ",\"trusted\":"  + std::string(truHit ? "true" : "false");
    j += ",\"local\":"    + std::string(localHit ? "true" : "false");
    j += ",\"verdict\":"  + sf::JsonString(verdict);
    if (!path.empty()) j += ",\"path\":" + sf::JsonString(path);
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------- hashchain
// ★ 这条命令存在的唯一目的：回答「病毒库到底有没有在工作」。
//   没有它，唯一能看到的证据是"日志里没有命中记录" —— 而那个现象
//   既能是"没有恶意文件"，也能是"库根本没装载"、也能是"实时链压根没查"。
//   三种成因的修法完全不同，必须能从一条命令里分开读出来。
bool CmdHashChain(HANDLE h, const std::string& req) {
    const int reset = sf::JsonGetInt(req, "reset");

    sf::pehash::Stats ps = sf::pehash::GetStats();
    sf::hashshare::LookupStats ls = sf::hashshare::GetLookupStats();

    bool malOpen = false, truOpen = false, impOpen = false, md5Open = false, sha1Open = false;
    long long malCount = 0, truCount = 0, impCount = 0, md5Count = 0, sha1Count = 0;
    {
        std::shared_lock<std::shared_mutex> lk(g_hlock);
        if (g_mal && g_mal->IsOpen())    { malOpen = true; malCount = g_mal->Count(); }
        if (g_tru && g_tru->IsOpen())    { truOpen = true; truCount = g_tru->Count(); }
        if (g_malImp && g_malImp->IsOpen()) { impOpen = true; impCount = g_malImp->Count(); }
        if (g_malMd5 && g_malMd5->IsOpen()) { md5Open = true; md5Count = g_malMd5->Count(); }
        if (g_malSha1 && g_malSha1->IsOpen()) { sha1Open = true; sha1Count = g_malSha1->Count(); }
    }

    std::string j = "{\"cmd\":\"hashchain\",\"ok\":true,\"data\":{";
    j += "\"subsystemReady\":" + std::string(sf::hashshare::IsHashSubsystemReady() ? "true" : "false");
    j += ",\"anyMaliciousLoaded\":" +
         std::string(sf::hashshare::AnyMaliciousLoaded() ? "true" : "false");

    // 库装载情况（"库到底在不在"）
    j += ",\"libs\":{";
    j += "\"malSha\":{\"open\":"  + std::string(malOpen ? "true" : "false") +
         ",\"count\":" + std::to_string(malCount) + "}";
    j += ",\"truSha\":{\"open\":"  + std::string(truOpen ? "true" : "false") +
         ",\"count\":" + std::to_string(truCount) + "}";
    j += ",\"malImp\":{\"open\":"  + std::string(impOpen ? "true" : "false") +
         ",\"count\":" + std::to_string(impCount) + "}";
    j += ",\"malMd5\":{\"open\":"  + std::string(md5Open ? "true" : "false") +
         ",\"count\":" + std::to_string(md5Count) + "}";
    j += ",\"malSha1\":{\"open\":" + std::string(sha1Open ? "true" : "false") +
         ",\"count\":" + std::to_string(sha1Count) + "}";
    j += "}";

    // ---- ★ 签名校验（四步线第 2 步）----
    //  刻意把它紧挨着上面那段"库在不在"：库里 `open:false` 的头号原因就是
    //  **被验签拒了**。分成两处写的话，排查时会先看到"库没装载"，
    //  然后跑去别处找原因，而答案其实在同一个回包里。
    j += ",\"sig\":{\"policy\":" +
         sf::JsonString(SigBypassEnabled() ? "BYPASSED" : "enforced");
    j += ",\"keys\":" + sf::JsonString(sf::libsig::BuiltinKeyIdsText());
    j += ",\"libs\":[";
    for (int i = 0; i < kLibCount; ++i) {
        if (i) j += ',';
        j += "{\"result\":"   + sf::JsonString(g_sigState[i].result);
        j += ",\"ok\":"       + std::string(g_sigState[i].ok ? "true" : "false");
        j += ",\"bypassed\":" + std::string(g_sigState[i].bypassed ? "true" : "false");
        j += ",\"loaded\":"   + std::string(g_sigState[i].loaded ? "true" : "false");
        j += '}';
    }
    j += "]}";

    // 判定链查询统计（"库有没有被问过"）
    j += ",\"lookup\":{\"queries\":"     + std::to_string(ls.queries);
    j += ",\"hits\":"                    + std::to_string(ls.hits);
    j += ",\"skippedNoDb\":"             + std::to_string(ls.skippedNoDb) + "}";

    // 哈希计算统计（"问之前算到了什么"）—— 四类成因分开报
    j += ",\"hash\":{";
    j += "\"shaCompute\":"  + std::to_string(ps.shaCompute);
    j += ",\"shaCacheHit\":"+ std::to_string(ps.shaCacheHit);
    j += ",\"shaTooBig\":"  + std::to_string(ps.shaTooBig);
    j += ",\"shaFail\":"    + std::to_string(ps.shaFail);
    j += ",\"impCompute\":" + std::to_string(ps.impCompute);
    j += ",\"impCacheHit\":"+ std::to_string(ps.impCacheHit);
    j += ",\"impNotPe\":"   + std::to_string(ps.impNotPe);
    j += ",\"impFail\":"    + std::to_string(ps.impFail);
    j += ",\"cacheEvicted\":"+ std::to_string(ps.cacheEvicted);
    j += ",\"maxBytes\":{\"sha\":" + std::to_string(sf::pehash::kShaMaxBytes) +
         ",\"imphash\":" + std::to_string(sf::pehash::kImphashMaxBytes) + "}";
    // ★★ 这里原本是 `j += "}}"` —— 但它只该关掉 hash 这一个对象。
    //   多出来的那个 `}` 让整段输出变成**尾部多一个右花括号的非法 JSON**。
    //
    //   为什么能潜伏这么久：**全工程没有任何一处消费 hashchain 的输出**
    //   （已逐类 grep 过 .ps1 / .py / .js / .sh，零引用），于是没有任何东西
    //   会因它报错。而它偏偏是「病毒库到底有没有在工作」的**唯一判据** ——
    //   等真需要它的那一天（线上排查）才发现它给不出可解析的结果，
    //   那是最坏的时机。所以顺手修掉，并在验收脚本里把 hashchain 也纳入解析校验。
    j += "}";       // ← 只关 hash

    if (reset != 0) {
        sf::pehash::ResetStats();
        sf::hashshare::ResetLookupStats();
        j += ",\"reset\":true";
    }
    j += "}}";      // ← 关 data + 根
    sf::WriteFramed(h, j);
    return true;
}

// ---------------------------------------------------------------- hashreload
bool CmdHashReload(HANDLE h, const std::string& /*req*/) {
    {
        std::unique_lock<std::shared_mutex> lk(g_hlock);
        LoadCloudLocked();
    }
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    std::string j = "{\"cmd\":\"hashreload\",\"ok\":true,\"data\":{";
    // ★ 重载后必须把验签结论一并回给调用方 —— 这是"刚下发完新库"的那一刻，
    //   也恰恰是最该知道"这批库到底验过没有"的时刻。
    j += "\"sigPolicy\":" + sf::JsonString(SigBypassEnabled() ? "BYPASSED" : "enforced");
    j += ",\"sigKeys\":" + sf::JsonString(sf::libsig::BuiltinKeyIdsText());
    j += ",\"localMalCount\":" + std::to_string(sf::hashshare::LocalMaliciousCount());
    j += ",\"libs\":" + LibsJsonLocked() + "}}";
    sf::WriteFramed(h, j);
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "dbstat",     CmdDbStat     },
    { "sql",        CmdSql        },
    { "dbcompact",  CmdDbCompact  },
    { "hashstat",   CmdHashStat   },
    { "hashq",      CmdHashQ      },
    { "hashchain",  CmdHashChain  },
    { "hashreload", CmdHashReload },
};

// ---------------------------------------------------------------- Init / Stop
bool InitSfdb() {
    g_dataDir = DataDirW();
    g_dbPath  = JoinUtf8(g_dataDir, L"guard.sfdb");

    std::wstring cloudW = g_dataDir + L"\\cloud";
    EnsureDirW(cloudW);
    g_cloudDir = WideToUtf8(cloudW);
    g_malPath    = JoinUtf8(cloudW, L"malicious.sfh");
    g_truPath    = JoinUtf8(cloudW, L"trusted.sfh");
    g_malImpPath = JoinUtf8(cloudW, L"malicious_imp.sfh");
    g_malMd5Path = JoinUtf8(cloudW, L"malicious_md5.sfh");
    g_malSha1Path= JoinUtf8(cloudW, L"malicious_sha1.sfh");

    // ★ 本地恶意库初始化（独立于云库，高危隔离自动入库；云库更新不触达）
    InitLocalLib();

    // ★★ 云库装载**必须与 sfdb 的开关解耦**（2026-09-25 修正）。
    //    原实现把它放在 `if (g_dbReady)` 里面 —— 于是 `guard.sfdb` 一旦打不开
    //    （磁盘满 / 文件被别的进程锁住 / 权限），**云端哈希库也一起不装载**。
    //    后果是：SQL 库出问题 → 病毒库静默消失 → 只剩启发式在扛，
    //    而日志里只有一行"数据库打开失败"，**没有任何一行说病毒库没加载**。
    //    这两件事在物理上毫无关系（一个是我们自研的 SQL 引擎，一个是只读
    //    mmap 的云库），凭什么一个坏了另一个也不干活。
    {
        std::shared_lock<std::shared_mutex> lk(g_hlock);
        LoadCloudLocked();
    }
    sf::hashshare::SetHashSubsystemReady(true);
    // ★ 放在这里（而不是文件末尾）还有个顺序上的理由：实时链是**别的分体
    //   的线程**在跑，主干的启动顺序只保证 Init 之间有序，不保证"Init 全部
    //   做完才起线程"。所以让哈希库在 Init 的前半段就绪，把窗口压到最小。

    bool ok = g_db.Open(g_dbPath);
    if (!ok) {
        g_dbErr = g_db.LastError();
        sf::LogDbg("[sfdb] ！！数据库打开失败：" + g_dbErr + " 路径=" + g_dbPath);
        // ★ 刻意登记一个"空实例"而不是干脆不登记：
        //   两种做法对 GlobalDb() 的返回值是一样的（都返回 nullptr），
        //   但显式登记会让启动日志里留下**一行**「全局实例已登记：db=空」。
        //   缺这一行时，后来排查"影子模式为什么一行都没写"就必须去猜
        //   是"没登记"还是"登记了但是空"——这两种情况的修法完全不同。
        sf::mod::RegisterGlobalDb(nullptr, false);
        // ★ 刻意不 return false：见文件头「为什么 Init 恒返回 true」。
        //   命令保持注册，让 dbstat / sql 能如实报出失败原因。
        return true;
    }
    g_dbReady = true;

    // 批量建表期间关掉每帧刷盘（快 1~2 个数量级），建完手动 Sync 一次。
    g_db.SetSyncOnWrite(false);
    bool schemaOk = EnsureSchema();
    g_db.SetSyncOnWrite(true);
    g_db.Sync();
    if (!schemaOk) g_dbErr = g_db.LastError();

    // ★ 登记时机：Open + 建表**都**成功之后。
    //   ready 传 schemaOk 而不是 g_dbReady —— 见 sfdbshare.h 的字段说明：
    //   "库打开了"和"表建好了、能写"是两件事，取用方要用后者。
    sf::mod::RegisterGlobalDb(&g_db, schemaOk);

    sf::sfdb::Stats s = g_db.GetStats();
    sf::LogDbg("[sfdb] 数据库就绪：" + g_dbPath + "，" + std::to_string(s.fileBytes) +
               " 字节，" + std::to_string(s.frames) + " 帧，" +
               std::to_string(s.tables.size()) + " 张表" +
               (s.recovered > 0 ? ("；打开时截断了 " + std::to_string(s.recovered) +
                                   " 字节损坏尾部（已自愈）") : std::string()));
    return true;
}

void StopSfdb() {
    // ★ 第一步就注销：让还在跑的取用方立刻看到"库不可用"。
    //   StopAll 已保证在叫到这里之前 join 掉了全部分体线程（见 module.cpp），
    //   所以此刻理论上没有并发的写方；先注销是**防御性**的，
    //   代价为零，换来的是"即便将来有人加了个没被 join 的写线程，
    //   它拿到的也是 nullptr 而不是一个正在 Close 的库"。
    sf::mod::UnregisterGlobalDb();
    sf::hashshare::SetHashSubsystemReady(false);
    {
        std::unique_lock<std::shared_mutex> lk(g_hlock);
        g_mal.reset();
        g_tru.reset();
        g_malImp.reset();
    }
    if (g_dbReady) {
        g_db.Sync();
        g_db.Close();
        g_dbReady = false;
    }
}

}  // namespace

// ===========================================================================
//  哈希库的跨模块只读查询（契约与设计理由见 hashshare.h）
// ===========================================================================
//  ★ 这里是**唯一**把 g_mal / g_tru / g_malImp 暴露出去的路径，而且是
//    "函数式"暴露：调用方永远拿不到裸指针。理由（务必读完再改）：
//
//      `hashreload` 命令会在另一个线程里 reset 掉这三个 unique_ptr，
//      然后装载新库。如果外部持有 HashDb*，那一刻起它就是一个**悬垂指针** ——
//      而"恰好有人 reload 的同时有个进程落地"这种时序，复现概率低、
//      现象随机（崩溃 or 读到谁都不知道的数据）、日志干净。
//      把生命周期完全关在本文件内，这类 bug 在**结构上不可能发生**。
//
//  ★ 锁的用法：查询走 shared_lock（读锁之间不互斥，并发查询不会串行化），
//    reload 走 unique_lock。查询期间库实例不可能被 reset。
namespace sf {
namespace hashshare {

namespace {
std::atomic<long long> g_queries{0}, g_hits{0}, g_skipped{0};
std::atomic<bool>      g_ready{false};

// 校验 64 个十六进制字符。**不合法一律当作"没有命中"，且不计入查询数** ——
// 否则一个被写坏的调用方会把自己伪装成"查了很多次、一次都没命中"，
// 让真正的排查方向（库没装载 / 没命中）完全错位。
bool ValidKey(const std::string& k) {
    if (k.size() != 64) return false;
    for (size_t i = 0; i < k.size(); ++i) {
        const char c = k[i];
        const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (!ok) return false;
    }
    return true;
}

// ---- 文件级小工具（步3 云库安装链用）----
//   ★ 一律走 *W API：内部路径统一 UTF-8，而 GetFileAttributesA 按 ANSI 解释
//     → 中文用户名（C:\Users\银泊\…）下会静默失败，动作被跳过且日志无痕（铁律 §4）。
//     Utf8ToWide 是本文件顶部那个。
bool LibPathExistsW(const std::string& utf8) {
    return GetFileAttributesW(Utf8ToWide(utf8).c_str()) != INVALID_FILE_ATTRIBUTES;
}

// 删文件：不存在算成功。只读属性会挡住 DeleteFileW，清一次属性再试 ——
// "备份文件一定不是只读的"正是那种以后会咬人的假设。
bool LibDropW(const std::string& utf8) {
    const std::wstring w = Utf8ToWide(utf8);
    if (GetFileAttributesW(w.c_str()) == INVALID_FILE_ATTRIBUTES) return true;
    if (DeleteFileW(w.c_str())) return true;
    SetFileAttributesW(w.c_str(), FILE_ATTRIBUTE_NORMAL);
    return DeleteFileW(w.c_str()) != 0;
}

bool LibMoveOverW(const std::string& fromUtf8, const std::string& toUtf8,
                  std::string& err) {
    const std::wstring f = Utf8ToWide(fromUtf8);
    const std::wstring t = Utf8ToWide(toUtf8);
    if (MoveFileExW(f.c_str(), t.c_str(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        return true;
    err = "MoveFileEx 错误码 " + std::to_string((long long)GetLastError());
    return false;
}
}  // namespace

bool HitMalicious(int algo, const std::string& key64Hex, std::string* outWhy) {
    if (outWhy) outWhy->clear();
    if (!ValidKey(key64Hex)) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;

    std::shared_lock<std::shared_mutex> lk(g_hlock);
    const sf::hashdb::HashDb* db = nullptr;
    const char* label = nullptr;
    if (algo == kAlgoSha256) {
        // ★ 本地恶意库叠加（高危隔离自动入库；独立于云库，云库更新不触达）。
        //   命中即视为恶意、跳过沙箱，优先级等同云库命中。
        if (sf::hashshare::HitLocalMaliciousSha256(key64Hex)) {
            if (outWhy) *outWhy = "本地恶意库(高危隔离自动入库)";
            return true;
        }
        db = g_mal.get(); label = "恶意库(SHA-256)";
    }
    else if (algo == kAlgoImphash) { db = g_malImp.get(); label = "恶意库(imphash)"; }
    else if (algo == kAlgoMd5)     { db = g_malMd5.get(); label = "恶意库(MD5)"; }
    else if (algo == kAlgoSha1)    { db = g_malSha1.get(); label = "恶意库(SHA-1)"; }
    else return false;                          // 未知键空间：不猜

    if (!db || !db->IsOpen()) {
        // ★ 库没装载是**正常状态**（新装机尚未下发），不算故障，但必须计数 ——
        //   否则"实时防护为什么没报毒"永远答不上来（是没命中，还是压根没查）。
        g_skipped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    g_queries.fetch_add(1, std::memory_order_relaxed);
    const bool hit = db->ContainsHash(key64Hex);
    if (hit) {
        g_hits.fetch_add(1, std::memory_order_relaxed);
        if (outWhy) *outWhy = std::string("命中") + label;
    }
    return hit;
}

// ---------------------------------------------------------------- 本地恶意库（契约见 hashshare.h）
//  ★ 设计：本机学习到的恶意哈希，独立于云库，落在 local\local_malicious.txt，
//    云库更新（libupdate / hashreload）永远不碰它。键空间固定 SHA-256。
bool AddLocalMaliciousSha256(const std::string& sha256Hex) {
    std::string h = sha256Hex;
    for (auto& c : h) c = (char)std::tolower((unsigned char)c);
    if (h.size() != 64) return false;
    for (char c : h) if (!std::isxdigit((unsigned char)c)) return false;
    if (!g_localInited) return false;
    {
        std::lock_guard<std::shared_mutex> lk(g_localMalMtx);
        if (g_localMalSet.count(h)) return true;     // 幂等：已存在不重写
        g_localMalSet.insert(h);
        if (!LocalMalTxtRewriteLocked()) { g_localMalSet.erase(h); return false; }
    }
    sf::LogDbg(std::string("[localmal] 高危隔离自动入库：sha256=") + h.substr(0, 16) +
               "… 当前 " + std::to_string(g_localMalSet.size()) + " 条");
    return true;
}

bool HitLocalMaliciousSha256(const std::string& sha256Hex) {
    if (!g_localInited) return false;
    std::string h = sha256Hex;
    for (auto& c : h) c = (char)std::tolower((unsigned char)c);
    std::shared_lock<std::shared_mutex> lk(g_localMalMtx);
    return g_localMalSet.count(h) > 0;
}

long long LocalMaliciousCount() {
    if (!g_localInited) return 0;
    std::shared_lock<std::shared_mutex> lk(g_localMalMtx);
    return (long long)g_localMalSet.size();
}

bool HitTrusted(int algo, const std::string& key64Hex) {
    if (algo != kAlgoSha256) return false;      // 刻意没有可信 imphash 库
    if (!ValidKey(key64Hex)) return false;
    if (!g_ready.load(std::memory_order_acquire)) return false;
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    if (!g_tru || !g_tru->IsOpen()) return false;
    return g_tru->ContainsHash(key64Hex);
}

bool AnyMaliciousLoaded() {
    if (!g_ready.load(std::memory_order_acquire)) return false;
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    return (g_mal && g_mal->IsOpen()) || (g_malImp && g_malImp->IsOpen())
        || (g_malMd5 && g_malMd5->IsOpen()) || (g_malSha1 && g_malSha1->IsOpen());
}

LookupStats GetLookupStats() {
    LookupStats s;
    s.queries     = g_queries.load(std::memory_order_relaxed);
    s.hits        = g_hits.load(std::memory_order_relaxed);
    s.skippedNoDb = g_skipped.load(std::memory_order_relaxed);
    return s;
}

void ResetLookupStats() {
    g_queries.store(0, std::memory_order_relaxed);
    g_hits.store(0, std::memory_order_relaxed);
    g_skipped.store(0, std::memory_order_relaxed);
}

void SetHashSubsystemReady(bool ready) {
    g_ready.store(ready, std::memory_order_release);
    sf::LogDbg(std::string("[hashdb] 哈希查询契约：") + (ready ? "就绪" : "已注销"));
}

bool IsHashSubsystemReady() {
    return g_ready.load(std::memory_order_acquire);
}

// ===========================================================================
//  库信息与安装 —— 步3 云库下载更新链（契约见 hashshare.h）
// ===========================================================================
bool GetLibInfo(int idx, LibInfo& out) {
    out = LibInfo();
    if (idx < 0 || idx >= kLibCount) return false;   // 越界不猜、不兜底

    std::shared_lock<std::shared_mutex> lk(g_hlock);
    const sf::hashdb::HashDb* db = nullptr;
    switch (idx) {
        case kLibIdxMalSha: out.path = g_malPath;    db = g_mal.get();    break;
        case kLibIdxTruSha: out.path = g_truPath;    db = g_tru.get();    break;
        case kLibIdxMalImp: out.path = g_malImpPath; db = g_malImp.get(); break;
        case kLibIdxMalMd5: out.path = g_malMd5Path; db = g_malMd5.get(); break;
        case kLibIdxMalSha1:out.path = g_malSha1Path; db = g_malSha1.get(); break;
        default: return false;
    }

    const LibSigState& ss = g_sigState[idx];
    out.sigChecked  = ss.checked;
    out.sigOk       = ss.ok;
    out.sigBypassed = ss.bypassed;
    out.sigResult   = ss.result;
    out.sigDetail   = ss.detail;
    out.sha256      = ss.sha256;
    out.loaded      = ss.loaded;

    // ★ loaded 与"实例真的可用"必须一致才算数。只信 ss.loaded 其实就够
    //  （它由 LoadCloudLocked 在 Open 成功之后才置 true），这里再核一次实例，
    //   成本为零，换来的是"将来有人调换了 LoadCloudLocked 里的置位顺序"时
    //   不会变成一句"库已装载"的假话。
    if (db && db->IsOpen()) {
        const sf::hashdb::Stats s = db->GetStats();
        out.count              = s.count;
        out.contentVersion     = s.contentVersion;
        out.contentVersionText = s.contentVersionText;
        out.builtAtUnix        = s.builtAtUnix;
    } else {
        out.loaded = false;
    }
    return true;
}

std::string CloudDirUtf8() {
    // g_cloudDir 只在 InitSfdb 里赋值一次、之后不变，但命令线程与 Init 之间
    // 没有强制顺序（主干只保证 Init 之间有序），所以照常取读锁 —— 零成本。
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    return g_cloudDir;
}

std::string LibsJsonSnapshot() {
    std::shared_lock<std::shared_mutex> lk(g_hlock);
    return LibsJsonLocked();
}

LibInstallResult InstallCloudLibs(const std::vector<LibInstallItem>& items) {
    LibInstallResult res;

    // 目标文件名由 idx 唯一推导 —— 与 InitSfdb 里赋给 g_malPath 的是同一组常量。
    // 不在这里另抄一份字面量："两处文件名"是那种不报错的错误。
    const std::string* kTargets[kLibCount] = { &g_malPath, &g_truPath, &g_malImpPath, &g_malMd5Path, &g_malSha1Path };

    // -----------------------------------------------------------------------
    //  0. 入参体检 —— 必须在**动任何文件之前**全部查完
    // -----------------------------------------------------------------------
    //  否则查到第三条才发现非法时，前两条的目标文件已经被改名成 .bak 了。
    if (items.empty()) { res.detail = "未指定要安装的库"; return res; }
    for (size_t i = 0; i < items.size(); ++i) {
        const LibInstallItem& it = items[i];
        if (it.idx < 0 || it.idx >= kLibCount) {
            res.detail = "库索引越界：" + std::to_string(it.idx);
            return res;
        }
        if (it.stagedLibPath.empty()) { res.detail = "暂存库路径为空"; return res; }
        if (!LibPathExistsW(it.stagedLibPath)) {
            res.detail = "暂存库文件不存在：" + it.stagedLibPath;
            return res;
        }
        // ★ 签名路径用与装载侧**同一个**推导函数（libsig::SigPathFor）——
        //   两端不可能不一致。
        const std::string sig = sf::libsig::SigPathFor(it.stagedLibPath);
        if (!LibPathExistsW(sig)) {
            res.detail = "暂存签名文件不存在：" + sig;
            return res;
        }
    }

    std::vector<std::string> targets;
    targets.reserve(items.size());
    for (size_t i = 0; i < items.size(); ++i) targets.push_back(*kTargets[items[i].idx]);

    std::unique_lock<std::shared_mutex> lk(g_hlock);

    // 失败时的一条龙复原：放掉 mmap → 删掉可能已换上的新库 → .bak 移回正式名
    // → 重新装载。**从备份完成那一刻起，任何一步失败都只能走这里**，
    // 否则会停在"库没了"或"库半新半旧"的状态上，而两种都不报错。
    auto rollback = [&](const std::string& why) {
        g_mal.reset();
        g_tru.reset();
        g_malImp.reset();
        g_malMd5.reset();
        g_malSha1.reset();         // ★ 必须先放 mmap，否则下面的删/移都做不成
        for (size_t i = 0; i < targets.size(); ++i) {
            const std::string& t   = targets[i];
            const std::string  sig = sf::libsig::SigPathFor(t);
            LibDropW(t);
            LibDropW(sig);
            std::string e;
            if (LibPathExistsW(t + ".bak"))   LibMoveOverW(t + ".bak", t, e);
            if (LibPathExistsW(sig + ".bak")) LibMoveOverW(sig + ".bak", sig, e);
        }
        LoadCloudLocked();
        res.ok         = false;
        res.rolledBack = true;
        res.failed     = (int)items.size();
        res.detail     = why + " —— 已回滚到旧库";
        res.libsJson   = LibsJsonLocked();
        // ★ 回滚必须大声：回滚完成后**表面一切正常**（库在、能查、只是旧的），
        //   这是"零症状假象"最典型的形态。这条日志是唯一能说明"曾经更新过、
        //   又退回去了"的痕迹。
        sf::LogDbg("[lib] ！！云库安装失败，已回滚：" + why);
    };

    // -----------------------------------------------------------------------
    //  1. 备份（目标存在才备份）
    // -----------------------------------------------------------------------
    for (size_t i = 0; i < targets.size(); ++i) {
        const std::string& t   = targets[i];
        const std::string  sig = sf::libsig::SigPathFor(t);
        std::string e;
        if (LibPathExistsW(t) && !LibMoveOverW(t, t + ".bak", e)) {
            rollback("备份旧库失败（" + t + "：" + e + "）");
            return res;
        }
        if (LibPathExistsW(sig) && !LibMoveOverW(sig, sig + ".bak", e)) {
            rollback("备份旧签名失败（" + sig + "：" + e + "）");
            return res;
        }
    }

    // -----------------------------------------------------------------------
    //  2. 卸载 —— 释放 mmap（事实一：正在 mmap 的文件替换不了）
    //     这一步与下面的替换**必须在同一把锁内**（事实二）：分两次加锁的话，
    //     中间那一小段"库全空"会被实时链读成 skippedNoDb —— 而它与
    //     "这个文件干净"在返回值上不可区分。
    // -----------------------------------------------------------------------
    g_mal.reset();
    g_tru.reset();
    g_malImp.reset();
    g_malMd5.reset();
    g_malSha1.reset();

    // -----------------------------------------------------------------------
    //  3. 换上暂存文件
    // -----------------------------------------------------------------------
    for (size_t i = 0; i < items.size(); ++i) {
        const std::string& t   = targets[i];
        const std::string  sig = sf::libsig::SigPathFor(t);
        std::string e;
        if (!LibMoveOverW(items[i].stagedLibPath, t, e)) {
            rollback("替换库文件失败（" + t + "：" + e + "）");
            return res;
        }
        if (!LibMoveOverW(sf::libsig::SigPathFor(items[i].stagedLibPath), sig, e)) {
            rollback("替换签名文件失败（" + sig + "：" + e + "）");
            return res;
        }
    }

    // -----------------------------------------------------------------------
    //  4. 重新装载 —— 内部会**再验一次签** + 重新 mmap
    // -----------------------------------------------------------------------
    //  ★ 这是刻意的第二次校验：mod_lib 在 .tmp 上验过一次，这里在**正式路径**
    //    上再验一次。两者之间隔着"重命名"这一步，而它恰恰是最可能出问题的一步
    //    （跨卷移动会退化成复制+删除、杀软可能拦截改名、目标名可能被占用）。
    LoadCloudLocked();

    // -----------------------------------------------------------------------
    //  5. 判定：**只认 g_sigState[].loaded**（它由 LoadCloudLocked 在 Open 成功
    //     之后才置 true），不看"文件是否存在"。库在却装不上（库头损坏 /
    //     Bloom 参数非法 / 条目数 0）正是最需要回滚的情况 —— 验签通过 ≠ 装得上。
    // -----------------------------------------------------------------------
    int bad = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        if (!g_sigState[items[i].idx].loaded) ++bad;
    }

    if (bad == 0) {
        // 成功：清掉备份（.bak 只在这一段临界区里存在）
        for (size_t i = 0; i < targets.size(); ++i) {
            LibDropW(targets[i] + ".bak");
            LibDropW(sf::libsig::SigPathFor(targets[i]) + ".bak");
        }
        res.ok        = true;
        res.installed = (int)items.size();
        res.detail    = "已安装 " + std::to_string(items.size()) + " 本库并重新装载";
        res.libsJson  = LibsJsonLocked();
        return res;
    }

    // 有库装不上 → **整体**回滚。不做"部分成功"：半新半旧会让"库版本"这个
    // 判据变得无法解释（下一次 libcheck 该拿哪个版本去比？）。
    rollback(std::to_string(bad) + " 本新库装载失败");
    return res;
}

bool ReloadCloudLibs() {
    {
        std::unique_lock<std::shared_mutex> lk(g_hlock);
        LoadCloudLocked();
    }
    return AnyMaliciousLoaded();
}

}  // namespace hashshare
}  // namespace sf

namespace sf {
namespace mod {

// ---------------------------------------------------------------------------
//  进程内实例登记（契约与理由见 sfdbshare.h）
// ---------------------------------------------------------------------------
//  ★ 这四个函数就是"跨模块写库"的**唯一**合法入口。任何分体想要往库里写，
//    都必须走 GlobalDb()，不许自己 new 一个 Database 打开同一个文件 ——
//    那样会得到两个互不知情的内存表，最终以"数据偶发消失"收场。
void RegisterGlobalDb(sf::sfdb::Database* db, bool ready) {
    g_regDb.store(db, std::memory_order_release);
    g_regReady.store(ready && db != nullptr, std::memory_order_release);
    sf::LogDbg(std::string("[sfdb] 全局实例已登记：db=") + (db ? "有效" : "空") +
               (ready && db ? "，可写" : "，不可写"));
}

void UnregisterGlobalDb() {
    g_regReady.store(false, std::memory_order_release);
    g_regDb.store(nullptr, std::memory_order_release);
}

sf::sfdb::Database* GlobalDb() {
    return g_regDb.load(std::memory_order_acquire);
}

bool GlobalDbReady() {
    return g_regReady.load(std::memory_order_acquire);
}

extern const Module kModule_sfdb = {
    "sfdb",
    InitSfdb,       // Init：建库 + 建表 + 装载云库（失败不致命，见文件头说明）
    nullptr,        // Run：不持有线程（所有操作都是"来一条命令做一件事"）
    StopSfdb,       // Stop：刷盘 + 关库（逆序收尾，不做耗时操作）
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
