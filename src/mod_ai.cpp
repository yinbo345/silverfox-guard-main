// mod_ai.cpp — 分体：人工智能引擎（特征层 + 模型层）的托管与管道命令
//
// ===========================================================================
//  本分体现在做什么、不做什么（边界写清楚，避免"看着像做完了"）
// ===========================================================================
//  做（本步 = 地基）：
//    · 托管一个只读推理模型（mmap，换模型时"先建好新的再换指针"）
//    · 把「原始进程事实」→ 48 维特征向量 这条链路做成**可查、可复现**的
//      也就是任何一台机器上都能用 aifeat 打出某个进程的向量，
//      直接拿去和日志/训练集对照 —— 这是后续训练与影子模式的必要前提
//    · 模型文件缺失/损坏时**如实报出**，绝不静默降级
//
//  不做（刻意留到下一步）：
//    · 不接入实时链路。原因很实在：现在还没有训练好的模型，
//      如果现在就往进程出生卡的热路径里挂一次 48 维前向，
//      等于给每次进程启动平白加开销，却得不到任何判定。
//      接入的前提是先有一版模型 + 影子模式跑一段时间的观测数据（写 ai_observe 表）。
//
//  ★ 为什么特征与分数分成两条命令（aifeat / aiscore）
//    aifeat 不碰模型，任何机器上都能用 —— 排查"AI 为什么这么判"时，
//    第一件要确认的事是"喂进去的到底是什么"，而不是"分数是多少"。
//    分成两条命令以后，"特征对不对"和"模型准不准"能被分开定位。
//
// ===========================================================================
//  命令清单
// ===========================================================================
//    aistat       引擎状态：特征维度 / 模型路径 / 是否装载 / 结构 / 参数量 / 前向次数
//    aifeat       由原始事实算出 48 维特征（**不需要模型**）
//    aiscore      同上 + 用模型打一个 0~1 的分数；多头模型还会给出行为标签归因
//    aimodelload  重新装载模型（换过模型文件后用，不必重启服务）
//
// ===========================================================================
//  ★ 一个网络干两件事（多头模型）
// ===========================================================================
//  原计划里「病毒行为判定」与「程序行为归因」是两条线，很容易顺势做成两个网络。
//  没必要：一个模型的槽里本来就装得下两个功能，**格式一个字节都不用改**
//  （理由见 aimodel.h 的「kind 的两种取值」）。约定 kind=2 时：
//
//      out[0]     恶意分            ← 模型①：拦不拦（唯一会进评分层的东西）
//      out[1..k]  行为标签置信度    ← 模型②：像什么（只给人看，不参与任何判定）
//
//  这两样**来自同一次前向** —— 合并成一个网络省下的正是这部分开销；
//  而且两个头共享前面的层（trunk），于是标签头的监督信号会反过来压住恶意分那头的
//  过拟合（两个任务互为正则），样本少的时候这一条比"多一个网络"值钱得多。
//
//  ⚠️ 纪律没有变：标签只用于**解释**。判定链路上仍然只有「恶意分 + 规则引擎」，
//     标签连加权都不参与 —— 见 docs/behavior-ml-plan.md 纪律一「模型分只加权、不判据」。
//
//  共用参数（与 aifeat.h 的 FeatureInput 一一对应，全部可选）：
//    image=     映像完整路径          cmd=      完整命令行
//    parent=    父进程映像路径
//    signed=1 image 有数字签名        signedparent=1 父进程有签名
//    vendor=1   image 有厂商版本资源  randname=1     文件名像随机串（调用方已判定）
//    ads=1      image 带 NTFS 备用数据流
//    age=<秒>   映像创建距今秒数（-1/缺省 = 未知）    size=<字节>（-1/缺省 = 未知）
//    softlv=<n> 落地升档级别（rollback 的 QuerySoftLanded 输出）
//    softzone=1 上一项的"软件自写区"成立
//    rulelevel=<n> rulescore=<n> rulehard=1 ruletag=<字符串>
//
//  ★ 为什么参数叫 "image" 而不是 "path"
//    mod_sfdb 的 hashq 已经用了 path=（要去算文件哈希），这里若重名，
//    同一个命令名表下两处含义不同的参数会让人写错脚本还查不出原因。
//
// ===========================================================================
//  ★ 为什么 Init 恒返回 true
// ===========================================================================
//  与 mod_sfdb 同理：模型不存在是**新装机器的正常状态**，不是故障。
//  若返回 false，主干会跳过整个分体，于是连 aistat 都查不到，
//  反而失去唯一能说明"模型为什么没生效"的手段。
#include "module.h"

#include "aifeat.h"
#include "ailabels.h"   // 多头模型的行为标签集（顺序即 out[1..] 的下标顺序）
#include "aimodel.h"
#include "aiobserve.h"  // ★ 影子模式投递契约（投递 = 热路径，处理 = 本文件的线程）
#include "common.h"    // WriteFramed / JsonString / JsonGetString / JsonGetInt / LogDbg
#include "scanner.h"   // ★ 特征富化要复用实时链路同一份判据（勿另写一份）
#include "sfdb.h"      // 写 ai_observe 表
#include "sfdbshare.h" // ★ 跨模块取库实例（本分体**不是**库的拥有者）
#include "sfstop.h"    // StopHandle / IsStopRequested（观察线程退出范式）

#include <windows.h>
#include <shlobj.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
//  影子模式私有实现的**前向声明**（实现在本文件后半段的 namespace sf::ai 里）
// ---------------------------------------------------------------------------
//  为什么非要提前声明：InitAi/StopAi 定义在前面（且在匿名命名空间内），
//  而 ObserveInit/ObserveShutdown 的实现在 1000 行开外 —— 不声明就是
//  「error C2039: ObserveInit 不是 sf::ai 的成员」，看起来像命名空间写错了，
//  实际只是**声明尚不可见**。
//  ⚠️ 三条不能动的细节：
//    1. 必须放在**全局作用域**。写进匿名命名空间会变成
//       (anonymous)::sf::ai::ObserveInit，与真正的 ::sf::ai::ObserveInit
//       是两个毫不相干的名字，照样报错（而且更难看出来）。
//    2. 必须带 static，与定义处保持一致。先声明成外部链接、定义时又写 static
//       是 ill-formed（[dcl.stc]）。
//    3. 这两个是**模块内部**的启停钩子，不是跨模块契约 —— 所以不进 aiobserve.h。
//       跨模块的那部分是 ObservePush / SetObserveEnabled / ObserveEnabled /
//       ObserveStats / ObserveResetStats，声明在 aiobserve.h。
namespace sf { namespace ai {
static void ObserveInit(const std::wstring& aiDirW);
static void ObserveShutdown();
}}  // namespace sf::ai

namespace {

// ===========================================================================
//  路径与编码（铁律：内部路径 UTF-8，文件 API 一律 *W）
// ===========================================================================
std::wstring DataDirW() {
    wchar_t p[MAX_PATH] = {0};
    std::wstring dir;
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, 0, p)) && p[0])
        dir = std::wstring(p) + L"\\SilverFoxGuard";
    else
        dir = L"C:\\ProgramData\\SilverFoxGuard";
    CreateDirectoryW(dir.c_str(), nullptr);
    dir += L"\\ai";
    CreateDirectoryW(dir.c_str(), nullptr);
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

// UTF-8 → 宽字符。
// ★ 影子模式要用它：`GetFileAttributesExW` 这类 *W API 收宽字符，
//   而内部路径一律是 UTF-8。直接上 *A 在中文用户名（C:\Users\银泊\…）下
//   会按 ANSI 解释 UTF-8 字节 → 静默失败（本项目的「UTF-8 路径铁律」）。
std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &w[0], n);
    return w;
}

bool FileExistsW(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}

// ===========================================================================
//  全局状态
// ===========================================================================
//  ★ 换模型的做法（与 mod_sfdb 装载云库同）：
//     先在新路径上把 Model 建好（各自持有独立 mmap 视图），
//     成功了再在写锁下换掉指针 —— 失败时旧模型**照常可用**，
//     不会出现"换到一半没有模型可用"的窗口。
//     ⚠️ 不能用"原地覆盖同一个路径"的做法：mmap 着的文件在 Windows 上
//        无法被 MoveFileEx 原子替换（实测 ERROR_USER_MAPPED_FILE）。
//        所以模型文件一律带版本号命名（proxy_v1.sfm / proxy_v2.sfm …），
//        新版本落到新文件名上，旧文件在换完指针之后再删。
std::wstring                 g_aiDirW;
std::string                  g_modelPath;      // 当前期望的模型路径
std::shared_mutex            g_mlock;
std::unique_ptr<sf::ai::Model> g_model;
std::string                  g_loadErr;        // 上次装载失败的原因（未装载时给 aistat 用）
long long                    g_loadedAtMs = 0;

long long NowMs() {
    LARGE_INTEGER f{}, c{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return (long long)((double)c.QuadPart * 1000.0 / (double)f.QuadPart);
}

// 便捷：统一失败响应
bool Fail(HANDLE h, const std::string& cmd, const std::string& why) {
    sf::WriteFramed(h, "{\"cmd\":" + sf::JsonString(cmd) + ",\"ok\":false,\"error\":" +
                          sf::JsonString(why) + "}");
    return true;
}

// ===========================================================================
//  请求 → FeatureInput
// ===========================================================================
//  刻意做成"缺省值 = 无迹象"：命令行里只写关心的几项，其余全按"没发现"处理。
//  这样 aifeat 可以被当成一个手边工具随手敲，而不是每次都要填 15 个字段。
sf::ai::FeatureInput ParseInput(const std::string& req) {
    sf::ai::FeatureInput in;
    in.imagePath        = sf::JsonGetString(req, "image");
    in.commandLine      = sf::JsonGetString(req, "cmd");
    in.parentImagePath  = sf::JsonGetString(req, "parent");
    in.ruleTag          = sf::JsonGetString(req, "ruletag");

    in.signedImage      = sf::JsonGetInt(req, "signed")     != 0;
    in.signedParent     = sf::JsonGetInt(req, "signedparent") != 0;
    in.hasVendorInfo    = sf::JsonGetInt(req, "vendor")     != 0;
    in.fileNameIsRandom = sf::JsonGetInt(req, "randname")   != 0;
    in.hasAds           = sf::JsonGetInt(req, "ads")        != 0;
    in.softLandedSysZone= sf::JsonGetInt(req, "softzone")   != 0;

    // age / size 的"未给"必须能与"给了 0"区分开：
    // JsonGetInt 取不到时返回 0，而 0 秒（刚创建）是**合法且有意义的取值**，
    // 所以先看字段在不在，再取值。混起来会把"未知"错当成"刚刚创建"。
    // ⚠️ 必须用 JsonGetInt64：JsonGetInt 返回 int，超 2GB 的文件（size=3e9）会被截断成负数，
    //    百年老文件的 age（约 3.1e9 秒）同样溢出。两者都不报错、只悄悄给错值。
    auto hasKey = [&](const char* k) {
        return req.find(std::string("\"") + k + "\"") != std::string::npos;
    };
    in.createdAtAgeSec = hasKey("age")  ? sf::JsonGetInt64(req, "age")  : -1;
    in.fileSizeBytes   = hasKey("size") ? sf::JsonGetInt64(req, "size") : -1;

    in.softLandedLv    = sf::JsonGetInt(req, "softlv");
    in.ruleLevel       = sf::JsonGetInt(req, "rulelevel");
    in.ruleScore       = sf::JsonGetInt(req, "rulescore");
    in.ruleHard        = sf::JsonGetInt(req, "rulehard") != 0;
    return in;
}

std::string FeatJson(const sf::ai::FeatureVector& fv) {
    int nz = 0;
    for (int i = 0; i < sf::ai::kFeatureDim; ++i) if (fv.Get(i) > 0.f) ++nz;
    std::string j = "{\"dim\":" + std::to_string(sf::ai::kFeatureDim);
    j += ",\"nonzero\":"    + std::to_string(nz);
    j += ",\"feat\":"       + sf::JsonString(fv.ToText());
    j += ",\"readable\":"   + sf::JsonString(fv.ToReadable());
    j += "}";
    return j;
}

// ===========================================================================
//  多头模型的标签输出 → JSON
// ===========================================================================
//  标签置信度到多少算"命中"。0.5 是多标签二分类的默认阈值。
//  ★ 只有这一处定义：调阈值时能一眼看到"改的就是这里"，不必满仓找。
const float kLabelHitThreshold = 0.5f;

std::string ScoreLabelsJson(const std::vector<float>& labels) {
    // ① 全部置信度，逗号分隔、顺序即标签表顺序 —— 给脚本逐维比对用。
    //    刻意跟 aifeat 的 "feat" 用同一种紧凑写法：两者都是"拿来跟训练集对数字"的东西，
    //    形状一致才好写一次脚本同时处理两边。
    std::string vec;
    char buf[32];
    for (size_t i = 0; i < labels.size(); ++i) {
        if (i) vec += ",";
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.4f", labels[i]);
        vec += buf;
    }
    std::string j = ",\"labels\":" + sf::JsonString(vec);

    // ② 标签集是否与本版本的表一致。
    //    推理侧能自动做的校验**只有这一条**（顺序错是查不出来的，见 ailabels.h）。
    //    对不上时必须显式报出来：那时所有标签名都是不可信的。
    const bool nameOk = sf::ai::AiLabelSetMatches((int)labels.size());
    j += ",\"labelSetOk\":" + std::string(nameOk ? "true" : "false");

    // ③ 命中项，按置信度**降序** —— 看归因的人想知道"最像什么"，
    //    而不是"哪个标签下标小"（下标小只是碰巧排在标签表前面）。
    //    26 个元素，用不着 std::sort：一次插入排序就够，还省掉一个 <algorithm> 依赖。
    std::vector<int> order;
    for (size_t i = 0; i < labels.size(); ++i) {
        if (!(labels[i] >= kLabelHitThreshold)) continue;   // 写成 !(>=) 顺带排掉 NaN
        size_t pos = 0;
        while (pos < order.size() && labels[(size_t)order[pos]] >= labels[i]) ++pos;
        order.insert(order.begin() + (long long)pos, (int)i);
    }

    j += ",\"hits\":[";
    for (size_t n = 0; n < order.size(); ++n) {
        const int i = order[n];
        if (n) j += ",";
        char p[32];
        _snprintf_s(p, sizeof(p), _TRUNCATE, "%.4f", labels[(size_t)i]);
        j += "{\"i\":" + std::to_string(i);
        // ★ 标签集对不上时**不给名字**：宁可显示 #3，也不要拿一张错位的表
        //   去编一个"看起来很合理"的中文名出来 —— 那是最难发现的一类错误
        //   （人会相信一个具体的名字，而不会去怀疑一个 #3）。
        // ⚠️ 下面三个都先落成 std::string 再进三元：三元的两边类型必须一致，
        //    `const char*` 与 `std::string` 混写是编译期错误（实测踩过）。
        const std::string lk = nameOk ? std::string(sf::ai::AiLabelKey(i))
                                     : ("#" + std::to_string(i));
        const std::string lzh = nameOk ? std::string(sf::ai::AiLabelZh(i))     : std::string();
        const std::string ltt = nameOk ? std::string(sf::ai::AiLabelAttack(i)) : std::string();
        j += ",\"k\":"  + sf::JsonString(lk);
        j += ",\"zh\":" + sf::JsonString(lzh);
        j += ",\"t\":"  + sf::JsonString(ltt);
        j += ",\"p\":"  + std::string(p);
        j += "}";
    }
    j += "]";
    return j;
}

// ===========================================================================
//                                                                    aistat
// ===========================================================================
bool CmdAiStat(HANDLE h, const std::string& /*req*/) {
    std::shared_lock<std::shared_mutex> lk(g_mlock);

    std::string j = "{\"cmd\":\"aistat\",\"ok\":true,\"data\":{";
    j += "\"featureDim\":"   + std::to_string(sf::ai::kFeatureDim);
    j += ",\"modelPath\":"   + sf::JsonString(g_modelPath);
    j += ",\"modelExists\":" + std::string(FileExistsW(g_aiDirW + L"\\proxy_v1.sfm") ?
                                          "true" : "false");
    j += ",\"loaded\":"      + std::string((g_model && g_model->IsLoaded()) ? "true" : "false");
    if (g_model && g_model->IsLoaded()) {
        sf::ai::ModelStats st = g_model->GetStats();
        j += ",\"layers\":"     + std::to_string(st.layers);
        j += ",\"kind\":"       + std::to_string(st.kind);
        j += ",\"multi\":"      + std::string(st.kind == sf::ai::kKindMulti ? "true" : "false");
        j += ",\"inDim\":"      + std::to_string(st.inDim);
        j += ",\"outDim\":"     + std::to_string(st.outDim);
        // 多头模型的标签头个数（outDim-1）；非多头为 0。
        // labelCount 与 labelSetOk 分开报：前者是模型**声明**了几个头，
        // 后者是这些头能否被本版本的标签表解释 —— 两者含义不同，不能合并成一个布尔量。
        const int lc = g_model->LabelCount();
        j += ",\"labelCount\":" + std::to_string(lc);
        if (lc > 0)
            j += ",\"labelSetOk\":" + std::string(
                sf::ai::AiLabelSetMatches(lc) ? "true" : "false");
        j += ",\"tag\":"        + sf::JsonString(st.tag);
        j += ",\"params\":"     + std::to_string(st.paramCount);
        j += ",\"fileBytes\":"  + std::to_string(st.fileBytes);
        j += ",\"forwards\":"   + std::to_string(st.forwards);
        j += ",\"createdAt\":"  + std::to_string(st.createdAtUnix);
        // 维度不匹配的模型等于没有模型（前向会读错偏移），必须显式报出来
        j += ",\"dimOk\":"      + std::string(sf::ai::CheckDim(st.inDim) ? "true" : "false");
    }
    if (!g_loadErr.empty())
        j += ",\"lastError\":" + sf::JsonString(g_loadErr);
    j += ",\"host\":\"freestanding-mlp\"";
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}


// ===========================================================================
//                                                                    aifeat
// ===========================================================================
bool CmdAiFeat(HANDLE h, const std::string& req) {
    sf::ai::FeatureInput in = ParseInput(req);
    sf::ai::FeatureVector fv = sf::ai::BuildFeatures(in);

    std::string j = "{\"cmd\":\"aifeat\",\"ok\":true,\"data\":";
    j += FeatJson(fv);
    j += "}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                   aiscore
// ===========================================================================
bool CmdAiScore(HANDLE h, const std::string& req) {
    sf::ai::FeatureInput in = ParseInput(req);
    sf::ai::FeatureVector fv = sf::ai::BuildFeatures(in);

    std::shared_lock<std::shared_mutex> lk(g_mlock);
    const bool loaded = g_model && g_model->IsLoaded();

    std::string j = "{\"cmd\":\"aiscore\",\"ok\":true,\"data\":{";
    j += "\"scored\":" + std::string(loaded ? "true" : "false");
    if (loaded) {
        const bool multi = (g_model->LabelCount() > 0);
        j += ",\"multi\":" + std::string(multi ? "true" : "false");

        bool ok = false;
        float s = 0.f;
        std::vector<float> labels;
        if (multi) {
            // 多头：**一次前向**同时拿到恶意分与全部标签头。
            // 这正是"一个网络干两件事"省下来的那部分开销 —— 若拆成两个模型，
            // 这里是两次前向 + 两套权重常驻内存。
            ok = g_model->ScoreLabels(fv, s, labels);
        } else {
            s = g_model->Score(fv, &ok);
        }

        // 必须把 ok 如实传出去 —— 把"算不了"报成 0 分，等于把不可疑当成了结论。
        j += ",\"scoreOk\":" + std::string(ok ? "true" : "false");
        if (ok) {
            char buf[32];
            _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%.4f", s);
            j += ",\"score\":";
            j += buf;
            if (multi) j += ScoreLabelsJson(labels);
        } else {
            std::string why = std::string("模型给不出分数（需 ") +
                              std::to_string(sf::ai::kFeatureDim) +
                              " 维特征输入；多头模型的 out[0] 才是恶意分）：";
            why += g_model->LastError();
            j += ",\"reason\":" + sf::JsonString(why);
        }
    } else {
        // 分两列举错原因，**不要**把三目运算符塞进函数参数里 ——
        // 三目的优先级低于 +，右括号会落错位置（这条就是编译期实测踩到的）。
        std::string why = g_loadErr;
        if (why.empty()) {
            why = std::string("未装载模型（把训练好的模型放到 ") + g_modelPath +
                  std::string(" 之后执行 aimodelload）");
        }
        j += ",\"reason\":" + sf::JsonString(why);
    }
    j += ",\"feat\":" + FeatJson(fv);
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                              aimodelload
// ===========================================================================
bool CmdAiModelLoad(HANDLE h, const std::string& req) {
    std::string path = sf::JsonGetString(req, "path");
    if (path.empty()) path = g_modelPath;

    // ① 先在**锁外**把新模型建好（mmap + 校验都可能耗上几十毫秒），
    //    这一步失败时旧模型一动不动。
    std::unique_ptr<sf::ai::Model> fresh(new sf::ai::Model());
    bool ok = fresh->Load(path);
    const std::string err = ok ? std::string() : fresh->LastError();

    long long loadedAt = 0;
    {
        std::unique_lock<std::shared_mutex> lk(g_mlock);
        if (ok) {
            g_model = std::move(fresh);
            g_loadErr.clear();
            g_modelPath = path;
            loadedAt = NowMs();
            g_loadedAtMs = loadedAt;
        } else {
            // ★ 装载失败**不动**当前模型：模型坏了不该让防护失去已有能力。
            //   同时把原因记下来（aistat 与 aiscore 都会如实带出）。
            g_loadErr = err;
        }
    }

    if (!ok) {
        sf::LogDbg("[ai] 模型装载失败：" + err + " 路径=" + path);
        return Fail(h, "aimodelload", err.empty() ? "装载失败" : err);
    }

    sf::ai::ModelStats st = g_model->GetStats();
    sf::LogDbg("[ai] 模型已装载：" + path + "，" + std::to_string(st.layers) + " 层，" +
               std::to_string(st.inDim) + "→" + std::to_string(st.outDim) + "，标签 " +
               st.tag + "，" + std::to_string(st.paramCount) + " 个参数" +
               (st.kind == sf::ai::kKindMulti ? "（多头）" : ""));
    std::string j = "{\"cmd\":\"aimodelload\",\"ok\":true,\"data\":{";
    j += "\"path\":"     + sf::JsonString(path);
    j += ",\"layers\":"  + std::to_string(st.layers);
    j += ",\"kind\":"    + std::to_string(st.kind);
    j += ",\"multi\":"   + std::string(st.kind == sf::ai::kKindMulti ? "true" : "false");
    j += ",\"inDim\":"   + std::to_string(st.inDim);
    j += ",\"outDim\":"  + std::to_string(st.outDim);
    j += ",\"tag\":"     + sf::JsonString(st.tag);
    j += ",\"params\":"  + std::to_string(st.paramCount);
    // 维度不匹配也**算装载成功**（文件本身没问题），但必须显式警告：
    // 这样的模型能算，只是算的东西不是本版本的特征向量。
    j += ",\"dimOk\":"   + std::string(sf::ai::CheckDim(st.inDim) ? "true" : "false");
    // 多头模型额外报标签头个数与"标签集能否被本版本解释"（见 aistat 的同类注释）
    const int lc = g_model->LabelCount();
    if (lc > 0) {
        j += ",\"labelCount\":"  + std::to_string(lc);
        j += ",\"labelSetOk\":"  + std::string(
            sf::ai::AiLabelSetMatches(lc) ? "true" : "false");
    }
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                 aiobstat
// ===========================================================================
//  影子模式的体检报告。为什么值得单独一条命令：
//  「影子模式开着但一条都没写进去」有四种完全不同的成因
//  （开关关着 / 线程没跑 / 队列满被丢 / 库写不进去），
//  只看"写了几条"是分不出来的 —— 而四种的修法互不相同。
//  这条命令把四个环节的数字分开摆出来。
bool CmdAiObStat(HANDLE h, const std::string& /*req*/) {
    sf::ai::ObserveStat st = sf::ai::ObserveStats();
    sf::sfdb::Database* db = sf::mod::GlobalDb();
    const bool dbOk = sf::mod::GlobalDbReady();

    long long rows = -1, nMal = -1, nBen = -1;
    long long dbBytes = -1;
    if (db && dbOk) {
        rows = db->CountRows("ai_observe");
        long long t = 0;
        if (db->QueryInt("SELECT COUNT(*) FROM ai_observe WHERE label = 'malware'", t)) nMal = t;
        if (db->QueryInt("SELECT COUNT(*) FROM ai_observe WHERE label = 'benign'", t))  nBen = t;
        dbBytes = db->GetStats().fileBytes;
    }

    std::string j = "{\"cmd\":\"aiobstat\",\"ok\":true,\"data\":{";
    j += "\"enabled\":"     + std::string(st.enabled  ? "true" : "false");
    j += ",\"threadUp\":"   + std::string(st.threadUp ? "true" : "false");
    j += ",\"dbReady\":"    + std::string(dbOk ? "true" : "false");
    j += ",\"queueNow\":"   + std::to_string(st.queueNow);
    j += ",\"queueHigh\":"  + std::to_string(st.queueHigh);
    j += ",\"enqueued\":"   + std::to_string(st.enqueued);
    j += ",\"droppedFull\":"+ std::to_string(st.droppedFull);
    j += ",\"droppedOff\":" + std::to_string(st.droppedOff);
    j += ",\"taken\":"      + std::to_string(st.taken);
    j += ",\"written\":"    + std::to_string(st.written);
    j += ",\"writeFail\":"  + std::to_string(st.writeFail);
    j += ",\"pruned\":"     + std::to_string(st.pruned);
    j += ",\"rows\":"       + std::to_string(rows);
    j += ",\"labelMalware\":"+ std::to_string(nMal);
    j += ",\"labelBenign\":" + std::to_string(nBen);
    j += ",\"dbBytes\":"    + std::to_string(dbBytes);
    // modelLoaded 单独报：影子模式**不依赖**模型（先攒语料、后训练），
    // 所以"没模型"不影响采集 —— 但调用方看 aiscore 之前必须知道这件事。
    j += ",\"modelLoaded\":" + std::string((g_model && g_model->IsLoaded()) ? "true" : "false");
    if (!st.lastErr.empty()) j += ",\"lastError\":" + sf::JsonString(st.lastErr);
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                 aiobdump
// ===========================================================================
//  导出样本文本（给训练脚本与人工复盘用）。
//  ★ 必须限行数：管道响应用的是浏览器原生消息通道，本项目的实测上限是 1MB ——
//    早先在扫描响应上撑到 1.3MB，表现为"扩展显示未连接"（看着像权限问题）。
//    一行样本约 500~900 字节，所以默认 20 行、硬上限 200 行（≈180KB）。
bool CmdAiObDump(HANDLE h, const std::string& req) {
    sf::sfdb::Database* db = sf::mod::GlobalDb();
    if (!db || !sf::mod::GlobalDbReady())
        return Fail(h, "aiobdump", "数据库不可用（sfdb 未就绪）");

    long long limit = sf::JsonGetInt(req, "limit");
    if (limit <= 0)   limit = 20;
    if (limit > 200)  limit = 200;          // ★ 硬上限，见上方注释
    const std::string label = sf::JsonGetString(req, "label");

    std::string sql = "SELECT id, at, proc, path, cmd, score, verdict, aiscore, label, tags, feat FROM ai_observe";
    if (!label.empty()) sql += " WHERE label = " + sf::sfdb::Database::Quote(label);
    sql += " ORDER BY at DESC LIMIT " + std::to_string(limit) + " OFFSET " +
           std::to_string((long long)sf::JsonGetInt(req, "offset"));

    sf::sfdb::ResultSet rs;
    if (!db->ExecOne(sql, rs))
        return Fail(h, "aiobdump", "查询失败：" + db->LastError());

    std::string arr;
    for (size_t i = 0; i < rs.rows.size(); ++i) {
        const std::vector<sf::sfdb::Value>& r = rs.rows[i];
        if (r.size() < 11) continue;      // 结构不符时跳过，不让它把整个响应带崩
        if (!arr.empty()) arr += ",";
        arr += "{";
        arr += "\"id\":"      + sf::JsonString(r[0].ToText());
        arr += ",\"at\":"     + std::to_string(r[1].ToInt());
        arr += ",\"proc\":"   + sf::JsonString(r[2].ToText());
        arr += ",\"path\":"   + sf::JsonString(r[3].ToText());
        arr += ",\"cmd\":"    + sf::JsonString(r[4].ToText());
        arr += ",\"score\":"  + std::to_string(r[5].ToInt());
        arr += ",\"verdict\":"+ sf::JsonString(r[6].ToText());
        arr += ",\"aiscore\":"+ std::to_string(r[7].ToInt());
        arr += ",\"label\":"  + sf::JsonString(r[8].ToText());
        arr += ",\"tags\":"   + sf::JsonString(r[9].ToText());
        arr += ",\"feat\":"   + sf::JsonString(r[10].ToText());
        arr += "}";
    }

    std::string j = "{\"cmd\":\"aiobdump\",\"ok\":true,\"data\":{";
    j += "\"count\":"  + std::to_string(rs.rows.size());
    j += ",\"limit\":" + std::to_string(limit);
    j += ",\"dim\":"   + std::to_string(sf::ai::kFeatureDim);
    // 把特征名表一并带上：没有它，导出的 48 个数字就是天书
    //（"第 17 维偏大"必须能翻译成"到底是哪个信号偏大"）。
    std::string names;
    for (int i = 0; i < sf::ai::kFeatureDim; ++i) {
        if (i) names += ",";
        names += sf::ai::kFeatureNames[i];
    }
    j += ",\"featNames\":" + sf::JsonString(names);
    j += ",\"rows\":[" + arr + "]}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                 aiobclear
// ===========================================================================
//  清空样本表。存在的意义是**隐私兜底**：命令行可能含敏感参数（token / 路径），
//  用户/开发者必须能一键把它们抹掉，而不是只能删库文件。
bool CmdAiObClear(HANDLE h, const std::string& /*req*/) {
    sf::sfdb::Database* db = sf::mod::GlobalDb();
    if (!db || !sf::mod::GlobalDbReady())
        return Fail(h, "aiobclear", "数据库不可用（sfdb 未就绪）");

    sf::sfdb::ResultSet rs;
    if (!db->ExecOne("DELETE FROM ai_observe", rs))
        return Fail(h, "aiobclear", "清空失败：" + db->LastError());

    // 删除在追加式存储里只是打墓碑，文件不会变小 —— 清空这种"彻底不要了"
    // 的场景正是 Compact 最好的用处（重写成只含活行的新文件）。
    db->Compact();
    sf::ai::ObserveResetStats();

    std::string j = "{\"cmd\":\"aiobclear\",\"ok\":true,\"data\":{";
    j += "\"deleted\":" + std::to_string(rs.affected);
    j += ",\"compact\":true}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                   aiobson
// ===========================================================================
//  开关影子模式。不带参数 = 只查询当前状态（不做任何改动）。
bool CmdAiObOn(HANDLE h, const std::string& req) {
    const bool hasOn = req.find("\"on\"") != std::string::npos;
    if (hasOn) sf::ai::SetObserveEnabled(sf::JsonGetInt(req, "on") != 0);

    std::string j = "{\"cmd\":\"aiobson\",\"ok\":true,\"data\":{";
    j += "\"enabled\":"  + std::string(sf::ai::ObserveEnabled() ? "true" : "false");
    j += ",\"changed\":" + std::string(hasOn ? "true" : "false");
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                  aiobmark
// ===========================================================================
//  给样本打真值标签。**这是"恶意样本从哪来"的答案**：
//  影子模式在用户机器上自动采集，它不可能知道某个进程是不是真恶意，
//  所以自动采的行 label 一律留空；在虚拟机里跑完样本后，
//  用 `aiobmark label=malware since=<跑样本前的时间戳>` 把那一批统一标上。
//
//  为什么按**时间窗**而不是按 id 打标：跑一个样本会产生一串子进程
//  （释放器 → 载荷 → PowerShell → …），逐个 id 打标既繁琐又容易漏；
//  而"这段时间里出现的进程都算恶意"是采集场景下天然正确的粒度。
bool CmdAiObMark(HANDLE h, const std::string& req) {
    const std::string label = sf::JsonGetString(req, "label");
    if (label.empty())
        return Fail(h, "aiobmark", "需要 label=<malware|benign|clear>");
    if (label != "malware" && label != "benign" && label != "clear")
        return Fail(h, "aiobmark", "label 只允许 malware / benign / clear");

    // ⚠️ 必须用 JsonGetInt64：Unix 毫秒约 1.76e12，超 int32 上限 21 倍，
    //    走 JsonGetInt 会被截断成一个正负不定的随机数 → 打标打在完全错误的时间窗上。
    const long long since = sf::JsonGetInt64(req, "since");
    if (since <= 0)
        return Fail(h, "aiobmark", "需要 since=<Unix 毫秒>（只标注该时刻之后的样本）");

    sf::sfdb::Database* db = sf::mod::GlobalDb();
    if (!db || !sf::mod::GlobalDbReady())
        return Fail(h, "aiobmark", "数据库不可用（sfdb 未就绪）");

    // "clear" 是把标签抹掉（标错了要能撤回），映射成空串。
    const std::string val = (label == "clear") ? std::string() : label;
    sf::sfdb::ResultSet rs;
    if (!db->ExecOne("UPDATE ai_observe SET label = " + sf::sfdb::Database::Quote(val) +
                     " WHERE at >= " + std::to_string(since), rs))
        return Fail(h, "aiobmark", "标注失败：" + db->LastError());

    sf::LogDbg("[ai] 样本标注：" + label + "，" + std::to_string(rs.affected) +
               " 行（since=" + std::to_string(since) + "）");
    std::string j = "{\"cmd\":\"aiobmark\",\"ok\":true,\"data\":{";
    j += "\"label\":"   + sf::JsonString(label);
    j += ",\"marked\":"  + std::to_string(rs.affected);
    j += ",\"since\":"   + std::to_string(since);
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

// ===========================================================================
//                                                                  aiobtag
// ===========================================================================
//  给样本打**行为标签真值**（多头模型的 out[1..26]）。
//
//  ★ 为什么这个命令必须存在（而不是"以后再补"）：
//    银泊定的架构是「一个网络同时干两件事」—— 恶意判定 + 行为归因。
//    前者靠 label 监督（aiobmark 已有），后者**只能靠真值标签监督**。
//    没有这条命令时，多头里的 26 个标签头既无监督目标、输出也不落地，
//    "两个功能"在架构上成立、在功能上是空的。
//
//  ★ 为什么值必须人工给（不能顺手拿 verdict 里的规则 tag 当标签）：
//    verdict 是规则引擎的输出。拿它当监督目标，模型学的就是"复述规则"，
//    等于白训一个网络 + 白付一次前向开销（ailabels.h 开头写死了这条纪律）。
//    标签头真正要吃下的是**规则没命中、但行为画像相似的样本** ——
//    这只有拿"这个样本真实干了什么"当目标才学得到。
//    所以在虚拟机里跑完样本，由跑样本的人按时间窗把真实行为标上去。
//
//  ★ 三种取值，语义互不相同（训练器靠这个区分，见 train_sfm1.py 的 t 字段）：
//      tags=b64,iex   → 这些行为真的发生了
//      tags=none      → **确认**这个样本不呈现任何这些行为（标签目标全 0）
//      tags=clear     → 撤回标注，回到"未标注"（训练时 mask=0，不猜）
//    'none' 与 'clear' 看着像，但一个是"我确认它干净"、一个是"我不知道"。
//    混成一个的话，干净样本会被当成未标注样本丢掉 —— 而干净的良性样本
//    恰恰是压误报最值钱的那一半数据。
// 去掉首尾空白（空格/制表/回车/换行都算）。只服务于下面的标签键解析：
// common.h 里没有 Trim，为这一处去加一个公共函数不划算，就近放静态。
// 用 `<= ' '` 而不是 isspace()：命令行传进来的分隔符本来就只有 ASCII 空白，
// 而这个比较对 0x80 以上的字节是安全的（不会像 isspace 那样受 locale 影响）。
static std::string TagTrim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && (unsigned char)s[b] <= ' ') ++b;
    while (e > b && (unsigned char)s[e - 1] <= ' ') --e;
    return s.substr(b, e - b);
}

bool CmdAiObTag(HANDLE h, const std::string& req) {
    const std::string raw = sf::JsonGetString(req, "tags");
    if (raw.empty())
        return Fail(h, "aiobtag", "需要 tags=<none|clear|逗号分隔的标签键>，例如 tags=b64,iex");

    // ⚠️ 与 aiobmark 同理：Unix 毫秒超 int32 21 倍，走 JsonGetInt 会被截断成
    //    正负不定的随机数 → 标在完全错误的时间窗上（错的时间窗不报错，只是数据变脏）。
    const long long since = sf::JsonGetInt64(req, "since");
    if (since <= 0)
        return Fail(h, "aiobtag", "需要 since=<Unix 毫秒>（只标注该时刻之后的样本）");

    // 归一化：按**标签表顺序**排序 + 去重 + 校验。
    //   校验是这里唯一不能省的一步 —— 'iex' 敲成 'ieX' 若被静默接受，
    //   训练器会把这批样本的标签目标做成"全 0 + 一个不存在的键"，
    //   而训练**不会报任何错**，只是模型的那一个头永远学不出东西。
    //   所以拼错的键一律拒绝，并把合法键全列出来（省一次翻源码）。
    std::string val;
    if (raw == "clear") {
        val.clear();                       // 空串 = 未标注
    } else if (raw == "none") {
        val = "none";
    } else {
        std::vector<bool> hit(sf::ai::kAiLabelCount, false);
        size_t pos = 0;
        while (pos <= raw.size()) {
            size_t comma = raw.find(',', pos);
            std::string k = (comma == std::string::npos) ? raw.substr(pos)
                                                         : raw.substr(pos, comma - pos);
            k = TagTrim(k);
            if (!k.empty()) {
                int idx = -1;
                for (int i = 0; i < sf::ai::kAiLabelCount; ++i)
                    if (k == sf::ai::AiLabelKey(i)) { idx = i; break; }
                if (idx < 0) {
                    std::string all;
                    for (int i = 0; i < sf::ai::kAiLabelCount; ++i) {
                        if (i) all += " ";
                        all += sf::ai::AiLabelKey(i);
                    }
                    return Fail(h, "aiobtag", "未知标签键 '" + k + "'。合法键：" + all);
                }
                hit[(size_t)idx] = true;   // 去重；顺序交由下表统一决定
            }
            if (comma == std::string::npos) break;
            pos = comma + 1;
        }
        for (int i = 0; i < sf::ai::kAiLabelCount; ++i) {
            if (!hit[(size_t)i]) continue;
            if (!val.empty()) val += ",";
            val += sf::ai::AiLabelKey(i);   // ★ 一律按标签表顺序落地，与模型输出下标同序
        }
        if (val.empty())
            return Fail(h, "aiobtag", "tags 里没有任何有效标签键；要清空请用 tags=clear");
    }

    sf::sfdb::Database* db = sf::mod::GlobalDb();
    if (!db || !sf::mod::GlobalDbReady())
        return Fail(h, "aiobtag", "数据库不可用（sfdb 未就绪）");

    sf::sfdb::ResultSet rs;
    if (!db->ExecOne("UPDATE ai_observe SET tags = " + sf::sfdb::Database::Quote(val) +
                     " WHERE at >= " + std::to_string(since), rs))
        return Fail(h, "aiobtag", "标注失败：" + db->LastError());

    sf::LogDbg("[ai] 样本行为标注：" + (val.empty() ? std::string("(clear)") : val) + "，" +
               std::to_string(rs.affected) + " 行（since=" + std::to_string(since) + "）");
    std::string j = "{\"cmd\":\"aiobtag\",\"ok\":true,\"data\":{";
    j += "\"tags\":"   + sf::JsonString(val);
    j += ",\"tagged\":" + std::to_string(rs.affected);
    j += ",\"since\":"  + std::to_string(since);
    j += "}}";
    sf::WriteFramed(h, j);
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "aistat",      CmdAiStat      },
    { "aifeat",      CmdAiFeat      },
    { "aiscore",     CmdAiScore     },
    { "aimodelload", CmdAiModelLoad },
    // 影子模式（契约见 aiobserve.h）
    { "aiobstat",    CmdAiObStat    },
    { "aiobdump",    CmdAiObDump    },
    { "aiobclear",   CmdAiObClear   },
    { "aiobson",     CmdAiObOn      },
    { "aiobmark",    CmdAiObMark    },
    { "aiobtag",     CmdAiObTag     },
};

// ---------------------------------------------------------------- Init / Stop
bool InitAi() {
    g_aiDirW = DataDirW();
    g_modelPath = WideToUtf8(g_aiDirW + L"\\proxy_v1.sfm");

    // ★ 影子模式初始化（分配队列 + 读回开关）。
    //   放在装载模型**之前**：队列必须早于任何投递就绪，
    //   而模型装载是"可失败"的一步 —— 顺序反过来的话，模型装载耗时期间
    //   进来的投递会撞上"队列还没分配"（ObservePush 里会直接丢弃）。
    sf::ai::ObserveInit(g_aiDirW);

    // 启动时尝试装载；文件不存在是正常状态，不报错、不影响服务启动。
    std::unique_ptr<sf::ai::Model> m(new sf::ai::Model());
    if (m->Load(g_modelPath)) {
        sf::ai::ModelStats st = m->GetStats();
        g_model = std::move(m);
        sf::LogDbg("[ai] 启动时装载模型成功：" + std::to_string(st.layers) + " 层，" +
                   std::to_string(st.inDim) + "→" + std::to_string(st.outDim) +
                   "，标签 " + st.tag +
                   (st.kind == sf::ai::kKindMulti ?
                       ("（多头，" + std::to_string(g_model->LabelCount()) +
                        " 个行为标签头）") : "") +
                   (sf::ai::CheckDim(st.inDim) ? "" : "  ⚠️ 输入维度与本版本特征不符！"));
    } else {
        g_loadErr = m->LastError();
        sf::LogDbg("[ai] 未装载模型（" + g_loadErr + "）；特征提取与 aifeat/aiscore 照常可用");
    }
    // ★ 恒返回 true：见文件头「为什么 Init 恒返回 true」
    return true;
}

void StopAi() {
    // 顺序：先收观测队列，再放模型。
    // 反过来（先放模型）会让"仍在处理中的最后几条事件"在无模型状态下推理
    // —— 虽然主干保证线程已 join，这里仍然按"依赖倒序"写，避免将来有人
    // 加了别的线程后只改一处。
    sf::ai::ObserveShutdown();
    std::unique_lock<std::shared_mutex> lk(g_mlock);
    g_model.reset();
}

}  // namespace

// ===========================================================================
//  ★ 影子模式（shadow mode）—— 契约见 aiobserve.h
// ===========================================================================
//  这一段把 aifeat.h 的「平铺事实 → 48 维特征」与 sfdb 的 ai_observe 表接起来。
//
//  分两个半场，边界只有一条：
//      · 热路径（service.cpp 的进程判定链路）：ObservePush —— 只搬内存里的东西
//      · 观察线程（本文件持有）：ObserveProcess —— 所有 I/O 富化 + 推理 + 写库
//  为什么必须分开见 aiobserve.h 文件头（热路径有延迟预算，而富化要读 PE 签名、
//  版本资源、备用数据流、文件创建时间，还要 FlushFileBuffers）。
//
//  ★ 为什么这一段放在 `namespace sf::ai` 而不是上面那个匿名命名空间
//    因为 ObservePush / SetObserveEnabled 等是**跨模块契约**（声明在 aiobserve.h），
//    必须外部链接；而匿名命名空间里的东西是内部链接的。
//    私有实现（队列、线程体、写库）仍然是 static —— 不外泄任何内部细节。
namespace sf {
namespace ai {


// ===========================================================================
//  ★ 判定层查询接口实现（2026-10-03 EDR 闭环：模型从影子转正）
// ===========================================================================
//  声明在 aimodel.h。**实现在这里而不是 aimodel.cpp**，因为 g_model 是本文件的
//  匿名 namespace 成员（aimodel.cpp 访问不到）—— 由本文件持有模型的生命周期，
//  判定层只通过下面三个窄函数访问，避免绕过热切换管理拿到已卸载实例。
//
//  ★ 加锁用 shared_lock：与上面的 aiscore 同一条路，保证模型热切换期间
//   判定层要么拿到旧模型、要么拿到新模型，**绝不拿到"正在卸载"的半状态**。

bool GlobalModelLoaded() {
    std::shared_lock<std::shared_mutex> lk(g_mlock);
    return g_model && g_model->IsLoaded();
}

float GlobalModelScore(const FeatureVector& fv, bool* ok) {
    if (ok) *ok = false;
    std::shared_lock<std::shared_mutex> lk(g_mlock);
    // ★ 未装载 = 明确报"取不到"，**绝不返回 0**。
    //   返回 0 会被调用方当成"模型判定为 0 分"，等于用虚构判据影响处置。
    if (!g_model || !g_model->IsLoaded()) return 0.f;
    float s = g_model->Score(fv, ok);
    return s;
}

bool GlobalModelLabels(const FeatureVector& fv, float& score, std::vector<float>& labels) {
    std::shared_lock<std::shared_mutex> lk(g_mlock);
    if (!g_model || !g_model->IsLoaded()) { score = 0.f; labels.clear(); return false; }
    return g_model->ScoreLabels(fv, score, labels);
}
// ---------------------------------------------------------------------------
//  常量（改这里就能调影子模式的行为，数值都带上"为什么是这个数"）
// ---------------------------------------------------------------------------
//  队列上限 1024：一条事件约 2 个字符串（路径 ~60B + 命令行 ~200B），
//    1024 条 ≈ 数百 KB 常驻。**不是拍脑袋**：观察线程每轮最多排空 256 条，
//    500ms 一轮 → 处理能力约 512 条/秒；而进程创建在**人类使用**的机器上
//    峰值也就每秒几十个（编译/解压这类批量场景）。1024 的缓冲足够吸收突发。
const size_t    kObsQueueCap       = 1024;
const int       kObsDrainPerWake   = 256;     // 每轮最多处理这么多条（让出 CPU）
const DWORD     kObsIdleMs         = 250;     // 轮询间隔（见 RunAi 里的理由）
const long long kObsPruneEvery     = 512;     // 每写这么多条检查一次淘汰
const long long kObsMaxRows        = 20000;   // ai_observe 保留上限（约 4~8MB 文本）
const long long kObsCompactGapMs   = 6LL * 3600 * 1000;  // 两次 Compact 的最小间隔
const long long kObsLogEveryMs     = 5LL * 60 * 1000;    // 汇总日志间隔

// ---------------------------------------------------------------------------
//  状态
// ---------------------------------------------------------------------------
std::atomic<bool>  g_obsEnabled{false};
std::atomic<bool>  g_obsThreadUp{false};

// ★ 队列用**环形缓冲**而不是 std::deque：
//   deque 每次 push 都可能分配节点，而这条路径是"每次进程创建"都要走的。
//   环形缓冲在 Init 时一次性分配，之后 push 只做赋值 —— 字符串槽位会被复写，
//   容量得以复用，稳态下基本不碰堆。
std::mutex        g_obsMu;
std::vector<ObserveEvent> g_obsRing;
size_t            g_obsHead = 0;    // 下一个写入槽
size_t            g_obsTail = 0;    // 下一个读取槽
size_t            g_obsCount = 0;

std::atomic<long long> g_obsEnq{0}, g_obsDropFull{0}, g_obsDropOff{0};
std::atomic<long long> g_obsTaken{0}, g_obsWritten{0}, g_obsWriteFail{0};
std::atomic<long long> g_obsPruned{0}, g_obsHigh{0};
std::atomic<unsigned long long> g_obsSeq{0};   // 投递序号（构成唯一 id，见 aiobserve.h）

std::mutex  g_obsErrMu;
std::string g_obsLastErr;
// （原 g_obsDbReadyAtWrite 已删：它把"最近一次写库时的库可用性"缓存下来喂给统计，
//   结果是"还没写过任何东西"时 aiobstat 会显示 dbReady=false，读起来像库坏了。
//   现在 ObserveStats 直接实时问 GlobalDbReady()。）

long long   g_obsLastLogMs = 0;
long long   g_obsLastCompactMs = 0;

std::wstring g_obsCfgPathW;    // <ai>\ai_shadow.txt —— 开关的落盘位置

// ---------------------------------------------------------------------------
//  开关的持久化
// ---------------------------------------------------------------------------
//  默认**启用**：当前阶段影子模式存在的唯一目的就是攒语料，
//  默认关掉等于这个功能永远不工作（而它不会有任何报错）。
//  配置文件缺失 = 全新机器 = 启用；文件内容首字符 '0' = 关闭。
void WriteObsEnabledFile(bool on) {
    if (g_obsCfgPathW.empty()) return;
    HANDLE h = CreateFileW(g_obsCfgPathW.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    const char* s = on ? "1" : "0";
    DWORD w = 0;
    WriteFile(h, s, 1, &w, nullptr);
    CloseHandle(h);
}

bool ReadObsEnabledFile() {
    if (g_obsCfgPathW.empty()) return true;
    HANDLE h = CreateFileW(g_obsCfgPathW.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return true;   // 没有配置 → 默认启用
    char buf[8] = {0};
    DWORD rd = 0;
    ReadFile(h, buf, sizeof(buf) - 1, &rd, nullptr);
    CloseHandle(h);
    if (rd == 0) return true;
    return buf[0] != '0';
}

void SetLastErr(const std::string& why) {
    std::lock_guard<std::mutex> lk(g_obsErrMu);
    g_obsLastErr = why;
}

// ---------------------------------------------------------------------------
//  队列：取一条（只搬数据，不做 I/O；见 aiobserve.h 契约③）
// ---------------------------------------------------------------------------
//  ★ 刻意用拷贝而不是 move：move 会把槽位里的字符串掏空，
//    下一次 push 就得重新分配 —— 而 push 在热路径上。宁可让观察线程
//    （完全空闲）多付一次拷贝。
static bool ObsTake(ObserveEvent& out) {
    std::lock_guard<std::mutex> lk(g_obsMu);
    if (g_obsCount == 0) return false;
    out = g_obsRing[g_obsTail];
    g_obsTail = (g_obsTail + 1) % g_obsRing.size();
    --g_obsCount;
    return true;
}

// ---------------------------------------------------------------------------
//  投递（**热路径** —— 任何 I/O 都不能出现在这里）
// ---------------------------------------------------------------------------
void ObservePush(const ObserveEvent& e) {
    if (!g_obsEnabled.load(std::memory_order_relaxed)) {
        g_obsDropOff.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    // 空事件直接丢：它只会占一个槽位而没有任何信息。
    if (e.pid == 0 && e.imagePath.empty()) return;

    std::lock_guard<std::mutex> lk(g_obsMu);
    if (g_obsRing.empty()) return;              // Init 还没跑（或分配失败）
    if (g_obsCount >= g_obsRing.size()) {
        // ★ 满即丢，绝不阻塞、绝不等候 —— 样本可以少，拦截不能慢。
        g_obsDropFull.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    g_obsRing[g_obsHead] = e;
    // ★ 入队即分配投递序号（见 aiobserve.h 里 seq 字段的说明）：
    //   (pid, atUnixMs) 不足以唯一 —— ETW 与 WMI 两个事件源可能在同一毫秒
    //   投递同一个进程，撞主键后第二条会被丢掉并推高 writeFail（假故障）。
    g_obsRing[g_obsHead].seq = g_obsSeq.fetch_add(1, std::memory_order_relaxed) + 1;
    g_obsHead = (g_obsHead + 1) % g_obsRing.size();
    ++g_obsCount;
    g_obsEnq.fetch_add(1, std::memory_order_relaxed);

    const long long hi = (long long)g_obsCount;
    if (hi > g_obsHigh.load(std::memory_order_relaxed))
        g_obsHigh.store(hi, std::memory_order_relaxed);
}

void SetObserveEnabled(bool on) {
    g_obsEnabled.store(on, std::memory_order_release);
    WriteObsEnabledFile(on);
    sf::LogDbg(std::string("[ai] 影子模式已") + (on ? "启用" : "停用") +
               "（本次运行内即时生效；开关已落盘）");
}

bool ObserveEnabled() {
    return g_obsEnabled.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
//  文件大小（富化用；取不到返回 -1）
// ---------------------------------------------------------------------------
static long long ObsFileSize(const std::string& pathUtf8) {
    if (pathUtf8.empty()) return -1;
    std::wstring w = Utf8ToWide(pathUtf8);
    if (w.empty()) return -1;
    WIN32_FILE_ATTRIBUTE_DATA d{};
    if (!GetFileAttributesExW(w.c_str(), GetFileExInfoStandard, &d)) return -1;
    return ((long long)d.nFileSizeHigh << 32) | (long long)d.nFileSizeLow;
}

// 规则引擎结论 → 一个短标签。
// ★ 为什么要把 lv 名字化而不直接存数字：verdict 这一列是人来读的，
//   而 `clean/suspect/blocked` 在导出的 CSV 里一眼能懂，`0/1/2` 不行。
//   标签（tag）拼在后面还是分两列？这里选择拼成一列：
//   tag 是"为什么"（判据名），和结论是同一件事的两个侧面，拆开会出现
//   "有结论无理由"的半截行；拼起来 TEXT 列也不长（如 blocked:ps-encoded）。
static std::string ObsVerdictText(const ObserveEvent& e) {
    std::string v = (e.ruleLevel >= 2) ? "blocked" : (e.ruleLevel == 1 ? "suspect" : "clean");
    if (!e.ruleTag.empty()) v += ":" + e.ruleTag;
    return v;
}

// ---------------------------------------------------------------------------
//  淘汰（表不能无限长；策略与"为什么"见下方注释）
// ---------------------------------------------------------------------------
static void ObsMaybePrune(sf::sfdb::Database* db) {
    long long n = 0;
    if (!db->QueryInt("SELECT COUNT(*) FROM ai_observe", n)) return;
    if (n <= kObsMaxRows) return;

    // 取"第 kObsMaxRows 新"那一行的 at 作为截止点，把更旧的删掉。
    // ★ 为什么不用子查询（DELETE ... WHERE at < (SELECT ...)）：
    //   本引擎不支持子查询（能力边界见 sfdb_sql.cpp 文件头），
    //   但支持 ORDER BY + LIMIT 1 OFFSET n —— 两条语句达到同样效果。
    long long cut = 0;
    if (!db->QueryInt("SELECT at FROM ai_observe ORDER BY at DESC LIMIT 1 OFFSET " +
                      std::to_string(kObsMaxRows), cut)) return;
    if (cut <= 0) return;

    sf::sfdb::ResultSet rs;
    if (!db->ExecOne("DELETE FROM ai_observe WHERE at < " + std::to_string(cut), rs)) {
        SetLastErr("淘汰失败：" + db->LastError());
        return;
    }
    g_obsPruned.fetch_add(rs.affected, std::memory_order_relaxed);

    // 删除只是打墓碑，文件不会变小（追加式存储）。引擎自己会置 dirty，
    // 但 Compact 是重写整个文件，不能每删一次就跑 —— 用时间间隔压制频率。
    sf::sfdb::Stats st = db->GetStats();
    const long long nowMs = NowUnixMs();
    if (st.dirty && (nowMs - g_obsLastCompactMs) > kObsCompactGapMs) {
        g_obsLastCompactMs = nowMs;
        db->Compact();
        sf::LogDbg("[ai] ai_observe 已压缩（淘汰墓碑，回收磁盘）");
    }
}

// ---------------------------------------------------------------------------
//  处理一条事件：富化 → 特征 → 推理 → 入库
// ---------------------------------------------------------------------------
//  ⚠️ 本函数**只允许**在观察线程上被调用。它做大量 I/O，
//     放在热路径上会直接拖慢进程判定（见 aiobserve.h）。
static void ObsProcessOne(const ObserveEvent& e) {
    ObserveEvent ev = e;   // 取局部副本，后续不动队列槽位

    // ---- ① 热路径已给的"平铺事实" ----
    FeatureInput in;
    in.imagePath         = ev.imagePath;
    in.commandLine       = ev.commandLine;
    in.parentImagePath   = ev.parentImagePath;
    in.ruleLevel         = ev.ruleLevel;
    in.ruleScore         = ev.ruleScore;
    in.ruleHard          = ev.ruleHard;
    in.ruleTag           = ev.ruleTag;
    in.softLandedLv      = ev.softLandedLv;
    in.softLandedSysZone = ev.softLandedSysZone;

    // ---- ② 需要 I/O 的部分：只在这条线程上做 ----
    //  ★ 全部复用 scanner.h 导出的**实时链路同一份**判据。
    //    在这里另写一份（哪怕只是"更宽松一点"）都会造成特征与线上判据分叉，
    //    而分叉是静默的 —— 两边日志都正常，只是不再是同一个东西。
    in.signedImage      = IsFileSignatureTrusted(ev.imagePath);
    in.hasVendorInfo    = HasVendorInfo(ev.imagePath);
    in.fileNameIsRandom = IsShortRandomFileName(ev.imagePath);
    in.hasAds            = FileHasSuspiciousAds(ev.imagePath);
    // ★ -1（未知）必须原样传下去：0 的含义是"刚刚创建"，是强可疑信号。
    //   把"读不到"折算成 0 会凭空加分，且完全静默。
    in.createdAtAgeSec  = FileCreatedAgeSec(ev.imagePath);
    in.fileSizeBytes    = ObsFileSize(ev.imagePath);
    if (!ev.parentImagePath.empty())
        in.signedParent = IsFileSignatureTrusted(ev.parentImagePath);

    FeatureVector fv = BuildFeatures(in);

    // ---- ③ 推理（可选）----
    //  ★ 没有模型**不是错误**：影子模式的首要任务是攒特征 + 规则结论，
    //    模型是后一步才有的东西。aiscore 记 **-1**（"当时无模型"），
    //    绝不记 0 —— 0 分的意思是"AI 认为不可疑"，那是一个结论。
    int aiscore = -1;
    {
        std::shared_lock<std::shared_mutex> lk(g_mlock);
        if (g_model && g_model->IsLoaded()) {
            bool ok = false;
            float s = 0.f;
            if (g_model->LabelCount() > 0) {
                std::vector<float> labels;   // 影子模式只存恶意分，标签不落库
                ok = g_model->ScoreLabels(fv, s, labels);
            } else {
                s = g_model->Score(fv, &ok);
            }
            if (ok) {
                int v = (int)(s * 100.f + 0.5f);
                if (v < 0)   v = 0;
                if (v > 100) v = 100;
                aiscore = v;
            }
        }
    }

    // ---- ④ 入库 ----
    sf::sfdb::Database* db = sf::mod::GlobalDb();
    if (!db || !sf::mod::GlobalDbReady()) {
        g_obsWriteFail.fetch_add(1, std::memory_order_relaxed);
        SetLastErr("库不可用（sfdb 未就绪）");
        return;
    }

    // id = 事件时间毫秒 + "-" + pid + "-" + 投递序号。
    //   为什么不只用 at-pid：ETW 与 WMI 两个事件源投递同一进程时可能落在同一毫秒
    //   → 撞主键 → 第二条被丢 + writeFail 虚高（表现成"库写不进去"的假故障）。
    //   序号由 ObservePush 在入队时分配，全局单调，所以 id 必唯一。
    const std::string id = std::to_string(ev.atUnixMs) + "-" + std::to_string(ev.pid) +
                           "-" + std::to_string(ev.seq);

    // ⚠️ 这里的每个字符串都必须过 Quote()：命令行里出现单引号是常态
    //    （`-Command "..."` / 路径带引号），不过转义会让 SQL 直接语法错，
    //    整条样本丢失 —— 而且错误看起来像"引擎坏了"。
    std::string sql = "INSERT INTO ai_observe (id, at, proc, path, cmd, score, verdict, aiscore, label, tags, feat) VALUES (";
    sql += sf::sfdb::Database::Quote(id);                       sql += ",";
    sql += std::to_string(ev.atUnixMs);                         sql += ",";
    sql += sf::sfdb::Database::Quote(sf::BaseName(ev.imagePath)); sql += ",";
    sql += sf::sfdb::Database::Quote(ev.imagePath);              sql += ",";
    sql += sf::sfdb::Database::Quote(ev.commandLine);            sql += ",";
    sql += std::to_string(ev.ruleScore);                         sql += ",";
    sql += sf::sfdb::Database::Quote(ObsVerdictText(ev));        sql += ",";
    sql += std::to_string(aiscore);                              sql += ",";
    sql += "''";                                                 sql += ",";  // label：自动采集一律留空
    sql += "''";                                                 sql += ",";  // tags：同上，只能事后 aiobtag
    sql += sf::sfdb::Database::Quote(fv.ToText());
    sql += ")";

    sf::sfdb::ResultSet rs;
    if (!db->ExecOne(sql, rs)) {
        g_obsWriteFail.fetch_add(1, std::memory_order_relaxed);
        SetLastErr(db->LastError());
        return;
    }
    g_obsWritten.fetch_add(1, std::memory_order_relaxed);

    const long long w = g_obsWritten.load(std::memory_order_relaxed);
    if (w == 1) {
        sf::LogDbg("[ai] 影子模式首条样本已落库：id=" + id + " verdict=" + ObsVerdictText(ev) +
                   " aiscore=" + std::to_string(aiscore) + " path=" + ev.imagePath);
    }
    if ((w % kObsPruneEvery) == 0) ObsMaybePrune(db);
}

// ---------------------------------------------------------------------------
//  观察线程体
// ---------------------------------------------------------------------------
//  ★ 为什么用**轮询**而不是"投递时 SetEvent 唤醒"：
//    SetEvent 是一次内核调用，而投递发生在实时判定链路上 ——
//    为了"样本早 250ms 落库"多付一次系统调用不划算（那条路径有延迟预算）。
//    250ms 的落库延迟对训练语料毫无影响：样本是拿来离线训练的，
//    不是拿来实时响应的。这条取舍与 aiobserve.h 的分工是同一件事的两面。
static void RunAi() {
    sf::LogDbg("[ai] 影子模式观察线程已启动（enabled=" +
               std::string(g_obsEnabled.load() ? "1" : "0") +
               "，队列上限 " + std::to_string(g_obsRing.size()) + "）");
    g_obsThreadUp.store(true, std::memory_order_release);

    ObserveEvent e;
    while (!sf::IsStopRequested()) {
        // ★ StopHandle() **可能为空**（脱离服务环境的回归程序），必须先判空 ——
        //   这条范式写在 sfstop.h 的文件头里，全项目统一。
        HANDLE h = sf::StopHandle();
        if (h) {
            if (WaitForSingleObject(h, kObsIdleMs) != WAIT_TIMEOUT) break;
        } else {
            Sleep(kObsIdleMs);
        }

        int drained = 0;
        while (drained < kObsDrainPerWake && ObsTake(e)) {
            ++drained;
            g_obsTaken.fetch_add(1, std::memory_order_relaxed);
            ObsProcessOne(e);
        }

        // 汇总日志：**不要一条样本一行日志** —— 那会把 guard.log 冲垮，
        // 而日志是本项目最重要的排查手段（冲垮之后真正的故障就看不见了）。
        const long long nowMs = NowUnixMs();
        if (nowMs - g_obsLastLogMs >= kObsLogEveryMs) {
            g_obsLastLogMs = nowMs;
            ObserveStat st = ObserveStats();
            if (st.enqueued > 0 || st.droppedFull > 0) {
                sf::LogDbg("[ai] 影子模式汇总：入队 " + std::to_string(st.enqueued) +
                           "，已写库 " + std::to_string(st.written) +
                           "，写失败 " + std::to_string(st.writeFail) +
                           "，队列满丢 " + std::to_string(st.droppedFull) +
                           "，当前水位 " + std::to_string(st.queueNow) + "/" +
                           std::to_string(st.queueHigh) +
                           (st.lastErr.empty() ? std::string() : ("，最近错误：" + st.lastErr)));
            }
        }
    }
    g_obsThreadUp.store(false, std::memory_order_release);
    sf::LogDbg("[ai] 影子模式观察线程已退出（累计写库 " +
               std::to_string(g_obsWritten.load()) + " 条，" +
               std::to_string(g_obsDropFull.load()) + " 条因队列满丢弃，" +
               std::to_string(g_obsWriteFail.load()) + " 条写失败）");
}

// ---------------------------------------------------------------------------
//  Init / Stop 钩子（由本文件的 InitAi / StopAi 调用；刻意不进 aiobserve.h）
// ---------------------------------------------------------------------------
static void ObserveInit(const std::wstring& aiDirW) {
    g_obsCfgPathW = aiDirW + L"\\ai_shadow.txt";
    {
        std::lock_guard<std::mutex> lk(g_obsMu);
        g_obsRing.assign(kObsQueueCap, ObserveEvent());
        g_obsHead = g_obsTail = g_obsCount = 0;
    }
    const bool on = ReadObsEnabledFile();
    g_obsEnabled.store(on, std::memory_order_release);
    g_obsLastLogMs = NowUnixMs();
    sf::LogDbg(std::string("[ai] 影子模式：") + (on ? "已启用" : "已停用（ai_shadow.txt=0）") +
               "，队列上限 " + std::to_string(kObsQueueCap) +
               "，表上限 " + std::to_string(kObsMaxRows) + " 行");
}

static void ObserveShutdown() {
    // 线程此刻已被主干 join（见 module.cpp 的 StopAll 两步走），
    // 所以这里碰队列不需要加锁；仍然加一下，代价为零。
    {
        std::lock_guard<std::mutex> lk(g_obsMu);
        g_obsHead = g_obsTail = g_obsCount = 0;
    }
}

// ---------------------------------------------------------------------------
//  统计与清空
// ---------------------------------------------------------------------------
ObserveStat ObserveStats() {
    ObserveStat s;
    s.enabled     = g_obsEnabled.load(std::memory_order_acquire);
    s.threadUp    = g_obsThreadUp.load(std::memory_order_acquire);
    s.enqueued    = g_obsEnq.load();
    s.droppedFull = g_obsDropFull.load();
    s.droppedOff  = g_obsDropOff.load();
    s.taken       = g_obsTaken.load();
    s.written     = g_obsWritten.load();
    s.writeFail   = g_obsWriteFail.load();
    s.pruned      = g_obsPruned.load();
    s.queueHigh   = g_obsHigh.load();
    {
        std::lock_guard<std::mutex> lk(g_obsMu);
        s.queueNow = (int)g_obsCount;
    }
    s.dbReady = sf::mod::GlobalDbReady();   // 实时求值，见 aiobserve.h 该字段的说明
    {
        std::lock_guard<std::mutex> lk(g_obsErrMu);
        s.lastErr = g_obsLastErr;
    }
    return s;
}

void ObserveResetStats() {
    g_obsEnq = 0; g_obsDropFull = 0; g_obsDropOff = 0;
    g_obsTaken = 0; g_obsWritten = 0; g_obsWriteFail = 0;
    g_obsPruned = 0;
    std::lock_guard<std::mutex> lk(g_obsErrMu);
    g_obsLastErr.clear();
}

}  // namespace ai
}  // namespace sf

namespace sf {
namespace mod {

extern const Module kModule_ai = {
    "ai",
    InitAi,         // Init：建目录 + 尝试装载模型（失败不致命）
    // Run：★ 影子模式观察线程（见 aiobserve.h 的分工）。
    // 它在本 TU 里是 static（内部链接）—— 主干只需要一个函数指针，
    // 没必要把它变成对外的符号；"只有本文件知道它"才是正确的可见性。
    sf::ai::RunAi,
    StopAi,         // Stop：释放 mmap 视图（线程已被主干 join）
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
