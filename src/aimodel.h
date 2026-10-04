// aimodel.h — AI 引擎的模型格式与前向推理（自研，零第三方依赖）
//
// ===========================================================================
//  为什么自己定格式，而不是用 ONNX / 某个 runtime
// ===========================================================================
//  与「不用微软 ESE」是同一套判断：
//    · 交付约束是**单 EXE、零第三方依赖**（/MT 静态链接，不装任何运行库）。
//      任何 nn runtime 都会引入一个 DLL 或一份可观的静态体积。
//    · 本引擎只需要一种极窄的能力：**定长输入 → 定长输出的多层感知机**。
//      没有卷积、没有注意力、没有动态形状、没有批量推理。
//    · 可审查性：整个文件格式在一屏里能画完（见下），
//      出问题时能直接 hexdump 出结论；ONNX 出问题只能靠工具链。
//  代价是"训练侧也要自己导出"。缓解办法：训练在离线脚本里做，
//  导出成这个格式只是写几十行字节 —— 而**推理侧**才是要上用户机器的那部分。
//
// ===========================================================================
//  文件格式（全部小端）
// ===========================================================================
//      ┌───────────────── 64 字节头 ─────────────────┐
//      │ magic(4)='SFM1' version(4)=1 kind(4)=1|2    │
//      │ layers(4) inDim(4) outDim(4) reserved(8)    │
//      │ createdAtUnix(8) tag(8) reserved(8)         │
//      │ checksum(8)                                 │
//      ├──── 层描述符 layers × 16 字节 ───────────────┤
//      │ inDim(4) outDim(4) act(4) reserved(4)       │
//      ├──── 权重区（按层顺序连续排布）───────────────┤
//      │ 第 0 层 W[outDim][inDim] float32（行主序）   │
//      │ 第 0 层 b[outDim]        float32            │
//      │ 第 1 层 W … 第 1 层 b …                     │
//      └─────────────────────────────────────────────┘
//
//  · 前向计算：y_j = act( Σ_i W[j*inDim + i] · x_i + b_j )
//  · act：0=线性 1=ReLU 2=Sigmoid 3=Tanh。输出层用 Sigmoid → 分数落在 [0,1]，
//    正好与规则引擎的"分数"直觉一致（越大越可疑）。
//  · checksum = 权重区的 FNV-1a 64。**只做损坏检测，不做篡改防护** ——
//    要防篡改得对模型文件本身签名，与云库哈希库一样属于部署链的事（留待后续）。
//    它挡的是"文件长度对、内容坏了"这一类：写盘中途掉电、磁盘坏块、被截断后补零。
//    ⚠️ 没有它的话，坏权重会算出一个**看起来完全正常的分数**，这是最难发现的失败。
//
// ===========================================================================
//  kind 的两种取值：一个网络怎么同时干两件事
// ===========================================================================
//  原计划里「病毒行为判定」与「程序行为归因」是两条线，很容易顺势做成两个网络。
//  但**一个模型的槽里本来就装得下两个功能，一个字节都不用改** ——
//  outDim 本来就是变量、Forward 本来就返回 OutDim() 个值、kind 字段本来就空着。
//  所以不新增格式，只给 kind 定一个含义：
//
//      kind = 1（kKindMlp）    纯 MLP：outDim 个输出**没有约定语义**。
//                              只有 outDim == 1 时才允许被当作"分数"（Score）。
//                              这是 v1 老模型，必须永远能被读出来。
//
//      kind = 2（kKindMulti）  多头 MLP：outDim = 1 + k
//                                out[0]     = 恶意分（模型①：拦不拦）∈[0,1]
//                                out[1..k]  = 行为标签置信度（模型②：像什么）∈[0,1]
//
//  ★ 为什么这**真的**是多头，而不是"凑数"
//    最后一层的权重是 W[outDim][hidden]，**每一行独立**。也就是说这一层本来就等价于
//    outDim 个各自独立的分类器，叠在同一份隐藏特征上 —— 这正是「共享 trunk + 多头」
//    的标准形状。加一个输出维度 = 加一个头，前面所有层（trunk）自动被两个任务共享。
//    共享 trunk 还有一个实打实的好处：两个任务互为正则，标签头的监督信号会反过来
//    压住恶意分那一头的过拟合 —— 样本少的时候这一条比"多一个网络"值钱得多。
//
//  ★ 为什么末层用 Sigmoid
//    恶意分要落在 [0,1]（与规则引擎的"分数"直觉一致，越大越可疑）；
//    每个标签是**互相独立**的二分类（一个程序可以同时"像 RAT"又"像持久化"），
//    也是各自一个 [0,1] 置信度。两边要的东西一样，所以末层一个 kActSigmoid 全覆盖。
//    ⚠️ 这里**不能**用 Softmax：Softmax 让各输出加和为 1、彼此互斥，
//       而"注入"和"持久化"从来都不互斥。
//
//  ★ 为什么 kind=1 且 outDim>=2 仍然被 Score 拒绝（见 Model::Score）
//    那种模型没有任何"哪一维是分数"的约定，取第 0 维纯属猜。宁可拒绝，
//    也不要给一个**来源不明的分数**——分数会被喂进评分层，来源不明就是隐患。
//    要出分数就显式声明 kind=2，把语义写进文件里。
//
// ===========================================================================
//  线程安全
// ===========================================================================
//  装载后**只读**，mmap 视图天然可多线程并发读。Forward 内部只用栈/局部缓冲，
//  不持有任何可变状态 —— 所以同一个 Model 可以被多条线程同时调用。
//  （计数器用原子、错误文本用短锁保护：这两处是 const 方法里唯一会写的东西，
//    裸写就是真实的数据竞争，而不是"理论上的"。）
//  唯一的竞争点是 Load / Unload 与 Forward 之间，由调用方保证（与 hashdb 同）。
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "aifeat.h"   // FeatureVector（Score 便捷入口需要）

namespace sf {
namespace ai {

// 激活函数编号（写进文件，**已有编号含义永不改变**）
enum Act : int {
    kActLinear  = 0,
    kActRelu    = 1,
    kActSigmoid = 2,
    kActTanh    = 3,
};

// 模型类型（写进文件头 kind 字段，**已有编号含义永不改变**）
// 详见文件头「kind 的两种取值」。
enum Kind : int {
    kKindMlp   = 1,   // 纯 MLP：outDim 个输出无语义约定，仅 outDim==1 时可当分数
    kKindMulti = 2,   // 多头 MLP：outDim = 1 + k，out[0]=恶意分，out[1..k]=行为标签
};

struct ModelStats {
    std::string path;
    bool        open      = false;
    int         kind      = 0;
    int         layers    = 0;
    int         inDim     = 0;
    int         outDim    = 0;
    std::string tag;
    long long   createdAtUnix = 0;
    long long   fileBytes = 0;
    long long   paramCount = 0;      // 权重 + 偏置的浮点个数
    long long   forwards  = 0;       // 本进程前向次数
};

// ===========================================================================
//  ★ 判定层查询接口（2026-10-03 EDR 闭环：模型从影子转正）
// ===========================================================================
//  【为什么需要这两个函数】
//  推理能力早就完备（Model::Score / ScoreLabels / BuildFeatures 全部就位），
//  但**判定层从未调用过** —— 此前只有 mod_ai.cpp 在统计查询与自测里用它。
//  这就是架构对比里说的「建了发动机没装在车上」：
//     三家（西瓜/PYAS/HeySafe-X）都有独立的模型/IOA 判定层；
//     我们有模型、有语料、有推理，**唯独判定层不接**。
//
//  【为什么不直接暴露 g_model】
//    g_model 由 mod_ai.cpp 持有并负责加载/卸载/热切换，
//    判定层直接拿裸指针会绕过它的生命周期管理（模型热切换时可能拿到已卸载实例）。
//    ⇒ 这里提供**窄接口**，与 g_model 同一个实例，不重复加载、不重复占内存。
//
//  【★ 硬纪律：未装载模型时必须返回 ok=false，调用方据此「不加权」】
//    绝不能返回一个"看起来正常"的默认分数 —— 那等于用虚构的判据影响处置，
//    是本产品明确禁止的（铁律：判据缺失必须可观测、不得静默补默认值）。
bool GlobalModelLoaded();

//  取模型给出的恶意分（0~1）。ok=false 表示**取不到**（未装载/维度不符/输入含 NaN），
//  此时 score 不可用，调用方**必须**跳过模型加权。
float GlobalModelScore(const FeatureVector& fv, bool* ok = nullptr);

//  多头模型的标签分（供告警文案与可解释性使用）。仅 kind=2 可用，否则返回 false。
bool GlobalModelLabels(const FeatureVector& fv, float& score, std::vector<float>& labels);

// ===========================================================================
//  只读推理
// ===========================================================================
class Model {
public:
    Model();
    ~Model();

    Model(const Model&)            = delete;
    Model& operator=(const Model&) = delete;

    bool Load(const std::string& pathUtf8);   // UTF-8 路径；只读 mmap
    void Unload();
    bool IsLoaded() const;
    std::string LastError() const;

    int InDim() const;
    int OutDim() const;
    int Layers() const;
    int KindId() const;           // 文件头 kind 字段（未装载时为 0）
    int LabelCount() const;       // 多头模型（kind=2）的标签头个数 k = OutDim()-1；非多头为 0
    std::string Tag() const;
    long long CreatedAtUnix() const;

    // 前向推理。inLen 必须等于 InDim()；out 被写成 OutDim() 个值。
    // 任何长度不符 / 未装载 / 输入含 NaN 都返回 false（**绝不返回一个"看起来正常"的分数**）。
    bool Forward(const float* in, int inLen, std::vector<float>& out) const;

    // 便捷入口：特征向量 → 全部输出（要求 InDim() == kFeatureDim）。
    // out 被写成 OutDim() 个值；kind=2 时 out[0]=恶意分、out[1..]=行为标签。
    bool Predict(const FeatureVector& fv, std::vector<float>& out) const;

    // 便捷入口：特征向量 → 单值分数。
    //   接受：kind=1 且 OutDim()==1（v1 老模型），或 kind=2（**out[0] 就是恶意分**）。
    //   拒绝：kind=1 且 OutDim()!=1 —— 那种模型没有"哪一维是分数"的约定，
    //         取第 0 维纯属猜（理由见文件头）。失败时返回 0 且 *ok=false。
    // ok 可为 nullptr；失败时返回 0。
    float Score(const FeatureVector& fv, bool* ok = nullptr) const;

    // 便捷入口：特征向量 → （恶意分 + 标签向量）。**仅 kind=2**，其余一律返回 false。
    // labels 被写成 LabelCount() 个值，下标 0 对应标签表第 0 项。
    bool ScoreLabels(const FeatureVector& fv, float& score,
                     std::vector<float>& labels) const;

    ModelStats GetStats() const;

private:
    struct Impl;
    Impl* p_;
};

// ===========================================================================
//  构造（离线训练导出 / 测试造模型时用）
// ===========================================================================
//  用法：
//      sf::ai::Builder b(kFeatureDim, 1, "proxy-v1");
//      b.AddLayer(kActRelu,    w0, 16, bias0);
//      b.AddLayer(kActSigmoid, w1, 1,  bias1);
//      b.Build("C:\\ProgramData\\SilverFoxGuard\\ai\\proxy_v1.sfm");
//
//  多头（一个网络同时出恶意分 + 行为标签）：
//      sf::ai::Builder b(kFeatureDim, 1 + kLabels, "proxy-v1", sf::ai::kKindMulti);
//      b.AddLayer(kActRelu,    w0, 32, b0);
//      b.AddLayer(kActSigmoid, w1, 1 + kLabels, b1);   // out[0] 恶意分，其余是标签
//      b.Build("...\\ai\\proxy_v1.sfm");
//      ⚠️ 多头的最后一层**必须**是 kActSigmoid：out[0] 要落在 [0,1] 当分数用，
//         各标签头也要各自一个 [0,1] 置信度（不能 Softmax，标签之间不互斥）。
class Builder {
public:
    // kind 默认 kKindMlp —— 既有单输出调用点不用改。造多头模型时传 kKindMulti，
    // 此时 outDim 必须 >= 2（out[0] 是恶意分，剩 outDim-1 个是标签头）。
    Builder(int inDim, int outDim, const std::string& tag, int kind = kKindMlp);
    ~Builder();

    Builder(const Builder&)            = delete;
    Builder& operator=(const Builder&) = delete;

    // 逐层追加。W 长度 = outDim × 本层输入维度（本层输入维度 = 上一层的 outDim，
    // 第一层为本构造的 inDim）；b 长度 = outDim。
    // 本层的 outDim 必须等于下一层的输入维度，最后一层必须等于构造时的 outDim ——
    // 这两条在 Build 时统一校验（提前校验会漏掉"最后一层对不上"这一种）。
    bool AddLayer(int act, const float* W, int outDim, const float* b);

    int  LayerCount() const;
    long long ParamCount() const;
    int  KindId() const;

    // 写 .tmp → FlushFileBuffers → MoveFileEx 原子替换。
    // 中途失败/掉电时目标路径上的旧模型完好无损（与 sfdb::Compact、hashdb::Build 同）。
    bool Build(const std::string& pathUtf8);

    std::string LastError() const;

private:
    struct Impl;
    Impl* p_;
};

}  // namespace ai
}  // namespace sf
