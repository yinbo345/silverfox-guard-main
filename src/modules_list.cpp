// modules_list.cpp — 分体清单（主干式架构里**唯一**需要手工登记的地方）
//
// ===========================================================================
//  加一个新分体的完整步骤（就这两步，没有第三处）
// ===========================================================================
//   ① 新建 `src/mod_xxx.cpp`：
//
//        #include "module.h"
//        #include "common.h"      // LogDbg / JsonString / JsonGetInt ...
//
//        static bool CmdXxxList(HANDLE h, const std::string& req) {
//            WriteFramed(h, "{\"cmd\":\"xxxlist\",\"ok\":true}");
//            return true;         // true = 已处理，主干读下一帧
//        }
//        static const sf::mod::CmdEntry kCmds[] = { { "xxxlist", CmdXxxList } };
//
//        namespace sf { namespace mod {
//        // ★ 对象名必须是 kModule_<清单里的名字>，这是唯一约定
//        // ★ 必须带 extern：否则 const 变量是内部链接，链接期报 LNK2001
//        extern const Module kModule_xxx = {
//            "xxx",          // 分体名（日志用）
//            nullptr,        // Init（可空）
//            nullptr,        // Run（可空；非空 → 主干起独立线程 + 自动 join）
//            nullptr,        // Stop（可空）
//            kCmds, 1        // 命令表
//        };
//        }}
//
//   ② 在下面的 SF_MODULE_LIST 里加一行 `X(xxx)`
//
//  构建脚本用通配符收录 src/*.cpp，所以**不需要**改 build.sh；
//  管道服务端查表分发，所以**不需要**改 service.cpp；
//  GUI 转发由主干统一处理，所以**不需要**改 gui.cpp。
//
// ===========================================================================
//  ★ 顺序即启动顺序
// ===========================================================================
//  StartAll() 按本清单顺序逐个 Init / 起线程；StopAll() **逆序** join + Stop。
//  排列原则：无依赖的基础分体在前，依赖他人运行结果的分体在后。
//  例：boot/keys 这类"读一个状态就返回"的分体放前面，rollback 这类
//  需要窗口期观察的分体放后面。
//
// ===========================================================================
//  ⚠️ X-Macro 的写法说明（它看起来怪，但换来的是"加分体只改一行"）
// ===========================================================================
//  SF_MODULE_LIST 本身不产生任何代码，只保存"有哪些分体"这一事实。
//  下面用它展开两次：一次生成 extern 声明，一次生成指针数组。
//  这样两处永远不会不同步 —— 手工维护两个列表必然会出现"声明了但没进数组"
//  （症状：分体编译进去却从没被启动，且不报任何错）。
#include "module.h"

namespace sf {
namespace mod {

// ---------------------------------------------------------------------------
//  ★ 分体清单：加一行即可
// ---------------------------------------------------------------------------
//  ★ sfdb / ai 刻意放在**最后**：它们都要在启动时做 mmap 装载
//    （sfdb = 自研 SQL 库 + 云端哈希库，ai = 只读推理模型），
//    是一段有磁盘 I/O 的初始化。没有任何分体依赖它们，所以放最后 ——
//    万一磁盘慢/文件大，拖慢的也只是它们自己，不会让 boot / keys / behavior
//    这些真正管拦截的分体晚挂载。
//    ai 排在 sfdb 之后：模型文件比库小得多，而 sfdb 的日志重放可能更慢。
//  ★ lib 必须排在 sfdb **之后**：它自己不碰正式库文件，只负责网络下载 + 暂存，
//    真正的「替换 + 重载」要调 sf::hashshare::InstallCloudLibs()，
//    而那是 mod_sfdb 的实现 → sfdb 没 Init 完它就找不到库路径与验签状态。
//    lib 排在 ai 之前：它只是起一个节流线程，不阻塞启动。
#define SF_MODULE_LIST(X) \
    X(boot)               \
    X(keys)               \
    X(behavior)           \
    X(gpu)                \
    X(packscan)           \
    X(iowatch)            \
    X(auditapi)           \
    X(sfdb)               \
    X(lib)                \
    X(ai)                 \
    X(sandbox)

// 展开 1：extern 声明
#define SF_DECL(n) extern const Module kModule_##n;
SF_MODULE_LIST(SF_DECL)
#undef SF_DECL

// 展开 2：指针数组（顺序 = 启动顺序）
const Module* const kAllModules[] = {
#define SF_ENTRY(n) &kModule_##n,
    SF_MODULE_LIST(SF_ENTRY)
#undef SF_ENTRY
};
#undef SF_MODULE_LIST

static const size_t kAllCount = sizeof(kAllModules) / sizeof(kAllModules[0]);

const Module* const* AllModules(size_t& count) {
    count = kAllCount;
    return kAllModules;
}

}  // namespace mod
}  // namespace sf
