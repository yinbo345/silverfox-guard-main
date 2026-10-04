// module.cpp — 主干托管器实现（契约见 module.h）
//
// 主干只做四件事：Init 分体、托管分体线程、分派管道命令、收尾。
// **不含任何业务判定逻辑** —— 判定属于分体，主干保持"薄"。
#include "module.h"

#include "common.h"      // LogDbg
#include "sfthread.h"    // RunThreadGuarded（双层异常兜底）

#include <thread>
#include <vector>
#include <string>

namespace sf {
namespace mod {

// ---------------------------------------------------------------------------
//  托管表：记录已挂载的分体及其线程
//  ★ 用 std::thread 的默认构造（joinable()==false）作"无线程分体"的占位，
//    这样 StopAll 可以统一遍历，不必区分两类。
// ---------------------------------------------------------------------------
namespace {
struct Hosted {
    const Module* m = nullptr;
    std::thread   th;
};
std::vector<Hosted> g_hosted;
bool g_started = false;
}  // namespace

// ---------------------------------------------------------------------------
//  启动
// ---------------------------------------------------------------------------
void StartAll() {
    if (g_started) {
        LogDbg("[mod] StartAll 重复调用，已忽略（幂等）");
        return;
    }
    g_started = true;

    size_t n = 0;
    const Module* const* all = AllModules(n);
    if (!all || n == 0) {
        LogDbg("[mod] 分体清单为空 —— 主线仅有主干自身，功能将缺失");
        return;
    }

    size_t mounted = 0, skipped = 0;
    for (size_t i = 0; i < n; ++i) {
        const Module* m = all[i];
        if (!m || !m->name) { ++skipped; continue; }

        // ---- Init：失败只跳过自己，不致命（见 module.h 约束 1）----
        if (m->Init) {
            bool ok = false;
            try {
                ok = m->Init();
            } catch (...) {
                ok = false;
            }
            if (!ok) {
                ++skipped;
                LogDbg(std::string("[mod] ") + m->name +
                       " 初始化失败 → 跳过该分体（其它分体不受影响）");
                continue;
            }
        }

        Hosted h;
        h.m = m;
        // ---- 线程托管：统一走 RunThreadGuarded（双层兜底）----
        if (m->Run) {
            h.th = std::thread([m] { RunThreadGuarded(m->name, m->Run); });
        }
        g_hosted.push_back(std::move(h));
        ++mounted;
        LogDbg(std::string("[mod] ") + m->name + " 已挂载" +
               (m->Run ? "（含独立线程）" : "") +
               (m->cmds && m->cmdCount ? ("（命令 " + std::to_string(m->cmdCount) + " 条）") : ""));
    }

    LogDbg("[mod] 挂载完成：成功 " + std::to_string(mounted) +
           " / 跳过 " + std::to_string(skipped) + " / 清单 " + std::to_string(n));
}

// ---------------------------------------------------------------------------
//  停止
// ---------------------------------------------------------------------------
void StopAll() {
    if (!g_started) return;

    // ---- 第一步：逆序 join 所有分体线程 ----
    // 逆序是为了让"后启动的"先停 —— 后启动的分体通常依赖先启动的，
    // 正向停会让依赖方先消失，产生一堆无意义的错误日志。
    for (auto it = g_hosted.rbegin(); it != g_hosted.rend(); ++it) {
        if (it->th.joinable()) it->th.join();
    }

    // ---- 第二步：逆序调用 Stop（线程都已停下，此时收尾是安全的）----
    for (auto it = g_hosted.rbegin(); it != g_hosted.rend(); ++it) {
        if (it->m && it->m->Stop) {
            try {
                it->m->Stop();
            } catch (...) {
                // 收尾阶段的异常同样不能逃逸到服务停止路径上
            }
        }
    }

    LogDbg("[mod] 全部分体已停止（" + std::to_string(g_hosted.size()) + " 个）");
    g_hosted.clear();
    g_started = false;
}

// ---------------------------------------------------------------------------
//  命令查表
// ---------------------------------------------------------------------------
const CmdEntry* FindCommand(const std::string& name) {
    if (name.empty()) return nullptr;
    size_t n = 0;
    const Module* const* all = AllModules(n);
    for (size_t i = 0; i < n; ++i) {
        const Module* m = all[i];
        if (!m || !m->cmds) continue;
        for (size_t j = 0; j < m->cmdCount; ++j) {
            if (m->cmds[j].name && name == m->cmds[j].name) return &m->cmds[j];
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
//  自检
//
//  为什么必须有：命令**重名**会让后注册者永久静默失效 —— 请求永远被
//  先注册的那个处理，后写的那个看起来"编译进去了、也注册了"，就是收不到。
//  这类问题在真实运行时没有任何报错，只能靠启动期自检暴露。
// ---------------------------------------------------------------------------
std::string SelfCheck() {
    std::string issues;
    size_t n = 0;
    const Module* const* all = AllModules(n);

    // 已见过的命令名（分体数量很少，线性查重足够，也避免引入额外容器）
    std::vector<std::pair<std::string, const char*>> seen;

    for (size_t i = 0; i < n; ++i) {
        const Module* m = all[i];
        if (!m)          { issues += "清单第 " + std::to_string(i) + " 项为空指针；"; continue; }
        if (!m->name)    { issues += "清单第 " + std::to_string(i) + " 项缺 name；"; continue; }

        if (m->cmds && m->cmdCount == 0)
            issues += std::string("分体 ") + m->name + " 有命令表但 cmdCount=0；";

        for (size_t j = 0; j < m->cmdCount; ++j) {
            const CmdEntry& c = m->cmds[j];
            if (!c.name || !*c.name) {
                issues += std::string("分体 ") + m->name + " 的第 " + std::to_string(j) + " 条命令名称为空；";
                continue;
            }
            if (!c.run) {
                issues += std::string("分体 ") + m->name + " 的命令 " + c.name + " 函数指针为空；";
                continue;
            }
            for (const auto& s : seen) {
                if (s.first == c.name) {
                    issues += std::string("命令重名：") + c.name + "（" + s.second +
                              " 与 " + m->name + "）—— 后者将永远收不到请求；";
                    break;
                }
            }
            seen.push_back({ c.name, m->name });
        }
    }
    return issues;
}

}  // namespace mod
}  // namespace sf
