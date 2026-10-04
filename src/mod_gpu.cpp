// mod_gpu.cpp — 分体：GPU 加速开关与地图进度
//
// 迁移自 service.cpp 的管道 if-else 链（gpuget / gpu / gpuprog 三条命令）。
// 实现逻辑逐字保留，仅：① 去掉 continue 改 return true；② 去掉两级缩进。
//
// 本分体**无独立线程**（Run=nullptr）—— 它只响应查询与开关，不做后台采集。
// GPU 地图的加载/卸载由 compute:: 自己的异步路径负责。
#include "module.h"

#include "common.h"     // WriteFramed / JsonString / JsonGetInt
#include "compute.h"    // IsGpuEnabled / SetGpuEnabled / LoadMapAsync / GetMapInfo ...

#include <string>

namespace {

bool CmdGpuGet(HANDLE h, const std::string& /*req*/) {
    sf::WriteFramed(h, std::string("{\"cmd\":\"gpuget\",\"gpu\":") +
                   (compute::IsGpuEnabled() ? "1" : "0") + "}");
    return true;
}

bool CmdGpu(HANDLE h, const std::string& req) {
    int on = sf::JsonGetInt(req, "on");
    compute::SetGpuEnabled(on == 1);
    if (on == 1) {
        // 开启：后台探测 GPU 性能并构建「特征地图」载入显存（进度经 gpuprog 查询）
        compute::LoadMapAsync();
    } else {
        // 关闭：立即释放显存中的地图与全部 GPU 资源（不残留一点显存占用）
        compute::UnloadMap();
    }
    sf::WriteFramed(h, std::string("{\"cmd\":\"gpu\",\"ok\":true,\"gpu\":") +
                   (compute::IsGpuEnabled() ? "1" : "0") + "}");
    return true;
}

bool CmdGpuProg(HANDLE h, const std::string& /*req*/) {
    // 地图加载进度（扩展端进度条轮询用）：阶段文案 + 百分比 + 地图规模 + 档位
    // tripped=true 表示本进程内 GPU 已熔断（驱动崩溃后自保停用），
    // 扩展端据此把开关置灰并提示"本机显卡驱动不稳定，已自动改用 CPU 扫描"。
    auto mi = compute::GetMapInfo();
    std::string s = "{\"cmd\":\"gpuprog\",\"loading\":" + std::string(mi.loading ? "true" : "false")
                  + ",\"loaded\":" + std::string(mi.loaded ? "true" : "false")
                  + ",\"pct\":" + std::to_string(mi.pct)
                  + ",\"stage\":" + sf::JsonString(mi.stage)
                  + ",\"error\":" + sf::JsonString(mi.error)
                  + ",\"patterns\":" + std::to_string(mi.patterns)
                  + ",\"states\":" + std::to_string(mi.states)
                  + ",\"bytes\":" + std::to_string((unsigned long long)mi.bytes)
                  + ",\"tier\":" + std::to_string(mi.tier)
                  + ",\"integrated\":" + std::string(mi.integrated ? "true" : "false")
                  + ",\"e2e\":" + std::to_string(mi.e2eMBs)
                  + ",\"cpu\":" + std::to_string(mi.cpuMBs)
                  + ",\"ratio\":" + std::to_string(mi.ratioPct)
                  + ",\"tripped\":" + std::string(compute::GpuTripped() ? "true" : "false")
                  + ",\"gpu\":" + sf::JsonString(mi.gpu) + "}";
    sf::WriteFramed(h, s);
    return true;
}

const sf::mod::CmdEntry kCmds[] = {
    { "gpuget",  CmdGpuGet  },
    { "gpu",     CmdGpu     },
    { "gpuprog", CmdGpuProg },
};

}  // namespace

namespace sf {
namespace mod {

extern const Module kModule_gpu = {
    "gpu",          // 分体名（日志用）
    nullptr,        // Init
    nullptr,        // Run（无线程）
    nullptr,        // Stop
    kCmds,
    sizeof(kCmds) / sizeof(kCmds[0])
};

}  // namespace mod
}  // namespace sf
