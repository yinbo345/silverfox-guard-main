// sfthread.h — 工作线程的统一兜底契约
//
// 【为什么抽出来】
// 旧架构里 RunThreadGuard / ThreadBodyCxx 是 service.cpp 的 static 函数，
// 只有 service.cpp 内的线程能用。一旦引入"分体模块"（见 module.h），
// 分体线程也必须享受同样的双层兜底 —— 否则新模块的异常会直接把服务带走，
// 而旧线程不会。这种"新代码更脆弱"的不对称是事故温床。
//
// 抽成公共契约后，主干托管分体线程时统一调用 RunThreadGuarded，
// 所有线程（主干自己的 + 所有分体的）走同一条兜底路径。
//
// 【两层兜底的必要性】
//  ① __try/__except 兜 SEH（访问违例、除零等硬件级异常）
//  ② try/catch(...) 兜 C++ 异常（bad_alloc、第三方 COM 抛出的等）
// 若都不兜：异常从线程逃逸 → CRT 调 std::terminate() → 进程静默死亡，
// 日志"干净地断掉"、退出码为 0，服务管理器只会按 sc failure 策略重启它 ——
// 用户看到的是"莫名其妙重启"，无从追查。
//
// ⚠️ MSVC 限制：同一函数内不能既用 __try 又展开 C++ 对象（C2712/C2713）。
//    所以实现里必须拆成两个函数，外层只做 SEH 且不声明任何非 POD 对象。
#pragma once

namespace sf {

// 在双层兜底中运行 fn。name 用于日志（建议与分体名一致，便于定位）。
// 本函数**不会**向上抛异常，也不会让 SEH 逃逸。
void RunThreadGuarded(const char* name, void (*fn)());

}  // namespace sf
