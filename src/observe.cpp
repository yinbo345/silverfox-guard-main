// observe.cpp — 放行后监控（灰名单）实现
//
//  存储：内存 unordered_map<lower(path), expireAtMs(steady_clock)>。
//  锁：shared_mutex（读多写少，进程创建事件源高频读、沙箱放行低频写）。
//  不落盘：观察名单是会话级「短期重点监控」，重启清空合理（重新送检会重建）。
#include "observe.h"

#include <unordered_map>
#include <shared_mutex>
#include <chrono>

namespace sf {
namespace {

std::shared_mutex                           g_obsMtx;
std::unordered_map<std::string, long long> g_obs;   // lower(path) -> expireAt(ms)

long long nowMs() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::string toLower(const std::string& s) {
    std::string o;
    o.reserve(s.size());
    for (char c : s) {
        if (c >= 'A' && c <= 'Z') o.push_back(static_cast<char>(c + 32));
        else                       o.push_back(c);
    }
    return o;
}

}  // namespace

void ObserveAdd(const std::string& path, int ttlSec) {
    if (path.empty()) return;
    const long long exp = nowMs() + static_cast<long long>(ttlSec) * 1000;
    std::unique_lock<std::shared_mutex> lk(g_obsMtx);
    g_obs[toLower(path)] = exp;
}

bool ObserveHit(const std::string& path) {
    if (path.empty()) return false;
    const std::string k = toLower(path);
    std::shared_lock<std::shared_mutex> lk(g_obsMtx);
    auto it = g_obs.find(k);
    if (it == g_obs.end()) return false;
    // 过期：读锁内不能 erase（需写锁），直接返回 false；
    // 真正删除交给 ObserveSweep，不影响正确性。
    if (it->second <= nowMs()) return false;
    return true;
}

void ObserveSweep() {
    const long long t = nowMs();
    std::unique_lock<std::shared_mutex> lk(g_obsMtx);
    for (auto it = g_obs.begin(); it != g_obs.end(); ) {
        if (it->second <= t) it = g_obs.erase(it);
        else                 ++it;
    }
}

}  // namespace sf
