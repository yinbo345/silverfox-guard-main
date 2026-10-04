// packscan.cpp — 压缩包落地深度检测实现（契约见 packscan.h）
#include "packscan.h"

#include "common.h"    // LogDbg / JsonGetInt / JsonGetString / JsonString
#include "probe.h"     // ScanTargetFile（已有完整递归解包 + 内容判定）
#include "sfstop.h"    // IsStopRequested / StopHandle
#include "sfthread.h"  // RunThreadGuarded（由分体托管时使用，这里自管线程）

#include <windows.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace sf {
namespace packscan {

// ---------------------------------------------------------------------------
//  队列与状态
// ---------------------------------------------------------------------------
namespace {
const size_t kQueueCap     = 64;    // 队列上限（满了丢最旧，见 packscan.h 的说明）
const size_t kDedupCap     = 1024;  // 去重集合上限（超了整体清空，粗糙但够用）
const size_t kRecentCap    = 20;    // 最近命中保留条数

std::mutex                g_mtx;
std::deque<std::string>   g_queue;
std::set<std::string>     g_dedup;       // 已入队过的路径（小写）
std::vector<std::string>  g_pendingOrder;// 便于 PendingJson 输出顺序

std::thread               g_thread;
std::atomic<bool>         g_running{false};
std::atomic<bool>         g_stop{false};
HitSink                   g_sink = nullptr;

std::atomic<unsigned long long> g_queued{0};
std::atomic<unsigned long long> g_scanned{0};
std::atomic<unsigned long long> g_hits{0};
std::atomic<unsigned long long> g_dropped{0};
std::atomic<unsigned long long> g_lastMs{0};
std::atomic<unsigned long long> g_scannedBytes{0};

// 最近命中（路径 / 等级 / 标题），供 GUI 列表
struct HitRec { std::string path, title, at; int level = 0; };
std::deque<HitRec> g_recent;
}  // namespace

// ---------------------------------------------------------------------------
//  扩展名判定
//
//  ⚠️ 与 probe.cpp 的 IsArchiveExt 必须保持一致（那边是 static，无法复用）。
//     两份清单不一致会导致"落地能入队、扫描却不解包"这类静默失效，
//     排查起来极难。改动任一处请同步另一处。
// ---------------------------------------------------------------------------
bool IsArchiveExt(const std::string& path) {
    std::string l = path;
    for (char& c : l) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    static const char* exts[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lzh", ".iso",
        ".cab", ".arj", ".wim", ".rpm", ".deb", ".xar", ".tgz", ".tbz", ".txz",
        ".msix", ".msu", ".appx"
    };
    for (const char* e : exts) {
        size_t n = 0; while (e[n]) ++n;
        if (l.size() >= n && l.compare(l.size() - n, n, e) == 0) return true;
    }
    return false;
}

static std::string LowerAscii(const std::string& s) {
    std::string o = s;
    for (char& c : o) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return o;
}

static uint64_t NowMsSteady() {
    static LARGE_INTEGER freq = [] {
        LARGE_INTEGER f{}; QueryPerformanceFrequency(&f); return f;
    }();
    LARGE_INTEGER c{};
    QueryPerformanceCounter(&c);
    if (freq.QuadPart <= 0) return GetTickCount64();
    return (uint64_t)((double)c.QuadPart * 1000.0 / (double)freq.QuadPart);
}

static std::string NowStrLocal() {
    SYSTEMTIME st; GetLocalTime(&st);
    char b[32];
    snprintf(b, sizeof(b), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return std::string(b);
}

// ---------------------------------------------------------------------------
//  入队（落地捕获调用，必须轻量）
// ---------------------------------------------------------------------------
void Enqueue(const std::string& archivePath) {
    if (archivePath.empty()) return;
    if (!IsArchiveExt(archivePath)) return;

    std::string key = LowerAscii(archivePath);
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        if (g_dedup.size() >= kDedupCap) g_dedup.clear();   // 粗糙上限，防无限增长
        if (!g_dedup.insert(key).second) return;            // 已扫过/已入队 → 去重
        if (g_queue.size() >= kQueueCap) {
            g_queue.pop_front();                            // 满了丢最旧（保新）
            g_dropped.fetch_add(1);
        }
        g_queue.push_back(archivePath);
        g_pendingOrder.push_back(archivePath);
    }
    g_queued.fetch_add(1);
    LogDbg("[packscan] 入队待检压缩包：" + archivePath);
}

// ---------------------------------------------------------------------------
//  消费者：逐个扫描（串行，避免并发解包把磁盘打满）
// ---------------------------------------------------------------------------
static void ConsumeLoop() {
    while (!g_stop.load()) {
        std::string path;
        {
            std::lock_guard<std::mutex> lk(g_mtx);
            if (!g_queue.empty()) {
                path = g_queue.front();
                g_queue.pop_front();
                // 同步从 pendingOrder 移除（用于 PendingJson 展示）
                for (auto it = g_pendingOrder.begin(); it != g_pendingOrder.end(); ++it) {
                    if (*it == path) { g_pendingOrder.erase(it); break; }
                }
            }
        }
        if (path.empty()) {
            HANDLE h = StopHandle();
            if (h) WaitForSingleObject(h, 1000);
            else Sleep(500);
            continue;
        }

        LogDbg("[packscan] 开始扫描：" + path);
        std::string json;
        try {
            json = ScanTargetFile(path);      // 内部含递归解包 + 逐层内容判定
        } catch (...) {
            LogDbg("[packscan] 扫描异常（已捕获，继续）：" + path);
            continue;
        }
        g_scanned.fetch_add(1);
        g_lastMs.store(NowMsSteady());

        int lv = 0;
        try { lv = JsonGetInt(json, "level"); } catch (...) { lv = 0; }
        std::string title, type;
        try {
            title = JsonGetString(json, "title");
            type  = JsonGetString(json, "type");
        } catch (...) {}

        LogDbg("[packscan] 完成：" + path + " level=" + std::to_string(lv) +
               " type=" + type + " title=" + title);

        if (lv >= 2) {
            g_hits.fetch_add(1);
            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (g_recent.size() >= kRecentCap) g_recent.pop_front();
                HitRec r;
                r.path  = path;
                r.title = title;
                r.at    = NowStrLocal();
                r.level = lv;
                g_recent.push_back(r);
            }
            // 交回服务层处置（隔离归档本体）。
            // ⚠️ 只回调 level>=2：压缩包里有个可疑小文件就弹卡会非常吵，
            //    而压缩包本身常常只是普通安装包。
            if (g_sink) {
                try {
                    g_sink(path, lv, title,
                           title.empty() ? std::string("压缩包内含高危文件") : title);
                } catch (...) {
                    LogDbg("[packscan] 回调异常（已捕获）");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
//  生命周期
// ---------------------------------------------------------------------------
void SetSink(HitSink sink) { g_sink = sink; }

bool Start() {
    bool expected = false;
    if (!g_running.compare_exchange_strong(expected, true)) return false;  // 幂等
    g_stop.store(false);
    g_thread = std::thread(ConsumeLoop);
    LogDbg("[packscan] 压缩包落地深度检测已启动（异步消费者，队列上限 64）");
    return true;
}

void Stop() {
    if (!g_running.exchange(false)) return;
    g_stop.store(true);
    if (g_thread.joinable()) g_thread.join();
    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_queue.clear();
        g_pendingOrder.clear();
    }
    LogDbg("[packscan] 已停止（累计入队 " + std::to_string(g_queued.load()) +
           " / 扫描 " + std::to_string(g_scanned.load()) +
           " / 命中 " + std::to_string(g_hits.load()) +
           " / 丢弃 " + std::to_string(g_dropped.load()) + "）");
}

bool IsRunning() { return g_running.load(); }

Stats GetStats() {
    Stats s;
    s.queued       = g_queued.load();
    s.scanned      = g_scanned.load();
    s.hits         = g_hits.load();
    s.dropped      = g_dropped.load();
    s.lastMs       = g_lastMs.load();
    s.scannedBytes = g_scannedBytes.load();
    return s;
}

std::string PendingJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::string j = "[";
    for (size_t i = 0; i < g_pendingOrder.size(); ++i) {
        if (i) j += ",";
        j += JsonString(g_pendingOrder[i]);
    }
    j += "]";
    return j;
}

std::string RecentHitsJson() {
    std::lock_guard<std::mutex> lk(g_mtx);
    std::string j = "[";
    for (size_t i = 0; i < g_recent.size(); ++i) {
        if (i) j += ",";
        const HitRec& r = g_recent[i];
        j += "{\"path\":"   + JsonString(r.path) +
             ",\"title\":"  + JsonString(r.title) +
             ",\"at\":"     + JsonString(r.at) +
             ",\"level\":"  + std::to_string(r.level) + "}";
    }
    j += "]";
    return j;
}

}  // namespace packscan
}  // namespace sf
