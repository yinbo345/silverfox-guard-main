// probe.cpp — 银狐主防「单文件启发式查杀引擎」（独立链路，不与全盘扫描纠缠）
// ---- 第一部分：工具 / PE 解析 / 熵 / 打包器指纹 ----
// 设计依据 2026-09 调研：杀软单文件静态启发 = 识别 / 结构异常 / 签名信任 / 语义证据 / 计分，
// 规避两类误报源：①「加壳单点定罪」②「字符串关键词泛匹配」（TRUSTEE 论文 + 火绒 FP 校准教训）。
// 全程离线、不运行样本；判定结果逐条给出证据（透明可复核）。
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define _WIN32_WINNT 0x0A00
#define WINVER 0x0A00
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <filesystem>

#include "probe.h"
#include "common.h"

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

namespace sfprobe {

// ================================================================ 小工具
static std::string lower(const std::string& s) {
    std::string r = s;
    for (auto& c : r) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return r;
}
static bool ends_with_i(const std::string& s, const char* suf) {
    size_t n = strlen(suf);
    if (s.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        char a = s[s.size() - n + i], b = suf[i];
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}
static bool contains_i(const std::string& hay, const char* needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}
static std::string basename_of(const std::string& p) {
    size_t b = p.find_last_of("\\/");
    return b == std::string::npos ? p : p.substr(b + 1);
}
static bool file_exists(const std::string& p) {
    return GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}
static uint64_t file_size(const std::string& p) {
    HANDLE h = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return 0;
    LARGE_INTEGER sz{};
    GetFileSizeEx(h, &sz);
    CloseHandle(h);
    return (uint64_t)sz.QuadPart;
}
static std::vector<uint8_t> read_prefix(const std::string& path, size_t max) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> buf(max);
    f.read((char*)buf.data(), (std::streamsize)max);
    buf.resize((size_t)f.gcount());
    return buf;
}
// 小写化后的文件内容前缀（≤scanMax），供家族串 / 白加黑名精确检索
static std::string read_lower_content(const std::string& path, size_t scanMax) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return std::string();
    std::string buf; buf.reserve(std::min(scanMax, (size_t)(4 << 20)));
    char chunk[1 << 18];
    size_t got = 0;
    while (got < scanMax) {
        f.read(chunk, sizeof(chunk));
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        size_t take = std::min((size_t)n, scanMax - got);
        for (size_t i = 0; i < take; ++i)
            buf.push_back((char)((chunk[i] >= 'A' && chunk[i] <= 'Z') ? chunk[i] - 'A' + 'a' : chunk[i]));
        got += take;
    }
    return buf;
}

// ================================================================ 熵
static double entropy(const uint8_t* p, size_t n) {
    if (n == 0) return 0.0;
    unsigned freq[256] = {0};
    for (size_t i = 0; i < n; ++i) ++freq[p[i]];
    double e = 0.0;
    for (int k = 0; k < 256; ++k) {
        if (!freq[k]) continue;
        double pr = (double)freq[k] / (double)n;
        e -= pr * log2(pr);
    }
    return e;
}

// ================================================================ PE 解析
struct SecInfo {
    std::string name;             // 原始名（小写化前）
    DWORD va = 0;                 // VirtualAddress
    DWORD vsz = 0, rsz = 0;       // VirtualSize / SizeOfRawData
    DWORD rawPtr = 0;             // PointerToRawData
    DWORD chars = 0;
    double ent = -1.0;            // -1=未计算
};
struct PeInfo {
    bool ok = false;
    bool is64 = false;
    DWORD epRva = 0;
    DWORD compileTs = 0;
    DWORD checkSum = 0;
    bool hasSecurityDir = false;  // 有证书表（签名载体）
    DWORD importRva = 0, importSize = 0;
    DWORD numSections = 0;
    bool epInText = false;        // 入口点是否落在 .text（正常编译产物通常如此）
    std::vector<SecInfo> secs;
};
// 解析 PE 头（输入：头部前缀缓冲，需覆盖节表）
static bool ParsePeHeader(const std::vector<uint8_t>& head, PeInfo& pi) {
    if (head.size() < 0x40) return false;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)head.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return false;
    if ((size_t)dos->e_lfanew + 4 >= head.size()) return false;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(head.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    const IMAGE_FILE_HEADER fh = nt->FileHeader;
    if (fh.Machine != IMAGE_FILE_MACHINE_I386 && fh.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    const WORD x86 = IMAGE_NT_OPTIONAL_HDR32_MAGIC, x64 = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    WORD magic = 0; DWORD ep = 0, check = 0, impR = 0, impS = 0, secDirS = 0, secAlign = 0;
    if (fh.Machine == IMAGE_FILE_MACHINE_AMD64) {
        size_t off = (size_t)dos->e_lfanew + 4 + 20;
        if (off + sizeof(IMAGE_OPTIONAL_HEADER64) > head.size()) return false;
        const IMAGE_OPTIONAL_HEADER64* oh = (const IMAGE_OPTIONAL_HEADER64*)(head.data() + off);
        magic = oh->Magic; if (magic != x64) return false;
        ep = oh->AddressOfEntryPoint; check = oh->CheckSum;
        impR = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        impS = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        secDirS = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        secAlign = oh->SectionAlignment;
    } else {
        size_t off = (size_t)dos->e_lfanew + 4 + 20;
        if (off + sizeof(IMAGE_OPTIONAL_HEADER32) > head.size()) return false;
        const IMAGE_OPTIONAL_HEADER32* oh = (const IMAGE_OPTIONAL_HEADER32*)(head.data() + off);
        magic = oh->Magic; if (magic != x86) return false;
        ep = oh->AddressOfEntryPoint; check = oh->CheckSum;
        impR = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        impS = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        secDirS = oh->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        secAlign = oh->SectionAlignment;
    }
    size_t secOff = (size_t)dos->e_lfanew + 4 + 20 + (fh.Machine == IMAGE_FILE_MACHINE_AMD64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32));
    DWORD nsec = fh.NumberOfSections;
    if (nsec == 0 || (size_t)nsec * sizeof(IMAGE_SECTION_HEADER) > head.size() - secOff) return false;
    pi.secs.clear(); pi.secs.reserve(nsec);
    for (DWORD i = 0; i < nsec; ++i) {
        const IMAGE_SECTION_HEADER* sh = (const IMAGE_SECTION_HEADER*)(head.data() + secOff + (size_t)i * sizeof(IMAGE_SECTION_HEADER));
        SecInfo s;
        size_t nl = 0; while (nl < 8 && sh->Name[nl]) ++nl;
        s.name.assign((const char*)sh->Name, nl);
        s.va = sh->VirtualAddress; s.vsz = sh->Misc.VirtualSize;
        s.rsz = sh->SizeOfRawData; s.rawPtr = sh->PointerToRawData;
        s.chars = sh->Characteristics;
        pi.secs.push_back(s);
    }
    // 入口点所在节：normal -> .text（或首个可执行代码节）。用 VA 区间判定。
    pi.epInText = false;
    if (secAlign >= 0x1000) {
        for (const auto& s : pi.secs) {
            DWORD secEnd = s.vsz ? s.va + s.vsz : s.va + s.rsz;
            if (ep >= s.va && ep < secEnd) {
                std::string ln = lower(s.name);
                if (ln == ".text") pi.epInText = true;
                else if (ln == ".vmp" || ln.rfind(".vmp", 0) == 0 || ln.rfind(".themida", 0) == 0 || ln.rfind(".aspack", 0) == 0 ||
                         ln.rfind(".mpress", 0) == 0 || ln.rfind("upx", 0) == 0 || ln.rfind(".nsp", 0) == 0)
                    pi.epInText = false;   // 壳入口节：视为异常（由加壳证据计分，不单独立罪）
                break;
            }
        }
    }
    pi.ok = true;
    pi.is64 = fh.Machine == IMAGE_FILE_MACHINE_AMD64;
    pi.epRva = ep;
    pi.compileTs = fh.TimeDateStamp;
    pi.checkSum = check;
    pi.importRva = impR; pi.importSize = impS;
    pi.hasSecurityDir = secDirS != 0;
    pi.numSections = nsec;
    return true;
}// ---- 第二部分：指纹识别 / 结构异常分析 / 签名验证 ----

// ================================================================ 打包器/安装器指纹
static const char* g_packedSec[] = {
    "upx0","upx1","upx2","upx",".vmp",".vmp0","vmp0",".themida",".aspack",".mpress",
    ".enigma",".nsp",".packed",".upx",".petite",".pecompact",".enigma0",".babyload",".diet"
};
static bool IsPackedSection(const std::string& nameLower) {
    for (const char* p : g_packedSec) if (nameLower == p) return true;
    // 生僻 8 字符内怪异节名放宽：以 '.' 开头且不在常见白名单里的节，仅作旁证不单独计
    return false;
}

// 常见正常节名（用于"怪异节名"识别——只作低权旁证）
static const char* g_normalSec[] = {
    ".text",".rdata",".data",".rsrc",".reloc",".bss",".idata",".tls",".edata",".pdata",
    ".xdata",".gfids",".mrdata",".didat",".00cfg",".loadcfg",".vol0",".vdm",".sxdata",".comment"
};
static bool IsNormalSection(const std::string& n) {
    for (const char* p : g_normalSec) if (n == p) return true;
    return false;
}

// 在文件里定位可打印 ASCII 魔数（大小写敏感，用于 NSIS/Inno 指纹；只搜前 16MB）
static bool FindAsciiMagic(const std::string& path, const char* magic, size_t scanLimitMB) {
    size_t limit = scanLimitMB << 20;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::string buf; buf.reserve(limit);
    char chunk[1 << 18];
    size_t got = 0;
    while (got < limit) {
        f.read(chunk, sizeof(chunk));
        std::streamsize n = f.gcount();
        if (n <= 0) break;
        size_t take = std::min((size_t)n, limit - got);
        buf.append(chunk, take);
        got += take;
    }
    return buf.find(magic) != std::string::npos;
}

// 类型：PE / NSIS / Inno / ZIP / OTHER
static const char* DetectType(const std::string& path, const PeInfo& pi, size_t fileSz,
                              const std::vector<uint8_t>& head) {
    if (pi.ok) {
        if (fileSz > 0) {
            if (FindAsciiMagic(path, "NullsoftInst", 16)) return "NSIS";
            if (FindAsciiMagic(path, "Inno Setup Setup Data (", 16)) return "INNO";
        }
        return "PE";
    }
    if (head.size() >= 4 && head[0] == 'P' && head[1] == 'K') return "ZIP";
    if (head.size() >= 6 && head[0] == 'R' && head[1] == 'a' && head[2] == 'r' && head[3] == '!' && head[4] == 0x1A) return "RAR";
    if (head.size() >= 6 && head[0] == 0x37 && head[1] == 0x7A && head[2] == 0xBC && head[3] == 0xAF && head[4] == 0x27 && head[5] == 0x1C) return "7Z";
    if (FindAsciiMagic(path, "NullsoftInst", 16)) return "NSIS";
    if (FindAsciiMagic(path, "Inno Setup Setup Data (", 16)) return "INNO";
    return "OTHER";
}

// ================================================================ 结构异常分析
struct Anom { int w; std::string name, desc; };   // w: 证据权重 1/2/3

// ---------------------------------------------------------------------------
//  ★ LooksLikeInstallerExe（2026-10-03 新增，供落地捕获分流用）
// ---------------------------------------------------------------------------
//  问题：`packscan::IsArchiveExt()` 只认 21 种**归档扩展名**（zip/rar/7z/…），
//        **`.exe` 不在内**。而银狐本体恰恰是「PE 头 + 内嵌 Inno/NSIS 载荷」的
//        自解压安装包（扩展名就是 .exe）⇒ 它永远进不了 packscan 队列，
//        只能靠单文件静态判定 —— **而单文件判定看不见包内的真实载荷**。
//        实测：138,913,585 B 的 Inno 包（YouDaoX64.exe）
//              `条目=21 nExec=0 nArchive=0 -> 跳过(包内无可执行项/嵌套包)`
//              随后 `level=2 score=320` 判得又准，**却因不解包而永远看不到里面是什么**。
//
//  判据：**只看外层魔数，不看扩展名**。
//    - "Inno Setup Setup Data ("  → Inno Setup（银狐常用）★ 只需扫这一条
//    - "NullsoftInst"             → NSIS
//  ★ 刻意**不**复用 DetectType：那个要完整解析 PE 头（ParsePeHeader），
//    而这里在 5 秒轮询的实时路径上，只想花一次小文件扫描的成本做分流判断。
//  ★ 失败返回 false = 宁可漏分流（走原路径），**绝不误分流**。
bool LooksLikeInstallerExe(const std::string& path) {
    try {
        const std::string l = lower(path);
        // 只对可执行体做这个判断（省掉一次文件扫描）
        if (!(ends_with_i(l, ".exe") || ends_with_i(l, ".com") || ends_with_i(l, ".scr")))
            return false;
        if (FindAsciiMagic(path, "Inno Setup Setup Data (", 16)) return true;
        if (FindAsciiMagic(path, "NullsoftInst", 16)) return true;
        return false;
    } catch (...) {
        return false;   // 任何异常都当"不是安装器"，交回原路径
    }
}

static double SectionEntropyAt(const std::string& path, DWORD rawPtr, DWORD rsz, void* tmp, size_t tmpSize) {
    if (rsz == 0) return -1.0;
    std::ifstream f(path, std::ios::binary);
    if (!f) return -1.0;
    f.seekg(rawPtr);
    size_t want = std::min((DWORD)tmpSize, rsz);
    f.read((char*)tmp, (std::streamsize)want);
    std::streamsize got = f.gcount();
    if (got <= 0) return -1.0;
    return entropy((const uint8_t*)tmp, (size_t)got);
}

// RVA -> 文件偏移（供导入表解析）
static bool RvaToRaw(const PeInfo& pi, DWORD rva, DWORD* outRaw) {
    for (const auto& s : pi.secs) {
        if (s.vsz > 0 && rva >= s.va && rva < s.va + s.vsz) {
            if (rva - s.va >= s.rsz) return false;
            *outRaw = s.rawPtr + (rva - s.va);
            return true;
        }
        if (s.vsz == 0 && s.rsz > 0 && rva >= s.va && rva < s.va + s.rsz) {
            *outRaw = s.rawPtr + (rva - s.va);
            return true;
        }
    }
    return false;
}

// 解析导入表：返回 import 函数名集合（小写）；解析失败返回 false（不判证据）
static bool ParseImports(const std::string& path, const PeInfo& pi, std::vector<std::string>& out, bool* onlyLdr) {
    out.clear();
    *onlyLdr = false;
    if (pi.importRva == 0) return false;
    DWORD raw = 0;
    if (!RvaToRaw(pi, pi.importRva, &raw)) return false;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    DWORD maxDesc = 64;
    size_t ldr = 0, total = 0;
    for (DWORD i = 0; i < maxDesc; ++i) {
        IMAGE_IMPORT_DESCRIPTOR d{};
        f.seekg(raw + (std::streamoff)i * sizeof(d));
        f.read((char*)&d, sizeof(d));
        if (f.gcount() != sizeof(d)) break;
        if (d.FirstThunk == 0 && d.Name == 0 && d.OriginalFirstThunk == 0) break;
        if (d.Name == 0) continue;
        DWORD nameRaw = 0;
        if (!RvaToRaw(pi, d.Name, &nameRaw)) continue;
        f.seekg(nameRaw);
        char nb[256] = {0};
        f.read(nb, sizeof(nb) - 1);
        std::string dll = lower(nb);
        // 三个库名 → 依序解析 thunk 函数名
        DWORD thunkRva = d.OriginalFirstThunk ? d.OriginalFirstThunk : d.FirstThunk;
        DWORD thunkRaw = 0;
        if (!RvaToRaw(pi, thunkRva, &thunkRaw)) continue;
        f.seekg(thunkRaw);
        const DWORD MAXTHUNK = 1024;
        for (DWORD k = 0; k < MAXTHUNK; ++k) {
            uint64_t val = 0;
            if (pi.is64) { f.read((char*)&val, 8); if (f.gcount() != 8) break; }
            else { DWORD v32 = 0; f.read((char*)&v32, 4); if (f.gcount() != 4) break; val = v32; }
            if (val == 0) break;
            if (val & ((uint64_t)1 << (pi.is64 ? 63 : 31))) { ++total; continue; }  // ordinal
            DWORD hintRaw = 0;
            if (!RvaToRaw(pi, (DWORD)(val & 0x7FFFFFFF), &hintRaw)) { ++total; continue; }
            f.seekg(hintRaw + 2);
            char fn[128] = {0};
            f.read(fn, sizeof(fn) - 1);
            std::string fnLower = lower(fn);
            if (!fnLower.empty()) {
                ++total;
                if (fnLower == "loadlibrarya" || fnLower == "loadlibraryw" || fnLower == "loadlibraryexa" ||
                    fnLower == "loadlibraryexw" || fnLower == "getprocaddress" || fnLower == "loadlibarya")
                    ++ldr;
                out.push_back(fnLower);
            }
        }
    }
    *onlyLdr = (total > 0 && ldr == total && total <= 8);
    return !out.empty() || (pi.importRva != 0 && pi.importSize > 0);
}

// 结构异常分析（全部证据带权重，交给上层按"签名/封装"降权）
static bool ParseImports(const std::string& path, const PeInfo& pi, std::vector<std::string>& out, bool* onlyLdr);   // 定义见下
static void AnalyzeStructure(const std::string& path, const PeInfo& pi, uint64_t fileSz, bool asInstaller,
                             std::vector<Anom>& out, std::vector<char>& scratch) {
    // 0) 导入表动态解析（先于其它：只对「导入极少且全部为 LoadLibrary/GetProcAddress」报警）
    {
        std::vector<std::string> imports;
        bool onlyLdr = false;
        if (ParseImports(path, pi, imports, &onlyLdr) && onlyLdr)
            out.push_back({2, "导入表仅动态解析", "导入表只有 LoadLibrary/GetProcAddress 等引导项，真实 API 运行时动态解析，典型加壳/注入载荷。"});
    }
    // 1) 节级（安装器跳过节数/怪异名/虚实比：NSIS/Inno stub 的节布局本身反常规，判了必误报）
    if (!asInstaller) {
        if (pi.numSections < 2) out.push_back({2, "节区数异常", "节区数量过少(" + std::to_string(pi.numSections) + ")，常见于压缩壳/迷你加载器。"});
        else if (pi.numSections > 20) out.push_back({1, "节区数异常", "节区数量过多(" + std::to_string(pi.numSections) + ")。"});
    }
    bool wxAny = false, packedName = false, weirdName = false;
    double textEnt = -1, rsrcEnt = -1, bssEnt = -1, firstExecEnt = -1;
    for (const auto& s : pi.secs) {
        if ((s.chars & IMAGE_SCN_MEM_WRITE) && (s.chars & IMAGE_SCN_MEM_EXECUTE)) wxAny = true;
        std::string ln = lower(s.name);
        if (IsPackedSection(ln)) packedName = true;
        if (!ln.empty() && ln[0] == '.' && !IsNormalSection(ln) && ln != ".text" && ln != ".rdata" && ln != ".data" && ln != ".rsrc")
            weirdName = true;
        if (s.rsz > 0 && s.rawPtr > 0 && s.rawPtr + s.rsz <= fileSz) {
            if (ln == ".text") textEnt = SectionEntropyAt(path, s.rawPtr, s.rsz, scratch.data(), scratch.size());
            else if (ln == ".rsrc") rsrcEnt = SectionEntropyAt(path, s.rawPtr, s.rsz, scratch.data(), scratch.size());
            else if (ln == ".bss") bssEnt = SectionEntropyAt(path, s.rawPtr, s.rsz, scratch.data(), scratch.size());
            else if ((s.chars & IMAGE_SCN_MEM_EXECUTE) && firstExecEnt < 0) firstExecEnt = SectionEntropyAt(path, s.rawPtr, s.rsz, scratch.data(), scratch.size());
        }
        // 虚实比：解包桩典型（VirtualSize >> RawSize）；安装器跳过（stub 布局反常规）。
        // 收敛：标准命名节不判——.data/.bss/.didat 等「未初始化数据节」天生 vsz≫rsz
        // （实测 cmd.exe 的 .data 比值 28.1×，完全合法），只对非标准命名的节判，阈值提到 50×。
        if (!asInstaller && !IsNormalSection(ln) && s.rsz > 0 && s.vsz > 50 * s.rsz)
            out.push_back({2, "节区虚实比异常", "非标准节区 " + s.name + " 虚拟大小远超原始大小(>50x)，疑似解包桩。"});
    }
    if (wxAny) out.push_back({2, "存在可写可执行节区", "检测到同时可写(W)与可执行(X)的节区，典型加壳/自解密特征。"});
    if (packedName) out.push_back({2, "发现加壳/打包器节名", "节名匹配已知加壳器(UPX/VMProtect/Themida/ASPACK/MPRESS 等)。"});
    if (!asInstaller && weirdName) out.push_back({1, "发现非标准节名", "存在非常规节名，可能是私有加壳器或异形包装。"});
    if (textEnt > 6.9) out.push_back({2, "代码节高熵", std::string("代码节(.text)熵 ") + std::to_string(textEnt).substr(0,4) + "，疑似压缩/加密(加壳)。"});
    else if (textEnt > 6.5) out.push_back({1, "代码节偏高熵", "代码节熵偏高，需结合其他证据。"});
    if (rsrcEnt > 7.2) out.push_back({2, "资源节高熵", "资源节( .rsrc )熵极高，常蕴含加密载荷。"});
    if (bssEnt > 0.05 && bssEnt > 0) out.push_back({2, "BSS 节非零熵", "未初始化数据节(.bss)熵非零，异常装填。"});
    // 2) 头部级
    if (pi.importRva == 0 || pi.importSize == 0)
        out.push_back({2, "无导入表", "可执行文件无导入表，代码依赖动态解析，典型加壳/注入载荷特征。"});
    if (!pi.epInText)
        out.push_back({2, "入口点异常", "程序入口点未落在标准代码节(.text)，常见于加壳引导代码。"});
    time_t now = time(nullptr);
    uint32_t ts = pi.compileTs;
    if (ts == 0 || ts == 0xFFFFFFFFu) out.push_back({2, "编译时间戳异常", "编译时间戳为空/越界(0 或 0xFFFFFFFF)，常见于自动化打包样本。"});
    // 「时间戳指向未来」只作旁证(w=1)不计入高危：现代 /Brepro 可复现构建把 TimeDateStamp 写成
    // 内容哈希，微软自家系统文件也会出现 2042 / 2060 / 2099 / 2100 年（实测 taskmgr/calc/powrprof/
    // version/winhttp 全部命中）——规则前提不成立，不能作为可疑依据。
    else if ((uint64_t)ts > (uint64_t)now + 365ull * 86400) out.push_back({1, "编译时间戳为未来值", "时间戳晚于当前一年以上（可复现构建 /Brepro 会把该字段写成内容哈希，非真实编译时间），仅作旁证。"});
    // 注：原「编译时间戳过旧(<1995)」「校验和缺失」两条误报率过高（老软件/大量正常程序均命中），已下线。
    // 3) overlay（节表末尾之后的数据）——安装器的归档数据在后段是常态，跳过
    DWORD endRaw = 0;
    for (const auto& s : pi.secs) {
        DWORD e = s.rawPtr + s.rsz;
        if (e > endRaw) endRaw = e;
    }
    if (!asInstaller && fileSz > endRaw + 4096) {
        uint64_t ovSize = fileSz - endRaw;
        if (ovSize > (4 << 20)) {
            // 大 overlay：读头部 256KB 测熵
            std::ifstream f(path, std::ios::binary);
            if (f) {
                f.seekg(endRaw);
                std::vector<char> tmp(std::min<uint64_t>(ovSize, 256 * 1024));
                f.read(tmp.data(), (std::streamsize)tmp.size());
                std::streamsize got = f.gcount();
                if (got > 1024) {
                    double e = entropy((const uint8_t*)tmp.data(), (size_t)got);
                    if (e > 7.4)
                        out.push_back({2, "附加数据高熵", "文件尾部存在大体积(" + std::to_string(ovSize / (1024 * 1024)) + "MB)高熵附加数据，疑似内嵌加密载荷。"});
                    else
                        out.push_back({1, "存在大体积附加数据", "文件尾部存在 " + std::to_string(ovSize / (1024 * 1024)) + "MB 附加数据(压缩包/资源)。"});
                }
            }
        } else if (ovSize > 512) {
            out.push_back({1, "存在附加数据", "超过节表范围存在附加数据(overlay)。"});
        }
    }
}

// ================================================================ 签名验证
// 返回：0=无/无效 1=有效(链完整, 任意) 2=有效且自签（自签代码证书） 3=存在签名但验签失败(被篡改)
static int VerifySigVerdict(const std::string& path, bool* hasTimestamp) {
    *hasTimestamp = false;
    wchar_t wpath[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH) <= 0) return 0;
    if (!file_exists(path)) return 0;
    WINTRUST_FILE_INFO fi{};
    fi.cbStruct = sizeof(fi);
    fi.pcwszFilePath = wpath;
    WINTRUST_DATA wd{};
    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;   // 离线语义：不查 CRL/OCSP，避免联网卡死
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &fi;
    wd.dwProvFlags = 0;
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG r = WinVerifyTrust(nullptr, &action, &wd);
    if (r != ERROR_SUCCESS) {
        // 无签名 / 签名存在但验证失败
        if (r == TRUST_E_NOSIGNATURE) return 0;
        if (r == TRUST_E_SUBJECT_FORM_UNKNOWN || r == TRUST_E_PROVIDER_UNKNOWN) return 0;
        return 3;
    }
    // 链完整：再取签名者证书判断是否自签 
    bool selfSigned = false;
    HCERTSTORE store = nullptr;
    HCRYPTMSG hMsg = nullptr;
    DWORD enc = 0, ct = 0, ft = 0;
    if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, wpath,
                         CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                         CERT_QUERY_FORMAT_FLAG_BINARY, 0,
                         &enc, &ct, &ft, &store, &hMsg, nullptr)) {
        PCCERT_CONTEXT cc = nullptr;
        if (store) cc = CertEnumCertificatesInStore(store, nullptr);
        if (cc) {
            const CERT_INFO* ci = cc->pCertInfo;
            if (ci && ci->Subject.cbData && ci->Issuer.cbData &&
                ci->Subject.cbData == ci->Issuer.cbData &&
                memcmp(ci->Subject.pbData, ci->Issuer.pbData, ci->Subject.cbData) == 0)
                selfSigned = true;
            CertFreeCertificateContext(cc);
        }
        // 时间戳粗略判定：签名者未认证属性(counter-signature/时间戳)非空
        DWORD szAttr = 0;
        if (hMsg && CryptMsgGetParam(hMsg, CMSG_SIGNER_UNAUTH_ATTR_PARAM, 0, nullptr, &szAttr) && szAttr > 0)
            *hasTimestamp = true;
        if (store) CertCloseStore(store, 0);
        if (hMsg) CryptMsgClose(hMsg);
    }
    return selfSigned ? 2 : 1;
}// ---- 第三部分：语义证据（家族串/白加黑/文件名）+ 7z 解包 + 主入口 ----

// ================================================================ 语义证据表（银狐特指·白名单式）
// 家族确定串：仅样本库/权威报告确认过的极特指项（小写）。不做任何泛化关键词。

// 检测特征串全部外置于规则文件（probe_rules.txt，随安装包分发），二进制内不保存任何恶意串，
// 避免杀软对「内含恶意家族特征串的程序本体」静态误报（火绒 Trojan/Loader 类）。
// 家族特征串：一条规则 = (家族ID, 特征串)
//
// ★ 2026-09-22 扩展：从「银狐专用」扩为**多家族定位**。
//   · 旧格式 `F|串`       → 家族固定 SilverFox（**完全兼容**，现有规则文件一行都不用改）
//   · 新格式 `G|家族|串`  → 指定家族（Gh0st / ValleyRAT / Miner / Ransom / GenericRAT …）
//
//   为什么用「家族 + 特指串」而不是关键词泛匹配：probe 的既定原则是
//   "仅样本库/权威报告确认过的极特指项，不做任何泛化关键词"（见上方注释）。
//   泛化词（如 "rat" "miner"）会大面积误报，而家族定位的价值恰在于**准**。
struct FamilyRule { std::string id, needle; };
struct RuleSet {
    std::vector<FamilyRule>  family;
    std::vector<std::string> badname, hijack, bait, spoof;
};
static std::string RulesFilePath() {
    char exe[MAX_PATH]; GetModuleFileNameA(nullptr, exe, MAX_PATH);
    std::string d = exe; size_t q = d.find_last_of('\\');
    std::string base = (q != std::string::npos) ? d.substr(0, q + 1) : "";
    const std::string cands[] = {
        base + "data\\probe_rules.txt",
        base + "probe_rules.txt",
        "C:\\ProgramData\\SilverFoxGuard\\probe_rules.txt"
    };
    for (const auto& c : cands) if (file_exists(c)) return c;
    return "";
}
// ★ 纵深防御（2026-09-25 取证新增）：规则值里禁止出现控制字符。
//   即使已经改成二进制读取，也不能让脏数据进入匹配引擎 —— 含 0x00/0x1A 的"规则串"
//   永远匹配不到正常文件名，却会污染规则表、让 rules loaded 计数虚高、掩盖真正的编码事故。
//   这里静默跳过并单独计数，LoadRules 结束时会在日志里明确报出来（便于事后发现文件被破坏）。
static bool HasCtrlChars(const std::string& s) {
    for (unsigned char c : s) if (c < 0x20 || c == 0x7F) return true;
    return false;
}
static RuleSet LoadRules() {
    RuleSet r;
    size_t dirty = 0;   // 被跳过的脏规则条数
    std::string fp = RulesFilePath();
    if (fp.empty()) { sf::LogDbg("[probe] rules file missing -> empty tables"); return r; }
    // ★★★ 必须以二进制模式打开 —— 这是本文件最贵的一行修复（2026-09-25）。
    //   事故现场：probe_rules.txt 第 61 行的 B| 段曾被转码工具损坏、混入了 0x1A（Ctrl+Z）。
    //   MSVC 的 std::ifstream 在**文本模式**下把 0x1A 当作文档结束符 —— 于是该行之后的
    //   70 行规则**全部读不到**：
    //     · S|（伪装热门软件名）14 条 → 全丢（chrome/qq/wechat/wps/taobao/alipay/360/telegram…）
    //     · G|（多家族特征串）丢 19 条 → Miner 挖矿 / Ransom 勒索 / GenericRAT 远控 一条都没生效
    //     · B|（钓鱼诱饵词）14 条 → 只剩第 1 条
    //   日志铁证：`rules loaded: 30 family / 8 names / 12 hijack / 1 bait / 0 spoof`
    //   文件实写：49 family / 8 names / 12 hijack / 14 bait / 14 spoof
    //   教训：规则库「写了但读不进来」比「完全没写」更危险 —— 它让所有人以为防护已经生效。
    std::ifstream f(fp, std::ios::binary);
    if (!f) { sf::LogDbg("[probe] rules open fail: " + fp); return r; }
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.size() < 3 || line[1] != '|') continue;
        std::string v = line.substr(2);
        if (v.empty()) continue;
        if (HasCtrlChars(v)) { ++dirty; continue; }   // ★ 纵向防御：脏数据永不进匹配引擎
        switch (line[0]) {
            case 'F': r.family.push_back({"SilverFox", lower(v)}); break;   // 兼容旧格式：F| 归银狐
            case 'G': {                                                      // ★ 新格式 G|家族|特征串
                size_t p = v.find('|');
                if (p != std::string::npos && p > 0) {
                    std::string id = v.substr(0, p);
                    std::string nd = lower(v.substr(p + 1));
                    // 特征串短于 5 字符会大面积误报（既定原则：只收极特指项）
                    if (nd.size() >= 5 && !id.empty()) r.family.push_back({id, nd});
                }
                break;
            }
            case 'N': r.badname.push_back(lower(v)); break;
            case 'H': r.hijack.push_back(lower(v)); break;
            case 'B': r.bait.push_back(v); break;
            case 'S': r.spoof.push_back(lower(v)); break;
        }
    }
    sf::LogDbg("[probe] rules loaded: " + std::to_string(r.family.size()) + " family / " +
               std::to_string(r.badname.size()) + " names / " + std::to_string(r.hijack.size()) +
               " hijack / " + std::to_string(r.bait.size()) + " bait / " + std::to_string(r.spoof.size()) + " spoof");
    // ★ 脏规则告警：有跳过就一定是文件被破坏过，必须留痕（否则规则静默变少永远查不出来）
    if (dirty)
        sf::LogDbg("[probe] ⚠ 规则文件含 " + std::to_string(dirty) +
                   " 条脏数据（控制字符），已跳过 —— 请检查 data\\probe_rules.txt 的编码是否被破坏");
    return r;
}
static const RuleSet& Rules() { static const RuleSet r = LoadRules(); return r; }
static const std::vector<FamilyRule>& FamilyRules() { return Rules().family; }

// 家族 ID → 中文显示名。
// 未登记的 ID 原样返回 —— 这样规则文件里加一个新家族时不会显示成空白，
// 而是显示它的 ID，让人一眼看出"这里有个没登记中文名的家族"。
static std::string FamilyDisplayName(const std::string& id) {
    if (id == "SilverFox")  return "银狐（游蛇）";
    if (id == "Gh0st")      return "Gh0st 幽灵";
    if (id == "ValleyRAT")  return "ValleyRAT";
    if (id == "Miner")      return "挖矿木马";
    if (id == "Ransom")     return "勒索软件";
    if (id == "GenericRAT") return "通用远控木马";
    return id;
}
static const std::vector<std::string>& KnownBadNames() { return Rules().badname; }
static const std::vector<std::string>& HijackDlls() { return Rules().hijack; }
static const std::vector<std::string>& BaitKws() { return Rules().bait; }
static const std::vector<std::string>& PopularSpoofs() { return Rules().spoof; }


// 递归解包深度计数（防 zip-in-zip 递归失控；允许嵌套解包到第 kMaxProbeDepth 层）
static thread_local int g_probeDepth = 0;
static const int kMaxProbeDepth = 5;                       // 归档嵌套深度上限（第 6 层起不再解包）
static thread_local uint64_t g_probeExtracted = 0;         // 本扫描累计解压字节（防解压炸弹）
static const uint64_t kMaxProbeExtracted = (2ull << 30);   // 累计解压预算（2GB，覆盖大型安装包）
static thread_local int g_probeFiles = 0;                  // 本扫描累计解包处理的文件数
static const int kMaxProbeFiles = 20000;

// ================================================================ 文件名规则
static bool IsExecLikeName(const std::string& baseLower) {
    // 决定「这个包值不值得解开」的 nExec。必须包含 DLL/脚本/驱动：银狐主体形态是
    // 「宿主 EXE + 同目录恶意 DLL」，只盯 exe 会让「只含 DLL / 只含脚本 / 只含驱动」的包整包跳过
    // （实测：只含 payload.dll、只含 install.hta、只含 rootkit.sys 的压缩包全部被判「不解包」）。
    return ends_with_i(baseLower, ".exe") || ends_with_i(baseLower, ".scr") ||
           ends_with_i(baseLower, ".pif") || ends_with_i(baseLower, ".com") ||
           ends_with_i(baseLower, ".msi") || ends_with_i(baseLower, ".bat") ||
           ends_with_i(baseLower, ".cmd") || ends_with_i(baseLower, ".lnk") ||
           ends_with_i(baseLower, ".dll") || ends_with_i(baseLower, ".sys") ||
           ends_with_i(baseLower, ".ocx") || ends_with_i(baseLower, ".cpl") ||
           ends_with_i(baseLower, ".hta") || ends_with_i(baseLower, ".wsf") ||
           ends_with_i(baseLower, ".jse") || ends_with_i(baseLower, ".vbs") ||
           ends_with_i(baseLower, ".ps1");
}
static bool IsScrambledUpperName(const std::string& name) {
    // 必须传【原始大小写】文件名。银狐随机名形态：全大写+数字（5D3F9A07）、大小写乱序混合（kdGJKg）、
    // 以及无元音的小写+数字（xk29fjl）。纯小写普通单词（notepad/console…）不是随机名。
    // ⚠ 历史 bug：调用方先把名字小写化再传进来 → 「必须含大写」恒假 → libglesv2 / aria2c / nsis7z
    //   这类正常「字母+数字」文件名被判随机名，成为单文件查杀的主要误报源之一。
    std::string b = name;
    size_t dot = b.find_last_of('.');
    if (dot != std::string::npos) b = b.substr(0, dot);
    if (b.size() < 5 || b.size() > 10) return false;
    bool hasUpper = false, hasDigit = false, hasVowel = false;
    for (char c : b) {
        if (c >= 'a' && c <= 'z') {
            if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') hasVowel = true;
        } else if (c >= 'A' && c <= 'Z') {
            hasUpper = true;
            char l = (char)(c - 'A' + 'a');
            if (l == 'a' || l == 'e' || l == 'i' || l == 'o' || l == 'u') hasVowel = true;
        } else if (c >= '0' && c <= '9') hasDigit = true;
        else return false;   // 含其它字符（下划线/中文/符号）不算随机名
    }
    if (!hasDigit) return false;              // 无数字 → 正常词（AutoHotkey 等大小写混合软件名不算）
    // 全小写 + 含元音 → 像正常单词（libglesv2 / aria2c / nsis7z / ffmpeg4）→ 不是随机名
    if (!hasUpper && hasVowel) return false;
    static const char* sysl[] = { "setupapi","comctl32","gdi32","kernel32","user32","advapi32","shell32","ntdll","ole32","oleaut32","ws2_32","wininet","crypt32","rpcrt4","version","winmm","msvcrt","shlwapi","dnsapi","secur32","notepad","write","winword","excel", "chrome","msedge","firefox","explorer","cmd","powershell" };
    std::string lb = lower(b);
    for (const char* s : sysl) if (lb == s) return false;
    return true;
}
// 对一个（包内或本体）文件名跑名称证据；返回证据（不判档）
// 名称层证据。返回「文件名类证据的最强权重」（0/1/2/3）；strongName 仅在【强名称信号】时置 true
// ——目前只认「已知坏名 / 双后缀伪装 / 钓鱼伪装文件名」。
// 随机名（IsScrambledUpperName）与「疑似伪装热门软件名」不进档位：前者无法与 libGLESv2 / aria2c /
// nsis7z 这类正常「字母+数字」库名区分（实测误报主因），随机名检测交由全盘扫描按「落地位置+父目录」
// 多证据收敛；后者本身就是低权旁证。
static int NameEvidence(const std::string& name, std::vector<Anom>& out, bool* strongName = nullptr) {
    std::string b = lower(name);
    for (const auto& nm : KnownBadNames())
        if (b == nm) { out.push_back({3, "已知木马化投递物文件名", "文件名与已捕获银狐投递物完全一致。"}); if (strongName) *strongName = true; return 3; }
    static const char* dbl[] = {
        ".pdf.exe",".jpg.exe",".jpeg.exe",".png.exe",".doc.exe",".docx.exe",".xls.exe",
        ".xlsx.exe",".rar.exe",".zip.exe",".txt.exe",".7z.exe",".wps.exe",".rtf.exe",
        ".pdf.scr",".jpg.scr",".png.scr"
    };
    for (const char* d : dbl)
        if (ends_with_i(b, d)) { out.push_back({2, "双后缀伪装", "文件名伪装成文档/图片（" + std::string(d) + "）。"}); if (strongName) *strongName = true; return 2; }
    if (IsScrambledUpperName(name)) {   // ← 传原始大小写名字（内部自己小写化只用于白名单比对）
        out.push_back({2, "随机大写名可执行文件", "文件名形如 5-10 位全大写字母数字随机组合（需结合落地位置与结构证据，仅作旁证）。"});
        return 2;   // 注意：不置 strongName → 不单独进档位
    }
    static const char* exts[] = { ".exe",".scr",".pif",".com",".msi",".bat",".cmd",".lnk" };
    bool isExec = false; for (const char* e : exts) if (ends_with_i(b, e)) { isExec = true; break; }
    if (isExec) {
        for (const auto& kw : BaitKws())
            if (b.find(kw) != std::string::npos) { out.push_back({2, "钓鱼伪装文件名", "文件名含人事/财务诱导词，且为可执行文件。"}); if (strongName) *strongName = true; return 2; }
        for (const auto& ps : PopularSpoofs())
            if (b.find(ps) != std::string::npos) { out.push_back({1, "疑似伪装热门软件名", "文件名带热门软件关键词（" + std::string(ps) + "），需结合签名与结构证据。"}); return 1; }
    }
    return 0;
}

// ================================================================ 7z 解包（列内嵌文件）
static bool FileExistsW(const std::wstring& p) {
    return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}
static std::wstring Find7zTool() {
    wchar_t exe[MAX_PATH] = {0};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring dir = exe;
    size_t p = dir.find_last_of(L'\\');
    if (p != std::wstring::npos) dir = dir.substr(0, p + 1);
    std::wstring cand = dir + L"bin\\7z.exe";
    if (FileExistsW(cand)) return cand;
    cand = dir + L"7z.exe";
    if (FileExistsW(cand)) return cand;
    wchar_t pf[MAX_PATH] = {0};
    if (GetEnvironmentVariableW(L"ProgramFiles", pf, MAX_PATH) > 0) {
        std::wstring c2 = std::wstring(pf) + L"\\7-Zip\\7z.exe";
        if (FileExistsW(c2)) return c2;
    }
    return L"";
}
// 列安装包内文件（Path = 行）；失败返回 false
static bool ListArchive7z(const std::wstring& sevenZ, const std::string& path, std::vector<std::string>& out) {
    wchar_t wpath[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH) <= 0) return false;
    std::wstring cmd = L"\"" + sevenZ + L"\" l -ba -slt \"" + wpath + L"\"";
    HANDLE hOutR = NULL, hOutW = NULL;
    SECURITY_ATTRIBUTES sa{ sizeof(sa) }; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) return false;
    if (!SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0)) { CloseHandle(hOutR); CloseHandle(hOutW); return false; }
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hOutW; si.hStdError = hOutW; si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi{};
    DWORD flags = CREATE_NO_WINDOW;
    BOOL ok = CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, TRUE, flags, nullptr, nullptr, &si, &pi);
    if (!ok) { CloseHandle(hOutR); CloseHandle(hOutW); return false; }
    CloseHandle(hOutW);
    std::string acc;
    char buf[16384];
    DWORD rd = 0;
    while (ReadFile(hOutR, buf, sizeof(buf), &rd, nullptr) && rd > 0) { acc.append(buf, rd); }
    CloseHandle(hOutR);
    WaitForSingleObject(pi.hProcess, 15000);
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    // 解析 "Path = xxx"
    size_t pos = 0;
    bool any = false;
    while (true) {
        size_t nl = acc.find('\n', pos);
        std::string line = (nl == std::string::npos) ? acc.substr(pos) : acc.substr(pos, nl - pos);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const char* key = "Path = ";
        size_t kp = line.find(key);
        if (kp != std::string::npos) {
            std::string v = line.substr(kp + strlen(key));
            // 剔除尾部 BS 标记（Properties 格式中 Path 后无 BS，但保险）
            size_t bs = v.find(" BS");
            if (bs != std::string::npos && v.size() - bs <= 8) v = v.substr(0, bs);
            out.push_back(v);
            any = true;
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return any;
}

// 7z 列包并取 (路径, 大小)，供体积预算与名称规则
static bool ListArchiveMeta(const std::wstring& sevenZ, const std::string& path,
                            std::vector<std::pair<std::string, uint64_t>>& out, uint64_t* totalOut) {
    if (totalOut) *totalOut = 0;
    wchar_t wpath[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH) <= 0) return false;
    std::wstring cmd = L"\"" + sevenZ + L"\" l -ba -slt \"" + wpath + L"\"";
    HANDLE hOutR = NULL, hOutW = NULL;
    SECURITY_ATTRIBUTES sa{ sizeof(sa) }; sa.bInheritHandle = TRUE;
    if (!CreatePipe(&hOutR, &hOutW, &sa, 0)) return false;
    if (!SetHandleInformation(hOutR, HANDLE_FLAG_INHERIT, 0)) { CloseHandle(hOutR); CloseHandle(hOutW); return false; }
    STARTUPINFOW si2{};
    si2.cb = sizeof(si2); si2.dwFlags = STARTF_USESTDHANDLES;
    si2.hStdOutput = hOutW; si2.hStdError = hOutW; si2.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION pi2{};
    BOOL ok = CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW,
                             nullptr, nullptr, &si2, &pi2);
    if (!ok) { CloseHandle(hOutR); CloseHandle(hOutW); return false; }
    CloseHandle(hOutW);
    std::string acc; char buf[16384]; DWORD rd = 0;
    while (ReadFile(hOutR, buf, sizeof(buf), &rd, nullptr) && rd > 0) acc.append(buf, rd);
    CloseHandle(hOutR);
    WaitForSingleObject(pi2.hProcess, 60000);
    DWORD code = 0; GetExitCodeProcess(pi2.hProcess, &code);
    CloseHandle(pi2.hProcess); CloseHandle(pi2.hThread);
    if (code != 0 && acc.empty()) return false;
    // 解析 -slt 块：Path = 与 Size =
    std::string curPath, curSize; uint64_t total = 0;
    auto commit = [&]() {
        if (curPath.empty()) return;
        uint64_t szv = 0;
        for (char c : curSize) if (c >= '0' && c <= '9') szv = szv * 10 + (uint64_t)(c - '0');
        out.emplace_back(curPath, szv);
        total += szv;
        curPath.clear(); curSize.clear();
    };
    size_t pos = 0; bool any = false;
    while (true) {
        size_t nl = acc.find('\n', pos);
        std::string ln = (nl == std::string::npos) ? acc.substr(pos) : acc.substr(pos, nl - pos);
        if (!ln.empty() && ln.back() == '\r') ln.pop_back();
        const char* kp = "Path = ";
        size_t k = ln.find(kp);
        if (k != std::string::npos) { commit(); curPath = ln.substr(k + strlen(kp)); any = true; }
        else {
            size_t ks = ln.find("Size = ");
            if (ks != std::string::npos) curSize = ln.substr(ks + 7);
        }
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    commit();
    if (totalOut) *totalOut = total;
    return any;
}

// 解压到指定目录（-aos 跳过已存在，-y 静默；超 600 秒视为失败）。
// 7z 退出码：0=成功 1=有警告但文件已解出（NSIS/Inno 常返回 1/2 附带尾部提示）——1 视为成功
//
// ★ 2026-09-27：拆成「宽字符核心 + ANSI 包装」两段，供沙箱模块复用。
//   沙箱需要对**已解压出来的载荷**送检（压缩包本身在沙箱里没有"跑起来"这回事），
//   解压这一步必须与全盘/单文件扫描链**共用同一个实现**，否则两条链路的
//   7z 调用参数（-aos/-y/超时/退出码语义）会悄悄漂移。
static bool ExtractArchive7zW(const std::wstring& sevenZ, const std::wstring& wpath,
                              const std::wstring& tmpDir) {
    std::wstring cmd = L"\"" + sevenZ + L"\" x -y -aos -o\"" + tmpDir + L"\" \"" + wpath + L"\"";
    STARTUPINFOW si3{}; si3.cb = sizeof(si3);
    PROCESS_INFORMATION pi3{};
    if (!CreateProcessW(nullptr, (LPWSTR)cmd.c_str(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si3, &pi3)) return false;
    DWORD w = WaitForSingleObject(pi3.hProcess, 600000);
    DWORD code = 0;
    if (w != WAIT_OBJECT_0) TerminateProcess(pi3.hProcess, 1);
    else GetExitCodeProcess(pi3.hProcess, &code);
    CloseHandle(pi3.hProcess); CloseHandle(pi3.hThread);
    return w == WAIT_OBJECT_0 && (code == 0 || code == 1);
}

static bool ExtractArchive7z(const std::wstring& sevenZ, const std::string& path, const std::wstring& tmpDir) {
    wchar_t wpath[MAX_PATH] = {0};
    if (MultiByteToWideChar(CP_ACP, 0, path.c_str(), -1, wpath, MAX_PATH) <= 0) return false;
    return ExtractArchive7zW(sevenZ, wpath, tmpDir);
}

// ANSI(系统代码页) → UTF-8（用于管道帧传输）
static std::string AnsiToUtf8(const std::string& in) {
    int nw = MultiByteToWideChar(CP_ACP, 0, in.c_str(), -1, nullptr, 0);
    if (nw <= 0) return in;
    std::wstring w(nw, L'\0');
    MultiByteToWideChar(CP_ACP, 0, in.c_str(), -1, &w[0], nw);
    int nu = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (nu <= 1) return in;
    std::string u(nu - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &u[0], nu, nullptr, nullptr);
    return u;
}

// 从解包目录迭代得到的宽字符路径 → UTF-8 / ANSI（UTF-16 真名直转，避免 ANSI 中转损中文名）
static std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    int nu = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (nu <= 1) return std::string();
    std::string u(nu - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &u[0], nu, nullptr, nullptr);
    return u;
}
// UTF-8 → 宽字符（供沙箱模块复用；项目铁律：路径必须转 UTF-16 再用 W 版 API）
static std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    int nw = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (nw <= 1) return std::wstring();
    std::wstring w(nw - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], nw);
    return w;
}
static std::string WideToAnsi(const std::wstring& w) {
    if (w.empty()) return std::string();
    int na = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (na <= 1) return std::string();
    std::string a(na - 1, '\0');
    WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &a[0], na, nullptr, nullptr);
    return a;
}

// 包内可执行文件名集合（供解包后逐个判定）
static bool IsDubiousPayloadExt(const std::string& l) {
    // 决定「解包后包内文件是否逐个判定」。补齐可承载载荷的扩展名（原先缺 .sys/.ocx/.cpl/.hta/.wsf/
    // .jse/.msix 等 → 这些载荷即使被解出来也静默跳过；实测 WebView2Runtime.7z 就有 5 个文件被静默略过）。
    return ends_with_i(l, ".exe") || ends_with_i(l, ".dll") || ends_with_i(l, ".scr") ||
           ends_with_i(l, ".com") || ends_with_i(l, ".msi") || ends_with_i(l, ".bat") ||
           ends_with_i(l, ".cmd") || ends_with_i(l, ".js") || ends_with_i(l, ".vbs") ||
           ends_with_i(l, ".ps1") || ends_with_i(l, ".jar") || ends_with_i(l, ".lnk") ||
           ends_with_i(l, ".sys") || ends_with_i(l, ".ocx") || ends_with_i(l, ".cpl") ||
           ends_with_i(l, ".hta") || ends_with_i(l, ".wsf") || ends_with_i(l, ".jse") ||
           ends_with_i(l, ".msix") || ends_with_i(l, ".msu") || ends_with_i(l, ".appx") ||
           ends_with_i(l, ".ax")  || ends_with_i(l, ".drv");
}

// 归档/可继续解包扩展名（嵌套压缩包也要解开来判）
static bool IsArchiveExt(const std::string& l) {
    static const char* exts[] = {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".lzh", ".iso",
        ".cab", ".arj", ".wim", ".rpm", ".deb", ".xar", ".tgz", ".tbz", ".txz",
        ".msix", ".msu", ".appx"    // 7z 可列/可解的现代打包容器（原先漏了 → 既不解包也无任何提示）
    };
    for (const char* e : exts) if (ends_with_i(l, e)) return true;
    return false;
}

// ================================================================ JSON & 判定
struct Verdict {
    int level = 0;              // 0 正常 1 可疑 2 危险
    int score = 0;
    std::string type = "OTHER";
    std::string title;
    std::string family;         // ★ 命中的家族 ID（空 = 未定家族）；供 UI 显示"疑似 X 家族"
    std::vector<Anom> hits;     // 按证据权值列出
};
static std::string JsonEsc(const std::string& s) {
    std::string r;
    for (unsigned char c : s) {
        switch (c) {
            case '"': r += "\\\""; break;
            case '\\': r += "\\\\"; break;
            case '\n': r += "\\n"; break;
            case '\r': break;
            case '\t': r += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); r += b; }
                else r += (char)c;
        }
    }
    return r;
}

std::string ScanTargetFile(const std::string& pathUtf8) {
    // 传输规范：path 为 UTF-8（管道/JSON），内部 I/O 用本机 ANSI 代码页（CreateFileA/ifstream）
    std::string path;
    // 「是否纯 ASCII」必须逐字节判高位：早先用 find_first_of("\x80\xff") 是错的——
    // 合法 UTF-8 永不产生 0xFF，0x80 也只出现在少数码点（如 考 U+8003 = E8 80 83），
    // 于是「下载」这类中文目录被判成"纯ASCII"而跳过转换，UTF-8 字节被当 GBK 传给 CreateFileA
    // → GetLastError=3 → 误报「空文件或无法读取」，且整个解包/判定链路全部跳过（实测 29% 无关误报、中文路径 100% 失效）。
    bool asciiOnly = pathUtf8.size() > 0;
    for (size_t i = 0; asciiOnly && i < pathUtf8.size(); ++i)
        if ((unsigned char)pathUtf8[i] >= 0x80) asciiOnly = false;
    if (asciiOnly) {
        path = pathUtf8;   // 纯 ASCII：无需转换
    } else {
        int nW = MultiByteToWideChar(CP_UTF8, 0, pathUtf8.c_str(), -1, nullptr, 0);
        if (nW > 0) {
            std::wstring w(nW, L'\0');
            MultiByteToWideChar(CP_UTF8, 0, pathUtf8.c_str(), -1, &w[0], nW);
            int nA = WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
            if (nA > 0) {
                path.resize(nA - 1);
                WideCharToMultiByte(CP_ACP, 0, w.c_str(), -1, &path[0], nA, nullptr, nullptr);
            }
        }
        if (path.empty()) path = pathUtf8;
    }
    Verdict v;
    // 我方产物/不可用输入：直接安全
    std::string base = basename_of(path);
    {
        std::string b = lower(base);
        if (b == "silverfoxguardsvc.exe" || b == "silverfoxshell.dll" || b == "update_ver.exe" ||
            b == "silverfoxenvscansvc.exe" || b == "silverfoxenvscan.exe")
            { std::string j = "{\"level\":0,\"score\":0,\"type\":\"SELF\",\"title\":\"银狐主防自身文件，无需查杀\",\"hits\":[]}"; return j; }
    }
    uint64_t sz = file_size(path);
    if (sz == 0) {
        // 诊断：路径转换/权限问题会在这里暴露（正常文件不可能恒为 0）
        sf::LogDbg(std::string("[probe] EMPTY/UNREADABLE ansi=") + path + " utf8=" + pathUtf8 +
                   " attr=" + std::to_string((int)GetFileAttributesA(path.c_str())));
        std::string j = "{\"level\":0,\"score\":0,\"type\":\"OTHER\",\"title\":\"空文件或无法读取\",\"hits\":[]}";
        return j;
    }
    // 1) 名称证据（返回文件名类最强权重 + 是否为强名称信号）
    bool nameStrong = false;
    int nameMaxW = NameEvidence(base, v.hits, &nameStrong);

    // 2) 读头 & 类型
    std::vector<uint8_t> head = read_prefix(path, 8 << 20);
    PeInfo pi;
    bool peOk = ParsePeHeader(head, pi);
    const char* typeS = DetectType(path, pi, (size_t)sz, head);
    v.type = typeS;
    bool installer = (std::string(typeS) == "NSIS" || std::string(typeS) == "INNO");

    // 3) 内容层（家族串 / 白加黑）——只对可执行/安装器/压缩包做，避免对文档等误扫
    std::string familyHit, hijackHit, familyId;
    if (peOk || installer || std::string(typeS) == "ZIP") {
        std::string c = read_lower_content(path, 2 << 20);
        for (const auto& fr : FamilyRules())
            if (c.find(fr.needle) != std::string::npos) {
                familyHit = fr.needle;
                familyId  = fr.id;      // ★ 多家族定位：连带记下是哪个家族
                break;
            }
        for (const auto& d : HijackDlls())
            if (c.find(d) != std::string::npos) { hijackHit = d; break; }
    }

    // 4) 结构异常（PE）
    std::vector<Anom> anoms;
    std::vector<char> scratch(256 << 10);
    if (peOk) AnalyzeStructure(path, pi, sz, installer, anoms, scratch);

    // 5) 解包扫描：任何文件都交给 7z 尝试识别/解压（zip/rar/7z/msi/cab/tar/gz/iso/自解压…全格式兼容），
    //    失败时仅对「确认是容器」的文件（识别为安装器/压缩包，或归档扩展名）给出提示，普通文件静默。
    //    嵌套压缩包递归解压（受深度/字节/文件数三重预算约束），7z 随安装包分发，目标机无需预装。
    const bool zipLike = (std::string(typeS) == "ZIP" || std::string(typeS) == "RAR" || std::string(typeS) == "7Z");
    const bool knownArchive = installer || zipLike;
    // 「真是容器」：决定了要不要向用户提示包内信息（7z 能把普通 PE/DLL 当容器列出，不能据此提示）
    const bool containerLike = knownArchive || IsArchiveExt(lower(base));
    std::vector<std::string> entries;
    std::string archiveNote;
    bool entryListOk = false;
    if (g_probeDepth < kMaxProbeDepth) {
        std::wstring sevenZ = Find7zTool();
        if (!sevenZ.empty()) {
            uint64_t totalSize = 0;
            std::vector<std::pair<std::string, uint64_t>> meta;
            if (ListArchiveMeta(sevenZ, path, meta, &totalSize)) {
                entryListOk = true;
                size_t nExec = 0, nArchive = 0;
                for (const auto& m : meta) {
                    std::string en = lower(m.first);
                    if (IsExecLikeName(en)) { ++nExec; NameEvidence(m.first, v.hits, nullptr); }
                    else if (IsArchiveExt(en)) ++nArchive;
                }
                // 只在「真是容器」时才提示包内情况；7z 能把普通 PE/DLL 的节区当条目列出来，
                // 否则每个 exe/dll 都会凭空多一条「压缩包内容：包内未发现可执行文件项」（纯误导）。
                if (nExec == 0 && nArchive == 0 && containerLike)
                    v.hits.push_back({0, "压缩包内容", "包内未发现可执行文件项。"});
                // 受控解压：单包 ≤1GB、条目 ≤20000、含可执行项/嵌套压缩包、且总预算未超限时才解。
                // 纯文档包（无 exe 无嵌套包）不解，避免白费 IO。大型安装包（数百 MB/数千条目）照常解。
                //
                // ★★ 2026-10-03 修正（真样本实证，preview4 之前一直漏这一类）：
                //   根因 = **7z 会把安装器的 PE 节区当成包内条目列出来**，而这些"条目名"
                //   往往是 `.text`/`.rsrc` 之类，**没有一个像可执行文件** ⇒ nExec=0
                //   ⇒ 命中 `nExec==0 && nArchive==0` ⇒ **主动跳过解包**。
                //   实证：138,913,585 B 的 Inno 包（银狐本体 YouDaoX64.exe）
                //        日志 `条目=21 总量=138913585B nExec=0 nArchive=0 -> 跳过(包内无可执行项/嵌套包)`，
                //        同一文件随后 `level=2 score=320` 判得又准，**却因不解包而永远看不到里面是什么**。
                //   修法：**外层已经确认是安装器**（NSIS/INNO）时，条目名不可信 ——
                //        它内层**必然**是文件，必须解。判据从"条目名像不像可执行体"
                //        改成"**外层类型 + 条目数**"，不依赖 7z 的条目命名。
                const bool installerForced = installer && meta.size() > 0;
                const bool canUnpack = (totalSize > 0 && totalSize <= (1ull << 30) &&
                                        meta.size() <= 20000 &&
                                        (nExec > 0 || nArchive > 0 || installerForced) &&
                                        g_probeExtracted + totalSize <= kMaxProbeExtracted);
                // 解包决策日志（此前该分支一行日志都没有，导致「为什么不解包」完全不可诊断）
                {
                    std::string why;
                    if (!(totalSize > 0)) why = "总量解析为0";
                    else if (totalSize > (1ull << 30)) why = "总量超1GB";
                    else if (meta.size() > 20000) why = "条目超2万";
                    else if (!(nExec > 0 || nArchive > 0) && !installerForced) why = "包内无可执行项/嵌套包";
                    else if (!(g_probeExtracted + totalSize <= kMaxProbeExtracted)) why = "累计预算耗尽";
                    sf::LogDbg("[probe-pack] " + base + " 条目=" + std::to_string(meta.size()) +
                               " 总量=" + std::to_string(totalSize) + "B nExec=" + std::to_string(nExec) +
                               " nArchive=" + std::to_string(nArchive) +
                               (installerForced ? " [安装器强制解包]" : "") +
                               (canUnpack ? " -> 解包" : (" -> 跳过(" + why + ")")));
                }
                if (canUnpack) {
                    wchar_t tbuf[MAX_PATH]; std::wstring tmp;
                    std::filesystem::path tmpP;
                    if (GetTempPathW(MAX_PATH, tbuf)) {
                        wchar_t pid[24]; swprintf_s(pid, L"_%lu", (unsigned long)GetCurrentProcessId());
                        tmp = std::wstring(tbuf) + L"SilverFoxProbe" + pid + L"_" + std::to_wstring(g_probeDepth);
                        tmpP = std::filesystem::path(tmp);
                        std::error_code ec0;
                        std::filesystem::remove_all(tmpP, ec0);
                        if (ExtractArchive7z(sevenZ, path, tmp)) {
                            g_probeExtracted += totalSize;
                            ++g_probeDepth;
                            try {
                                std::error_code ec1;
                                for (auto it = std::filesystem::recursive_directory_iterator(
                                         tmpP, std::filesystem::directory_options::skip_permission_denied, ec1);
                                     it != std::filesystem::recursive_directory_iterator(); ++it) {
                                    if (g_probeFiles >= kMaxProbeFiles) break;
                                    std::error_code e2;
                                    if (!it->is_regular_file(e2)) continue;
                                    std::wstring fpW = it->path().wstring();   // UTF-16 真名，避免 ANSI 中转损中文
                                    std::string fp = WideToAnsi(fpW);
                                    if (!IsDubiousPayloadExt(lower(fp)) && !IsArchiveExt(lower(fp))) continue;
                                    ++g_probeFiles;
                                    std::string u8 = WideToUtf8(fpW);
                                    if (u8.empty()) continue;
                                    std::string sub = sf::ScanTargetFile(u8);   // 递归：嵌套压缩包/安装器在深层继续解包
                                    int lv = sf::JsonGetInt(sub, "level");
                                    if (lv >= 1) {
                                        std::string t = sf::JsonGetString(sub, "title");
                                        v.hits.push_back({2, "包内可疑文件",
                                                          "解包发现 " + std::string(basename_of(u8)) + "：" +
                                                          (t.empty() ? "可疑" : t) + "。"});
                                        if (lv >= 2) { v.level = 2; v.score += 200; }
                                        else if (v.level < 1) v.level = 1;
                                    }
                                }
                            } catch (...) {}
                            --g_probeDepth;
                        } else if (containerLike) {
                            sf::LogDbg("[probe-pack] " + base + " 解压失败（加密/损坏/私有变体）");
                            v.hits.push_back({0, "压缩包内容", "解压失败（加密/损坏/私有变体），未检查包内文件。"});
                        }
                    }
                    std::error_code ec2;
                    std::filesystem::remove_all(tmpP, ec2);   // 清理解压副本
                }
            } else if (containerLike) {
                sf::LogDbg("[probe-pack] " + base + " 7z 列包失败（非标准容器/加密头）");
                v.hits.push_back({0, "压缩包内容", "内容无法解析为已知压缩/安装包格式（加密/私有变体或非标准容器）。"});
            }
        } else if (containerLike) {
            sf::LogDbg("[probe-pack] " + base + " 未找到 7z（bin\\7z.exe / 7z.exe / ProgramFiles 均无）");
            v.hits.push_back({0, "压缩包内容", "本机无 7-Zip，未解析包内文件（仅静态指纹）。"});
        }
    }

    // 6) 签名（离线语义：仅作参考，不直接放行/定罪）
    bool hasTs = false;
    int sig = VerifySigVerdict(path, &hasTs);
    bool validSig = (sig == 1 || sig == 2);          // 链完整（自签也算有效链，但下面单独降权）
    bool selfSigned = (sig == 2);
    int sigTone = 1;                                  // 权重系数
    if (validSig) sigTone = 2;                        // 有效签名 → 证据降一档（×0.5）
    if (validSig)
        v.hits.insert(v.hits.begin(), {0, "数字签名", selfSigned ? "存在自签 Authenticode 签名（链完整，自签证书效力弱）。" : "存在有效数字签名（含时间戳" + std::string(hasTs ? "" : "?") + "），可信度上调。"});

    // 7) 语义命中折价：家族串命中即使有签名也只降为可疑级（防证书被窃取场景）
    bool familyStrong = !familyHit.empty();

    // 8) 计分与档位（保守）
    // 解包段可能已按「包内子文件命中」把 level 拉到 1/2，档位链的 else「正常」分支不得把它复位。
    int innerLevel = v.level;
    int anomHigh = 0, anomLow = 0, anomTotal = 0;
    for (const auto& a : anoms) {
        int w = (sigTone == 2) ? (a.w + 1) / 2 : a.w;   // 有有效签名 → 结构异常降权取半
        if (w >= 2) ++anomHigh; else if (w >= 1) ++anomLow;   // ← 必须用降权后的 w（此前用 a.w 计数，
                                                              //    (void)w; 把降权值丢弃，导致「有签名降一档」从未生效）
    }
    anomTotal = (int)anoms.size();
    // 名称层证据只用 NameEvidence 的返回值（文件名类），不从 v.hits 反查——
    // 「包内可疑文件」「压缩包内容」等容器/结构证据也是 w=2，反查会把它们误当文件名可疑。
    int nameHigh = nameMaxW;                                  // >=3：已知坏名精确命中
    int nameMid  = (nameStrong && nameMaxW == 2) ? 2 : 0;    // ==2：双后缀伪装 / 钓鱼伪装文件名（随机名不单独进档）

    if (nameHigh >= 3) {                                   // 已知坏名精确命中
        v.level = 2; v.score += 320;
        v.title = "命中已知木马化投递物";
    } else if (familyStrong) {
        v.level = validSig ? 1 : 2;                        // 有效签名降为可疑
        v.score += validSig ? 100 : 320;
        // ★ 多家族定位：把家族 ID 带出去，UI 据此显示「疑似 X 家族」而不是笼统的"银狐"
        v.family = familyId;
        const std::string famName = FamilyDisplayName(familyId);
        v.title = "命中" + famName + "家族特征串";
        v.hits.push_back({3, famName + "家族特征串",
                          "文件内容包含" + famName + "确认特征（" + familyHit + "）。"});
        // 白加黑：仅「无签名的安装器（NSIS/Inno 静态包）」命中才定罪——包内含被劫持模块名是真实投递信号；
        // 普通 PE/脚本命中系统 DLL 名（powrprof/version/dbghelp…）极常见（正常安全/系统工具都会引用），
        // 不再凭内容字符串判危（教训：自家 SilverFoxEnvScanSvc.exe 被误报 300 分）。普通命中只作展示旁证。
    } else if (!hijackHit.empty() && !validSig && installer) {
        v.level = 2; v.score += 300;
        v.title = "发现白加黑载荷特征";
        v.hits.push_back({2, "白加黑载荷名", "安装包内含已知被劫持模块名（" + std::string(hijackHit) + "）。"});
    } else if (anomHigh >= 4 && !validSig) {
        v.level = 2; v.score += 200 + anomHigh * 40;
        v.title = "多项结构异常且无有效签名";
    } else if (anomHigh >= 4) {
        v.level = 1; v.score += 100 + anomHigh * 20;
        v.title = "多项结构异常（有签名，降级可疑）";
    } else if (anomHigh >= 3) {
        v.level = 1; v.score += 90 + anomHigh * 30;
        v.title = "存在多项高权结构异常";
    } else if (anomHigh >= 2) {
        v.level = 1; v.score += 80;
        v.title = "存在多项可疑结构特征";
    } else if (nameMid >= 2) {
        v.level = 1; v.score += 70;
        v.title = "文件名高度可疑";
    } else {
        // 正常：合并提示型证据展示，不判危；但包内子文件已判定可疑时保留升级
        v.level = std::max(v.level, innerLevel);
        v.title = v.level >= 1 ? "压缩包内含可疑文件" : "未发现可疑特征";
    }
    // 白加黑名兜底：未构成定罪档（非 installer 或已签名）时仅并入展示，绝不凭内容字符串孤证升档——
    // 普通程序/脚本/安全工具引用系统 DLL 名（powrprof/version/dbghelp…）是常态（误报教训：自家 SilverFoxEnvScanSvc.exe 300 分）。
    if (!hijackHit.empty() && v.title != "发现白加黑载荷特征")
        v.hits.push_back({2, "白加黑载荷名", "内容含已知被劫持模块名（" + hijackHit + "）。正常安全/系统工具也可能引用，仅作提示，需结合签名与同目录实体 DLL 判定。"});
    // 证据进 hits（结构证据已在 anoms，需并入 v.hits）
    for (auto& a : anoms) v.hits.push_back(a);

    // 9) JSON 输出
    // 展示收敛：w==1 的低权信息项不列进「可疑证据」；有有效签名时，文件名诱导/随机名/白加黑等
    // 文件名声誉类旁证一并隐去（避免正常软件被一排「可疑」吓到），w==0 提示类保留。
    auto isNoise = [&](const Anom& h) {
        if (h.w == 0) return false;
        if (h.w == 1) return true;
        if (validSig && (h.name.find("伪装") != std::string::npos ||
                         h.name.find("随机大写") != std::string::npos ||
                         h.name.find("白加黑") != std::string::npos))
            return true;
        return false;
    };
    std::string j;
    j += "{\"level\":" + std::to_string(v.level) + ",\"score\":" + std::to_string(v.score) +
         ",\"type\":\"" + v.type + "\",\"title\":\"" + JsonEsc(v.title) + "\"";
    // ★ 多家族定位结果。空时不输出该字段 —— 前端据此判断「未定家族」，
    //   避免显示一个空的家族标签（那会让人以为"分析失败"）。
    if (!v.family.empty()) {
        j += ",\"family\":\""     + JsonEsc(v.family) + "\"";
        j += ",\"familyName\":\"" + JsonEsc(FamilyDisplayName(v.family)) + "\"";
    }
    j += ",\"hits\":[";
    bool first = true;
    for (const auto& h : v.hits) {
        if (h.name.empty() || isNoise(h)) continue;
        if (!first) j += ",";
        first = false;
        j += "{\"sev\":" + std::to_string(h.w) + ",\"name\":\"" + JsonEsc(h.name) +
             "\",\"desc\":\"" + JsonEsc(h.desc) + "\"}";
    }
    j += "]}";
    sf::LogDbg("[probe] " + base + " ->level=" + std::to_string(v.level) + " score=" +
               std::to_string(v.score) + " type=" + v.type);
    return j;
}

// ---------------------------------------------------------------------------
//  导入的 DLL 名列表（白加黑检测的基础设施，2026-09-22）
//
//  为什么需要它：DLL 劫持 / 侧加载（"白加黑"）的典型形态是
//      合法签名的 exe ＋ 同目录一个固定名恶意 DLL（version.dll / libcurl.dll …）
//  这个 exe 本身是干净的，查它的签名毫无用处 —— **要抓的是那个 DLL**。
//  而找 DLL 的唯一静态入口就是读 exe 的导入表：它声明了"我会加载哪些 DLL"。
//
//  与上面的 ParseImports 是两个用途，不要合并：
//    · ParseImports  → 要**函数名**（判"只导入 LoadLibrary/GetProcAddress"= 动态解析/加壳特征）
//    · ParseImportDlls → 要**DLL 名**（判同目录是否存在可被劫持的同名文件）
//
//  只读导入表描述符的 Name 字段（RVA → 文件偏移 → 读字符串），不解析 thunk，
//  所以比 ParseImports 轻得多。
// ---------------------------------------------------------------------------
static bool ParseImportDlls(const std::string& path, const PeInfo& pi, std::vector<std::string>& out) {
    out.clear();
    if (pi.importRva == 0) return false;
    DWORD raw = 0;
    if (!RvaToRaw(pi, pi.importRva, &raw)) return false;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    for (DWORD i = 0; i < 64; ++i) {     // 描述符数组以全零项结尾；64 项是防御性上限
        IMAGE_IMPORT_DESCRIPTOR d{};
        f.seekg(raw + (std::streamoff)i * sizeof(d));
        f.read((char*)&d, sizeof(d));
        if (f.gcount() != sizeof(d)) break;
        if (d.FirstThunk == 0 && d.Name == 0 && d.OriginalFirstThunk == 0) break;
        if (d.Name == 0) continue;
        DWORD nameRaw = 0;
        if (!RvaToRaw(pi, d.Name, &nameRaw)) continue;
        f.seekg(nameRaw);
        char nb[256] = {0};
        f.read(nb, sizeof(nb) - 1);
        std::string dll = lower(nb);
        // 去重（同一个 DLL 不会出现两次，但损坏样本可能有重复描述符）
        if (!dll.empty() && std::find(out.begin(), out.end(), dll) == out.end())
            out.push_back(dll);
    }
    return !out.empty();
}

bool ImportedDlls(const std::string& path, std::vector<std::string>& out) {
    out.clear();
    std::vector<uint8_t> head = read_prefix(path, 1 << 20);   // 1MB 足够覆盖节表
    PeInfo pi;
    if (!ParsePeHeader(head, pi) || !pi.ok) return false;
    return ParseImportDlls(path, pi, out);
}

}  // namespace sfprobe

namespace sf {
std::string ScanTargetFile(const std::string& path) { return sfprobe::ScanTargetFile(path); }

// 读取 PE 的导入 DLL 名（小写、去重）。
// 返回 false = 非 PE 或解析失败 —— 调用方**不得**据此判定任何东西。
bool ImportedDlls(const std::string& path, std::vector<std::string>& out) {
    return sfprobe::ImportedDlls(path, out);
}

// ★ LooksLikeInstallerExe（2026-10-03）：判断 .exe 是否其实是自解压安装器。
//   实现体在 sfprobe（它要用 static 的 lower/ends_with_i/FindAsciiMagic），
//   这里只做转发 —— 与 ImportedDlls 同一模式，避免重复实现。
bool LooksLikeInstallerExe(const std::string& path) {
    return sfprobe::LooksLikeInstallerExe(path);
}

// ---------------------------------------------------------------------------
//  归档解压（供沙箱模块复用）
// ---------------------------------------------------------------------------
// 定位：**这不是"解包分析"，是"把真实文件解压出来"**。
//   沙箱模块需要拿到压缩包（zip/rar/7z/自解压 exe）里**落在磁盘上的真实载荷**，
//   再把它们逐个送进沙箱**运行**观察。
//   为什么不能直接把压缩包送沙箱：压缩包不是可执行体，送进去它"什么都不会发生"
//   —— 那不是"干净"，那是**观察根本不适用**（见 sandbox.h 的 verdict 语义）。
//   为什么不用 probe 的 ListArchiveMeta 那套"列条目 + 静态判定"：那是**静态**
//   视角（只看包内文件名与内容特征）。沙箱要的是行为，必须真落盘、真运行。
//   两者目标不同，不能互相替代。
//
// ⚠️ 编码纪律：入参是 **UTF-8**，本函数内部转 UTF-16 再传给 W 版 API /
//    7z 命令行。项目铁律：UTF-8 路径必须转 UTF-16（中文文件名/路径）。
std::string Find7z() {
    const std::wstring w = sfprobe::Find7zTool();
    return w.empty() ? std::string() : sfprobe::WideToUtf8(w);
}

bool ExtractArchiveTo(const std::string& archivePathUtf8, const std::string& destDirUtf8) {
    const std::wstring sevenZ = sfprobe::Find7zTool();
    if (sevenZ.empty()) return false;
    const std::wstring wp = sfprobe::Utf8ToWide(archivePathUtf8);
    const std::wstring wd = sfprobe::Utf8ToWide(destDirUtf8);
    if (wp.empty() || wd.empty()) return false;
    return sfprobe::ExtractArchive7zW(sevenZ, wp, wd);
}
}  // namespace sf