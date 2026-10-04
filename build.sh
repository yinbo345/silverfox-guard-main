#!/usr/bin/env bash
# 银狐主防程序构建脚本（MSVC，静态单文件 /MT）
set -e

# ---- ★ 必须关掉 MSYS2 的 POSIX→Windows 路径参数转换（2026-09-24 加）----
# 症状：cl 报 `D9024 无法识别的源文件类型 ".../PortableGit/.../nologo"`，
#       紧接着成千上万条 C4819 / C2143 / C2065 —— 因为 /nologo /MT /utf-8
#       /O2 /EHsc /W3 全被当成路径转成了 `C:/.../PortableGit/<ver>/<flag>`。
#       /utf-8 一旦失效，带中文的源文件立刻按 936 代码页解析 → 成片假报错，
#       看起来像"自己改崩了"，实则是**编译参数没生效**（本项目踩过的老坑，
#       与 /Zs 语法检查必须带 /utf-8 是同一个根因）。
# 注意：本脚本内所有路径已是 Windows 风格（D:/...），不需要任何转换。
export MSYS2_ARG_CONV_EXCL="*"

VC="C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC/14.44.35207"
SDK="C:/Program Files (x86)/Windows Kits/10"
SDKVER="10.0.26100.0"
# WebView2 SDK（来自 nuget：microsoft.web.webview2 1.0.2651.64）
WV2="C:/Users/tianl/.nuget/packages/microsoft.web.webview2/1.0.2651.64"

export INCLUDE="$VC/include;$SDK/Include/$SDKVER/ucrt;$SDK/Include/$SDKVER/um;$SDK/Include/$SDKVER/shared;$SDK/Include/$SDKVER/winrt;$WV2/build/native/include"
export LIB="$VC/lib/x64;$SDK/Lib/$SDKVER/ucrt/x64;$SDK/Lib/$SDKVER/um/x64;$WV2/build/native/x64"

CL="$VC/bin/Hostx64/x64/cl.exe"
# ★ 开源版：路径由**脚本自身位置**推导，不再写死 D:/SilverFoxGuard。
#   原写法 `SRC="D:/SilverFoxGuard/src"` 对任何克隆的用户都是死路 ——
#   他们的仓库在别处，而 build.sh 会去改别人机器上那个（可能不存在的）目录，
#   更糟的是可能**污染**那里。推导方式：$0 的绝对路径去掉脚本名。
#   兼容：从任意目录 `bash /path/to/repo/build.sh` 都能正确工作。
_SELF="${BASH_SOURCE[0]:-$0}"
ROOT="$(cd "$(dirname "$_SELF")" && pwd)"
SRC="$ROOT/src"
DIST="$ROOT/dist"
mkdir -p "$DIST"

# 预授权：dist 下的 EXE 一旦被 HardenFileAcl 收过权，链接器会报 LNK1104
icacls.exe 'D:\SilverFoxGuard\dist\SilverFoxGuardSvc.exe' /grant "$(whoami):F" >/dev/null 2>&1 || true

echo "==> 编译 SilverFoxGuardSvc.exe（服务 + Native Messaging 宿主 单程序，WebView2 通知 + 主界面）"
# 子系统必须是 WINDOWS(GUI)：WebView2 宿主，避免子进程冒出控制台黑框
# --console 调试模式由 main.cpp 的 EnsureConsoleForDebug() 手动挂回控制台
# ★ 2026-09-19：服务运行时其 EXE 被加载器锁死，无法原地覆盖（LNK1104/1168）。
# 一律链接到 .new.exe，末尾再智能替换：正式名换得动就换成正式名；
# 换不动（被运行时锁住）就留给部署脚本（2026-09-25 改写，理由见下方"智能替换"段）。
NEWEXE="$DIST/SilverFoxGuardSvc.new.exe"

# ---- ★ 源文件自动收录（2026-09-22 主干式架构）----
# 不再手工维护编译单元列表：src/*.cpp 全收，排除 *_regress.cpp（回归程序自带 main，
# 且刻意不依赖服务全局态）。这样「新增一个分体文件」不需要改本脚本 ——
# 这正是"加功能只改一处"的另一半（另一半是 modules_list.cpp 的清单一行）。
#
# ⚠️ 用 shell 数组而非 `$(ls ...)` 拼接：路径含空格时后者会断开，且 set -e 下
#    容易把"通配符无匹配"当成成功。这里显式判断空集，避免编出空命令行。
SOURCES=()
for _f in "$SRC"/*.cpp; do
  _b=$(basename "$_f")
  case "$_b" in
    *_regress.cpp) continue ;;   # 回归测试可执行文件，自带 main，不进服务
    etw.cpp)       continue ;;   # ★ 未接入的历史文件（2026-09-22 由本通配符首次暴露）
                                 #   它引用 common.h 里并不存在的 NowMs/W2A，从未编译过。
                                 #   功能上已被 netwatch.cpp（网络）+ WmiProcessWatch（进程）取代。
                                 #   保留源码作参考；将来若要接入进程事件，需先补齐依赖并单独验证。
                                 #   排除是"未接入历史文件"的白名单，不是常态 —— 新分体一律自动收录。
  esac
  SOURCES+=("$_f")
done
if [ ${#SOURCES[@]} -eq 0 ]; then
  echo "!! 未收录到任何源文件（$SRC/*.cpp）—— 检查路径是否正确"
  exit 1
fi
echo "==> 自动收录源文件 ${#SOURCES[@]} 个（新增 .cpp 无需改本脚本）"

# ---- ★ 构建期验签公钥覆盖（2026-09-25，对应「验签公钥怎么放 → 构建期可配置」）----
# 用途：用一个**一次性测试钥匙**构建一版，端到端演练「验签成功 / 验签失败」两条路，
#       演练完直接重新构建即可回到仓库里的正式公钥，仓库中不留任何痕迹。
#
#       SFH_KEY_ID=sfh1-test SFH_PUBKEY_HEX=<128位hex> bash build.sh
#
# 只影响**服务端**（本脚本）。离线签名工具 build_libsigkey.sh 刻意**不认**这两个变量：
# 它是"哪把钥匙算官方钥匙"的裁判，让环境变量能改裁判的口径，
# 会造出"用哪把钥匙签的"与"工具认为哪把是官方的"错位 —— 而那种错位要等到
# 签名验不过才发现。要演练工具侧，改头文件后重新构建即可（动作更重，但有痕迹）。
#
# ★ 引号：cl 的 /D 值里必须带**真实的引号字符**，否则预处理器会把 128 位 hex
#   当成一个标识符 → 成片报错。写法必须是 \"/DSFH_...=\\\"...\\\"\" 这一形态；
#   直接写 /DSFH_PUBKEY_HEX="abc" 会被 bash 吃掉引号（2026-09-25 用 dfprobe 实测：
#   带转义的写法能原样到达预处理器，输出 KEYID=[sfh1-1] / PUBHEX_LEN=64）。
#
# ★ 为什么必须成对、且必须打印：一个"其实没生效的覆盖"与"根本没做覆盖"在行为上
#   完全一样（都验不过测试钥匙的签名）。所以 ① 只给一个变量时**直接报错退出**
#   （半覆盖会让内置表换了钥匙、签名方还在用旧钥匙）；② 生效时在输出里大声说出来。
EXTRA_DEFS=()
if [ -z "${SFH_KEY_ID+x}" ] && [ -z "${SFH_PUBKEY_HEX+x}" ]; then
  echo "==> 验签公钥：使用 src/sfh_pubkey.h 内置的正式公钥（未做构建期覆盖）"
elif [ -n "${SFH_KEY_ID+x}" ] && [ -n "${SFH_PUBKEY_HEX+x}" ]; then
  _kid="${SFH_KEY_ID}"
  _pub="${SFH_PUBKEY_HEX}"
  if [ -z "$_kid" ] && [ -z "$_pub" ]; then
    # 成对给空串 = 有意的 fail-closed 演练（BuiltinKeyCount()==0 → 拒绝装载任何库）
    echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
    echo "  验签公钥：**构建期覆盖为「无公钥」(fail-closed 演练)**"
    echo "  本版产物会拒绝装载**任何**病毒库（BuiltinKeyCount()==0 → kNoKeyConfigured）。"
    echo "  这不是故障，是演练；演练完重新不带变量构建即可回到正式公钥。"
    echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  elif [ -z "$_kid" ] || [ -z "$_pub" ]; then
    echo "!! 构建期覆盖：SFH_KEY_ID 与 SFH_PUBKEY_HEX 只能**同时为空**（fail-closed 演练）"
    echo "!!             或**同时非空**（换钥匙演练）；只给一个是半覆盖状态，拒绝构建。"
    echo "!!             当前：SFH_KEY_ID 长度 ${#_kid}，SFH_PUBKEY_HEX 长度 ${#_pub}"
    exit 1
  else
    # 长度/字符集自检：宁可现在报错，也别产出一个"公钥是垃圾、所有库都验不过"的 EXE。
    if [ ${#_pub} -ne 128 ]; then
      echo "!! SFH_PUBKEY_HEX 长度 ${#_pub} ≠ 128（应为 X||Y 共 64 字节 = 128 位小写 hex）"
      exit 1
    fi
    case "$_pub" in
      *[!0-9a-f]*)
        echo "!! SFH_PUBKEY_HEX 含非 [0-9a-f] 字符 —— 必须是**小写** hex（libsig.cpp 不宽松解析）"
        exit 1 ;;
    esac
    echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
    echo "  验签公钥：**构建期覆盖生效**（仅本次构建，仓库文件未改动）"
    echo "    keyId  = $_kid"
    echo "    pubkey = ${_pub:0:16}…${_pub:112:16}（128 位 hex）"
    echo "  本版产物只认这把测试钥匙；正式私钥签出的库会验签失败 —— 这正是演练内容。"
    echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  fi
  # 写成 EXTRA_DEFS 数组元素；引号必须是**值的一部分**（见上面 ★ 引号那段）
  EXTRA_DEFS=("/DSFH_KEY_ID=\"$_kid\"" "/DSFH_PUBKEY_HEX=\"$_pub\"")
else
  echo "!! 构建期覆盖必须成对提供：SFH_KEY_ID 与 SFH_PUBKEY_HEX（只给一个会造出半覆盖状态）"
  echo "!!   只想演练 fail-closed：SFH_KEY_ID= SFH_PUBKEY_HEX= bash build.sh"
  exit 1
fi

# ${ARR[@]+"${ARR[@]}"} 是"数组可能为空"的通用安全展开（老 bash 下空数组会变成
# 一个空参数，正好会被 cl 当成"空文件名"报错）。本脚本不假设 bash 版本。
"$CL" /nologo /MT /std:c++17 /utf-8 /O2 /EHsc /W3 \
  ${EXTRA_DEFS[@]+"${EXTRA_DEFS[@]}"} \
  "${SOURCES[@]}" \
  /Fe:"$NEWEXE" \
  /link "$SRC/resource.res" /SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup /MACHINE:X64 \
  advapi32.lib bcrypt.lib shell32.lib gdi32.lib user32.lib shcore.lib dwmapi.lib \
  ole32.lib oleaut32.lib uuid.lib wbemuuid.lib \
  WebView2LoaderStatic.lib \
  psapi.lib iphlpapi.lib ws2_32.lib taskschd.lib shlwapi.lib comsuppw.lib wtsapi32.lib \
  winhttp.lib

# ---- ★ 火绒产物抢救（2026-09-19 新增，权宜之计）----
# 问题：火绒把本程序判为 Ransom/LockFile.af，在 link.exe 写出 EXE 后立即删除，
#       导致「编译成功但产物消失」→ 服务只能跑旧二进制 → 误以为"改了代码没用"。
#       实测 09-16~09-19 共 12 份构建产物被隔离。卡巴斯基对同一文件零告警（佐证误报）。
# 治本：把 D:\SilverFoxGuard\dist 与 D:\SilverFoxEnvScan\SilverFoxGuard 加入火绒「信任区」，
#       且必须在信任范围里勾上「行为监控」。
# 下面这段只是争取时间：链接近完成即立刻复制一份到暂存目录（副本在火绒扫描窗口之外，
#       通常能存活），供信任区配好后取回。**不能替代信任区**。
STASH="C:/temp/sf_stash"
mkdir -p "$STASH"
if [ -f "$NEWEXE" ]; then
  _ts=$(date +%H%M%S)
  # ★ 2026-10-01：本机 Git Bash 里 **`cp` 不存在**（实测 `command -v cp` 为空），
  #   原写法 `cp ... 2>/dev/null` 于是**每次都静默走失败分支**，并打印
  #   「文件可能已被火绒删除」——把"命令缺失"伪装成"产物被删"，
  #   排查时会把注意力完全引向火绒信任区（而那里根本没配错）。
  #   改为探测可用命令；两者皆无时**明确说明**，不再冒充火绒事故。
  _cp=""
  command -v cp >/dev/null 2>&1 && _cp="cp -f"
  [ -z "$_cp" ] && command -v install >/dev/null 2>&1 && _cp="install -m 644"
  if [ -n "$_cp" ] && $_cp "$NEWEXE" "$STASH/SilverFoxGuardSvc_${_ts}.exe" 2>/dev/null; then
    echo "==> [抢救] 已暂存产物副本 → $STASH/SilverFoxGuardSvc_${_ts}.exe"
  elif [ -z "$_cp" ]; then
    echo "!! [抢救] 本机既无 cp 也无 install —— 跳过暂存（不影响构建）"
  else
    echo "!! [抢救] 暂存失败（文件可能已被火绒删除）"
  fi
else
  echo "!! [抢救] 链接后未发现产物——极可能已被火绒实时防护删除"
  echo "!!        请把 $DIST 加入火绒信任区（信任范围须含「行为监控」）"
fi

# ---- ★ 构建期覆盖的**事后核对**（覆盖了，就必须真的编进去）----
# 为什么非要有这一步：`-D` 失效的方式太多了 —— 头文件里的 #ifndef 守卫被人删掉、
# 参数被某个 shell 层吃掉、写成了不带 \" 的形态（那会直接编译失败，还算好的）……
# 而**失效的表现与"没做覆盖"完全一致**：编出来的还是仓库正式公钥。
# 光靠上面那段 banner 打印"覆盖生效"是自说自话 —— banner 只证明我们**打算**覆盖，
# 不证明编译**真的**照做了。所以这里回到产物里找 keyId 这个字符串：
# keyId 是签名消息的一部分，必然作为字面量躺在二进制里（Slots() 在运行时用它）。
if [ ${#EXTRA_DEFS[@]} -gt 0 ] && [ -n "${_kid:-}" ]; then
  if grep -aq -F "$_kid" "$NEWEXE" 2>/dev/null; then
    echo "==> [覆盖核对] 产物中确认含 keyId \"$_kid\" —— 构建期覆盖确已编入"
  else
    echo "!! [覆盖核对] 产物里搜不到 keyId \"$_kid\" —— 覆盖**没生效**！"
    echo "!!            编出来的是 src/sfh_pubkey.h 里的正式公钥，不是你要的测试钥匙。"
    echo "!!            多半是 -D 参数在中途被吃掉，或头文件里的 #ifndef 守卫被删了。"
    exit 1
  fi
fi

# ---- 注入 VersionInfo 版本资源（须在签名前）----
# cvtres 对 RT_VERSION 有目录树合并 bug，改用 BeginUpdateResource/UpdateResource 注入
UPDVER="$ROOT/dist/update_ver.exe"
if [ -f "$UPDVER" ]; then
  echo "==> 注入 VersionInfo 版本资源（update_ver.exe）"
  "$UPDVER" "$NEWEXE" || echo "!! 版本注入失败（不影响功能，仅详情页空白）"
else
  echo "!! 未找到 $UPDVER，跳过版本注入（详情页版本信息为空）"
fi

# ---- Authenticode 代码签名（自保必需，勿跳过）----
# VerifySelfIntegrity 自检要求 EXE 携带官方签名（内置指纹）；未签名 EXE 会被判「自身完整性失败」
SIGNTOOL="C:/Program Files (x86)/Windows Kits/10/bin/10.0.26100.0/x64/signtool.exe"
PFX="$ROOT/signing/silverfox-sign.pfx"
PFX_PW_FILE="$ROOT/signing/.pfx-password"
# 读取密码并去掉可能的 UTF-8 BOM 与首尾空白。
# ⚠ 踩坑：该文件带 UTF-8 BOM（EF BB BF），直接用 $(cat ...) 会把 BOM 当成密码的一部分，
#    signtool 报 "The specified PFX password is not correct."，导致整条构建在签名处中断。
PFX_PW=""
if [ -f "$PFX_PW_FILE" ]; then
  PFX_PW=$(tr -d '\357\273\277\r\n' < "$PFX_PW_FILE")
fi

echo "==> Authenticode 签名 SilverFoxGuardSvc.exe（自保校验必需）"
if [ ! -f "$PFX" ]; then
  echo "-- 未提供签名证书（signing/silverfox-sign.pfx），跳过 Authenticode 签名。"
  echo "   ★ 自编译版本没有证书是**正常**的，不影响功能。"
  echo "     但要知道两件事："
  echo "       ① 杀毒软件对'未签名程序'的误报率明显更高（缺少信誉）"
  echo "       ② Windows 会在每次运行时提示'未知发布者'"
  echo "     要消除：自备代码签名证书（PFX + 密码文件），放在 signing/ 下即可自动生效。"
elif [ -f "$PFX_PW_FILE" ]; then
  "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$PFX_PW" "$NEWEXE"
elif [ -n "${SF_SIGN_PWD:-}" ]; then
  "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$SF_SIGN_PWD" "$NEWEXE"
else
  echo "!! 未提供签名密码（.pfx-password 或 SF_SIGN_PWD），跳过签名——发布版必须签名！"
fi

# ---- 智能替换：把本次产物换到正式名，用「换得动换不动」当唯一判据 ----
# ★★ 但它还有一个**静默**后果，2026-09-25 实测踩到：
#    安装器（installer.nsi）引用的是**正式名** `dist\SilverFoxGuardSvc.exe`。
#    服务一旦在跑，本脚本就只留 .new.exe → 末尾那次 makensis 会**不带任何报错地**
#    把一个旧服务 EXE 打进安装包，然后打印"完成"。
#    症状：安装包体积正常、能装、能跑，但里面根本没有本次改的代码 ——
#    属于本项目最忌的一类失败（构建"成功"而产物是旧的）。
#    所以下面用一个 STALE 标记把这件事变成硬错误：宁可这次不打安装包，
#    也不要产出一个看起来正常、内容却是旧的包。
#
# ★★ 2026-09-25 重写：原判据是「sc.exe query 说服务停了没有」，两个毛病：
#    ① sc.exe 被安全策略拦 / 不在 PATH 时，脚本会在这一行整段死掉，或者误判；
#    ② 更根本的是它**猜错了对象**——「服务在不在跑」与「正式名能不能被覆盖」
#       根本不是一回事，前者推不出后者。实测（2026-09-25）：服务明明在跑
#       （SilverFoxGuardSvc.exe PID 5008），`mv` 到 dist\ 正式名却成功了。
#       旧代码此时会打印「服务运行中」并**放弃替换**，把一个本来完全正确的产物
#       留在 .new.exe 上、还要人再跑一次部署脚本 —— 顺便还留下一句假话。
#    真正的判据只有一个：**正式名换得动吗**。
#      · 换得动 → 磁盘上的正式名就是本次产物 → 可以打包（正确）。
#      · 换不动 → 正式名还是旧的 → 绝不打包。
#    这与下面两道「双保险」是同一条思路：只认**观测到的事实**，不认**推断出的结论**。
#
# ★ 一句必须记住的话：**"磁盘上的文件换了" ≠ "服务换成了新代码"。**
#   mv 成功只证明文件被替换；正在运行的服务是否也换了，取决于它的映像路径以及
#   何时重启。Windows 允许重命名正在运行的 EXE（加载器以 FILE_SHARE_DELETE 打开
#   映像，重命名是元数据操作；而链接器需要**写**访问，才会报 LNK1104/LNK1168）——
#   所以完全可能出现"文件已经是新的、进程里跑的还是旧代码"。
#   停服→替换→启动那三步由「部署新主防.bat」负责，别拿本脚本的 mv 成功当部署成功。
PACKAGED_STALE=0
icacls.exe 'D:\SilverFoxGuard\dist\SilverFoxGuardSvc.exe' /grant "$(whoami):F" >/dev/null 2>&1 || true
if _mverr=$(mv -f "$NEWEXE" "$DIST/SilverFoxGuardSvc.exe" 2>&1); then
  echo "==> 新产物已就位 → dist\\SilverFoxGuardSvc.exe"
else
  echo "!! 替换正式名失败，新产物保留为 SilverFoxGuardSvc.new.exe"
  echo "!!   原因（多为服务正从正式名加载，文件被映像锁住）：${_mverr:-（无错误输出）}"
  echo "    请运行桌面「部署新主防.bat」完成停服→替换→重启。"
  PACKAGED_STALE=1
fi
# 双保险（两道独立检查，任何一道不过都按"旧产物"处理）：
#   ① 痕迹：正式名里必须有本次新代码的字符串。只在源文件确实存在时才查 ——
#      否则将来删掉 mod_ai.cpp 会让这个检查永远为假、把正常构建也拦下来。
#   ② 时间戳：正式名的 mtime 必须晚于**参与编译的**源文件。
#      这一条不依赖任何具体字符串，是通用的兜底（"构建后 stat 比对时间戳"这条铁律）。
if [ "$PACKAGED_STALE" = "0" ]; then
  if [ -f "$SRC/mod_ai.cpp" ] && ! grep -aq -F "aifeat" "$DIST/SilverFoxGuardSvc.exe" 2>/dev/null; then
    echo "!! 正式名产物里搜不到本次新代码的痕迹（aifeat）——按旧产物处理"
    PACKAGED_STALE=1
  fi
fi
# ③ 病毒库验签代码的存在性（2026-09-25 加）。这条与 ② 抓的不是同一类失败：
#   ② 抓的是"产物是旧的"，而这条抓的是"产物是新的、但**这一块功能整个没了**"。
#   具体场景：哪天有人把 libsig.cpp 加进上面的排除名单、或把它改名/挪走，
#   编译照常成功、EXE 照常新鲜、② 照样通过（② 比的是"有没有源文件比产物新"，
#   而编译单元消失是"少了一个源文件"，不产生更新的时间戳）——
#   于是产出一个**没有验签模块**的新鲜 EXE，病毒库形同虚设，而构建报告一切正常。
#   这是"静默降级"最典型的一种，只有回到产物里找痕迹才抓得到。
#   守卫生效条件：只在 libsig.cpp 确实存在时才查（否则将来真的删掉它会永远为假）。
if [ "$PACKAGED_STALE" = "0" ]; then
  if [ -f "$SRC/libsig.cpp" ] && ! grep -aq -F "SFH1-SIG-V1" "$DIST/SilverFoxGuardSvc.exe" 2>/dev/null; then
    echo "!! 正式名产物里搜不到病毒库验签的域分离前缀（SFH1-SIG-V1）——"
    echo "!!   说明 libsig.cpp 没被编进去（改名？被排除？），本版病毒库验签是**失效**的。"
    PACKAGED_STALE=1
  fi
fi
if [ "$PACKAGED_STALE" = "0" ]; then
  NEWER=$(find "$SRC" -maxdepth 1 \( -name '*.cpp' -o -name '*.h' \) \
            ! -name '*_regress.cpp' ! -name 'etw.cpp' \
            -newer "$DIST/SilverFoxGuardSvc.exe" -print -quit 2>/dev/null)
  if [ -n "$NEWER" ]; then
    echo "!! 正式名产物早于源文件（$(basename "$NEWER")）——按旧产物处理"
    PACKAGED_STALE=1
  fi
fi

# ---- Shell 扩展 DLL（Win11 一级右键菜单，稀疏包 IExplorerCommand）----
echo "==> 编译 SilverFoxShell.dll（Win11 一级右键菜单）"
mkdir -p "$DIST/shell"
"$CL" /nologo /LD /MT /std:c++17 /utf-8 /O2 /EHsc \
  "$SRC/shell/SilverFoxShell.cpp" /Fe:"$DIST/shell/SilverFoxShell.dll" \
  /link advapi32.lib ole32.lib uuid.lib shlwapi.lib shell32.lib
if [ -f "$UPDVER" ]; then
  "$UPDVER" "$DIST/shell/SilverFoxShell.dll" || echo "!! DLL 版本注入失败（不影响功能）"
fi
if [ -f "$PFX" ]; then
  if [ -f "$PFX_PW_FILE" ]; then
    "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$PFX_PW" "$DIST/shell/SilverFoxShell.dll"
  elif [ -n "${SF_SIGN_PWD:-}" ]; then
    "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$SF_SIGN_PWD" "$DIST/shell/SilverFoxShell.dll"
  else
    echo "!! 未提供签名密码，DLL 未签名（发布版必须签名）"
  fi
fi

# ---- ★ 阶段二：沙箱注入探针 DLL（时间加速 + 行为自报）----
# 独立的 DLL，不进服务 EXE（src/probe/ 在 src/*.cpp 通配之外）。
# 随服务 EXE 一起部署到 dist\，服务端 Detect 会按同目录探测并注入。
echo "==> 编译探针 DLL probe64.dll（注入沙箱内样本进程）"
"$CL" /nologo /LD /MT /std:c++17 /utf-8 /O2 /EHsc /DPROBE_EXPORTS \
  "$SRC/probe/probe.cpp" /Fe:"$DIST/probe64.dll" \
  /link /MACHINE:X64 kernel32.lib
if [ -f "$DIST/probe64.dll" ]; then
  if grep -aq -F "SFPROBE" "$DIST/probe64.dll" 2>/dev/null; then
    echo "==> probe64.dll 已就位（含 SFPROBE 标记）"
  else
    echo "!! probe64.dll 找不到 SFPROBE 标记（疑似未编入探针逻辑）"
  fi
else
  echo "!! probe64.dll 编译失败"
fi
if [ -f "$PFX" ] && [ -f "$DIST/probe64.dll" ]; then
  if [ -f "$PFX_PW_FILE" ]; then
    "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$PFX_PW" "$DIST/probe64.dll"
  elif [ -n "${SF_SIGN_PWD:-}" ]; then
    "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$SF_SIGN_PWD" "$DIST/probe64.dll"
  else
    echo "!! 未提供签名密码，probe64.dll 未签名（发布版必须签名）"
  fi
fi

# x86 探针（32 位样本注入，best-effort：x86 编译器缺失则只覆盖 x64 样本）
CL86="$VC/bin/Hostx64/x86/cl.exe"
if [ -f "$CL86" ]; then
  echo "==> 编译探针 DLL probe32.dll（32 位样本注入）"
  INCLUDE86="$VC/include;$SDK/Include/$SDKVER/ucrt;$SDK/Include/$SDKVER/um;$SDK/Include/$SDKVER/shared"
  LIB86="$VC/lib/x86;$SDK/Lib/$SDKVER/ucrt/x86;$SDK/Lib/$SDKVER/um/x86"
  INCLUDE="$INCLUDE86" LIB="$LIB86" "$CL86" /nologo /LD /MT /std:c++17 /utf-8 /O2 /EHsc /DPROBE_EXPORTS \
    "$SRC/probe/probe.cpp" /Fe:"$DIST/probe32.dll" /link /MACHINE:X86 kernel32.lib
  if [ -f "$DIST/probe32.dll" ]; then
    if [ -f "$PFX" ]; then
      if [ -f "$PFX_PW_FILE" ]; then
        "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$PFX_PW" "$DIST/probe32.dll"
      elif [ -n "${SF_SIGN_PWD:-}" ]; then
        "$SIGNTOOL" sign /fd SHA256 /f "$PFX" /p "$SF_SIGN_PWD" "$DIST/probe32.dll"
      else
        echo "!! 未提供签名密码，probe32.dll 未签名"
      fi
    fi
  else
    echo "!! probe32.dll 编译失败（32 位样本将不被探针覆盖，降级处理）"
  fi
else
  echo "!! 未找到 x86 编译器，跳过 probe32.dll（32 位样本将不被探针覆盖）"
fi

# 探针自检程序（调试用，不随安装包发布）：验证 hook 真生效
echo "==> 编译探针自检程序 probe_selftest.exe"
"$CL" /nologo /MT /std:c++17 /utf-8 /O2 /EHsc \
  "$SRC/probe/probe_selftest.cpp" /Fe:"$DIST/probe_selftest.exe" \
  /link /MACHINE:X64 kernel32.lib

# ---- ★★ 判据自测套件（C3，2026-10-03）------------------------------------
# 为什么必须每次构建都跑：
#   今天为「判据写死表面特征」这类 bug 返工了四版（落地捕获），每一版都是被
#   **「不该收的反例」**打回的，不是被 code review 看出来的
#   （is-0001.tmp 顺序号 / Office GUID 目录 / PackageCache 短 GUID / %TEMP% 短名）。
#   ⇒ 判据类改动没有反例常驻就一定会重犯。**只测正例等于没测。**
# 这个套件不随安装包发布（与其它 regress 一样是调试用），但**必须在构建里跑**，
#   否则「改了判据 → 忘了跑回归」就等于没测。
echo "==> 编译并运行判据自测套件 criteria_regress.exe"
"$CL" /nologo /MT /std:c++17 /utf-8 /O2 /EHsc /W3 /wd4244 \
     /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS \
     /I"$SRC" "$SRC/criteria_regress.cpp" "$SRC/criteria.cpp" \
     /Fe:"$DIST/criteria_regress.exe"
# ★ 编译失败即中止
if [ ! -f "$DIST/criteria_regress.exe" ]; then
  echo "!! ★★ 判据自测套件编译失败（criteria_regress.exe 未生成）—— 中止构建"
  echo "   （判据类改动没有回归兜底就会重犯今天那四版返工，见 criteria_regress.cpp 头部）"
  exit 1
fi
if "$DIST/criteria_regress.exe"; then
  echo "   ★ 判据自测全部通过"
else
  RC=$?
  echo "!! ★★ 判据自测未通过（退出码 $RC）—— 中止构建"
  echo "   本轮改动很可能引入了误报或漏报；详见上方逐条 [FAIL] 输出。"
  exit $RC
fi

# ---- ★ 无结论决策自测（2026-10-03 加）----
#  errhold 是「删文件」的唯一授权闸门（只认令牌），它的失效面是不可逆的：
#  令牌校验松 ⇒ 任何本地程序能让服务删任意文件；回调缺装配 ⇒ 文件被永久锁死。
#  两类都**不报错**，所以必须有自测兜底并纳入硬失败。
echo "==> 无结论决策自测（errhold）"
# ★★ 必须 `< /dev/null`（2026-10-03 实测卡死 18 分钟）：
#   main.cpp 里有 `GetFileType(stdin)==FILE_TYPE_PIPE ⇒ 走 RunNmHost` 这条
#   （浏览器拉起 NM 宿主时 stdin 就是匿名管道）。而 shell 里的 `if cmd; then`
#   会把命令的 stdout 接成管道来做条件判断 —— 在 Git Bash 下这会连带让
#   **stdin 变成管道** ⇒ 自测分支根本没被走到，进程进去读管道 ⇒ 永久阻塞。
#   表现：构建不报错、不退出、也不打自测输出，肉眼看就是"卡住了"。
#   正解：显式给 stdin 接 NUL，让它不是管道。
if "$DIST/SilverFoxGuardSvc.exe" --errhold-selftest < /dev/null; then
  echo "   ★ errhold 自测全部通过"
else
  RC=$?
  echo "!! ★★ errhold 自测未通过（退出码 $RC）—— 中止构建"
  exit $RC
fi

# ---- ★ 弹窗卡片渲染验收（2026-10-03 加，无头 Edge 截图）----
# 为什么必须有这一步（今天真踩到）：
#   决策卡的按钮是 **innerHTML 动态注入** 的，而绑定函数在 paint() 之后才跑。
#   本轮加「删掉 / 不删除」两枚按钮时，index.html 里**漏声明** ERR_TOKEN
#   （该文件独立解析 hash，不共享 main.js 作用域）⇒ `vErr && ERR_TOKEN`
#   恒为 false ⇒ **决策卡完全不渲染、动作区空白**，而页面**不报任何错**、
#   服务端照常发卡、照常登记待决、照常超时自动删除。
#   纯代码审查看不出来（每处都"对"），只有真渲染一次才知道。
#   同族已吃过两次亏：① 动态按钮绑不上（只有关闭钮能用）；② 漏加 card.action
#      到 has-btns 判据（品牌字被按钮压住）。故一并纳入硬失败。
#
# 判据（三层，缺一层就放过事故）：
#   ① main.js 的 URLSearchParams 字段表**含** errtoken/errleft（静态检查）
#   ② index.html 的 hashArgs() 分隔符与 URLSearchParams.toString() 一致（都是 &）
#   ③ 实渲染：error+令牌 ⇒ 2 枚按钮 + 非空倒计时；无令牌/不适用 ⇒ 1 枚
#
# ★★ 2026-10-04 换掉旧验收的原因（旧版对本事故**完全无感**）：
#   旧版只拿 index.html + 手工拼的 hash 截图 ⇒ **完全绕过 main.js**。
#   而真事故（VM 10-04 实测）恰恰在 main.js：它自己解析出了 ERR_TOKEN/ERR_LEFT
#   （所以弹窗寿命 30 秒是对的、服务端照常超时删除），却**没把字段写进 URL hash** ⇒
#   index.html 独立解析拿不到 ⇒ 只弹「知道了」的普通卡 + 到点自动删。
#   症状像产品逻辑，其实是**一个字段都没传过去** —— 直连页面的旧脚本看不出任何异常。
NODE_PATH_WS="C:/Users/tianl/.workbuddy/binaries/node/workspace/node_modules"
NODE_BIN="C:/Users/tianl/.workbuddy/binaries/node/versions/22.22.2-3/node.exe"
if [ -f "$NODE_BIN" ] && [ -d "$NODE_PATH_WS/playwright-core" ]; then
  echo "==> 决策卡验收（静态字段表 + 分隔符一致性 + 实渲染）"
  # ★ 指向 **dist/toast**（安装包的真实来源），不是开发位 ——
  #   验收必须打最终会进包的那份，否则"开发位对、dist 旧"会漏过。
  #   路径基于 $ROOT 推导（见文件上方 ROOT 的定义），不写死绝对路径。
  SF_APP="$ROOT/dist/toast/resources/app/index.html" \
  NODE_PATH="$NODE_PATH_WS" \
  "$NODE_BIN" "$ROOT/tools/验收_决策卡.js"
  if [ $? -ne 0 ]; then
    echo "!! ★★ 决策卡验收未通过 —— 中止构建"
    echo "   （凭据没转发进 hash 时不报错，只弹没按钮的卡 + 到点自动删）"
    exit 1
  fi
else
  echo "== 跳过弹窗卡片渲染验收（无 playwright-core 或 node）"
  echo "   ★ 这是**静默失效高危项**：决策卡不渲染时页面不报错，"
  echo "     用户看不到按钮、文件却在 30 秒后被自动删除。"
fi

# ---- ★ GUI 包刷新：界面改动必须重压 gui.7z（2026-09-25 加）----
# 为什么需要这段：installer.nsi 引用的是**磁盘上已存在的** gui.7z，而本脚本
#   此前**从不重压它** —— 于是「改了界面 → 跑 build.sh → 安装包里还是旧界面」
#   全程**不报任何错**：makensis 成功、安装包生成、SHA256 照常打印。
# 实拍到的实例（09-25 第七轮）：dist\gui\resources\app\index.html 已是含
#   「病毒库」页的新版（129,742 B），而 gui.7z 里还是 09-24 的旧版（111,633 B）
#   —— 打出的安装包界面**缺了整个页面**。热替换部署看不出问题（它不走 7z），
#   只有新装机的用户才会发现。
#   这与 PACKAGED_STALE 属同一类事故（"构建成功"被误读成"包是新的"），
#   故用同一手法处理：**实测比对时间戳，过期就重压，并明确打印出来**。
SZ7Z="/c/Program Files/7-Zip/7z.exe"

# ---- ★★ 7z 打包/校验工具（2026-10-02 加，血的教训）---------------------------------
# 为什么需要这一段（实测事故）：
#   原写法 `7z a "$ARCHIVE" <dir>` 是**原地写入**。进程一旦中途被杀（工具超时 SIGTERM /
#   杀软拦截 / 磁盘写满），留下的是一个**半截归档**：7z 签名 `37 7A BC AF 27 1C` 还在，
#   但紧跟其后的 start-header CRC 与 next-header 偏移**全为 0** ⇒ 7-Zip 报 "Is not archive"。
#   更毒的是这个坏文件**拿到了新鲜 mtime** ⇒ 下面基于 `find -newer` 的"是否过期"判据
#   反而认定"已是最新、跳过重压" ⇒ **坏包被一路带进安装包，且构建日志毫无异常**。
#   实测：toast.7z 从健康 88,423,229 B 变成损坏 18,839,371 B，而日志照打
#   "toast.7z 已是最新（卡片不比它新），跳过重压"，安装包比上一版凭空小 90 MB 无人察觉。
#   故本脚本从此：① 先压到 `.new`；② `7z t` 实测；③ 测通了才原子替换（旧包留 .prev）；
#   ④ **已存在的 7z 若测不通，一律视为"需要重压"，不看时间戳**；
#   ⑤ 坏包移作 `.bad`，**绝不覆盖**健康的 `.prev`（否则唯一的干净备份也没了）。
#   ★ 别改回"直接 7z a 覆盖原文件" —— 那正是本事故的成因。
# ★★ 必须把归档路径转成 Windows 形式再喂给 7z.exe（2026-10-02 加，实测）
#   本脚本第 13 行 `export MSYS2_ARG_CONV_EXCL="*"` 关掉了 MSYS2 的 POSIX→Windows
#   参数转换（MSVC 编译必需），于是 `/d/SilverFoxGuard/gui.7z` 会**原样**传给 7z.exe ——
#   而 7z 把前导 `/` 当成**开关**（如 `/d` 未知开关）⇒ 报错退出 2。
#   实测四种组合：排除转换+POSIX=exit 2（坏）｜排除转换+Windows=0｜不排除+POSIX=0｜
#   cygpath -w=0。故：**凡传给 7z 的路径一律先 cygpath -w**。返回 0 的后两种都覆盖到了。
#   ★ 别图省事把 7z 调用改回直接传 $ROOT/xxx.7z（POSIX 形式）—— 在排除转换的构建环境里必挂。
_sf_w() { cygpath -w "$1" 2>/dev/null || printf '%s' "$1"; }

sf_7z_valid() {                       # $1=归档路径；0=有效
  [ -f "$1" ] || return 1
  "$SZ7Z" t "$(_sf_w "$1")" >/dev/null 2>&1
}
sf_7z_repack() {                      # $1=归档  $2=$DIST 下的源目录名  $3=人类可读名
  local _arc="$1" _dir="$2" _what="$3" _new="$1.new"
  rm -f "$_new"
  ( cd "$DIST" && "$SZ7Z" a -t7z -mx=9 -mmt=on "$(_sf_w "$_new")" "$_dir" >/dev/null )
  if ! sf_7z_valid "$_new"; then
    echo "!! $_what 打包失败：$_new 不是有效归档 —— **保留旧包、不做替换**"
    echo "   常见原因：7z 被中途杀掉 / 磁盘满 / 杀软拦截。请重跑本脚本。"
    rm -f "$_new"
    return 1
  fi
  if [ -f "$_arc" ]; then
    if sf_7z_valid "$_arc"; then
      mv -f "$_arc" "$_arc.prev"
    else
      mv -f "$_arc" "$_arc.bad"
      echo "  （旧包本身已损坏，移作 $(basename "$_arc").bad，未覆盖健康的 .prev）"
    fi
  fi
  mv -f "$_new" "$_arc"
  echo "  重压完成：$(stat -c%s "$_arc") 字节（旧包留作 .prev）"
}

GUI_7Z="$ROOT/gui.7z"
GUI_SRC="$DIST/gui/resources/app/index.html"
if [ ! -f "$SZ7Z" ]; then
  echo "!! 找不到 7-Zip（$SZ7Z）—— 跳过 gui.7z 校验（安装包可能带旧界面）"
elif [ ! -f "$GUI_SRC" ]; then
  echo "!! 缺少 $GUI_SRC —— 跳过 gui.7z 校验"
elif [ ! -f "$GUI_7Z" ]; then
  echo "==> gui.7z 不存在 → 新建（来自 dist/gui 整目录）"
  sf_7z_repack "$GUI_7Z" gui "gui.7z"
# ★ 2026-10-02 修判据（一）：原来拿 `$GUI_SRC`（**单个** index.html）与 7z 比 mtime ——
#   于是改 main.js / style.css / 任何非 index.html 的文件时判据恒假，**静默不重压**，
#   安装包继续带旧界面（与本节开头那次事故同型，只是触发条件更隐蔽）。
#   现改为「整目录里存在比 7z 新的文件就重压」。**别改回单文件比较。**
#   另注：也**不能拿目录自身 mtime 当判据** —— 改文件内容不会刷新目录时间戳，
#   只有增删目录项才会（实测 dist/toast 目录停在 09-27，而里面的 main.js 已是 10-02）。
# ★ 2026-10-02 修判据（二）：**现有 7z 本身要先自检**。半截归档的 mtime 比源文件新，
#   `find -newer` 会判定"不过期"，于是坏包永远得不到修复。这一条必须排在时间戳之前。
elif ! sf_7z_valid "$GUI_7Z"; then
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo "  gui.7z **已损坏**（不是有效归档）→ 无条件重压"
  echo "  通常是上一次 7z 被中途杀掉留下的半截文件；其新鲜 mtime 会骗过时间戳判据。"
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  sf_7z_repack "$GUI_7Z" gui "gui.7z"
elif [ -n "$(find "$DIST/gui" -type f -newer "$GUI_7Z" -print -quit 2>/dev/null)" ]; then
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo "  界面比 gui.7z 新 → **重压 gui.7z**"
  echo "  不重压的话本次安装包里是**旧界面**，而且不会报错 —— 装机后才发现少东西。"
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  sf_7z_repack "$GUI_7Z" gui "gui.7z"
else
  echo "==> gui.7z 已是最新（界面不比它新，且归档自检通过），跳过重压"
fi

# ---- ★ toast 包刷新：告警卡片改动必须同步 dist + 重压 toast.7z（2026-10-01 加）----
# 为什么需要这段（银泊 10-01 报「沙箱分析的结果卡不显示 / 不显示评分」）：
#   toast（告警弹窗）与 gui 是**两个独立的 Electron 应用、两个独立的 7z**，
#   而本脚本此前**只重压 gui.7z** —— toast.7z 自生成后**从未被本脚本更新**。
#   于是同一次卡片改动出现**三条路径三种时效**：
#     · toast-app/resources/app/      ← 开发位（改的地方，最新）
#     · dist/toast/resources/app/     ← deploy_guard.ps1 的部署源（旧）
#     · toast.7z → installer.nsi:205  ← 新装机用户拿到的（更旧）
#   症状与 gui 那次（09-25）**完全同形**：热部署看不出问题，
#   只有新装机才发现卡片是旧的；而且 dist 的旧副本会把修复**覆盖回去**。
#   故用同一手法：先同步开发位 → dist，再实测时间戳，过期就重压。
TOAST_APP="$ROOT/toast-app/resources/app"
TOAST_DIST="$DIST/toast/resources/app"
TOAST_7Z="$ROOT/toast.7z"
TOAST_SRC="$TOAST_DIST/index.html"
# 同步：**只覆盖比 dist 新的**（不冲掉更新的版本）
if [ ! -d "$TOAST_APP" ]; then
  echo "!! 缺少 $TOAST_APP —— 跳过 toast 同步"
elif [ ! -d "$TOAST_DIST" ]; then
  echo "!! 缺少 $TOAST_DIST —— 跳过 toast 同步（先跑一次部署以生成目录）"
else
  _cpsync=""
  command -v cp >/dev/null 2>&1 && _cpsync="cp -f"
  [ -z "$_cpsync" ] && command -v install >/dev/null 2>&1 && _cpsync="install -m 644"
  if [ -z "$_cpsync" ]; then
    echo "!! 本机既无 cp 也无 install —— 跳过 toast 同步（安装包可能是旧卡片）"
  else
    _synced=0
    for _f in "$TOAST_APP"/*; do
      [ -f "$_f" ] || continue
      _n=$(basename "$_f")
      if [ ! -f "$TOAST_DIST/$_n" ] || [ "$_f" -nt "$TOAST_DIST/$_n" ]; then
        $_cpsync "$_f" "$TOAST_DIST/$_n" 2>/dev/null && _synced=$((_synced+1))
      fi
    done
    echo "==> toast 开发位 → dist 同步：$_synced 个文件更新"
  fi
fi
# 重压判定：与 gui.7z 同一套（时间戳比对 → 过期即重压 → 旧包留 .prev）
if [ ! -f "$SZ7Z" ]; then
  echo "!! 找不到 7-Zip（$SZ7Z）—— 跳过 toast.7z 校验（安装包可能带旧卡片）"
elif [ ! -f "$TOAST_SRC" ]; then
  echo "!! 缺少 $TOAST_SRC —— 跳过 toast.7z 校验"
elif [ ! -f "$TOAST_7Z" ]; then
  echo "==> toast.7z 不存在 → 新建（来自 dist/toast 整目录）"
  sf_7z_repack "$TOAST_7Z" toast "toast.7z"
# ★ 2026-10-02 修判据（与上面 gui.7z 同型）：原来只拿 index.html 比 mtime，
#   于是「只改了 main.js」时判据恒假 → 不重压 → 安装包带旧卡片，且**不报任何错**
#   （实测：改了 main.js 后本行仍打印"toast.7z 已是最新"，只有解包核对才看得出）。
#   改为「整目录里存在比 7z 新的文件就重压」。
# ★ 2026-10-02 修判据（二）：**先给现有 toast.7z 做完整性自检** —— 实测本日 11:34 那次
#   重压中途被杀，留下 18,839,371 B 的半截包（健康包 88,423,229 B），其 mtime 却比
#   dist 里的 main.js 新，于是后续两次构建全部跳过重压，坏包直送安装包。
elif ! sf_7z_valid "$TOAST_7Z"; then
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo "  toast.7z **已损坏**（不是有效归档）→ 无条件重压"
  echo "  通常是上一次 7z 被中途杀掉留下的半截文件；其新鲜 mtime 会骗过时间戳判据。"
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  sf_7z_repack "$TOAST_7Z" toast "toast.7z"
elif [ -n "$(find "$DIST/toast" -type f -newer "$TOAST_7Z" -print -quit 2>/dev/null)" ]; then
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo "  告警卡片比 toast.7z 新 → **重压 toast.7z**"
  echo "  不重压的话本次安装包里是**旧卡片**，且不会报错 —— 装机后才发现。"
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  sf_7z_repack "$TOAST_7Z" toast "toast.7z"
else
  echo "==> toast.7z 已是最新（卡片不比它新，且归档自检通过），跳过重压"
fi

# ---- 7z 运行库（已复制带到新工程则跳过压缩）----
RUNTIME7Z="$ROOT/WebView2Runtime.7z"
echo "==> 运行库已就绪，跳过 7z 压缩（$RUNTIME7Z）"

echo "==> 构建安装包（NSIS，7z 运行库内嵌进安装包）"
NSIS="/c/Program Files (x86)/NSIS/makensis.exe"
if [ "$PACKAGED_STALE" = "1" ]; then
  echo ""
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo "  已跳过 NSIS 打包：dist\\SilverFoxGuardSvc.exe 不是本次编译的产物。"
  echo "  现在打出来的安装包里会是**旧服务**，装上去看不到本次改动。"
  echo "  下一步：先停服（桌面「部署新主防.bat」或在服务管理器里停止），"
  echo "          再重新运行本脚本 —— 那时正式名会被替换，安装包才会是真的。"
  echo "★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★★"
  echo ""
else
  OutName=$(grep -ao 'OutFile "[^"]*"' "$ROOT/installer.nsi" | head -1 | sed 's/OutFile "//; s/"$//')
  # ---- ★ 2026-10-02：makensis 前必须先等 dist EXE「解锁」----
  #  真凶不是杀软，是**我们自己的「送检封锁」**：
  #    新落地的 EXE → 落地捕获 → 自动送检 → MakeHold 持
  #    (GENERIC_READ, FILE_SHARE_DELETE) 句柄，**拒绝所有读者**约 2–3 分钟；
  #    NSIS 撞进这个窗口就报
  #      File: failed opening file "D:\SilverFoxGuard\dist\SilverFoxGuardSvc.exe"
  #    —— 现象是「编译成功但打包失败」，与代码无关。实测 2 次都是这个原因，
  #    本脚本作者一度误判为「火绒扫描新签名 EXE 的瞬时锁」。证据链：
  #      20:20:08 [rollback] 落地初筛命中（1级）: dist\SilverFoxGuardSvc.exe
  #      20:20:12 [sandbox]  ★送检封锁：原件已锁定 → holds\hSFx671d2j05\…
  #      20:21:50 [sandbox]  ★送检封锁解除 → 重跑 makensis 即成功
  #    判据：`cat` 得通就读得到（句柄锁在 open 阶段抛共享冲突，**与 ACL 无关**
  #          —— 实测 ACL 上 tianl 是完全控制，照样读不了）。
  _w=0
  while [ $_w -lt 30 ]; do
    if cat "$DIST/SilverFoxGuardSvc.exe" >/dev/null 2>&1; then break; fi
    _w=$((_w+1))
    echo "   ⏳ dist EXE 暂不可读（多为自家送检封锁中，约 2–3 分钟）—— 等 10s 重试（$_w/30）"
    sleep 10
  done
  if [ $_w -ge 30 ]; then
    echo "!! 等锁超时 300s —— 仍直接尝试打包（大概率失败；可稍后单独重跑 makensis）"
  fi
  # ★ 传 -DROOT：installer.nsi 里的 File/OutFile 全部用 $ROOT 引用（不再写死绝对路径），
  #   这样任何人克隆后都能直接编译，不会去引用/污染他自己机器上不存在的目录。
  #   makensis 的 -D 会把 $ROOT 变成**Windows 风格**路径，所以用 cygpath 转换。
  "$NSIS" "-DROOT=$(cygpath -w "$ROOT")" "$ROOT/installer.nsi"
  if [ -n "$OutName" ] && [ -f "$OutName" ]; then
    echo "==> 安装包指纹（记下来用于核对，别只看体积）"
    sha256sum "$OutName"
  fi
fi

echo "==> 完成（本次编译的服务 EXE 指纹）"
sha256sum "$DIST/SilverFoxGuardSvc.exe" 2>/dev/null || true
# ★ 2026-09-25 加：把"文件换了 ≠ 服务换了"这件事钉在构建输出的最后一行。
#   前面那次 mv 成功只证明磁盘上的文件被替换了；Windows 允许重命名正在运行的
#   EXE，所以完全可能"文件已是新的、进程里跑的还是旧代码"。
#   本项目在这一点上栽过不止一次（换 EXE 不换 gui.html / 换 GUI 不重启 GUI），
#   所以宁可每次多印一行，也不要让人把"构建成功"误读成"已生效"。
echo "   ★ 提醒：以上指纹只说明**磁盘上**的正式名是本次产物。"
echo "     要让改动真正生效，必须跑桌面「部署新主防.bat」（停服→替换→启动→重启 GUI）。"
ls -la "$DIST"
# 安装包输出名以 installer.nsi 的 OutFile 为准
ls -la "$ROOT"/SilverFoxGuard-preview*-Setup*.exe 2>/dev/null | tail -3
