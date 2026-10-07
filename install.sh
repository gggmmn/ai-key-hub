#!/bin/bash
# ══════════════════════════════════════════════════════════════════
#  AI 密钥网关 · 一键部署脚本   （纯 HTTP，无需证书）
#
#  用法：把本脚本和 ai-keys.tar.gz 放在同一个目录，然后执行
#          bash install.sh
#
#  它做什么：① 解压主程序到 /root/ai-keys  ② 问你要端口和口令
#            ③ 配好开机自启  ④ 启动并打印连接地址
# ══════════════════════════════════════════════════════════════════
set -e

DEST="/root/ai-keys"
TARBALL="ai-keys.tar.gz"
UNIT="/etc/systemd/system/ai-keys.service"
SVC="ai-keys"
VER="1.0"
DEF_PORT=47586

R="\033[0m"; B="\033[1m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; E="\033[31m"
ok()  { printf "  ${G}✅${R} %s\n" "$1"; }
er()  { printf "  ${E}❌${R} %s\n" "$1"; }
inf() { printf "  ${C}·${R}  %s\n" "$1"; }
warn(){ printf "  ${Y}⚠${R}  %s\n" "$1"; }

printf "\n${B}${C}"
printf "╔══════════════════════════════════════════════════╗\n"
printf "║     AI 密钥网关  ·  一键部署（HTTP）  v%s      ║\n" "$VER"
printf "╚══════════════════════════════════════════════════╝\n"
printf "${R}\n"

# ─────────── ① 依赖自动检测 + 缺失自动补装 ───────────
[ "$(id -u)" = "0" ] || { er "请用 root 运行：sudo bash install.sh"; exit 1; }

SELF_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$SELF_DIR" || exit 1
if [ ! -f "$TARBALL" ]; then
  er "同目录下找不到 $TARBALL"
  inf "当前目录：$SELF_DIR"
  inf "请把 install.sh 和 $TARBALL 放在一起再运行"
  exit 1
fi

# 探测包管理器（支持主流发行版）
detect_pm() {
  for _p in apt-get dnf yum apk pacman zypper; do
    command -v "$_p" >/dev/null 2>&1 && { echo "$_p"; return 0; }
  done
  echo ""
}
PM="$(detect_pm)"

# 命令名 → 各发行版里的包名
pkgname() {
  case "$PM:$1" in
    pacman:python3) echo python ;;
    *:python3)      echo python3 ;;
    *:curl)         echo curl ;;
    *:ss)           echo iproute2 ;;
    *)              echo "$1" ;;
  esac
}

pm_install() {
  case "$PM" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
             DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
    dnf)     dnf install -y -q "$@" ;;
    yum)     yum install -y -q "$@" ;;
    apk)     apk add --no-cache "$@" ;;
    pacman)  pacman -Sy --noconfirm "$@" ;;
    zypper)  zypper -n install "$@" ;;
    *)       return 1 ;;
  esac
}

# ensure_cmd <命令> <用途> [must]  —— 缺了就自动装，装不上则报错或跳过
ensure_cmd() {
  local cmd="$1" desc="$2" must="${3:-}"
  if command -v "$cmd" >/dev/null 2>&1; then
    ok "$desc（$cmd 已存在）"; return 0
  fi
  if [ -z "$PM" ]; then
    if [ "$must" = "must" ]; then
      er "$desc 缺失（$cmd），且本机没有任何受支持的包管理器"
      er "请手动安装后重跑本脚本"
      exit 1
    fi
    warn "$desc 缺失（$cmd），无法自动安装 —— 已跳过"
    return 1
  fi
  inf "$desc 缺失 → 正在自动安装「$(pkgname "$cmd")」 ..."
  if pm_install "$(pkgname "$cmd")" >/tmp/aikeys-pm.log 2>&1 && command -v "$cmd" >/dev/null 2>&1; then
    ok "$desc 已自动补装成功"
    return 0
  fi
  if [ "$must" = "must" ]; then
    er "$desc 安装失败！安装日志见 /tmp/aikeys-pm.log"
    tail -10 /tmp/aikeys-pm.log 2>/dev/null | sed 's/^/       /'
    exit 1
  fi
  warn "$desc 自动安装失败，已跳过（不影响主要功能）"
  return 1
}

printf "${B}── 依赖自动检测 ──${R}\n"
inf "系统：$(grep -s PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
inf "包管理器：${PM:-未检测到}"
ensure_cmd python3 "Python 3 运行时" must
ensure_cmd curl    "curl（健康检查用）"
ensure_cmd ss      "iproute2（端口占用检测用）"

# 系统 CA 证书 —— 网关要访问上游 HTTPS 服务商，没它全部密钥都会连不上
if [ -e /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/ssl/certs/ca-bundle.crt ]; then
  ok "系统 CA 证书（访问上游 HTTPS 用）"
elif [ -n "$PM" ]; then
  inf "缺少系统 CA 证书 → 正在自动安装 ca-certificates ..."
  pm_install ca-certificates >/tmp/aikeys-pm.log 2>&1 || true
  if [ -e /etc/ssl/certs/ca-certificates.crt ]; then ok "CA 证书已补装"
  else warn "CA 证书没装上 —— 访问 https 上游可能会证书报错"; fi
else
  warn "缺少系统 CA 证书，且无法自动安装"
fi

PY="$(command -v python3 || true)"
# ★ 优先用系统 python：生成的启动脚本会被 cron/systemd 调用，那时候 PATH 很干净，
#   写绝对路径最稳（避免指向某个以后会被删掉的虚拟环境）
if [ -x /usr/bin/python3 ]; then PY="/usr/bin/python3"; fi
[ -n "$PY" ] || { er "python3 仍不可用，请手动安装后重跑"; exit 1; }
PYV="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
case "$PYV" in
  3.8|3.9|3.1[0-9]) ok "Python $PYV" ;;
  *) er "Python 版本过低：$PYV（需要 3.8 或更高）"; exit 1 ;;
esac

# Python 自带模块缺失（某些精简发行版会拆包）→ 尝试补装
if ! "$PY" -c "import ssl,hmac,secrets,http.server,urllib.request,socket" 2>/dev/null; then
  warn "Python 缺少必要模块（ssl/hmac/secrets/http.server…）→ 尝试补装"
  for _p in python3-full python3-openssl python3-minimal; do
    [ -z "$PM" ] && break
    pm_install "$_p" >/tmp/aikeys-pm.log 2>&1 || true
    "$PY" -c "import ssl,hmac,secrets,http.server,urllib.request,socket" 2>/dev/null && break
  done
  "$PY" -c "import ssl,hmac,secrets,http.server,urllib.request,socket" 2>/dev/null \
    || { er "Python 模块仍不完整，请手动安装 python3-full（Debian/Ubuntu）"; exit 1; }
fi
ok "Python 模块完整（纯标准库，零 pip 包）"
"$PY" -c "import ssl; ssl.create_default_context()" 2>/dev/null \
  && ok "SSL 上下文可用（能调上游 HTTPS）" \
  || warn "SSL 上下文创建失败 —— 上游 https 调用可能报错（国内可安装 ca-certificates）"

# ─────────── ② 解压部署 ───────────
printf "\n"
if [ -d "$DEST/data" ]; then
  warn "检测到已有部署，将【保留】$DEST/data 里的密钥数据"
fi
inf "解压到 $DEST ..."
mkdir -p "$DEST/data" "$DEST/logs"
chmod 700 "$DEST/data"
tar xzf "$TARBALL" -C /root
[ -f "$DEST/server.py" ] || { er "解压后没找到 $DEST/server.py，压缩包可能损坏"; exit 1; }
[ -f "$DEST/static/index.html" ] || { er "解压后没找到管理界面 index.html"; exit 1; }
ok "主程序      $DEST/server.py"
ok "管理界面    $DEST/static/index.html"

# ★ 实体机专属坑：本机可能已经装过一份（unit 指向别的位置）
#    直接覆盖会静默把原服务的启动配置改掉 —— 必须让用户确认
if [ -f "$UNIT" ] && ! grep -q "$DEST/server.py" "$UNIT" 2>/dev/null; then
  printf "\n"
  warn "本机已经存在一个 $SVC.service，但它指向的是【别的位置】："
  grep -E "^ExecStart" "$UNIT" 2>/dev/null | sed 's/^/       /'
  er   "继续的话会【覆盖这个 unit 文件】，原来那个服务的启动方式会被替换"
  inf  "（原位置的数据文件不会被删除，但那个服务将不再被管理）"
  read -rp "     确定要覆盖吗？(y/N) " _ov || _ov=""
  if [ -z "$_ov" ] && [ ! -t 0 ]; then
    er "非交互环境无法确认 —— 已中止，未做任何改动"
    exit 1
  fi
  [[ "$_ov" =~ ^[Yy]$ ]] || { printf "\n"; inf "已取消，未做任何改动。"; exit 0; }
  warn "将覆盖原 unit（原服务会被替换成这一份）"
fi

# ─────────── ③ 问端口 ───────────
printf "\n${B}── 请设置两个参数 ──${R}\n"
while :; do
  # 支持 AIKEYS_PORT 环境变量直接指定（便于自动化；不设则照常询问）
  if [ -n "${AIKEYS_PORT:-}" ]; then PORT="$AIKEYS_PORT"; AIKEYS_PORT=""
  else read -rp "  1) 服务端口 [回车用默认 $DEF_PORT]： " PORT || PORT=""; fi
  PORT="${PORT:-$DEF_PORT}"
  if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
    er "端口必须是 1-65535 之间的数字"
    [ -t 0 ] || { er "标准输入已结束，无法继续询问"; exit 1; }
    continue
  fi
  if command -v ss >/dev/null 2>&1 && ss -tln 2>/dev/null | grep -q ":$PORT "; then
    er "端口 $PORT 已被占用："
    ss -tlnp 2>/dev/null | grep ":$PORT " | sed 's/^/       /'
    read -rp "     仍要继续吗？(y/N) " _a || _a=""
    if [ -z "$_a" ] && [ ! -t 0 ]; then
      er "端口被占用，且标准输入已结束 —— 无法继续询问"
      inf "请换一个空闲端口重跑，或先停掉占用 $PORT 的程序"
      inf "非交互部署可以这样指定端口：AIKEYS_PORT=8080 bash install.sh"
      exit 1
    fi
    [[ "$_a" =~ ^[Yy]$ ]] || continue
  fi
  break
done
ok "端口：$PORT"

# ─────────── ④ 问口令 ───────────
while :; do
  if [ -n "${AIKEYS_PASSWORD:-}" ]; then     # 环境变量直接指定（自动化用）
    PW1="$AIKEYS_PASSWORD"; PW2="$AIKEYS_PASSWORD"; AIKEYS_PASSWORD=""
  elif [ -t 0 ]; then                         # 终端里：不回显
    read -rsp "  2) 访问口令（输入时不显示）： " PW1 || PW1=""; printf "\n"
    read -rsp "     再输一次确认：             " PW2 || PW2=""; printf "\n"
  else                                        # 管道/自动化：回显
    read -rp  "  2) 访问口令： " PW1 || PW1=""
    read -rp  "     再输一次确认： " PW2 || PW2=""
  fi
  if [ -z "$PW1" ] && [ ! -t 0 ]; then
    er "标准输入已结束，没有读到口令"
    inf "非交互部署可以这样指定口令：AIKEYS_PASSWORD='你的口令' bash install.sh"
    exit 1
  fi
  [ -n "$PW1" ] || { er "口令不能为空"; continue; }
  [ "${#PW1}" -ge 6 ] || { er "口令太短，至少 6 位"; continue; }
  [ "$PW1" = "$PW2" ] || { er "两次输入不一致，请重新输入"; continue; }
  break
done
ok "口令：${#PW1} 位（已确认）"

# ─────────── ⑤ 开机自启：有 systemd 就用它；没有就生成启动脚本 ───────────
printf "\n"
STARTER="/root/ai-keys-start.sh"
USE_SYSTEMD=0

if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  cat > "$UNIT" <<EOF
[Unit]
Description=AI API Key Hub ($SVC)
After=network.target

[Service]
Type=simple
ExecStart=$PY $DEST/server.py --port $PORT --data-dir $DEST/data --static $DEST/static --no-tls
Restart=always
RestartSec=3
StandardOutput=append:$DEST/logs/app.log
StandardError=append:$DEST/logs/app.err

[Install]
WantedBy=multi-user.target
EOF
  USE_SYSTEMD=1
  ok "检测到 systemd → 已写入系统服务（含开机自启）"
  inf "unit 文件：$UNIT"
  printf "\n  ${B}${G}★ 本机有 systemd，由系统服务托管 ——【不需要】额外的启动脚本，也没生成它。${R}\n"
else
  USE_SYSTEMD=0
  printf "\n"
  warn "本机【没有 systemd】（或者是被当前环境屏蔽了 /run/systemd/system）"
  warn "→ 无法配置系统级开机自启"
  inf "→ 不用担心：我在 /root 下生成一个启动脚本给你用"
fi

# ── 没有 systemd 才生成启动脚本 ──
if [ "$USE_SYSTEMD" = "0" ]; then
  cat > "$STARTER" <<'STARTEREOF'
#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#  AI 密钥网关 · 启动脚本
#  （因为本机没有 systemd，用这个脚本启动 / 停止 / 查看服务）
#
#     bash /root/ai-keys-start.sh start      启动
#     bash /root/ai-keys-start.sh stop       停止
#     bash /root/ai-keys-start.sh restart    重启
#     bash /root/ai-keys-start.sh status     看状态
#
#  特点：
#   · start 以「守护」方式运行 —— 进程意外退出会自动重启
#   · 用 setsid 脱离终端，关掉 SSH 窗口不会被杀
# ═══════════════════════════════════════════════════════════════
DIR="__DIR__"
PY="__PY__"
PORT="__PORT__"
PIDFILE="$DIR/ai-keys.pid"
LOG="$DIR/logs/app.log"

running() { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; }

runloop() {
  while :; do
    "$PY" "$DIR/server.py" --port "$PORT" --data-dir "$DIR/data" --static "$DIR/static" --no-tls
    _rc=$?
    echo "[$(date '+%F %T')] 进程退出（退出码 $_rc），3 秒后自动重启" >> "$LOG"
    sleep 3
  done
}

start() {
  if running; then echo "✅ 已经在运行（PID $(cat "$PIDFILE")）"; return 0; fi
  mkdir -p "$DIR/logs"
  setsid "$0" __runloop >> "$LOG" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
  sleep 1.5
  if running; then
    echo "✅ 已启动（PID $(cat "$PIDFILE")）"
    echo "   本机地址：http://127.0.0.1:$PORT/"
    echo "   日志：    tail -f $LOG"
  else
    echo "❌ 启动失败，看日志：$LOG"
    tail -10 "$LOG" 2>/dev/null
    return 1
  fi
}

stop() {
  if ! running; then echo "ℹ️  当前没在运行"; rm -f "$PIDFILE"; return 0; fi
  P="$(cat "$PIDFILE")"
  kill -TERM -- "-$P" 2>/dev/null || kill -TERM "$P" 2>/dev/null
  sleep 1.5
  kill -KILL -- "-$P" 2>/dev/null || kill -KILL "$P" 2>/dev/null
  rm -f "$PIDFILE"
  echo "🛑 已停止"
}

case "${1:-start}" in
  __runloop) runloop ;;
  start)   start ;;
  stop)    stop ;;
  restart) stop; sleep 1; start ;;
  status)
    if running; then
      echo "✅ 运行中（PID $(cat "$PIDFILE")）"
      printf "   健康检查："
      curl -s -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null || printf "（curl 不可用或服务无响应）"
      echo
    else
      echo "⛔ 没在运行（用 start 启动）"
    fi ;;
  *) echo "用法：bash $0 {start|stop|restart|status}" ;;
esac
STARTEREOF
  chmod +x "$STARTER"
  sed -i "s|__DIR__|$DEST|g; s|__PY__|$PY|g; s|__PORT__|$PORT|g" "$STARTER"
  ok "已生成启动脚本：$STARTER"

  # 顺手尝试用 cron @reboot 实现开机自启
  if command -v crontab >/dev/null 2>&1; then
    _cur="$(crontab -l 2>/dev/null)"
    if printf '%s' "$_cur" | grep -qF "ai-keys-start.sh"; then
      ok "cron 里已有 @reboot 记录（不重复添加）"
    else
      { [ -n "$_cur" ] && printf '%s\n' "$_cur"
        printf '@reboot %s start >/dev/null 2>&1\n' "$STARTER"; } | crontab - 2>/dev/null \
        && ok "已加入 cron @reboot → 重启后自动拉起" \
        || warn "cron 写入失败，可手动 crontab -e 添加：@reboot $STARTER start"
    fi
  else
    warn "本机也没有 cron —— 开机自启请自行处理（见下面【开机自启】说明）"
  fi
fi

# ─────────── ⑥ 设置口令 ───────────
inf "写入访问口令 ..."
printf '%s' "$PW1" | "$PY" "$DEST/server.py" --data-dir "$DEST/data" --set-password-stdin >/dev/null
chmod 600 "$DEST/data/data.json" 2>/dev/null || true
ok "口令已写入（PBKDF2 加盐哈希，不存明文）"

# ─────────── ⑦ 启动 ───────────
inf "启动服务 ..."
if [ "$USE_SYSTEMD" = "1" ]; then
  systemctl daemon-reload
  systemctl enable "$SVC" >/dev/null 2>&1 || true
  systemctl restart "$SVC"
else
  # ★ 精确匹配本部署的进程，别用宽泛的 "[a]i-keys/server.py"
  #   （那会误杀 /opt/ai-keys 之类的其它同名部署）
  pkill -f "$DEST/server.py" 2>/dev/null || true
  sleep 0.5
  bash "$STARTER" start || true
  sleep 0.5
fi

# ─────────── ⑧ 健康检查 ───────────
HEALTH=""
for i in 1 2 3 4 5 6 7 8 9 10; do
  HEALTH="$(curl -s -m 2 "http://127.0.0.1:$PORT/health" 2>/dev/null || true)"
  [ -n "$HEALTH" ] && break
  sleep 0.6
done
printf "\n"
if printf '%s' "$HEALTH" | grep -q '"ok"'; then
  ok "服务已启动，健康检查通过"
else
  er "健康检查没通过！"
  inf "错误日志：$DEST/logs/app.err"
  tail -12 "$DEST/logs/app.err" 2>/dev/null | sed 's/^/       /'
  if [ "$USE_SYSTEMD" = "1" ]; then
    inf "也可以看： journalctl -u $SVC -n 30 --no-pager"
  fi
  exit 1
fi

# ─────────── ⑨ 读回网关令牌 ───────────
_SETTINGS="$("$PY" -c 'import json,sys
try:
    s = json.load(open(sys.argv[1]))["settings"]
except Exception:
    s = {}
print(s.get("gateway_token","(读取失败)"), s.get("model_alias","auto"))' "$DEST/data/data.json" 2>/dev/null || echo "(读取失败) auto")"
TOKEN="${_SETTINGS%% *}"
ALIAS="${_SETTINGS##* }"

# ─────────── ⑨b 探测可用于连接的 IPv4 地址 ───────────
# ★ 不能只用 `ip route get 1.1.1.1`：云服务器有 NAT，取到的是【内网】地址
is_priv_ip() {
  case "$1" in
    10.*|192.168.*|127.*|169.254.*|0.*) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    *) return 1 ;;
  esac
}

# 默认路由用的那个地址（真机上的主网卡地址）
DEFIP=""
if command -v ip >/dev/null 2>&1; then
  DEFIP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
fi

# 本机所有非回环 IPv4（★ 排除虚拟网卡：WireGuard/docker/网桥/隧道 等，
#   否则会把 wg0 的 10.x.x.1 当成"内网地址"推荐给用户）
LAN_IPS=""
if command -v ip >/dev/null 2>&1; then
  LAN_IPS="$(ip -4 -o addr show scope global 2>/dev/null \
             | grep -vE '^[0-9]+: (wg|tun|tap|docker|br-|virbr|veth|zt|tailscale)[0-9]*' \
             | awk '{print $4}' | cut -d/ -f1)"
elif command -v hostname >/dev/null 2>&1; then
  LAN_IPS="$(hostname -I 2>/dev/null | tr ' ' '\n')"
fi
LAN_IPS="$(printf '%s\n' "$LAN_IPS" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
           | grep -vE '^(127\.|169\.254\.|0\.)')"

# 把主网卡地址排到最前（推荐"内网地址"时用它）
if [ -n "$DEFIP" ]; then
  LAN_IPS="$(printf '%s\n%s\n' "$DEFIP" "$LAN_IPS" \
             | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
             | grep -vE '^(127\.|169\.254\.|0\.)' | awk '!seen[$0]++')"
else
  LAN_IPS="$(printf '%s\n' "$LAN_IPS" | awk '!seen[$0]++')"
fi

# 查真实公网 IP（多服务轮流试，含国内可用的）
PUBIP=""
if command -v curl >/dev/null 2>&1; then
  for _u in https://ipv4.icanhazip.com https://ipinfo.io/ip \
            http://members.3322.org/dyndns/getip https://myip.ipip.net https://api.ipify.org; do
    _r="$(curl -s -m 4 "$_u" 2>/dev/null | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
    if [ -n "$_r" ] && ! is_priv_ip "$_r"; then PUBIP="$_r"; break; fi
  done
fi

# 主用地址：优先公网 → 第一个内网 → 127.0.0.1
MAIN="$PUBIP"
[ -z "$MAIN" ] && MAIN="$(printf '%s\n' "$LAN_IPS" | head -1)"
[ -z "$MAIN" ] && MAIN="127.0.0.1"

# ─────────── ⑩ 打印连接信息 ───────────
printf "\n${B}${G}"
printf "╔══════════════════════════════════════════════════╗\n"
printf "║                  ✨  部署完成！                  ║\n"
printf "╚══════════════════════════════════════════════════╝\n"
printf "${R}\n"

printf "${B}【管理后台】${R}服务已监听 ${B}0.0.0.0:%s${R}，下面任选一个打开（输你刚设的口令）：\n\n" "$PORT"
if [ -n "$PUBIP" ]; then
printf "    🌍 ${B}公网${R}   ${C}http://%s:%s/${R}\n" "$PUBIP" "$PORT"
fi
for _ip in $LAN_IPS; do
  [ "$_ip" = "$PUBIP" ] && continue
  if is_priv_ip "$_ip"; then
printf "    🏢 ${B}内网${R}   ${C}http://%s:%s/${R}\n" "$_ip" "$PORT"
  else
printf "    🌍 ${B}公网${R}   ${C}http://%s:%s/${R}\n" "$_ip" "$PORT"
  fi
done
printf "    🏠 ${B}本机${R}   ${C}http://127.0.0.1:%s/${R}\n" "$PORT"
if [ -z "$PUBIP" ] && [ -z "$LAN_IPS" ]; then
printf "\n    ${Y}⚠ 没探测到任何可用 IP（这台机器可能只有回环网卡）。${R}\n"
elif [ -z "$PUBIP" ]; then
printf "\n    ${Y}⚠ 没能查到公网 IP（没网/被墙/纯内网）。如果是云服务器，\n"
printf "      去云控制台看「公网 IP」，用它替换上面的内网地址。${R}\n"
fi
printf "\n"

printf "${B}【客户端配置】${R}（Cherry Studio / NextChat / Cursor / one-api …）\n"
printf "    Base URL :  ${C}http://%s:%s/v1${R}\n" "$MAIN" "$PORT"
printf "    API Key  :  ${C}%s${R}\n" "$TOKEN"
printf "    模型名   :  ${C}%s${R}   ← 填这个就等于「自动挑一把能用的密钥」\n" "$ALIAS"
if [ -n "$PUBIP" ] && [ -n "$LAN_IPS" ]; then
printf "    ${Y}↑ 上面用的是公网地址；客户端若和服务器在同一内网，换成 %s${R}\n" "$(printf '%s\n' "$LAN_IPS" | head -1)"
fi
printf "\n"

printf "${B}【文件位置】${R}\n"
printf "    程序      %s/server.py\n" "$DEST"
printf "    界面      %s/static/index.html\n" "$DEST"
printf "    密钥数据  %s/data/data.json   ${Y}(0600，请备份)${R}\n" "$DEST"
printf "    加密种子  %s/data/master.key  ${E}(0600，丢了密钥全废！必须备份)${R}\n" "$DEST"
printf "    日志      %s/logs/app.log\n\n" "$DEST"

printf "${B}【管理命令】${R}\n"
if [ "$USE_SYSTEMD" = "1" ]; then
printf "    重启      systemctl restart %s\n" "$SVC"
printf "    停止      systemctl stop %s\n" "$SVC"
printf "    看状态    systemctl status %s\n" "$SVC"
printf "    看日志    journalctl -u %s -f\n" "$SVC"
else
printf "    启动      ${C}bash %s start${R}\n" "$STARTER"
printf "    停止      ${C}bash %s stop${R}\n" "$STARTER"
printf "    重启      ${C}bash %s restart${R}\n" "$STARTER"
printf "    看状态    ${C}bash %s status${R}\n" "$STARTER"
printf "    看日志    tail -f %s/logs/app.log\n" "$DEST"
fi
printf "    ★ 换端口 / 换口令：重跑一次 sudo bash install.sh 即可（原数据会保留）\n"

printf "\n${B}【开机自启】${R}\n"
if [ "$USE_SYSTEMD" = "1" ]; then
printf "    ${G}✅ 已用 systemd 配置好开机自启${R}（systemctl is-enabled %s → enabled）\n" "$SVC"
printf "    ${B}★ 本机有 systemd，所以【不需要】启动脚本 —— 我也没有生成它。${R}\n"
printf "       日常用：systemctl {start|stop|restart|status} %s\n" "$SVC"
else
printf "    ${Y}⚠ 本机没有 systemd，无法配置系统级开机自启。${R}\n"
printf "    ${B}${G}★ 已在 /root 下生成启动脚本（本机没有 systemd 才生成）：${R}\n"
printf "       ${C}%s${R}\n\n" "$STARTER"
printf "       启动   ${C}bash %s start${R}\n" "$STARTER"
printf "       停止   ${C}bash %s stop${R}\n" "$STARTER"
printf "       重启   ${C}bash %s restart${R}\n" "$STARTER"
printf "       状态   ${C}bash %s status${R}\n\n" "$STARTER"
printf "    ${B}★ 重启机器后服务如果没自己起来，就执行第一条 start。${R}\n"
printf "    ★ 该脚本自带守护：进程崩了会自动拉起；setsid 脱离终端，关掉 SSH 也不会被杀。\n"
fi
printf "\n"

printf "${Y}${B}【重要提醒】${R}\n"
printf "    ${Y}1.${R} 这是 ${B}纯 HTTP${R} 部署 —— 令牌会明文传输，建议只在内网/可信网络使用\n"
printf "    ${Y}2.${R} 要从 ${B}外网${R}访问：云服务器去控制台${B}放行安全组端口 %s${R}；\n" "$PORT"
printf "       家用宽带需要在路由器上做${B}端口映射${R}（本机防火墙也别忘了：ufw/firewalld）\n"
printf "    ${Y}3.${R} ${E}务必备份${R} data.json 和 master.key —— 两个一起丢 = 所有密钥永久无法恢复\n"
printf "\n"
