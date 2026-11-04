#!/usr/bin/env bash
# setup-kali-bridge.sh —— 一键把 ArTeX 容器接到宿主 Kali 工具链
#
# 在你的 Kali 宿主机上运行（不是在容器里）：
#   bash ~/Desktop/setup-kali-bridge.sh              # 安装并验证
#   bash ~/Desktop/setup-kali-bridge.sh --check      # 只体检，不改任何东西
#   bash ~/Desktop/setup-kali-bridge.sh --uninstall  # 撤销（删 key / 白名单 / 容器内配置）
#
# 它做的事：
#   1) 生成专用 SSH key（~/.ssh/artex_bridge，空口令）
#   2) 装命令白名单到 ~/.local/bin/kali-allowlist 并把公钥授权进去（幂等）
#   3) 把私钥投进 ArTeX 容器 + 在容器内建 `kali` 命令（带默认 KALI_HOST/USER）
#   4) 从容器里跑一次真实工具验证
#
# 可选：--persist 额外写 compose override，让容器重建后仍然生效
set -uo pipefail

KEY="$HOME/.ssh/artex_bridge"
ALLOW_BIN="$HOME/.local/bin/kali-allowlist"
AUTH="$HOME/.ssh/authorized_keys"
MODE="install"
PERSIST=0
CONTAINER=""
DK="${DOCKER:-docker}"
KALI_USER="${KALI_USER:-$(whoami 2>/dev/null || echo root)}"
GREEN=$'\033[32m'; RED=$'\033[31m'; YEL=$'\033[33m'; DIM=$'\033[2m'; NC=$'\033[0m'

for a in "$@"; do
  case "$a" in
    --check)     MODE="check" ;;
    --uninstall) MODE="uninstall" ;;
    --persist)   PERSIST=1 ;;
    --container=*) CONTAINER="${a#*=}" ;;
    -h|--help)   sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "未知参数: $a"; exit 2 ;;
  esac
done

ok(){ echo "${GREEN}[ok]${NC} $*"; }
warn(){ echo "${YEL}[!]${NC} $*"; }
err(){ echo "${RED}[x]${NC} $*"; }
step(){ echo; echo "${DIM}── $* ──${NC}"; }

# ---------------------------------------------------------------- 0. 找容器
find_container(){
  if [ -n "$CONTAINER" ]; then echo "$CONTAINER"; return; fi
  local c
  c=$($DK ps --format '{{.Names}}' 2>/dev/null | grep -i artex | head -1)
  [ -n "$c" ] && { echo "$c"; return; }
  # 退而求其次：找跑着 artex 二进制的容器
  for n in $($DK ps --format '{{.Names}}' 2>/dev/null); do
    if $DK exec "$n" test -x /app/artex 2>/dev/null; then echo "$n"; return; fi
  done
}

$DK version >/dev/null 2>&1 || { err "docker 不可用；若需要 sudo，请用: DOCKER=\"sudo docker\" bash $0"; exit 1; }
C=$(find_container)
[ -n "${C:-}" ] || { err "找不到 ArTeX 容器，用 --container=<名字> 指定"; $DK ps --format '  {{.Names}}  {{.Image}}'; exit 1; }
ok "ArTeX 容器: $C"
KALI_HOST=$($DK exec "$C" python3 -c '
import struct, socket
for line in open("/proc/net/route").read().splitlines()[1:]:
    f = line.split()
    if len(f) > 2 and f[1] == "00000000":
        print(socket.inet_ntoa(struct.pack("<L", int(f[2], 16))))
        break
' 2>/dev/null | head -1)
[ -n "$KALI_HOST" ] || KALI_HOST="172.18.0.1"
ok "容器看到的宿主网关: $KALI_HOST"

# ---------------------------------------------------------------- 卸载
if [ "$MODE" = "uninstall" ]; then
  step "卸载"
  [ -f "$KEY" ] && rm -f "$KEY" "$KEY.pub" && ok "删除 $KEY"
  [ -f "$ALLOW_BIN" ] && rm -f "$ALLOW_BIN" && ok "删除 $ALLOW_BIN"
  if [ -f "$AUTH" ] && [ -f "$KEY.pub" ]; then :; fi
  grep -v 'artex-bridge' "$AUTH" > "$AUTH.tmp" 2>/dev/null && mv "$AUTH.tmp" "$AUTH" && chmod 600 "$AUTH" && ok "移除 authorized_keys 中的 bridge 条目"
  $DK exec "$C" rm -f /root/.ssh/id_ed25519 /usr/local/bin/kali 2>/dev/null && ok "清理容器内 key 与 kali 命令"
  exit 0
fi

# ---------------------------------------------------------------- 1. 体检
step "1/4 体检"
$DK exec "$C" sh -c 'command -v nmap >/dev/null && echo nmap-ok' 2>/dev/null | grep -q ok && ok "容器内有工具链"
$DK exec "$C" test -f /app/skills/kali-toolbox/scripts/kali_bridge.sh 2>/dev/null \
  && ok "容器内有 kali_bridge.sh" \
  || { err "容器里缺 /app/skills/kali-toolbox/scripts/kali_bridge.sh"; exit 1; }
systemctl is-active ssh >/dev/null 2>&1 || systemctl is-active sshd >/dev/null 2>&1 \
  && ok "sshd 运行中" || warn "sshd 似乎没跑（sudo apt install openssh-server && sudo systemctl enable --now ssh）"
[ "$MODE" = "check" ] && { echo; ok "体检完成（--check 不改动任何东西）"; exit 0; }

# ---------------------------------------------------------------- 2. key
step "2/4 SSH 密钥与授权"
mkdir -p "$HOME/.ssh" "$HOME/.local/bin"; chmod 700 "$HOME/.ssh"
if [ -f "$KEY" ]; then ok "沿用已有 $KEY"; else
  ssh-keygen -t ed25519 -f "$KEY" -N '' -C "artex-bridge" >/dev/null && ok "生成 $KEY"
fi
chmod 600 "$KEY"

cat > "$ALLOW_BIN" <<'ALLOWEOF'
#!/bin/sh
# ArTeX 桥的 SSH 命令白名单
ALLOW="nmap|masscan|nikto|nuclei|ffuf|gobuster|sqlmap|hydra|msfconsole|searchsploit|netexec|crackmapexec|responder|tcpdump|dig|whois|curl|httpx|subfinder|amass|nslookup"
cmd=$(echo "${SSH_ORIGINAL_COMMAND:-}" | awk '{print $1}')
[ -z "$cmd" ] && exit 0
echo "$cmd" | grep -Eq "^($ALLOW)$" || { echo "denied: $cmd" >&2; exit 3; }
exec sh -c "$SSH_ORIGINAL_COMMAND"
ALLOWEOF
chmod +x "$ALLOW_BIN"
ok "白名单: $ALLOW_BIN"

touch "$AUTH"; chmod 600 "$AUTH"
PUB=$(cat "$KEY.pub")
if grep -qF "$PUB" "$AUTH" 2>/dev/null; then ok "公钥已授权"; else
  echo "command=\"$ALLOW_BIN\",restrict,pty $PUB" >> "$AUTH"
  ok "公钥已写入 authorized_keys（带命令白名单）"
fi

# ---------------------------------------------------------------- 3. 投递
step "3/4 投递到容器"

# 容器是 Debian 精简镜像，常常没有 ssh 客户端
if $DK exec "$C" sh -c 'command -v ssh >/dev/null 2>&1'; then
  ok "容器内已有 ssh 客户端"
else
  warn "容器内缺 ssh 客户端，正在安装 openssh-client …"
  $DK exec "$C" sh -c 'export DEBIAN_FRONTEND=noninteractive;     unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy;     apt-get update -qq && apt-get install -y --no-install-recommends openssh-client' >/dev/null 2>&1 \
    && ok "openssh-client 已安装" \
    || err "自动安装失败，请手工执行: $DK exec $C apt-get install -y openssh-client"
fi

$DK exec "$C" mkdir -p /root/.ssh 2>/dev/null
$DK cp "$KEY" "$C:/root/.ssh/id_ed25519" >/dev/null && $DK exec "$C" chmod 600 /root/.ssh/id_ed25519 && ok "私钥已放入容器"
$DK exec "$C" sh -c "cat > /usr/local/bin/kali <<'WRAPEOF'
#!/bin/sh
export KALI_HOST=$KALI_HOST
export KALI_USER=$KALI_USER
export KALI_KEY=/root/.ssh/id_ed25519
exec /app/skills/kali-toolbox/scripts/kali_bridge.sh \"\$@\"
WRAPEOF
chmod +x /usr/local/bin/kali" && ok "容器内命令: kali（默认 host=$KALI_HOST user=$KALI_USER）"

if [ "$PERSIST" = "1" ]; then
  CFG=$($DK inspect "$C" --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' 2>/dev/null)
  SVC=$($DK inspect "$C" --format '{{ index .Config.Labels "com.docker.compose.service" }}' 2>/dev/null)
  if [ -n "$CFG" ] && [ -n "$SVC" ]; then
    BASE="${CFG%%,*}"; DIR=$(dirname "$BASE")
    case "$(basename "$BASE")" in
      compose.yaml|compose.yml) OV="$DIR/compose.override.yaml" ;;
      *) OV="$DIR/docker-compose.override.yml" ;;
    esac
    cat > "$OV" <<OVEOF
# 由 setup-kali-bridge.sh 生成：让 ArTeX 容器重建后仍能调到宿主 Kali
services:
  $SVC:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - $KEY:/root/.ssh/id_ed25519:ro
OVEOF
    ok "已写 override: $OV"
    ( cd "$DIR" && $DK compose -f "$BASE" -f "$OV" up -d "$SVC" ) && ok "容器已按 override 重建"
    $DK cp "$KEY" "$C:/root/.ssh/id_ed25519" >/dev/null 2>&1 || true
  else
    warn "不是 compose 起的容器，跳过 --persist；重建容器时记得加 -v $KEY:/root/.ssh/id_ed25519:ro"
  fi
fi

# ---------------------------------------------------------------- 4. 验证
step "4/4 验证"
if $DK exec "$C" sh -c 'kali whois example.com' >/tmp/kali_verify.out 2>/tmp/kali_verify.err; then
  ok "桥接成功 —— 容器已能调用宿主 Kali 工具"
  head -3 /tmp/kali_verify.out | sed 's/^/    /'
else
  err "验证失败："; sed 's/^/    /' /tmp/kali_verify.err | head -5
  echo
  warn "常见原因："
  echo "    · sshd 没起或只听 127.0.0.1 → sudo systemctl enable --now ssh"
  echo "    · 网关不对 → 容器内 ip route，改 KALI_HOST 后重跑"
  echo "    · 用户名不对 → KALI_USER=<你的用户名> bash $0"
  exit 1
fi

cat <<EOF

${GREEN}完成${NC}。在 ArTeX 任务的 bash 里直接用：

    kali nmap -sV -Pn -p- --min-rate 2000 <目标IP>
    kali nikto -h https://<目标>
    kali searchsploit apache 2.4
    kali msfconsole -q -x "use auxiliary/scanner/portscan/tcp; set RHOSTS <目标>; run; exit"

（`kali` = 容器内 /usr/local/bin/kali，已带 KALI_HOST/KALI_USER，自动绕白名单校验）
撤销：bash $0 --uninstall
EOF
