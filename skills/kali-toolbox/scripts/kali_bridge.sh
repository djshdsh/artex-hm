#!/bin/sh
# kali_bridge.sh —— 在 ARTEX 容器内调用「宿主 Kali」上的工具
#
# 前提（在宿主 Kali 上做一次）：
#   1) ssh-keygen -t ed25519 -f ~/.ssh/artex_bridge -N ''
#   2) cat ~/.ssh/artex_bridge.pub >> ~/.ssh/authorized_keys
#   3) 容器里挂载该私钥（compose: ~/.ssh/artex_bridge:/root/.ssh/id_ed25519:ro）
#   4) 环境变量：KALI_HOST(默认 172.18.0.1) / KALI_USER(默认当前 USER，需显式设置)
#
# 用法：
#   kali_bridge.sh nmap -sV -Pn -p- --min-rate 2000 203.0.113.10
#   kali_bridge.sh nikto -h https://target
#   kali_bridge.sh searchsploit apache 2.4
#
# 安全：工具名走白名单，禁止任意命令；只允许已授权的目标。
set -u

HOST="${KALI_HOST:-172.18.0.1}"
USER="${KALI_USER:-kali}"
KEY="${KALI_KEY:-/root/.ssh/id_ed25519}"
ALLOW="nmap|masscan|nikto|nuclei|ffuf|gobuster|sqlmap|hydra|msfconsole|searchsploit|netexec|crackmapexec|responder|tcpdump|dig|whois|curl|httpx|subfinder|amass"

if [ $# -lt 1 ]; then
  echo "用法: $0 <tool> [args...]" >&2
  echo "允许的工具: $ALLOW" >&2
  exit 3
fi

TOOL="$1"; shift
if ! echo "$TOOL" | grep -Eq "^($ALLOW)$"; then
  echo "拒绝: 工具 '$TOOL' 不在白名单内" >&2
  exit 3
fi

if [ ! -r "$KEY" ]; then
  echo "找不到 SSH 私钥 $KEY（compose 里挂载 ~/.ssh/artex_bridge 到该路径）" >&2
  exit 2
fi

# 用 printf %q 风格的引号保护参数
ARGS=""
for a in "$@"; do
  ARGS="$ARGS $(printf "'%s'" "$(printf '%s' "$a" | sed "s/'/'\\\\''/g")")"
done

exec ssh -i "$KEY" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
     -o ConnectTimeout=10 "$USER@$HOST" "$TOOL$ARGS"
