# Kali 工具链接入 —— 参考

## 1. 环境事实（先对齐认知）

| 项 | 实测值 |
|---|---|
| ARTEX 进程 | Debian 12 (bookworm) **容器**，`/app/artex` |
| 宿主 | **Kali Rolling 2026.1**，kernel `7.1.5+kali-cloud-amd64` |
| 容器 IP / 网关 | 172.18.0.3 / **172.18.0.1**（宿主，22 端口开放、8787 开放） |
| DNS | 127.0.0.11 → 被劫持为 **fake-IP**（外部域名返回 `198.18.x.x`） |
| 出网 | 透明代理 TUN；`http_proxy=host.docker.internal:7890` **是坏的**（CONNECT 挂死） |
| 出站公网 IP | 45.149.92.22 / 45.149.92.7（HK, AS401443，NAT 池轮换） |

**结论**：容器 ≠ 你的 Kali shell。宿主那套 `msfconsole / nikto / seclists / netexec / impacket` 默认**用不到**，
要么把工具搬进容器，要么让容器通过 SSH 调宿主（第 4 节）。

## 2. 网络能力边界（最容易踩的坑，已实测）

```bash
kx nmap -sT -Pn -p 1,22,80,443,8080 198.18.0.7     # 某个外部域名的 fake-IP
# 结果：全部 open  ← 假阳性！透明代理对所有 SYN 都接受
kx nmap -sT -Pn -p 22,2375,8787 172.18.0.1          # 内网真实地址
# 结果：22 open / 2375 closed / 8787 open  ← 正常
```

| 目标类型 | 端口扫描 | Web 工具 | 说明 |
|---|---|---|---|
| 容器内网段 / 172.18.x.x | ✅ 可信 | ✅ | 正常路由 |
| 外部域名（fake-IP） | ❌ **全是假 open** | ✅ | 单条 TCP 由代理转发，HTTP 正常 |
| 外部真实 IP | ❌ 挂住/超时 | ⚠️ 视端口 | 建议转宿主执行 |

→ 需要**可信的端口/NSE/爆破结果**时，一律走 SSH 桥到宿主 Kali。

## 3. 安装/补齐命令（容器内）

apt 同样要绕坏代理：

```bash
kx apt-get update
kx apt-get install -y --no-install-recommends sqlmap hydra gobuster whatweb dirb wfuzz masscan john hashcat tcpdump socat proxychains4 sshpass dnsrecon ffuf
```

Debian bookworm 里**没有**的：`nikto`、`seclists`、`nuclei`、`feroxbuster`、`netexec`、`metasploit`。
补充方式：

```bash
# nuclei（Go 静态二进制）
kx curl -sSL -o /tmp/nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_<ver>_linux_amd64.zip
# seclists（体积大，按需）
kx git clone --depth 1 https://github.com/danielmiessler/SecLists /opt/SecLists
```

> 容器重启后 apt 装的会丢（overlay 层），要持久化就改 Dockerfile / compose build。

## 4. SSH 桥到宿主 Kali（推荐路径）

### 4.1 宿主侧准备（在你的 Kali 上执行一次）

```bash
# 1) 生成专用 key（容器用）
ssh-keygen -t ed25519 -f ~/.ssh/artex_bridge -N ''
# 2) 授权（限命令白名单更安全，见下）
cat ~/.ssh/artex_bridge.pub >> ~/.ssh/authorized_keys
# 3) 如要限制：在 authorized_keys 条目前加
#    command="/usr/local/bin/kali-allowlist",restrict ssh-ed25519 AAAA...
# 4) 起一个专用账号（可选）
```

`/usr/local/bin/kali-allowlist`（宿主侧白名单包装）：

```bash
#!/bin/sh
ALLOW="nmap|masscan|nikto|nuclei|ffuf|gobuster|sqlmap|hydra|msfconsole|searchsploit|netexec|crackmapexec|responder|tcpdump|curl|dig|whois"
cmd=$(echo "$SSH_ORIGINAL_COMMAND" | awk '{print $1}')
echo "$cmd" | grep -Eq "^($ALLOW)$" || { echo "denied: $cmd" >&2; exit 3; }
exec sh -c "$SSH_ORIGINAL_COMMAND"
```

### 4.2 容器侧调用

```bash
export KALI_HOST=172.18.0.1 KALI_USER=<你的用户名>
kx /app/skills/kali-toolbox/scripts/kali_bridge.sh nmap -sV -Pn -p- --min-rate 2000 <TARGET_IP>
```

### 4.3 compose 补丁（把 key 挂进来）

```yaml
services:
  artex:
    extra_hosts:
      - "host.docker.internal:host-gateway"
    volumes:
      - ~/.ssh/artex_bridge:/root/.ssh/id_ed25519:ro
      - /app/data:/app/data
```

或走 docker.sock 路线（更重，能让容器直接 `docker run kalilinux/kali-rolling`）：

```yaml
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

## 5. 常驻踩坑清单

| 现象 | 原因 | 处理 |
|---|---|---|
| 所有命令超时 | 坏代理 | 加 `kx` 前缀 |
| nmap 全端口 open | fake-IP + 透明代理 | 换真实 IP 或走宿主 |
| wfuzz 报 pycurl 未链 OpenSSL | Debian 打包问题 | HTTPS 用 ffuf/gobuster |
| DNS 解析出 198.18.x.x | fake-IP 机制 | `kx dig @1.1.1.1 +short 域名` 取真实记录 |
| apt 更新失败 | apt 也吃代理 | `kx apt-get update` |
| masscan 无输出 | 缺 NET_RAW 或容器网卡限制 | 用 `nmap -sT`；或转宿主 |
| 容器重启工具消失 | overlay 不持久 | 改 Dockerfile |

## 6. 与其它 skill 的组合

- **PHP2Shell 评估**：`kx /app/skills/php2shell-rce/scripts/php2shell_check.py --url ...`
  （注意：HTTP 类请求走透明代理是通的，可直接跑）；
- **Node/nginx 版本核对**：同样可直接用，都是 HTTP 层；
- **需要打端口/爆破/抓包**：先转宿主（第 4 节），再按各 skill 的流程走。

## 7. 常用命令速查

```bash
# 指纹
kx whatweb -a 3 https://T
kx curl -sSI https://T | head -20
# 目录
kx ffuf -u https://T/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -t 20
kx gobuster dir -u https://T -w /usr/share/wordlists/dirb/common.txt -t 20
kx dirb https://T /usr/share/wordlists/dirb/common.txt
# 注入
kx sqlmap -u "https://T/?id=1" --batch --level=2 --risk=2
kx sqlmap -r /tmp/req.txt --batch --dbs
# 端口（内网）
kx nmap -sT -Pn -sV -sC -p- --min-rate 2000 10.0.0.5
kx nmap --script http-title,http-headers,http-methods -p80,443,8080 T
# 口令
kx hydra -L users.txt -P pass.txt -t 4 ssh://T
kx hydra -l admin -P pass.txt T http-post-form "/login:u=^USER^&p=^PASS^:F=invalid"
# 破解
kx john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5 hash.txt
kx hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
# 抓包/转发
kx tcpdump -i any -nn -A 'tcp port 80' -c 200 -w /tmp/p.pcap
kx socat TCP-LISTEN:9000,fork TCP:T:80
kx proxychains4 -f /etc/proxychains4.conf curl -sS http://internal/
```

---

## 8. 一键脚本 `setup-kali-bridge.sh`

在宿主 Kali 上运行，自动完成「建 key → 授权（带白名单）→ 投递进容器 → 建 `kali` 命令 → 验证」。

```bash
# 从容器里拷到桌面（一条命令）
docker cp $(docker ps --filter name=artex -q | head -1):/app/skills/kali-toolbox/scripts/setup-kali-bridge.sh ~/Desktop/
chmod +x ~/Desktop/setup-kali-bridge.sh

~/Desktop/setup-kali-bridge.sh --check        # 先体检，不改任何东西
~/Desktop/setup-kali-bridge.sh                # 正式安装 + 验证
~/Desktop/setup-kali-bridge.sh --persist      # 额外写 compose override（容器重建后仍生效）
~/Desktop/setup-kali-bridge.sh --uninstall    # 撤销
```

**它不会做的事**：不装 `ssh-server`、不装 Kali 专属工具、不改你的 `authorized_keys` 里已有条目（幂等追加）。
**前置**：宿主 `sshd` 在跑；docker 需要 sudo 时用 `DOCKER="sudo docker" ~/Desktop/setup-kali-bridge.sh`。

装好后容器内直接：`kali nmap -sV target` / `kali nikto -h https://target`（`kali` 是容器内 `/usr/local/bin/kali` 包装器）。

### 9.x 已知坑：容器缺 ssh 客户端

首次接桥时报 `exec: ssh: not found`，因为 Debian 精简镜像没装 `openssh-client`。

```bash
# 容器内补装（apt 也要绕坏代理）
docker exec artex-artex-1 sh -c 'unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; \
  apt-get update -qq && apt-get install -y --no-install-recommends openssh-client'
```

`setup-kali-bridge.sh` 已内置该步骤（检测不到就自动装）。容器重建后仍需重跑一次脚本。
