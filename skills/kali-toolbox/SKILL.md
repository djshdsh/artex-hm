---
name: kali-toolbox
description: 在 ARTEX 容器内调用 Kali 工具链（nmap/sqlmap/hydra/gobuster/ffuf/whatweb/wfuzz/john/hashcat/tcpdump/socat/proxychains 等）时的清单、调用规范与网络限制说明。任何需要端口扫描、NSE、口令爆破、抓包、SQL 注入验证、目录爆破的任务都应先读本 skill。
---
# Kali 工具链（ARTEX 容器内）

## 0. 两条铁律（先看这个）

1. **所有命令加 `kx` 前缀**：容器环境变量里有个坏代理（`host.docker.internal:7890`），不加会全部超时。
   ```bash
   kx nmap -sV target      # 不是 nmap -sV target
   ```
   `kx` = `env -u http_proxy -u https_proxy ... "$@"`，已装在 `/usr/local/bin/kx`。

2. **对外网目标做端口扫描/抓包不可信**。容器出口是透明代理 TUN + fake-IP DNS（`198.18.0.0/16`），
   实测对一个 fake-IP 扫 `1,22,80,443,8080` **全部报 open**（假阳性）；换成真实公网 IP 则直接挂住（超时）。
   → Web 类工具（curl/whatweb/ffuf/gobuster/sqlmap/httpx 风格请求）单条 TCP 走代理，**可用**；
   → 端口扫描 / masscan / NSE / 非 HTTP 爆破，**必须转到宿主机 Kali 跑**（见第 4 节 SSH 桥）。

---

## 1. 容器内已装清单（Debian 12 容器，宿主是 Kali）

| 工具 | 版本 | 主要用途 |
|---|---|---|
| nmap | 7.93（605 个 NSE 脚本） | 端口/服务/脚本扫描（仅内网可信） |
| masscan | 1.3.2 | 大段快速 SYN（内网用） |
| sqlmap | 1.7.2 | SQLi 检测/验证 |
| hydra | 9.4 | 在线口令测试 |
| sshpass | 1.09 | 非交互 SSH |
| john | 1.9.0 | 离线破解 |
| hashcat | 6.2.6 | 离线破解（GPU/CPU） |
| gobuster | 3.5 | 目录/DNS 爆破 |
| ffuf | 1.1.0 | 通用 fuzz |
| dirb | 2.22 | 目录扫描（字典齐） |
| wfuzz | 3.1.0 | fuzz（HTTPS 有坑，见下） |
| whatweb | 0.5.5 | Web 指纹 |
| tcpdump | 4.99.3 | 抓包（仅容器网卡） |
| socat | 1.7.4 | 转发/隧道 |
| proxychains4 | 4.16 | 代理链 |
| 其它 | — | nc/openssl/dig/whois/curl/wget/git/jq/python3/node |

字典：`/usr/share/wordlists/`（dirb/common.txt、dirbuster/…）；rockyou 未装，需要时从 `/usr/share/wordlists` 找或自备。

---

## 2. 调用范式（按阶段，别跳步）

| 阶段 | 命令样例 |
|---|---|
| 指纹 | `kx whatweb -a 3 https://T` |
| 目录 | `kx ffuf -u https://T/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403` |
| 参数 / 注入 | `kx sqlmap -u "https://T/?id=1" --batch --level=2 --risk=2 --technique=BEU` |
| 端口（内网） | `kx nmap -sT -Pn -sV -sC -p- --min-rate 2000 10.x.x.x` |
| 抓包 | `kx tcpdump -i any -nn -A 'tcp port 80' -c 200` |
| 破解（离线） | `kx john --wordlist=rockyou.txt hash.txt` |

**顺序纪律**：先 whatweb/curl 判技术栈 → 再决定用哪类工具；别一上来就 `--dump-all` 或全端口 SYN。

---

## 3. 授权与破坏性红线

- 只测授权目标；禁止扫非目标网段、禁止把容器当跳板打第三方；
- SQLi：**只证明存在**（`--dbs` / `--current-user` / 时间盲注），不 dump 业务表；
- 口令：只用自有账号与自建字典，`-t 4` 起步，遇到锁定/验证码立即停；
- 抓包：只看容器网卡，不要试图抓宿主流量；
- 爆破类不要并发打满，避免把业务打挂（ARTEX 规则里 DoS 一律降级）。

---

## 4. 补齐容器里没有的工具（三条路）

容器不是 Kali，缺 `msfconsole` / `nikto` / `nuclei` / `seclists` / `netexec` / `impacket`。

| 路径 | 适合 | 代价 |
|---|---|---|
| **A. SSH 桥到宿主 Kali**（推荐） | 要用宿主原版工具、要对公网做真实端口扫描 | 需在宿主配 SSH key + 白名单，见 `scripts/kali_bridge.sh` |
| B. 容器内装 Debian 包 | sqlmap/nikto 之外的常规工具 | `kx apt-get install`（apt 也要绕代理，见 reference） |
| C. 静态二进制 | nuclei/ffuf/feroxbuster 等 Go 工具 | 从 GitHub releases 拉，注意校验与版本 |

详见图 `reference.md` 第 3–5 节（含 compose 补丁、白名单脚本、踩坑清单）。
