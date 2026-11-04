---
name: recon-and-content-discovery
description: 资产面侦察与内容发现（子域/端口/服务指纹/目录与文件爆破/参数发现/JS 提取接口/技术栈识别）。当意图涉及"摸摸有什么""找目录""找子域""扫端口""找接口"时读本 skill。
---
# 侦察与内容发现 Playbook

> 目标不是"扫得全"，是**把攻击面变成可被后续意图消费的结构化资产**（每个发现都要 insert_assets）。

## 0. 容器网络前提（必读，否则白扫）

容器出口是透明代理 TUN + fake-IP DNS（`198.18.0.0/16`）：
- ✅ **HTTP/HTTPS 类工具可用**：curl / whatweb / ffuf / gobuster / sqlmap / wfuzz / nuclei(http)
- ❌ **端口扫描不可信**：对 fake-IP 扫会全部报 open。masscan / nmap SYN 需转到宿主机 Kali 跑（见 `kali-toolbox` skill 的 SSH 桥）
- 所有命令加 `kx` 前缀，避免命中容器里的坏代理

## 1. 起手三件事

```bash
kx whatweb -a 3 http://TARGET/            # 技术栈 + 版本
curl -sI http://TARGET/                    # 头信息、Server、Cookie 名
curl -s http://TARGET/robots.txt http://TARGET/sitemap.xml http://TARGET/.well-known/security.txt
```

## 2. 子域与资产扩张

```bash
# 被动：证书透明度 / 公开数据（容器内可跑）
curl -s "https://crt.sh/?q=%25.TARGET&output=json" | jq -r '.[].name_value' | sort -u
curl -s "https://api.hackertarget.com/hostsearch/?q=TARGET"

# 主动 DNS 爆破（dnsx 在容器内）
kx dnsx -d TARGET -w /usr/share/dirb/wordlists/common.txt -a -resp

# 泛解析检测（不做这步，爆破结果全是假的）
dig +short RANDOM.TARGET
```
**子域接管判定**（高价值，直接记 finding）：CNAME 指向 `*.s3.amazonaws.com` / `*.herokuapp.com` / `*.github.io` / `*.azurewebsites.net` / `*.cloudfront.net` 且目标未注册 → 注册即接管。

## 3. 目录与文件发现

```bash
# 首选 ffuf（快、可过滤）
kx ffuf -u http://TARGET/FUZZ -w /usr/share/dirb/wordlists/common.txt -mc 200,204,301,302,401,403 -t 40

# 递归 + 后缀
kx ffuf -u http://TARGET/FUZZ -w /usr/share/dirb/wordlists/big.txt -e .php,.bak,.zip,.old,.txt,.json,.env

# 备份/敏感文件定向
kx ffuf -u http://TARGET/FUZZ -w - <<'EOF'
.git/config
.git/HEAD
.env
.env.bak
config.php.bak
www.zip
backup.zip
db.sql
.DS_Store
swagger.json
openapi.json
api-docs
phpinfo.php
server-status
actuator/env
actuator/heapdump
console
EOF
```
**避开假 200**：先请求一个随机路径看到"自定义 404 页面"的特征（长度/标题），用 `-fs <len>` 过滤。

## 4. 参数发现

```bash
# 从页面/JS 里抽参数名
curl -s http://TARGET/ | grep -oE '[a-zA-Z0-9_\-]{2,20}=' | sort -u

# 盲目加参数（后端可能认未声明的参数）
kx ffuf -u "http://TARGET/page?FUZZ=1" -w params.txt -fs <baseline_len>

# 隐藏头
kx ffuf -u http://TARGET/api/me -H "FUZZ: 1" -w headers.txt -mc all -fs <baseline>
# 候选：X-Forwarded-For X-Original-URL X-Rewrite-URL X-User-Id X-Org-Id X-Admin
```

## 5. JS 提取接口（现代 SPA 的核心攻击面）

```bash
# 抓所有 JS
curl -s http://TARGET/ | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//;s/"//'

# 从 bundle 里抽路径与密钥（关键一步，往往比爆破更有效）
for f in $(cat js.txt); do curl -s "http://TARGET$f"; done > all.js
grep -oE '"/[a-zA-Z0-9_\-/{}$.]{3,60}"' all.js | sort -u
grep -oE 'https?://[a-zA-Z0-9.\-]+' all.js | sort -u          # 第三方/内部域名
grep -oiE '(api[_-]?key|secret|token|ak|sk)["'\'']?\s*[:=]\s*["'\''][^"'\'']{8,}' all.js
```
**不要只做正则**：看 sourcemap（`*.js.map`）能直接还原源码与完整路由表。

## 6. 技术栈定向（有指纹之后再决定打哪）

| 指纹 | 后续动作 |
|---|---|
| Spring Boot | `/actuator` 全家（env/heapdump/mappings）、`/v2/api-docs` |
| Swagger/OpenAPI | 直接读 spec → 拿全部接口和参数，喂给后续意图 |
| Jenkins/GitLab/Nexus | 已知 CVE + 匿名访问面 |
| WordPress | `wp-json/wp/v2/users` 枚举、插件版本 → 已知漏洞 |
| Nginx 反代 | 路径规范化绕过（见 modern-web-surface） |
| GraphQL | `/graphql` 内省 |
| 若依/JeecgBoot/Shiro | 已知默认口令与反序列化 |
| 对象存储（OSS/S3） | 桶列表、ACL 写权限、`?list-type=2` |

## 7. 输出规范（必须做）

每一条发现都 `insert_assets`，`type` 用准确值：
```
subdomain / ip / service(带 port+product+version) / endpoint(带 method+path+params) / tech / credential
```
参数与响应特征写在 props 里。**侦察阶段发现的疑似漏洞不要 report_finding**，用 `record_fact` 记 inferred，交给规划者派专门意图验证。

## 8. 效率纪律

- 一个意图内先广后深：先把面铺开（资产登记），再挑 1–2 个最有戏的深入。
- 命中 WAF/403 时换 UA、换路径变体、降速；别在一个路径上死磕 10 次。
- 记录用的命令与关键输出（evidence），后面报告直接能用。
