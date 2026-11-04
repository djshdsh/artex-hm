# PHP2Shell 参考材料

## 1. 来源（均为一手）

| 来源 | 链接 |
|---|---|
| PHP 官方公告（2026-10-21） | https://www.php.net/archive/2026.php#2026-10-21-5 |
| GHSA — CVE-2026-109618 | https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w |
| GHSA — CVE-2026-109619 | https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp |
| Wiz 研究博客 | https://www.wiz.io/blog/php2shell-php-rce |
| Calif 专题（含 "Exploiting Nginx with PHP-FPM" 演示） | https://calif.io/php2shell/ |
| 专题站 | https://www.php2shell.com/ |
| oss-security 同日帖 | http://www.openwall.com/lists/oss-security/2026/10/21/6 、/16 、/17 、/23 |
| PHP Foundation | https://thephp.foundation/blog/2026/10/21/todays-php-security-release-and-how-were-strengthening-php-security/ |
| 厂商缓解 | Cloudflare / Fastly / Vercel / AWS / Imperva 同日公告 |

## 2. 版本矩阵

| 分支 | 受影响 | 修复 |
|---|---|---|
| 8.5 | < 8.5.12 | 8.5.12 |
| 8.4 | < 8.4.27 | 8.4.27 |
| 8.3 | < 8.3.36 | 8.3.36 |
| 8.2 | < 8.2.35 | 8.2.35 |
| 8.1 / 7.x / 5.x | 受影响（至少其一） | 无上游修复 |

## 3. OOM 构造细节（GHSA 原文要点）

1. **无可用 Content-Length 的 multipart**：可通过初始 `post_max_size` 检查，并继续提供解码后的 body 数据。
2. **单个 part 无限多 header**：PHP 内部表示这些 header 的内存开销远大于线格式，可在 `post_max_size` 之内耗尽 `memory_limit`。
3. **空 file 控件**：不计入 `max_file_uploads`，但仍创建常规文件元数据数组；嵌套字段名会把生成的数组工作成倍放大。
4. 应用层也可通过"攻击者可控输入触发足够大的分配/重复内存使用"达到 OOM。

> 组合建议：先用 (2) 稳定顶内存，再用 (1) 绕过体积限制喂数据；(3) 用来在受限上传点放大。

## 4. SAPI 差异（GHSA 原文结论）

- **Apache mod_php**：无条件执行 request shutdown（即使 startup 失败）。startup 阶段自动 body 解析就可能 OOM 并早退，此时状态临时非法，shutdown 继续处理 → **应用代码执行前就触发**。这是目前已演示的、应用无关的路径。
- **php-fpm**：startup 失败时**退出子进程**，脏状态随之消失，子进程被池移除。正常 startup 之后的 OOM 仍可能处于"未记账早退"的上下文，shutdown 会处理非法状态 → 源码层面 susceptible，**但无完整 FPM 利用被演示**。
- **FrankenPHP**：类似 mod_php（无条件 shutdown）→ 很可能可做应用无关攻击。
- **LSAPI**（LiteSpeed）：建模同 FPM，偏应用特定。

## 5. 缓解措施（GHSA 原文）

### CVE-2026-109618
- 补丁：去掉 OOM 路径的 `longjmp()`；改为下一个 VM safe point 的"软 OOM"，超过第二道更高阈值则 `_exit()`。正常内存限制能力保留。
- 无法升级：`memory_limit=-1` 并从外部强制限额（cgroup / 容器 / FPM 池限制）。**不是完整缓解**：mmap 等底层分配失败时仍可能走 longjmp。

### CVE-2026-109619
- "升级到包含完整状态复位补丁的版本是唯一可靠缓解。**不存在通用的配置级缓解**"——因为任意应用、扩展或服务器路径都可能发布或消费陈旧状态，且没有可预测的日志特征。
- PHP 8.5 无法升级时：`fatal_error_backtraces=0` + **重启所有 worker**（只覆盖已确认那条 producer）。
- session 生命周期那条：`session.upload_progress.enabled=0` + 重启所有 worker（即使打了补丁，不用该特性也建议关）。

## 6. 报告中可引用的影响描述

> 未授权攻击者可在应用代码执行前取得 webserver 用户权限的代码执行；由于洞在引擎层，应用自身安全编码无法规避。此外，短暂存活的请求内存（含其他用户的凭据、会话、密钥）可能被同 worker 的后续请求读取，等同于 Heartbleed 式跨租户泄露。

## 7. 排查清单（防守方）

```bash
# 1) 版本
php -v | head -1
# 包管理器视角（示例）
dpkg -l | grep -E '^ii\s+php' ; rpm -qa | grep -E '^php'
# 容器镜像
docker images | grep -i php

# 2) SAPI
apache2ctl -M 2>/dev/null | grep -i php        # 有 php_module 即 mod_php
php-fpm -v 2>/dev/null

# 3) 相关配置
php -i | grep -E 'memory_limit|post_max_size|max_file_uploads|fatal_error_backtraces|session.upload_progress'
```

## 8. 探测时的流量特征（蓝队可用于检测）

- 单个 multipart part 携带异常多的 header（几十~数百）；
- multipart 请求缺失/伪造 Content-Length，或使用 chunked 传输超大解码体；
- 大量空 file 控件 + 深层嵌套字段名；
- 紧接着的后续请求触发 500/内存相关错误，或 worker 突然消失（FPM `child exited on signal`）。

---

## 9. 公开 PoC 实现细节（2026-10 全网复现情况）

### 9.1 时间线

| 日期 | 事件 |
|---|---|
| 2026-10-20 | 漏洞细节/利用材料提前外泄 |
| 2026-10-21 14:00 UTC | PHP 官方发布 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 |
| 2026-10-21 起 | GitHub 大量 PoC 与扫描器上线（数小时内破千星） |

### 9.2 核心原语：`session.upload_progress` 的 UAF 写

公开实现里最主流的一条（对应 109619 的 session 生命周期路径）。四步：

| 步 | 动作 | 代码位置（`ext/session/session.c`） |
|---|---|---|
| 1 埋指针 | rfc1867 进度回调把两个裸 `zval*`（`post_bytes_processed` / `current_file_bytes_processed`）缓存进 session HashTable 的 `arData` | ~L3292 / L3318 |
| 2 释放 | 上传停滞超过 `session.upload_progress.min_freq`（默认 1s），再次 `FILE_DATA` → `php_session_rfc1867_update()` → `php_session_initialize()` → `php_session_track_init()` → `zend_array_destroy()` 释放 `arData` | ~L236–252 |
| 3 写穿 | 后续进度更新执行 `ZVAL_LONG(post_bytes_processed, new_bytes)`，往**已释放 bucket** 写入 | ~L3331–3332 |
| 4 接管 | 用同尺寸堆块占坑，把悬垂指针变成伪造 `zval` → 指向伪造的 `zend_fcall_info` / `zend_internal_function` → `zend_call_function()` → `system()` | — |

**堆喷要点**：bucket 按尺寸分档，必须精确命中被释放的那一档；`session.upload_progress.min_freq` 决定"卡多久"才能触发第二次 update。

### 9.3 远程绕过 ASLR（9bie 方案，实测 5/5）

只用 HTTP、目标是 `<?php echo "OK\n"; ?>`、不改 `memory_limit`、`display_errors=Off`：

```
A1  END-cleanup send_cookie OOM      → 把 worker 推到可控的干净状态
B1  stale-id OOB read                → 读泄漏：libphp 基址 + 主 chunk 分布
A2  主分配                           → 占住目标尺寸
B2  触发                             → zif_system 地址写入 → 命令执行
```

- 单次约 2 秒，worker 不需重启，目标 ini 不动；
- 偏移靠 `zval_ptr_dtor` 与 `zend_call_function` 的距离（`--syms` 标定），按发行版/构建适配（Debian Bookworm、Ubuntu Noble/Jammy）；
- 跨构建直接抄偏移必挂，必须本地同构建标定。

### 9.4 五条公开攻击链

| 链 | 手法 | 前置条件 | SAPI |
|---|---|---|---|
| **A** | 上传文件名注入 session 文件 + 应用 LFI 包含 | 应用有 LFI 落点 | 全 SAPI |
| **B** | `var_destroy` UAF → 覆盖 `var_dump` handler（经 `/proc/self/mem`） | 应用调用 `unserialize()` | 全 SAPI |
| **C** | 污染 FPM worker `PS(serializer)` → 文件名注入序列化对象 → `__destruct` | 有端点 `ini_set('session.serialize_handler','php_serialize')` | FPM |
| **D** | OOM 破坏 → 陈旧 `EG()` | **无**（任意 mod_php 站点） | mod_php |
| **E** | FPM session OOM → 陈旧 `BG()` | producer：任意 `session_start()` 端点；consumer：**任意端点** | FPM |

> A/C 严格说不是纯内存破坏（A=session 文件投毒，C=序列化器错配），但都能不加认证打通。
> **consumer 可以在应用代码之前跑**（rfc1867 在 SAPI startup 阶段执行），所以"页面里没有 session_start()"不等于安全 —— 已有实测：`nosession.php` 作为 consumer 触发 502。

### 9.5 公开仓库索引与局限

| 仓库 | 能力 | 局限 |
|---|---|---|
| `ikow/php2shell-poc` | 5 条链 + 13 条 Suricata / 5 条 Sigma / 7 条 ModSecurity 规则 | D/E 两条核心链的 exp 收费 |
| `9bie/php2shell-bypass-aslr-exp` | 官方环境一条命令 RCE，单 worker | 单 worker 才稳；多 worker 靠重试 |
| `eness/php2shell-...-PoC` | 单文件 `poc_109618.py` + 完整缓解章节 | 需按目标构建标定 `--syms` |
| `openai/php2shell-checker` | **仅版本检测**（`X-Powered-By`/`Server`/`php -v`） | 头被隐藏即 UNKNOWN |
| `syrex1013/php2shell` | PoC + Docker UAF 复现环境 | 实验室导向 |

### 9.6 归因陷阱（写报告时务必注意）

- 多数公开 PoC 实际打的是 **CVE-2026-109619**（跨请求陈旧全局态 / session 生命周期），却在标题里写 109618；
- 官方分界：**109618 = OOM + `longjmp` 路径**，**109619 = 跨请求悬垂全局态**；
- 报告里要么分别归因，要么写"同时满足两条的触发条件"，别混写。

### 9.7 最有效的一行防御

**在 multipart POST body 中拦截 `PHP_SESSION_UPLOAD_PROGRESS`**（WAF/反代均可）。正常业务几乎不使用，正好覆盖两条 CVE 的主打路径。
其次：`session.upload_progress.enabled=0` + **重启所有 worker**（改 ini 不重启 worker 无效）。
