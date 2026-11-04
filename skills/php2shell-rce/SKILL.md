---
name: php2shell-rce
description: 判定与评估 PHP 核心 CVE-2026-109618 / CVE-2026-109619（PHP2Shell，2026-10-21 披露，CVSS 9.8）：OOM 错误处理与陈旧全局态导致的未授权 RCE 及跨请求内存泄露。目标为 PHP 8.2–8.5（mod_php / php-fpm / php-cgi / FrankenPHP / LiteSpeed）且需要做版本核对、SAPI 可达性判断、OOM 可触发性探测或编写影响面报告时使用。
---
# PHP2Shell：PHP 核心双 RCE（CVE-2026-109618 / CVE-2026-109619）

2026-10-21 协调披露。Calif + OpenAI（Patch the Planet）+ Wiz 发现，PHP 官方同日发布修复。
**与目标应用代码无关**：洞在 PHP 引擎自身，WordPress / Laravel / 自研代码一样中招。

---

## 0. 授权边界（Agent 必读）

| 允许 | 禁止 |
|---|---|
| 版本核对、SAPI 指纹、单次低强度 OOM 可触发性探测 | 批量打点、批量扫描同网段 |
| 证明内存泄露存在（拿 1 组样本即停） | 下载/留存目标业务数据、导出数据库 |
| 授权范围内的 RCE 证明（单条无害命令回显，如 `id`） | 写 webshell、留后门、持久化、横向移动 |
| 记录完整请求/响应作为证据 | 业务高峰期做 OOM 测试（会打挂 worker、造成 502） |

OOM 类测试天然带 DoS 属性：**每个目标只做一次**，先说清楚，最好在业务低峰。

---

## 1. 30 秒速查

| 项 | 内容 |
|---|---|
| CVE-2026-109618 | RCE via OOM corruption（GHSA-w8hw-w9fx-j79w） |
| CVE-2026-109619 | RCE via stale global state（GHSA-6wmf-4rv5-p3rp） |
| 评分 | CVSS 3.1 **9.8** / CVSS 4.0 **9.2**，Critical |
| 受影响 | `< 8.2.35`、`< 8.3.36`、`< 8.4.27`、`< 8.5.12`（即 8.2–8.5 全分支旧版）；Wiz 称可追到 5.4 |
| 修复 | **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** |
| 8.1 及更早 | 上游不再维护，无官方补丁（只能靠发行版 backport 或升级） |
| 前置条件 | 无需认证；无需应用存在漏洞；需能发起 HTTP 请求 |

---

## 2. 根因（怎么实现的）

### 2.1 CVE-2026-109618 —— OOM 打断初始化，shutdown 消费无效内存

PHP 用 `longjmp()` 处理 OOM 来退出当前上下文、中止请求处理。某些上下文中，**请求内存处于"已可达但尚未初始化完"的中间态**；此刻任意一次分配失败都会提前跳栈，PHP 没有为这种早退记账，request memory 留在非法状态。

关键点：
- **失败的那次分配跟这块非法内存可以毫无关系**——只要在窗口内 OOM 就行；
- 随后 request shutdown 会读它、或按它的值分支 → 内存破坏 → RCE；
- 多种 OOM 策略可稳定复现。

### 2.2 CVE-2026-109619 —— worker 全局态悬垂指针（producer / consumer）

PHP 有大量全局态（error / session / object / extension）暂时指向"某个请求拥有的内存"，正常流程在释放请求堆前会复位。两种方式让它漏掉：

- **producer**：fatal error（含 OOM）让操作提前中止，跳过了配套的 reset；
- **producer（另一种）**：warning 等非致命诊断在 shutdown 期间已经清空后又把它填了回去。

结果：请求堆已 free，worker 的全局字段还指着它。**同一 worker 处理的下一个请求**，在正常初始化把它覆盖掉之前，某个操作读取/释放/按它分支 → UAF → 可构造 RCE。

要成功需要 producer + consumer 成对出现，且落在同一个 worker 上（跨请求）。

---

## 3. 决定性因素：SAPI（决定你有没有戏）

| SAPI | 可利用性 | 原因 |
|---|---|---|
| **Apache mod_php** | **最高，已实证** | 无论 request startup 成功与否都无条件执行 shutdown；自动 body 解析即可在应用代码执行前 OOM，**应用无关** |
| **FrankenPHP** | 高（源码层面类似 mod_php） | 同样无条件调用 shutdown，推测可做应用无关攻击 |
| **php-fpm** | 中（受限） | startup 失败会**杀掉子进程**（把脏状态带走）；正常 startup 后 OOM 仍可能在 shutdown 处理非法状态。官方结论：源码上 susceptible，但没有完整公开利用 |
| **LSAPI** | 中 | 建模同 FPM，偏应用特定 |
| **php-cgi** | 需按部署判断 | 取决于每次请求是否新进程（新进程 = 脏状态不残留） |

> 结论：**先判 SAPI 再谈 PoC**。在 FPM 上把 mod_php 的利用链照抄，基本是白打。

---

## 4. 可达性判定（不触发也能判掉一半）

1. **版本**：`X-Powered-By: PHP/x.y.z`、`Server:`、报错页脚、默认 404、`composer.lock`/`/phpinfo.php` 若意外暴露。
2. **SAPI 推断**：
   - `Server: Apache/2.4.x` + `X-Powered-By: PHP/*` → mod_php 概率高；
   - `Server: nginx/*` + `X-Powered-By: PHP/*` → FastCGI/FPM；
   - `Server: FrankenPHP`、`Server: LiteSpeed` 直接点名。
   - 补充：`.php` 请求 500 时看响应体是否有 FPM 特征；`/status`、`/ping` 若开放可读 FPM 池信息。
3. **前置配置**：
   - 是否允许大 multipart（上传点、`post_max_size`）；
   - 反代 header 上限（nginx `large_client_header_buffers`、`proxy_buffer_size`）——**header 膨胀这条路要先过反代**；
   - `memory_limit` 越小越容易 OOM；`pm.max_children` 越大，跨请求命中同一 worker 的概率越高（也更伤业务）。
4. **快速否证**：已是修复版本 → 直接结束，不再往下走。

---

## 5. 利用链（怎么做，以"构造要点 + 观测点"表述）

**Step 0 · 定位 SAPI**：见第 4 节。mod_php 才有"应用无关"打法。

**Step 1 · 造 OOM**（官方列出的三条"合法"路线，均在 `post_max_size` 表面限制内）：
- (a) multipart **没有可用 Content-Length**（如 chunked）→ 绕过初始 `post_max_size` 检查，还能继续喂解码后的 body；
- (b) 单个 part 塞**不限量的 header**——线格式很小，进 PHP 内存后放大数倍，足以顶爆 `memory_limit`；
- (c) **空 file 控件不计入 `max_file_uploads`** 但仍生成文件元数据数组；再加上嵌套字段名，数组工作量成倍放大。

**Step 2 · 确认 worker 复用**：keep-alive 长连接、或同一出口 IP 连续请求；FPM 看 `pm` 策略（static/ondemand 影响命中率）。

**Step 3 · 触发 consumer**：让下一个请求走到会读陈旧全局态的操作（具体 consumer 随内部状态类型不同而不同，官方未公开完整链）。

**Step 4 · 建立原语**：优先做**跨请求内存泄露**（证明力强、破坏性小），再谈稳定 RCE。

> 实战提醒：公开材料只到"原理 + 部分构造"，没有成品武器化 PoC。别信网上"一键 exp"。

---

## 6. 能得到什么

- **未授权 RCE**，身份是 webserver 用户（`www-data` / `apache` / `nginx`）；
- mod_php 场景下发生在**任何应用代码执行之前**——应用有没有洞都无所谓；
- **Heartbleed 式跨请求内存泄露**：同一 worker 处理过的别人的密码、session、token、API key、证书；
- 影响面：所有未升级的 PHP 8.2–8.5 站点（含 WordPress/Drupal/MediaWiki 生态）。

---

## 7. 失败模式 / 常见误判

| 现象 | 真实原因 |
|---|---|
| 打不出 OOM | 反代先拦了超长 header；`memory_limit=-1` 或很大 |
| OOM 了但没后续 | FPM 杀掉子进程，脏状态没留下 |
| 偶发成功、不可复现 | worker 池大 + 负载均衡，producer/consumer 落到不同 worker |
| 网站 502 一片 | 你把 worker 打死了 —— 立刻停手并记录 |
| 用 8.1 以下的版本判定"不受影响" | 错。旧版同样受影响，只是官方不修 |

---

## 8. 检测与修复

**版本核对**
```bash
php -v
curl -sI https://target/ | grep -iE 'x-powered-by|server'
```

**修复（唯一完整手段）**：升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35。

**无法升级时的官方缓解（都是部分缓解，原话是 "only complete mitigation is updating"）**
- CVE-2026-109618：`memory_limit=-1` 并在**外部**（cgroup / FPM `pm.*` / 容器 limit）强制限额 —— 去掉可预测的 per-request 上限，但底层 mmap 失败时仍可能走 longjmp；
- CVE-2026-109619：8.5 可设 `fatal_error_backtraces=0`，并**重启所有 worker**（只覆盖已确认的那条 producer）；`session.upload_progress.enabled=0` + 重启 worker（只覆盖 session 生命周期那条）；
- 架构层：**弃用 mod_php**，改 FPM（这是把"应用无关"降成"应用相关"的最有效手段）；
- WAF：Cloudflare / Fastly / AWS / Imperva / Akamai 均已发布规则（拦 multipart 异常与 header 膨胀）。

**补丁原理（写报告时可用）**：去掉 OOM 路径上的 `longjmp()`，改为在下一个 VM safe point 触发"软 OOM"，超第二道硬阈值则 `_exit()` 立即退出 —— shutdown 不再看到非法状态。

---

## 9. ARTEX 证据标准

| 结论 | 证据要求 | report_finding |
|---|---|---|
| **confirmed RCE** | 版本回显 + 完整请求/响应报文 + 单条命令回显（如 `id`） | severity=**critical**，vulnclass=`rce` |
| **confirmed 内存泄露** | 版本回显 + 两个请求的报文 + 泄露样本（凭据脱敏） | severity=**critical**，vulnclass=`memory-disclosure` |
| **OOM 可触发性成立** | 探测报文 + 状态码/耗时/连接重置对比 | severity=**medium**，注明"未取得 RCE，仅证明不稳定状态可达" |
| **仅版本命中** | 版本回显 | 记"潜在风险"，severity≤**medium**，明确写"未验证" |

禁止：把 "版本低" 直接写成 "存在 RCE"。

---

## 10. 脚本

- `scripts/php2shell_check.py` —— 无害指纹/版本判定：`--url` 或 `--version`，输出受影响/已修复 + SAPI 推断。
- `scripts/php2shell_probe.py` —— **需 `--authorized`** 的可达性探针，两种模式：
  - `--mode session`（默认，**无害**）：对照两个 multipart，看带 `PHP_SESSION_UPLOAD_PROGRESS` 的
    请求是否让本来不开 session 的端点返回 `Set-Cookie: PHPSESSID` → 判定公开 PoC 主路径
    （rfc1867 进度回调在 SAPI 启动阶段执行）是否可达；
  - `--mode oom`（**带 DoS 性质**）：chunked multipart + header 膨胀，判 OOM 可触发性；
  - `--mode auto --deep`：先 session 后 oom；`--drip 1.5` 可放慢上传跨过 `min_freq`。

详见 `reference.md`：第 1-8 节是官方公告口径；**第 9 节是公开 PoC 的实现细节**（UAF 写四步、
ASLR 远程绕过、五条攻击链 A–E 对照、公开仓库索引、CVE 归因陷阱、一行防御）。