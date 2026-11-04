---
name: nginx-2026-10-advisories
description: nginx 2026-10 安全公告批次：1.31.7 / 1.30.6 修复的五枚 CVE（alias+rewrite 缓冲区溢出、表达式求值溢出、HTTP/3 请求体注入、TLS session ticket 密钥未初始化导致会话伪造、AIO 释放后使用），以及同期 njs 1.0.2 的两枚 CVE 和 Traefik Ingress NGINX 的两个 HIGH。用于版本核对、配置可达性判定（alias/rewrite、http3、session ticket、aio+ssi）、影响评估与报告编写。
---
# nginx 2026-10 安全批次

**先厘清一个事实，避免后续 agent 编造**：2026-10-21 当天 nginx 本体**没有**发新 CVE
（当天发的是 1.31.8，只有 bugfix：working_directory、HTTP/3 SIGBUS、kTLS 日志等）。
按 NVD 当日 544 条全量、nginx.org 安全页、nginx-announce、oss-security 核对，均无 nginx 本体条目。
本批次实际是 **2026-10-14 的 1.31.7（mainline）/ 1.30.6（stable）安全版**。

---

## 0. 授权边界

改造配置、开启 debug 日志、触发崩溃均需授权；溢出类 PoC 只在授权目标上做单次验证，
不做批量扫描；`--with-debug` 仅在测试环境启用。

---

## 1. 速查（nginx 本体，1.31.7+ / 1.30.6+ 修复）

| CVE | 官方级别 | 问题 | 受影响版本 | 触发前提 |
|---|---|---|---|---|
| CVE-2026-15176 | medium | `alias` + `rewrite` 改写 URI 后映射文件路径时 worker 缓冲区溢出 | 0.1.29–1.31.6 | 同时用 `alias` 和 `rewrite`，且 URI 被改写后落到 alias 路径 |
| CVE-2026-93479 | medium | 求值含变量的字符串表达式时缓冲区溢出（影响 document root 计算与请求日志） | 1.31.2–1.31.6、1.30.0–1.30.5 | `root`/`error_log`/`access_log` 等位置使用含变量的复杂表达式 |
| CVE-2026-95101 | medium | HTTP/3 下未知帧的一部分被当作请求体 → 绕过 `client_max_body_size` 或向前端请求注入数据 | 1.25.0–1.31.6 | 启用 HTTP/3 |
| CVE-2026-97629 | medium（mTLS 场景按满分读） | TLS session ticket 轮转时第三个密钥槽未初始化（全零）→ **可伪造会话、绕过客户端证书认证** | 1.23.2–1.31.6 | `ssl_session_cache shared` + tickets 开启 + **没有** `ssl_session_ticket_key` |
| CVE-2026-97205 | medium | 异步文件 I/O（AIO）下特定配置触发释放后使用（SSI 的 `include virtual`） | 0.8.11–1.31.6 | `aio on` + SSI `include virtual` |

> 官方级别都写 medium，但 95101（绕过体积限制/请求注入）与 97629（**会话伪造**）实际危害够高危，
> 报告里按实际影响定级，并在正文注明"nginx 官方标高为 medium"。

## 2. 同期相关面

| 组件 | CVE | 级别 | 问题 |
|---|---|---|---|
| njs 1.0.2（2026-10-14） | CVE-2026-101025 | — | 解析畸形 XML 时内存泄漏，重复输入可耗尽 worker 内存（DoS），0.7.10 引入 |
| njs 1.0.2 | CVE-2026-101019 | — | XML 属性值中实体引用处理不完整 → JS 访问器取到的值与规范化结果不一致，影响签名 XML 校验 |
| Traefik（Ingress NGINX provider，2026-10-22） | CVE-2026-114636 | HIGH 8.7 | ssl-passthrough Ingress 在非 TLS 入口生成的 HTTP 路由不套用 access-control 注解 → 鉴权绕过 |
| 同上 | CVE-2026-114638 | HIGH 8.7 | `auth-tls-secret` 名字点转横线归一化后碰撞，合并客户端 CA → 持他站 CA 证书者可访问 |

## 3. 逐条：怎么实现的 / 怎么做 / 能得到什么

### 3.1 CVE-2026-15176（alias + rewrite 溢出）
- **本质**：请求 URI 被 `rewrite` 改写后再由 `alias` 映射为文件路径，长度记账错误 → worker 堆溢出。
- **判可达**：`nginx -T | grep -nE 'alias|rewrite'`，看是否同一 `location` 内共存。
- **怎么做**：构造长 URI，先命中 `rewrite` 规则，再落进 `alias` 目录映射；逐步加长，观察 worker 是否异常退出（`signal 11`）。
- **能得到什么**：worker 崩溃（DoS）；精心构造可内存破坏 → 理论上 RCE（官方未演示）。

### 3.2 CVE-2026-93479（表达式求值溢出）
- **本质**：含变量的字符串表达式求值时缓冲区溢出，影响 document root 计算与请求日志写入。
- **判可达**：`nginx -T | grep -nE 'root .*\$|log_format .*\$|access_log .*\$'`。
- **怎么做**：控制参与变量的部分（Host、URI、header），让表达式结果超长。
- **能得到什么**：worker 崩溃 / 日志上下文内存破坏。

### 3.3 CVE-2026-95101（HTTP/3 请求体注入）
- **本质**：HTTP/3 下未知帧的一部分被当成请求体 → 体积限制被绕过，或把数据注进上游请求。
- **判可达**：`nginx -T | grep -n 'http3'`，且实际支持 QUIC（UDP 443）。
- **怎么做**：走 HTTP/3（`curl --http3-only`）发未知帧，观察上游是否收到多余数据 / `client_max_body_size` 是否失效。
- **能得到什么**：**请求走私**（绕过体积限制、向后端注入），可组合出权限绕过或缓存投毒；单靠它不直接 RCE。

### 3.4 CVE-2026-97629（会话伪造）★ 危害最高
- **本质**：session ticket 密钥轮转时有一把密钥未初始化 → 攻击者可用可预测/可控密钥加密出**被服务端接受**的 ticket。
- **判可达**（注意方向，别搞反）：命中条件是 **`ssl_session_cache shared:` 存在 + `ssl_session_tickets` 未关闭 + 没有显式 `ssl_session_ticket_key`**。
  配了静态 key 文件反而是**缓解**（不走轮转缓存）。有 `ssl_verify_client on/optional` 时影响升级为认证绕过。
  根因是 `ngx_ssl_rotate_ticket_keys()` 只 memcpy 了 2 个槽（应为 3），第三槽全零。
- **怎么做**：抓一份合法 session + 服务器公开证书 → 算出 nginx 的 20 字节 `session_id_context` 回填 →
  用**全零 key_name / AES key / HMAC key** 封装 ticket（`HMAC 覆盖 key_name||iv||ciphertext`）→
  塞进 TLS 1.2 ClientHello 的 session_ticket 扩展；**ServerHello 带非空 session_id 且无 Certificate** 即接受。
- **能得到什么**：**不完成真实握手就恢复会话**；在"证书决定访问权"的场景（mTLS/开放银行/零信任/K8s ingress）
  直接**绕过客户端证书认证**，F5 给 6.5/8.3，mTLS 部署按满分 10.0 读。
- **报告角度**：这是本批里最该按高危写的。

### 3.5 CVE-2026-97205（AIO UAF）
- **本质**：`aio on` 且 SSI 页含 `include virtual` 时，异步 I/O 与请求生命周期错配 → 释放后使用。
- **判可达**：`nginx -T | grep -nE 'aio +on|ssi +on'`，再看 `.shtml` 里有没有 `include virtual`。
- **能得到什么**：worker 崩溃；UAF 在特定堆布局下可代码执行。

## 4. 检测与核对

```bash
nginx -v                      # 版本
nginx -V 2>&1 | tr ' ' '\n'   # 编译参数：--with-http_v3_module / --with-debug / --with-threads
nginx -T                      # 生效配置
# 关键 directive 自查
nginx -T 2>/dev/null | grep -nE 'alias|rewrite|http3|ssl_session_(cache|tickets|ticket_key)|ssl_verify_client|aio +on|ssi +on'
# 容器镜像
docker images | grep -i nginx
```

在线判定（仅版本，不可靠但可筛）：
```bash
curl -sI https://target/ | grep -i '^server:'
```
> `Server` 头常被 `server_tokens off` 抹掉版本，**不要只靠响应头定版本**。

## 5. 修复与缓解

| 问题 | 修复 | 临时缓解 |
|---|---|---|
| 全部 5 条 | 升到 **1.31.7+ / 1.30.6+**（注意 1.31.8 只是 bugfix，别误以为它才修洞） | — |
| 15176 | 同上 | 避免 `alias` 与 `rewrite` 同 location；改用 `root` + `try_files` |
| 93479 | 同上 | 日志/dir root 里别用复杂变量表达式 |
| 95101 | 同上 | 关闭 HTTP/3；上游加体积限制（`client_max_body_size` 之外再限） |
| 97629 | 同上 | `ssl_session_tickets off;` 或配显式 `ssl_session_ticket_key` 文件（有 key 文件即不命中） |
| 97205 | 同上 | 关闭 `aio`，或去掉 SSI `include virtual` |
| njs CVE | njs **1.0.2** | 不用 XML 签名校验路径；限制 worker 内存 |
| Traefik Ingress NGINX | Traefik **v3.7.14** | 关闭 ssl-passthrough 路由的 HTTP 入口；避免 auth-tls-secret 名字归一化后碰撞 |

## 6. 报告要点（ARTEX 证据标准）

| 结论 | 证据 | severity |
|---|---|---|
| 会话伪造成功（97629） | 伪造前后的 ticket + 后台访问回显 | **high/critical** |
| HTTP/3 走私（95101） | 两组请求对比：超限 body 被上游接收 | **high** |
| worker 崩溃（15176/93479/97205） | 崩溃前后 `nginx -V` + error.log 中的 `signal 11` | **medium** |
| 仅版本落后 | `nginx -v` 输出 | **medium**，注明"未验证配置可达性" |

**关键区分**：这五条全部**依赖配置**。仅版本落后不等于可利用——必须在报告里写明命中了哪条 directive。

详见 `reference.md`：
- 第 1–7 节是官方公告口径与配置自查；
- **第 8 节是公开 PoC 情况**——这批里只有 **CVE-2026-97629 有完整公开 PoC**（PhiNode Labs，一键伪造 ticket + 完整读写），
  其余四枚无公开利用代码；8.1 含一行补丁、ticket 布局、sid_ctx 坑、暴露四连条件与 CVSS 口径。

脚本 `scripts/nginx_check.py`（v2）按**配置组合**判定，不再单条 grep 就算命中：
- 15176 = `alias` + `rewrite` 同时存在；97205 = `aio on` + `ssi on`；
- 97629 = `ssl_session_cache shared` + tickets 未关 + **无** `ssl_session_ticket_key`（有 key 文件是缓解），
  若另有 `ssl_verify_client` 则影响升级为**客户端证书认证绕过**。
