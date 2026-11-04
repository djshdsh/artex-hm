# nginx 2026-10 批次 —— 参考材料

## 1. 来源

| 来源 | 链接 |
|---|---|
| nginx 安全公告总表 | https://nginx.org/en/security_advisories.html |
| nginx CHANGES（1.31.x） | https://nginx.org/en/CHANGES |
| nginx CHANGES（1.30.x 稳定线） | https://nginx.org/en/CHANGES-1.30 |
| njs 变更日志（1.0.2，2026-10-14） | https://nginx.org/en/docs/njs/changes.html |
| F5 公告（示例） | https://my.f5.com/manage/s/article/K000162416 （15176）等 |
| Traefik 公告 | https://github.com/traefik/traefik/security/advisories/GHSA-qvj7-gq9c-hp7q 、GHSA-rv2h-qh7j-xrjw |
| NVD（当日全量核对） | https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=2026-10-21T00:00:00.000&pubEndDate=2026-10-21T23:59:59.999 |

## 2. 时间线（容易踩坑）

| 日期 | 事件 |
|---|---|
| 2026-10-14 | **1.31.7（mainline）+ 1.30.6（stable）** 发布，修 5 枚 CVE；同日 **njs 1.0.2** 修 2 枚 |
| 2026-10-21 | **1.31.8** 发布 —— **只有 bugfix，无 Security 条目**（working_directory 相对路径、HTTP/3 SIGBUS、kTLS 日志、Solaris 编译） |
| 2026-10-22 | Traefik CVE-2026-114636 / 114638 公开（Ingress NGINX provider，HIGH 8.7） |

> 若有人声称"10-21 nginx 爆高危漏洞"，先按本表对齐：多半是把 10-14 的 1.31.7/1.30.6 公告转报，
> 或把 Traefik 的 Ingress NGINX 当成了 nginx 本体。

## 3. 五枚 CVE 的原文摘要（CHANGES 1.31.7 / 1.30.6）

- **CVE-2026-15176**：使用 `alias` 指令且请求 URI 被 `rewrite` 改写后映射为文件路径时，worker 进程可能发生缓冲区溢出。
- **CVE-2026-93479**：求值含变量的字符串表达式时可能缓冲区溢出，影响 http 与 stream 模块中的 document root 计算与请求日志。（致谢 Matt Suiche, Tolmo Inc）
- **CVE-2026-95101**：HTTP/3 下未知帧的一部分可能被当作请求体，导致绕过 `client_max_body_size` 或向被代理请求注入数据。（致谢 Hansol Lee, GOTROOT）
- **CVE-2026-97629**：TLS session ticket 密钥轮转时其中一把密钥未初始化，可能允许伪造会话。（致谢 PhiNode Labs）
- **CVE-2026-97205**：异步文件 I/O（AIO）下，SSI 页含 `include virtual` 的特定配置可能触发释放后使用。（致谢 cyberlancer）

## 4. 版本边界

| CVE | 受影响 | 修复 |
|---|---|---|
| 15176 | 0.1.29–1.31.6 | 1.31.7+ / 1.30.6+ |
| 93479 | 1.31.2–1.31.6、1.30.0–1.30.5 | 1.31.7+ / 1.30.6+ |
| 95101 | 1.25.0–1.31.6 | 1.31.7+ / 1.30.6+ |
| 97629 | 1.23.2–1.31.6 | 1.31.7+ / 1.30.6+ |
| 97205 | 0.8.11–1.31.6 | 1.31.7+ / 1.30.6+ |
| njs 101025/101019 | 0.7.10 – 1.0.1（引入自 commit 9161a840） | njs 1.0.2 |

## 5. 历史同源问题（写报告时可做对比，说明这是"老毛病复发"）

| CVE | 年份 | 与哪条同源 |
|---|---|---|
| CVE-2024-31079 / 2024-32760 / 2024-34161 / 2024-35200 | 2024 | HTTP/2 与 MP4 模块系列溢出 |
| CVE-2025-23419 | 2025 | TLS 会话恢复相关（与 97629 同域） |
| CVE-2026-42533 / 42530 | 2026 | map+regex 溢出 / HTTP/3 UAF（本批的前一批，1.31.3+ 已修） |

## 6. 配置自查清单

```bash
nginx -T 2>/dev/null | grep -nE '^\s*(alias|rewrite)\b'          # 15176
nginx -T 2>/dev/null | grep -nE '^\s*(root|log_format|access_log|error_log)\b.*\$'  # 93479
nginx -T 2>/dev/null | grep -nE 'listen .*quic|http3'            # 95101
# 97629：先看是否 shared cache + tickets 未关 + 无静态 key 文件
nginx -T 2>/dev/null | grep -nE 'ssl_session_cache|ssl_session_tickets|ssl_session_ticket_key'
#   命中条件 = shared cache 存在 AND 没有 'ssl_session_tickets off' AND 没有 ssl_session_ticket_key
#   另看 ssl_verify_client：有它则影响从"会话伪造"升级为"客户端证书认证绕过"
nginx -T 2>/dev/null | grep -n 'ssl_verify_client'
nginx -T 2>/dev/null | grep -nE '^\s*aio\s+on|^\s*ssi\s+on'     # 97205
```

## 7. 蓝队检测特征

- 短时间大量超长 URI 且命中 rewrite → alias 的路径（15176）；
- UDP/443 上的非标准 QUIC 帧、请求体超 `client_max_body_size` 仍被上游收到（95101）；
- 同一 session ticket 结构出现"密钥指纹异常"的批次（97629）；
- worker 反复 `signal 11`、`worker process exited on signal 11`（15176/93479/97205）。

---

## 8. 公开 PoC / 复现情况（2026-10）

| CVE | 公开 PoC | 现状 |
|---|---|---|
| CVE-2026-15176 | ❌ 无 | 只有 CHANGES + 补丁 diff |
| CVE-2026-93479 | ❌ 无 | 同上 |
| CVE-2026-95101 | ❌ 无 | 同上（需自建 HTTP/3 环境） |
| **CVE-2026-97629** | ✅ **有完整 PoC** | `PhiNode-Labs/nginx-cve-2026-97629`：一键伪造 ticket + 完整读写会话 |
| CVE-2026-97205 | ❌ 无 | 仅有发行版补丁跟踪站（`suominen/CVE-2026-97205`） |
| njs 1.0.2 两枚 | ❌ 无 | 官方 changelog 描述已足够定位 |
| Traefik 两枚 | ❌ 无 | 有 GHSA，无独立 PoC |

### 8.1 CVE-2026-97629 完整拆解（唯一有公开 PoC 的一条）

**根因：一个 `2` 应该是 `3`**

```c
// ngx_ssl_rotate_ticket_keys()
ngx_memcpy(keys->elts, cache->ticket_keys,
-          2 * sizeof(ngx_ssl_ticket_key_t));
+          3 * sizeof(ngx_ssl_ticket_key_t));
```

nginx 每 worker 维护三把 ticket key（current / previous / next）。轮转时只拷了**两个**槽，
第三个槽在启动后再没被写过 → 在默认 Linux 构建上那块内存是**全零**，且**每个 worker 都一样**。

**为什么全零就能被利用**：解密回调会遍历三个槽。攻击者提交一个 key_name 为 **16 字节全零**的伪造
ticket，就能命中那个未初始化的槽，nginx 用**全零的 AES key 和 HMAC key**去解封 —— 这两把钥匙人人都会猜。

**Ticket 布局（RFC 5077 + OpenSSL）**

```
ticket     = key_name(16) || iv(16) || ciphertext || hmac(32)
key_name   = 0x00 * 16                       # 命中 keys->elts[2].name
aes_key    = 0x00 * 32                       # 命中 keys->elts[2].aes_key
hmac_key   = 0x00 * 32                       # 命中 keys->elts[2].hmac_key
ciphertext = AES-256-CBC(aes_key, iv).encrypt(pkcs7_pad(session_blob))
hmac       = HMAC-SHA256(hmac_key, key_name || iv || ciphertext)
```

> **两个坑（公开 PoC 里有明确记录）**：
> 1. **HMAC 覆盖范围**是 `key_name || iv || ciphertext`（整个 ticket 去掉尾部 32 字节），**不是**只有 iv||密文；
> 2. **`session_id_context` 必须回填**。`openssl s_client -sess_out` 导出的 blob 里 cont[4] 是空的，
>    而 nginx 用 `SHA-1("HTTP" || SHA-1(证书) || [CA 名])` 设置了非空 sid_ctx，OpenSSL 在 resume 时会校验，
>    不回填就退回完整握手（看起来"打不中"，其实是这个原因）。

**利用步骤（4 步）**

1. 用 `openssl s_client` 抓一份合法 session + 服务器公开证书；
2. 由证书算出 nginx 的 20 字节 `session_id_context`，回填进 session DER；
3. 用全零 key_name / AES key / HMAC key 加密该 session，组成 ticket，塞进 TLS 1.2 ClientHello 的
   session_ticket 扩展（ext `0x0023`）；
4. 读响应判定：**ServerHello 带非空 session_id 且没有 Certificate 消息** → ticket 被接受、会话恢复成功。
   进阶版还能派生密钥，直接在伪造会话上收发 HTTP。

**暴露条件（四条全中才算中）**

- 版本在 1.23.2 – 1.31.6（NGINX Plus ≤ 37.0.5）；
- 配了 `ssl_session_cache shared:...`；
- `ssl_session_tickets on`（默认）**且没有**显式 `ssl_session_ticket_key`；
- 有"证书决定访问权"的场景（mTLS / client cert）。

**影响**：F5 给 CVSS 3.1 **6.5** / 4.0 **8.3**；**mTLS 部署下按满分 10.0 读**——因为直接绕过客户端证书认证。
命中面：开放银行（PSD2/FAPI）、医疗数据交换、5G 核心网、K8s ingress、零信任。

**缓解**：升级到 1.31.7 / 1.30.6（Plus 37.0.5.1 / 37.1.0.1）；不能升级就 `ssl_session_tickets off;`，
或显式配置 `ssl_session_ticket_key` 文件并自行轮转（**有 key 文件反而不受影响**）。

**PoC 文件（PhiNode Labs）**：`poc/make_forged_session.py`（算 sid_ctx 并回填）、
`poc/forge_ticket.py`（伪造并判定 TICKET ACCEPTED）、`poc/forge_ticket_full.py`（完整读写）、
`patch/0001-sync-third-ticket-key-slot.patch`、`evidence/`（抓包输出）。

**时间线**：2026-06 发现 → 08 报 F5 SIRT → 09 定级 → **10-12 分配 CVE** → **10-14 公告 + 修复**。

### 8.2 其余四枚为什么没有公开 PoC

- **15176 / 93479**：溢出发生在 worker 内部堆上，需要精确的 URI 长度与堆布局，且要配合特定
  `alias`/`rewrite` 或日志表达式配置；公开研究普遍停在"能打出 `signal 11`"。
- **95101**：要做 HTTP/3 未知帧，得自己实现 QUIC 栈或在 `ngtcp2` 上打补丁，门槛高。
- **97205**：`aio on` + SSI `include virtual` 的组合在生产里少见，复现环境搭建成本高。

→ **写报告时**：这四枚只能写"版本 + 配置命中，存在理论风险"，**不能**写"已利用"。
反过来，97629 有完整公开 PoC，报告里可以写"公开可复现"来提升可信度。

### 8.3 交叉引用

Calif 的 PHP2Shell 专题里有一段《Exploiting Nginx with PHP-FPM》——那是把 **nginx 当作 PHP-FPM 的
攻击载体**（反代如何影响 multipart 转发、header 上限、body 缓冲），不是 nginx 自身的漏洞。
做 PHP2Shell 评估时看 `php2shell-rce` 这个 skill，别和本 skill 的 5 枚 CVE 混为一谈。
