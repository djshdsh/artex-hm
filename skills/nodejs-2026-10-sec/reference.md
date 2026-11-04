# Node.js 2026-10-21 安全版本 —— 参考材料

## 1. 来源

| 来源 | 链接 |
|---|---|
| 官方公告（2026-10-21） | https://nodejs.org/en/blog/vulnerability/october-2026-security-releases |
| 安全策略 / 提交 | https://nodejs.org/en/security/ 、https://github.com/nodejs/node/blob/main/SECURITY.md |
| 订阅 | https://groups.google.com/forum/#!forum/nodejs-sec |

## 2. 发布物

| 线 | 版本 |
|---|---|
| 22.x | v22.23.4 |
| 24.x | v24.22.1 |
| 26.x | v26.12.1 |

三条线最高级别均为 **HIGH**。EOL 版本同样受影响但不再发版。

## 3. CVE 明细

### 3.1 CVE-2026-111497 — Brotli 解码器越界写 → RCE（HIGH，26/24/22）

- 类别：CWE-787 越界写 / 内存破坏。
- 触发面：任何把**攻击者可控数据**交给 Brotli 解压的代码。
- 审代码时的搜索关键词：
  ```bash
  grep -rn "brotliDecompress\|createBrotliDecompress\|Content-Encoding" --include=*.js --include=*.mjs --include=*.ts .
  ```
- 典型危险模式：
  - `if (req.headers['content-encoding'] === 'br') body = brotliDecompressSync(buf)`
  - 上传文件预览/解压、消息队列消费、缓存反序列化前的解压。
- 影响：进程级代码执行；即使利用不成功也常伴随崩溃（DoS）。

### 3.2 CVE-2026-105482 — dns.resolve NUL 截断（HIGH）

- 现象：传入含 `\x00` 的名字，校验函数看到全串，`dns.resolve` 在 NUL 处截断。
- 利用：SSRF 白名单 / 出网白名单 / 域名后缀校验被绕过。
- 正确修法（不只是升级）：**先解析再校验**，且用解析出的 IP 建连，禁止二次解析（防 DNS rebinding）。

### 3.3 CVE-2026-105483 — 全角数字 IP 的 TLS 主机名绕过（HIGH，26/24）

- 证书 SAN 里写成全角数字的 IP 与请求的主机名比对不当 → 错名证书被接受。

### 3.4 CVE-2026-106069 — 松散解析导致的 TLS 主机名绕过（HIGH，26/24/22）

- `host` 能被"松散解析"为 IP 时，证书 IP SAN 校验逻辑被绕过。

### 3.5 MEDIUM

- **CVE-2026-105481**：keep-alive 复用连接时，会把"请求发出前写入的响应"当作本次响应处理 → 响应错位/串包。队列型服务、代理型服务要重点看。
- **CVE-2026-106072**：非规范 IPv4 主机名（如 `127.1`、八进制/十六进制写法）导致 DNS SAN 可认证 IP 端点。
- **CVE-2026-106074**：`crypto.randomUUID()` / `randomInt()` 的熵缓存在用户态启动快照与 SEA 中被保存 → 每个进程重复相同值。**安全影响**：把 UUID 当 token/幂等键/重置码的系统直接可预测。

### 3.6 LOW

- **CVE-2026-106070**：`ZipFile` 在 ZIP header 校验失败后仍返回攻击者控制的前缀字节（26.x）。
- **CVE-2026-106071**：权限模型通配符基数查找过度授权（26.x）。
- **CVE-2026-106073**：`fs.realpathSync` 绕过权限模型（26/24/22）。

## 4. 依赖同步更新

c-ares、OpenSSL（24/22）、SQLite（22）、Undici（26/24/22）、**ca-cert（eMudhra 中间 CA 被攻陷）**。
→ 报告里要单列一条：**根/中间 CA 信任被污染**，影响面大于单个 CVE。

## 5. 防守方排查

```bash
# 版本
node -v ; docker images | grep -i node
# 依赖
npm audit --omit=dev || true
# Brotli 面
grep -rn "brotli" --include=*.js --include=*.mjs .
# 随机数误用
grep -rn "randomUUID\|randomInt" --include=*.js . | head
# SSRF 校验写法
grep -rn "dns.resolve\|net.isIP\|url.hostname" --include=*.js .
```

## 6. 流量侧特征

- `Content-Encoding: br` 且 body 为畸形/截断的 brotli 流；
- 主机名/URL 参数中出现 `%00`、全角数字（`１２７.０.０.１`）、八进制 IP；
- keep-alive 连接上短时间内响应与请求数量错位（需应用层埋点）。

---

## 7. 公开 PoC / 复现情况（2026-10）

### 7.1 全网检索结论

| CVE | 公开 PoC | 说明 |
|---|---|---|
| **CVE-2026-111497** | **有（仅 DoS 级）** | `dimasma0305/CVE-2026-111497-POC`（自校验、loopback 实验）；另有 `CaterMaoZi`、`hypnguyen1209`、`TahuCryptsi` 等小仓库 |
| CVE-2026-105482 | 无独立 PoC | 概念简单，可用任意 DNS 查询器手工验证 |
| CVE-2026-105483 / 106069 | 无独立 PoC | 需自建错名证书端点 |
| CVE-2026-106074 | 无 | 用 SEA 打快照后读两次 `randomUUID()` 即可自证 |
| 其余 MED/LOW | 无 | — |

### 7.2 CVE-2026-111497 的公开复现细节（重要）

公开仓库 `cve-2026-111497` 的结论是：**攻击者可见的最高已证影响是拒绝服务（DoS），没有可用的公开接口 RCE**。
这与官方公告"permits remote code execution"存在口径差，写报告时要分开表述。

**复现前提**：Node 是运行时不是网络服务，实验用了一个"分帧解压服务"，内部只调用**公开 API**
`zlib.createBrotliDecompress()`。这说明真实的攻击面判定标准是：**是否存在把攻击者数据喂给
`brotliDecompress*` / `createBrotliDecompress` 的代码路径**。

**触发方式（两阶段）**：

| 阶段 | 数据 | 说明 |
|---|---|---|
| 1 | **23,068,690 字节**的畸形 Brotli 流 | 固定样本，发送前校验 SHA256 `b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4` |
| 等待 | 服务的普通完成 ACK | 保证第一阶段被完整解码 |
| 2 | **127 字节**覆写阶段 | 在已破坏的堆状态上落写 |

**错误指纹**：修复后的版本会返回 `ERR__ERROR_FORMAT_BLOCK_SWITCH`（块切换格式错误）并保持健康——
说明缺陷点位于 **Brotli 块切换（block switch）解析**，不是普通的截断/长度校验问题。

**版本矩阵（实测）**：

| 运行时 | 结果 |
|---|---|
| 20.19.5（EOL） | DoS 成功，无修复版对照 |
| 22.23.3 | DoS 成功 |
| **22.23.4** | **已修复**（拒绝畸形流） |
| 24.22.0 | DoS 成功 |
| **24.22.1** | **已修复** |
| 26.12.0 | DoS 成功 |
| **26.12.1** | **已修复** |

### 7.3 报告口径建议

| 事实 | 怎么写 |
|---|---|
| 官方公告写 RCE | 引用 nodejs.org，写"厂商评级为 RCE" |
| 公开只复现到 DoS | 写"公开可验证影响为进程崩溃（DoS）；RCE 未公开验证" |
| 目标确实解压攻击者数据 | 这是**必要条件**，写成 high（DoS 可达）+ 注明潜在 RCE |

**不要**把"版本低于修复线"直接写成"存在 RCE"——这正是多数扫描器报告被降级的原因。
