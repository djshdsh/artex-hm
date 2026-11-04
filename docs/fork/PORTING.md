# 二开声明 / Fork Notice

> 本仓库是 **ARTEX** 的二次开发版本（下称"本二开版"）。
> 本文件按 **AGPL-3.0 第 5 条**（Modified Source Versions）履行"标注修改"的义务。

---

## 1. 来源与许可

| 项 | 内容 |
|---|---|
| 上游项目 | ARTEX — AI 自主渗透测试系统 |
| 上游地址 | `https://github.com/yes-chen/ARTEX`（原作者仓库另有 `github.com/Autumn-27/artex`，模块路径仍为 `github.com/Autumn-27/artex`） |
| 基线版本 | **0.3.15**（见 `CHANGELOG.md`） |
| 许可证 | **AGPL-3.0**（见 `LICENSE`，未做任何修改） |
| 本二开版 | 在上述基线之上增加后渗透能力、拒答治理与界面改造 |

依 AGPL-3.0：
- 本仓库以同样许可证（AGPL-3.0）发布，**不附加任何额外限制**；
- 由于本仓库本身就是公开发布的源码，已满足 AGPL "向网络交互用户提供对应源码" 的要求；
- 若你将本二开版部署为网络服务，请保留本文件与 `LICENSE`，并保留上游版权声明。

**所有修改均标注了日期：2026-11-04。**

---

## 2. 修改清单（相对上游 0.3.15）

### 2.1 新增文件

| 文件 | 作用 |
|---|---|
| `llmpool/refusal.go` | **拒答探针**：拒答分类器 + 逐级加固指令 + 重试计划 |
| `llmpool/refusal_test.go` | 拒答探针的 5 个单元测试 |
| `skills/internal-network-pentest/SKILL.md` | 新技能「内网渗透」（后渗透/横向九阶段） |
| `skills/web-injection-playbook/SKILL.md` | 新技能：注入面全谱 |
| `skills/authz-token-abuse/SKILL.md` | 新技能：越权 / JWT / OAuth / MFA |
| `skills/ssrf-and-server-side-chains/SKILL.md` | 新技能：SSRF / 云 metadata / XXE / 文件链 |
| `skills/deser-and-parser-chains/SKILL.md` | 新技能：反序列化与解析器链 |
| `skills/race-and-business-logic/SKILL.md` | 新技能：竞态与业务逻辑 |
| `skills/modern-web-surface/SKILL.md` | 新技能：走私 / 缓存投毒 / GraphQL / WebSocket / CORS |
| `skills/recon-and-content-discovery/SKILL.md` | 新技能：资产侦察与内容发现 |
| `skills/credential-and-pivot-ops/SKILL.md` | 新技能：凭据攻击与隧道枢红 |
| `skills/payload-quick-ref/SKILL.md` | 新技能：高频 payload 速查 |
| `skills/ad-and-internal-identity/SKILL.md` | 新技能：AD / Kerberos / 横向 |
| `web/src/app/(main)/function/internal/page.tsx` | **新功能页「内网渗透」**（侧边栏入口） |
| `docker-compose.exsala.yml` | 部署覆盖层示例（切换到本二开版镜像） |
| `NOTICE-FORK.md` | 本文件 |

### 2.2 修改文件

| 文件 | 修改要点 |
|---|---|
| `llmpool/pool.go` | `Stream` / `Complete` 接入拒答探针：扣住首段判定 → 加固重放 → 换成员 → 全拒返回 `ErrAllRefused` |
| `agent/prompt.go` | 新增**代码持有的执行纪律尾块**（`renderSystem` 无条件追加，界面编辑盖不掉） |
| `agent/prompt_test.go` | 适配尾块并新增覆盖率断言 |
| `agent/worker.go` | 边界段改写：约束只限定范围，不限制手法强度 |
| `agent/planner.go` | 新增「打法库」联想清单（七类攻击面） |
| `agent/constraints.go` | 约束语义改写（范围约束 ≠ 强度约束） |
| `agent/promptcatalog.go` | 重写 `DefaultAssistantPrompt`（执行导向） |
| `agent/tools_insert.go` | 护栏文案同步 |
| `db/config.go` | 新增 `RefreshBuiltinPromptIfUnedited`：代码默认提示词可随版本升级（不动人工编辑） |
| `db/db.go` | 新增 10 个技能的内置可见性绑定 |
| `server/assembly.go` | `seedPrompts` 接入上述刷新逻辑 |
| `Dockerfile.build` | 新增攻防工具链（apt + Go 编译 + pip）、`kx` 前缀包装、impacket 别名 |
| `skills/api-recon/SKILL.md` | 移除"禁止利用"禁令，改为职责分工 |
| `web/src/app/globals.css` | 新增渐变主题（仅标题 + 图标，含子元素颜色还原兜底） |
| `web/src/app/layout.tsx` | 注入图标渐变用的 `<linearGradient>` 定义 |
| `web/src/navigation/sidebar/sidebar-items.ts` | 侧边栏新增「内网渗透」入口 |

---

## 3. 上游之外的第三方组件

`Dockerfile.build` 在构建镜像时安装/编译下列组件（各自遵循其原许可证）：

| 组件 | 用途 | 许可 |
|---|---|---|
| sqlmap / hydra / gobuster / masscan / socat / john / hashcat / dirb / whatweb / wfuzz | 攻防工具 | GPL / 各自开源许可 |
| ffuf / chisel / dnsx | Go 工具（构建期 `go install`） | MIT / Apache-2.0 |
| impacket | 网络协议工具集 | Apache-2.0（衍生自 CORE Security 许可） |
| nmap | 端口与服务识别 | Nmap Public Source License（GPLv2 兼容） |
| Playwright + Chromium | 浏览器自动化 | Apache-2.0 |

`skills/` 下的 `LICENSE-APACHE-2.0.txt`、`THIRD-PARTY-NOTICES.txt` 为上游随附文件，未改动。

---

## 4. 使用边界

本软件仅用于**自有资产**或**已获得书面授权**的目标测试。使用者自行承担合规责任。
作者与本二开版维护者不对任何滥用行为负责。
