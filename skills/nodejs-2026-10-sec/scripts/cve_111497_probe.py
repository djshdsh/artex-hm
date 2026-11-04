#!/usr/bin/env python3
"""
cve_111497_probe.py —— CVE-2026-111497（Node.js Brotli 解码器越界写）可达性探针 v2

只判"服务端是否把攻击者数据交给 Brotli 解码"，并用合法数据测解压边界。
不发送任何畸形流、不触发越界写、不制造崩溃。

三种能力：
  decode   对照法：合法 br 体被正常处理、明文冒充 br 失败 → 确认在解码攻击者数据
  ratio    发送高压缩比合法流（默认解压后 200KB），看服务端是否限制解压体积（DoS 面）
  truncated （可选，--malformed）发一个被截断的小流，只观察错误码/指纹，不追求崩溃

用法:
    python3 cve_111497_probe.py --url https://t/api/echo --authorized
    python3 cve_111497_probe.py --url ... --authorized --ratio --max-decompressed 5000000
    python3 cve_111497_probe.py --url ... --authorized --header 'Content-Type: application/json'
    python3 cve_111497_probe.py --url ... --authorized --malformed

退出码: 0=确认在解码攻击者数据（暴露） 1=未观察到 2=错误 3=参数
"""
import argparse
import base64
import json
import re
import ssl
import sys
import urllib.request

# 合法 brotli 流（由 node zlib.brotliCompressSync 生成）
BROTLI_HELLO = b"\x0b\x02\x80hello\x03"                      # -> "hello"
BROTLI_200K = base64.b64decode("Wz8Ng18iKB4LBPIJBgA=")        # -> b"A"*200_000   (14 字节)
BROTLI_5M = base64.b64decode("mz9LTPglguKxQCBfiAk=")          # -> b"A"*5_000_000 (14 字节)

# 已知缺陷点在 Brotli 的 block switch 解析
ERR_HINTS = re.compile(
    r"ERR__ERROR_FORMAT_BLOCK_SWITCH|BROTLI|brotli|decompress|invalid\s+stream|INVALID_ARGUMENT",
    re.I)


def post(url, body, headers, timeout=12):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"User-Agent": "Mozilla/5.0", **headers})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(8000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, e.read(4000).decode("utf-8", "ignore")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--header", action="append", default=[])
    ap.add_argument("--ratio", action="store_true", help="加测高压缩比载荷")
    ap.add_argument("--max-decompressed", type=int, default=5_000_000,
                    help="ratio 模式使用的解压后大小上限（200000 或 5000000）")
    ap.add_argument("--malformed", action="store_true", help="额外发一次截断流看错误指纹")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if not a.authorized:
        print("拒绝执行：需先确认授权（--authorized）。", file=sys.stderr)
        return 3

    hdrs = {}
    for h in a.header:
        k, _, v = h.partition(":")
        hdrs[k.strip()] = v.strip()

    out = {"url": a.url}
    br = {**hdrs, "Content-Encoding": "br"}

    # --- 1) decode：对照
    s_ok, b_ok = post(a.url, BROTLI_HELLO, br)                  # 合法 br
    s_fake, b_fake = post(a.url, b"hello", br)                  # 明文冒充 br
    s_plain, b_plain = post(a.url, b"hello", hdrs)              # 对照
    decoded = s_ok is not None and s_ok < 400 and s_ok != s_fake
    out["decode"] = {
        "valid_brotli": {"status": s_ok, "body": b_ok[:160]},
        "plain_as_brotli": {"status": s_fake, "body": b_fake[:160]},
        "plain": {"status": s_plain, "body": b_plain[:160]},
        "server_decodes_brotli": decoded,
        "error_fingerprint": bool(ERR_HINTS.search((b_fake or "") + (b_ok or ""))),
    }

    # --- 2) ratio：解压体积是否受限
    if a.ratio:
        bomb = BROTLI_5M if a.max_decompressed >= 5_000_000 else BROTLI_200K
        size = 5_000_000 if bomb is BROTLI_5M else 200_000
        s_b, b_b = post(a.url, bomb, br, timeout=20)
        accepted = s_b is not None and s_b < 400
        out["ratio"] = {
            "compressed_bytes": len(bomb),
            "decompressed_claim": size,
            "ratio": f"{size/len(bomb):.0f}:1",
            "status": s_b,
            "accepted": accepted,
            "body": b_b[:160],
            "note": ("服务端接受了高压缩比流 → 未限制解压体积，进程内存可被放大（DoS 面）"
                     if accepted else "被拒/出错，可能限制了解压体积"),
        }

    # --- 3) malformed：只看错误指纹（不追求崩溃）
    if a.malformed:
        mal = BROTLI_HELLO[:6]                      # 截断
        s_m, b_m = post(a.url, mal, br, timeout=15)
        out["malformed"] = {
            "status": s_m, "body": b_m[:200],
            "fingerprint": bool(ERR_HINTS.search(b_m or "")),
        }

    primary = out["decode"]["server_decodes_brotli"]
    out["verdict"] = ("服务端确实在解码攻击者可控的 Brotli 数据 → CVE-2026-111497 面成立"
                      if primary else "未观察到解码行为（或无法区分）")

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        d = out["decode"]
        print(f"目标              : {a.url}")
        print(f"合法 br           : {d['valid_brotli']['status']}")
        print(f"明文冒充 br       : {d['plain_as_brotli']['status']}")
        print(f"对照组(明文)      : {d['plain']['status']}")
        print(f"是否解码攻击者数据: {'是' if primary else '否/无法判断'}")
        if "ratio" in out:
            r = out["ratio"]
            print(f"压缩比测试        : {r['ratio']}（{r['compressed_bytes']}B → 声称 "
                  f"{r['decompressed_claim']}B）status={r['status']}")
            print(f"  {r['note']}")
        if "malformed" in out:
            print(f"截断流            : status={out['malformed']['status']} "
                  f"指纹识别={out['malformed']['fingerprint']}")
        print(f"判定              : {out['verdict']}")
        print("\n提示: 官方评级为 RCE，但公开可复现影响只到 DoS。"
              "报告写 high（DoS 可达 + 潜在 RCE），别直接写'已 RCE'。")
    return 0 if primary else 1


if __name__ == "__main__":
    sys.exit(main())
