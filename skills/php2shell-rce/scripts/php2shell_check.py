#!/usr/bin/env python3
"""
php2shell_check.py —— PHP2Shell (CVE-2026-109618 / CVE-2026-109619) 无害指纹判定

只做 GET/HEAD，不触发 OOM、不发送攻击载荷。

用法:
    python3 php2shell_check.py --url https://target/
    python3 php2shell_check.py --version 8.3.27
    python3 php2shell_check.py --version 8.3.27 --sapi apache-mod-php --json

退出码: 0=受影响 1=已修复 2=未知 3=参数错误
"""
import argparse
import json
import re
import ssl
import sys
import urllib.request

FIXED = {"8.5": (8, 5, 12), "8.4": (8, 4, 27), "8.3": (8, 3, 36), "8.2": (8, 2, 35)}
AFFECTED_TEXT = "< 8.2.35 / < 8.3.36 / < 8.4.27 / < 8.5.12"

SAPI_HINTS = [
    (re.compile(r"frankenphp", re.I), "frankenphp", "高（类似 mod_php）"),
    (re.compile(r"litespeed", re.I), "litespeed", "中（类似 FPM）"),
    (re.compile(r"apache", re.I), "apache(可能 mod_php)", "最高（若确为 mod_php）"),
    (re.compile(r"nginx", re.I), "php-fpm/fastcgi", "中（FPM 会回收脏状态）"),
]


def parse_version(text):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", text or "")
    return tuple(int(x) for x in m.groups()) if m else None


def verdict(v):
    major_minor = f"{v[0]}.{v[1]}"
    if major_minor in FIXED:
        return ("已修复" if v >= FIXED[major_minor] else "受影响"), FIXED[major_minor]
    if v < (8, 2, 0):
        return "受影响（上游无补丁，需发行版 backport 或升级）", None
    return "未知（该分支不在官方补丁列表，按受影响处理）", None


def http_get(url, timeout=8):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=timeout) as r:
        return r.status, dict(r.headers), r.read(200_000).decode("utf-8", "ignore")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url")
    ap.add_argument("--version")
    ap.add_argument("--sapi")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if not a.url and not a.version:
        ap.print_help()
        return 3

    out = {"affected": None, "php_version": None, "sapi": a.sapi, "evidence": []}

    if a.url:
        try:
            status, hdr, body = http_get(a.url)
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
            print(json.dumps(out, ensure_ascii=False, indent=2) if a.json else out["error"])
            return 2
        hlow = {k.lower(): v for k, v in hdr.items()}
        server = hlow.get("server", "")
        powered = hlow.get("x-powered-by", "")
        out["evidence"].append(f"HTTP {status} Server={server!r} X-Powered-By={powered!r}")
        for pat, name, risk in SAPI_HINTS:
            if pat.search(server):
                out["sapi"] = out["sapi"] or name
                out["sapi_risk"] = risk
                break
        ver = parse_version(powered) or parse_version(server)
        if not ver:
            m = re.search(r'PHP/(\d+\.\d+\.\d+)', body or "")
            ver = tuple(int(x) for x in m.groups()) if m else None
            if m:
                out["evidence"].append(f"body 中出现 PHP/{m.group(1)}")
        out["php_version"] = ".".join(map(str, ver)) if ver else None
    else:
        ver = parse_version(a.version)
        out["php_version"] = a.version

    if ver:
        state, fixed = verdict(ver)
        out["affected"] = state
        out["fixed_in"] = ".".join(map(str, fixed)) if fixed else None
        out["rule"] = AFFECTED_TEXT
    else:
        out["affected"] = "未知（未取到版本号）"

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f"PHP 版本 : {out['php_version']}")
        print(f"SAPI     : {out['sapi']}  {out.get('sapi_risk','')}")
        print(f"判定     : {out['affected']}")
        if out.get("fixed_in"):
            print(f"修复版本 : {out['fixed_in']}")
        for e in out["evidence"]:
            print(f"证据     : {e}")
        print("\n注意: 版本命中≠可利用。mod_php 才有'应用无关'路径；FPM 需 producer/consumer。")

    state = out.get("affected") or ""
    if state.startswith("已修复"):
        return 1
    if state.startswith("受影响"):
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
