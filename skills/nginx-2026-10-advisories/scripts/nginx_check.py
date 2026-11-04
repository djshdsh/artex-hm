#!/usr/bin/env python3
"""
nginx_check.py —— nginx 2026-10 安全批次：版本 + 配置可达性核对 v2

与 v1 的区别：五条 CVE 全部是"配置组合"才有意义，v2 按组合判定，不再单条 grep 就算命中。
  - 15176 需要 alias 与 rewrite 同时存在
  - 97205 需要 aio on 与 ssi on 同时存在
  - 97629 需要 shared session cache + tickets 未关 + 无静态 ssl_session_ticket_key
          （配了 key 文件反而是缓解），若有 ssl_verify_client 则影响升级为认证绕过

用法:
    python3 nginx_check.py --version 1.30.5
    python3 nginx_check.py --url https://target/            # 读 Server 头（常被 server_tokens off 抹掉）
    python3 nginx_check.py --config dumped.conf             # nginx -T 的输出
    python3 nginx_check.py --local                          # 跑 nginx -V / nginx -T
    python3 nginx_check.py --version 1.31.6 --config '...' --json

退出码: 0=受影响(版本或配置命中) 1=不受影响 2=未知 3=参数错误
"""
import argparse
import json
import re
import shutil
import ssl
import subprocess
import sys
import urllib.request

FIXED = {"mainline": (1, 31, 7), "stable": (1, 30, 6)}

# CVE -> 引入版本下界
INTRO = {
    "CVE-2026-15176": (0, 1, 29),
    "CVE-2026-93479": (1, 30, 0),
    "CVE-2026-95101": (1, 25, 0),
    "CVE-2026-97629": (1, 23, 2),
    "CVE-2026-97205": (0, 8, 11),
}

F = {
    "alias":        re.compile(r"(^|[;{}\s])alias\s", re.M),
    "rewrite":      re.compile(r"(^|[;{}\s])rewrite\s", re.M),
    "var_expr":     re.compile(r"(^|[;{}\s])(root|log_format|access_log|error_log)\s[^;]*\$", re.M),
    "http3":        re.compile(r"listen[^;]*\bquic\b|(^|[;{}\s])http3\s+on", re.M),
    "shared_cache": re.compile(r"ssl_session_cache\s+shared:", re.M),
    "tickets_off":  re.compile(r"ssl_session_tickets\s+off", re.M),
    "key_file":     re.compile(r"ssl_session_ticket_key\s", re.M),
    "verify_client":re.compile(r"ssl_verify_client\s+(on|optional|optional_no_ca)", re.M),
    "aio_on":       re.compile(r"(^|[;{}\s])aio\s+on", re.M),
    "ssi_on":       re.compile(r"(^|[;{}\s])ssi\s+on", re.M),
}


def parse(v):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def is_fixed(v):
    if v >= FIXED["mainline"]:
        return True
    if v[:2] == (1, 30) and v >= FIXED["stable"]:
        return True
    return False


def analyse(version, text):
    """返回受影响 CVE 列表与理由。version 为 None 时只做配置观察（不判可达）。"""
    flags = {k: bool(rx.search(text or "")) for k, rx in F.items()}
    res = {"flags": flags, "exposures": [], "observations": []}

    # 97629 的方向容易搞反，单独给观察结论
    if flags["shared_cache"] and flags["tickets_off"]:
        res["observations"].append("tickets 已关闭 → 97629 不可达")
    elif flags["key_file"]:
        res["observations"].append("存在静态 ssl_session_ticket_key → 不走轮转缓存，97629 不可达")
    elif flags["shared_cache"]:
        res["observations"].append("shared cache + tickets 开启 + 无静态 key → 97629 的配置条件齐全")

    if version is None:
        return res
    if is_fixed(version):
        res["verdict"] = "已修复"
        return res

    v = version
    def add(cve, why, impact):
        res["exposures"].append({"cve": cve, "why": why, "impact": impact})

    if v >= INTRO["CVE-2026-15176"] and flags["alias"] and flags["rewrite"]:
        add("CVE-2026-15176", "alias 与 rewrite 同时存在", "worker 堆溢出 → 崩溃/理论 RCE")
    if v >= INTRO["CVE-2026-93479"] and flags["var_expr"]:
        add("CVE-2026-93479", "root/日志中使用含变量的表达式", "worker 溢出 → 崩溃")
    if v >= INTRO["CVE-2026-95101"] and flags["http3"]:
        add("CVE-2026-95101", "启用了 HTTP/3", "绕过 client_max_body_size / 请求注入（走私）")
    if v >= INTRO["CVE-2026-97629"] and flags["shared_cache"] and not flags["tickets_off"] and not flags["key_file"]:
        impact = ("**客户端证书认证绕过**（mTLS 场景按满分读）"
                  if flags["verify_client"] else "会话伪造 → 身份劫持")
        add("CVE-2026-97629", "shared cache + tickets on + 无静态 key", impact)
    if v >= INTRO["CVE-2026-97205"] and flags["aio_on"] and flags["ssi_on"]:
        add("CVE-2026-97205", "aio on 与 ssi on 同时存在", "释放后使用 → 崩溃/理论 RCE")

    res["verdict"] = "受影响" if res["exposures"] else "版本落后但配置未命中"
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version")
    ap.add_argument("--url")
    ap.add_argument("--config")
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    raw, text, evidence = a.version, a.config, []

    if a.local:
        exe = shutil.which("nginx")
        if exe:
            raw = subprocess.run([exe, "-v"], capture_output=True, text=True).stderr
            evidence.append(raw.strip())
            if not text:
                try:
                    text = subprocess.run([exe, "-T"], capture_output=True, text=True,
                                          errors="ignore").stdout or None
                except Exception:
                    pass
        else:
            evidence.append("本机未找到 nginx 可执行文件")

    if not raw and a.url:
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=ctx))
        try:
            req = urllib.request.Request(a.url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
            with opener.open(req, timeout=8) as r:
                srv = r.headers.get("Server", "")
                evidence.append(f"Server: {srv}")
                raw = srv
        except Exception as e:
            evidence.append(f"请求失败: {type(e).__name__}: {e}")

    if text and not text.lstrip().startswith(("server", "http", "user", "worker", "#")):
        try:
            with open(a.config, encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except (OSError, ValueError):
            pass    # 允许直接贴配置文本

    v = parse(raw)
    res = analyse(v, text)
    out = {"version": ".".join(map(str, v)) if v else None,
           "verdict": res.get("verdict", "未知（未取到版本）"),
           "exposures": res["exposures"], "flags": res["flags"],
           "observations": res["observations"], "evidence": evidence,
           "fixed_in": "1.31.7+ / 1.30.6+"}

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f"版本     : {out['version']}")
        print(f"判定     : {out['verdict']}")
        if out["exposures"]:
            print("可达 CVE :")
            for e in out["exposures"]:
                print(f"  - {e['cve']}: {e['why']} → {e['impact']}")
        else:
            print("可达 CVE : 无（配置未命中）")
        for o in out["observations"]:
            print(f"观察     : {o}")
        for e in evidence:
            print(f"证据     : {e}")
        print("\n注意: 这五条全部依赖配置。版本落后≠可利用，报告里必须写明命中的 directive 组合。")

    if out["verdict"] == "已修复" or out["verdict"] == "版本落后但配置未命中" or out["verdict"] == "不受影响":
        return 1
    if out["verdict"] == "受影响":
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
