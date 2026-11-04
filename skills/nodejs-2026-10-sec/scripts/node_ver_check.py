#!/usr/bin/env python3
"""
node_ver_check.py —— Node.js 2026-10-21 安全版本核对

用法:
    python3 node_ver_check.py                     # 读本机 node -v
    python3 node_ver_check.py --version v20.11.0
    python3 node_ver_check.py --package-json ./package.json --engines
    python3 node_ver_check.py --version 24.22.1 --json

退出码: 0=受影响 1=已修复 2=未知/EOL 3=参数错误
"""
import argparse
import json
import re
import shutil
import subprocess
import sys

FIXED = {26: (26, 12, 1), 24: (24, 22, 1), 22: (22, 23, 4)}
EOL = (20, 18, 0)

# 按线列出受影响 CVE（用于输出提示）
LINE_CVES = {
    "all": ["CVE-2026-111497", "CVE-2026-105482", "CVE-2026-106069",
            "CVE-2026-105481", "CVE-2026-106072", "CVE-2026-106074", "CVE-2026-106073"],
    26: ["CVE-2026-105483", "CVE-2026-106070", "CVE-2026-106071"],
    24: ["CVE-2026-105483"],
}


def parse(v):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", v or "")
    return tuple(int(x) for x in m.groups()) if m else None


def get_local():
    exe = shutil.which("node")
    if not exe:
        return None
    try:
        return subprocess.run([exe, "-v"], capture_output=True, text=True, timeout=10).stdout.strip()
    except Exception:
        return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version")
    ap.add_argument("--package-json")
    ap.add_argument("--engines", action="store_true", help="只读 package.json 的 engines.node")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    raw = a.version or get_local()
    if a.package_json and not raw:
        try:
            pkg = json.load(open(a.package_json))
            raw = (pkg.get("engines") or {}).get("node")
        except Exception as e:
            print(f"读取 package.json 失败: {e}", file=sys.stderr)
            return 3

    if not raw:
        print("未找到 Node.js 版本：未安装 node，或未提供 --version", file=sys.stderr)
        return 2

    v = parse(raw)
    out = {"raw": raw, "version": ".".join(map(str, v)) if v else None}
    if not v:
        print(f"无法解析版本: {raw}", file=sys.stderr)
        return 2

    line = v[0]
    if line in FIXED:
        fixed = FIXED[line]
        affected = v < fixed
        out.update({"line": f"{line}.x", "fixed_in": ".".join(map(str, fixed)),
                    "affected": affected,
                    "cves": LINE_CVES["all"] + LINE_CVES.get(line, [])})
        verdict = "受影响" if affected else "已修复"
    elif v < EOL:
        out.update({"line": f"{line}.x", "affected": True, "fixed_in": None,
                    "cves": LINE_CVES["all"], "note": "EOL 线，不再发版，必须升级"})
        verdict = "受影响（EOL，无官方修复）"
    else:
        out.update({"line": f"{line}.x", "affected": None, "fixed_in": None})
        verdict = "未知（不在 22/24/26 补丁线，按未覆盖处理）"

    out["verdict"] = verdict
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(f"Node.js   : {out['version']}  ({out['line']})")
        print(f"判定      : {verdict}")
        if out.get("fixed_in"):
            print(f"修复版本  : {out['fixed_in']}")
        if out.get("cves"):
            print("相关 CVE  : " + ", ".join(out["cves"]))
        if out.get("note"):
            print(f"备注      : {out['note']}")
        print("\n提示: 版本命中≠可利用。Brotli 那条要求目标真的解压攻击者可控数据。")

    if out["affected"] is True:
        return 0
    if out["affected"] is False:
        return 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
