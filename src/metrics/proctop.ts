'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:child_process';

/**
 * 进程排行：全量进程 + 瞬时 CPU（与系统卡片同一套 /proc 差分与 EMA 平滑）。
 * 2026-10-13 改造：不再截断成「内存 TOP15」，改为返回全部进程（硬上限 500 行），
 * 单行补 ppid 与 subtree_mem_mb / subtree_cpu（该节点含全部后代的和），供前端构树。
 */

const { exec, execSync } = require('child_process') as typeof import('child_process');
const { promisify } = require('util') as typeof import('util');

const execAsync = promisify(exec);

// 注意：collectAllProcCpu（probe/system.ts）与 SYSTEMD_SERVICES（probe/services.ts）在模块顶层
// require 会连带加载 state.ts，进而在 import 时就建立 Redis 连接（测试进程会因此挂住）。
// 为让本模块可被单测安全 import（纯函数不触碰 ps/docker/Redis），这两个依赖延迟到 collectProcesses
// 内首次调用时再 require（CJS require 有缓存，重复调用无额外开销）。

// 安全上限：全量进程的正常规模在数百条，硬上限兜底防止极端环境下响应体过大。
const MAX_PROCESS_ROWS = 500;

// ps 输出的一行（内部中间结构，比对外响应多出 comm/args/rss_kb 原始字段）
type ProcRow = {
  pid: number;
  ppid: number;
  comm: string;
  args: string;
  rss_kb: number;
  mem_mb: number;
  cpu: number;
};

// ps 文本行格式：`pid ppid comm(定宽 16) rss pcpu args`。
// 为什么给 comm 定宽：进程可能把 comm 改成含空格的名字（实测 next-server (v1、node /home/jopl），
// 纯按空白切分会把列错位、把 RSS 读成 0（会少算几百 MB）。给 comm 固定 16 列（comm 上限 15 字符）
// 后按位解析即可对齐；comm 之后的 rss/pcpu 为定宽数值列，args 为行尾剩余。
const PS_LINE_RE = /^\s*(\d+)\s+(\d+)\s+(.{16})\s+(\d+)\s+([\d.]+)\s*(.*)$/;

// 对外响应的一行：内存自身 RSS / CPU 自身，子树字段为含全部后代的和
type ProcNode = {
  name: string;
  pid: number;
  ppid: number;
  mem_mb: number;
  cpu: number;
  subtree_mem_mb: number;
  subtree_cpu: number;
};

/* ============ 纯函数（供单测直接调用，不触碰真实 ps / docker） ============ */

// ps 文本 → 行数组。列序 pid,ppid,comm,rss,pcpu,args，其中 comm 定宽 16 列（见 PS_LINE_RE）。
// rss 单位 kB → mem_mb 取整；pcpu 直接作为 cpu 兜底（collectProcesses 再用 /proc 差分结果覆盖）。
function parsePsOutput(text: string): ProcRow[] {
  const rows: ProcRow[] = [];
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const m = PS_LINE_RE.exec(line);
    if (!m) continue;
    const pid = parseInt(m[1], 10);
    const ppid = parseInt(m[2], 10);
    const rssKb = parseInt(m[4], 10) || 0;
    rows.push({
      pid,
      ppid: Number.isFinite(ppid) ? ppid : 0,
      comm: m[3].trimEnd(),
      rss_kb: rssKb,
      mem_mb: Math.round(rssKb / 1024),
      args: m[6].trim(),
      cpu: Math.round((parseFloat(m[5]) || 0) * 10) / 10
    });
  }
  return rows;
}

// 从 containerd shim 的 args 里取 `-id <容器 ID>`（兼容 --id；容器 ID 为十六进制）。
function extractShimContainerId(args: string): string | null {
  const m = /(?:^|\s)--?id\s+([0-9a-fA-F]{6,64})(?=\s|$)/.exec(String(args || ''));
  return m ? m[1] : null;
}

// docker ps --format '{{.ID}} {{.Names}}' 文本 → Map<短 ID（12 位）, 容器名>
function parseDockerPs(text: string): Map<string, string> {
  const map = new Map<string, string>();
  for (const line of String(text).split('\n')) {
    const t = line.trim();
    if (!t) continue;
    const sp = t.indexOf(' ');
    if (sp <= 0) continue;
    const id = t.slice(0, sp).trim();
    const name = t.slice(sp + 1).trim();
    if (id && name) map.set(id, name);
  }
  return map;
}

// 前缀匹配：shim args 里通常是 64 位全长 ID，docker ps 给的是 12 位短 ID。
function matchContainerName(
  containerId: string | null,
  map: Map<string, string> | null | undefined
): string | null {
  if (!containerId || !map || map.size === 0) return null;
  for (const [shortId, name] of map) {
    if (containerId.startsWith(shortId)) return name;
  }
  return null;
}

// 进程命名：优先级 systemd MainPID → 容器 shim（容器名）→ opencode / agent-browser /
// pi / aionui / node / python → comm 兜底。规则与改造前一致，仅新增 shim 一条。
function resolveProcessName(
  row: ProcRow,
  pidToService: Map<number, string>,
  containerMap: Map<string, string>
): string {
  const { pid, comm, args } = row;
  if (pidToService.has(pid)) return pidToService.get(pid) as string;
  if (/^containerd-shim/.test(comm)) {
    // docker 不可用 / 查不到 → 静默回退 comm，不报错
    const name = matchContainerName(extractShimContainerId(args), containerMap);
    return name || comm;
  }
  if (comm === 'opencode' || args.includes('opencode')) return 'opencode';
  if (comm === 'agent-browser' || args.includes('agent-browser')) return 'agent-browser';
  if (comm === 'pi' || args.includes('pi-coding-agent') || /(^|\/)pi(\.js)?$/.test(args.trim())) {
    // pi coding agent（@earendil-works/pi-coding-agent）：启动后会把进程标题改写成纯 "pi"，
    // 故优先按 comm 判定；另保留包名/裸命令两种兜底形态
    return 'pi';
  }
  if (comm === 'aioncore' || args.includes('aioncore') || args.includes('aionui-src')) {
    // AionUi WebUI：主进程是 bun 包装器 + node(tsx/cross-env) + aioncore 后端 + esbuild 子进程，
    // 不归类的话在榜单里会被拆成一堆无名 node/aioncore，看不出是同一个项目
    return 'aionui';
  }
  if (comm === 'node' || args.includes('node')) return 'node';
  if (/^python/.test(comm)) return 'python';
  return comm;
}

// 截断 + 合计（纯函数）：count 为截断前总数，total_mem_mb 为全部进程 RSS 之和（MB，整数，
// 按原始 kB 汇总后一次取整，与 `ps -eo rss … | awk '{s+=$1} END{print s/1024}'` 同口径）。
// 超出硬上限按内存降序截断，truncated=true。rows 需含 rss_kb / mem_mb。
function summarizeProcesses<T extends ProcRow>(rows: T[], limit = MAX_PROCESS_ROWS) {
  const count = rows.length;
  const total_mem_mb = Math.round(rows.reduce((s, r) => s + r.rss_kb, 0) / 1024);
  const truncated = rows.length > limit;
  const sorted = [...rows].sort((a, b) => b.rss_kb - a.rss_kb);
  const processes = truncated ? sorted.slice(0, limit) : sorted;
  return { processes, count, truncated, total_mem_mb };
}

// 构造父子关系并算子树合计（纯函数）：按 ppid 挂到父节点；ppid 不在集合内 / 自环视为根。
// 节点子树合计 = 自身 + 全部后代之和；对异常环路做保护（回边直接跳过），保证绝不无限递归。
function buildProcessTree<T extends { pid: number; ppid: number; mem_mb: number; cpu: number }>(
  rows: T[]
): Array<T & { subtree_mem_mb: number; subtree_cpu: number }> {
  const nodes = rows.map((r) => ({ ...r, subtree_mem_mb: r.mem_mb, subtree_cpu: r.cpu }));
  const byPid = new Map<number, (typeof nodes)[number]>();
  for (const n of nodes) byPid.set(n.pid, n);

  const children = new Map<number, number[]>();
  for (const n of nodes) {
    if (n.ppid && n.ppid !== n.pid && byPid.has(n.ppid)) {
      const list = children.get(n.ppid);
      if (list) list.push(n.pid);
      else children.set(n.ppid, [n.pid]);
    }
  }

  const mark = new Map<number, 0 | 1 | 2>(); // 0/未访问 1/访问中 2/完成
  const visit = (pid: number) => {
    const n = byPid.get(pid);
    if (!n || mark.get(pid) === 1) return null; // 环路回边：跳过，不计入
    if (mark.get(pid) === 2) return n;
    mark.set(pid, 1);
    let mem = n.mem_mb;
    let cpu = n.cpu;
    for (const c of children.get(pid) || []) {
      const child = visit(c);
      if (child) {
        mem += child.subtree_mem_mb;
        cpu += child.subtree_cpu;
      }
    }
    n.subtree_mem_mb = mem;
    n.subtree_cpu = Math.round(cpu * 10) / 10;
    mark.set(pid, 2);
    return n;
  };
  for (const n of nodes) visit(n.pid);
  return nodes;
}

/* ============ 采集 ============ */

// docker ps 一次，建「12 位短 ID → 容器名」映射；超时 3s，失败静默返回空 Map（不影响其余进程）。
async function collectContainerNames(): Promise<Map<string, string>> {
  try {
    const { stdout } = await execAsync("docker ps --format '{{.ID}} {{.Names}}'", {
      encoding: 'utf-8',
      timeout: 3000
    });
    return parseDockerPs(stdout);
  } catch {
    return new Map();
  }
}

// 采集全部进程（不再截断为 TOP15）：
// - 命名：pid 命中 systemd 主进程映射 → 服务名；containerd shim → 容器名（前缀匹配，失败回退 comm）；
//   其余按 comm/args 兜底分类。
// - CPU：统一走 collectAllProcCpu() 的单次 /proc 全量遍历，各进程 cpu 取 perPid.get(pid)、
//   total_cpu 取 totalPct，同一请求内同源同差分基准；pid 缺失时用 ps pcpu 兜底。
// - 安全上限 500：按内存降序截断并标 truncated；count / total_mem_mb 均为截断前全量口径。
// 返回 { processes, count, truncated, total_mem_mb, total_cpu }。
async function collectProcesses(): Promise<{
  processes: ProcNode[];
  count: number;
  truncated: boolean;
  total_mem_mb: number;
  total_cpu: number;
}> {
  // 延迟加载（见文件头说明）：仅在真正采集时拉起 system/services 依赖
  const { collectAllProcCpu } = require('../probe/system.ts') as {
    collectAllProcCpu: () => { perPid: Map<number, number>; totalPct: number };
  };
  const { SYSTEMD_SERVICES } = require('../probe/services.ts') as {
    SYSTEMD_SERVICES: string[];
  };

  // 1. systemd 正规化：逐服务查 MainPID，非 0 记录 pid→服务名映射（并发查询，全部结束后再采样）
  const pidToService = new Map<number, string>();
  const systemdTask = Promise.allSettled(
    SYSTEMD_SERVICES.map(async (svc) => {
      try {
        const { stdout } = await execAsync(`systemctl show ${svc} -p MainPID --value`, {
          encoding: 'utf-8',
          timeout: 3000
        });
        const pid = parseInt(stdout.trim(), 10);
        if (pid > 0) pidToService.set(pid, svc);
      } catch (e: any) {
        // 单位不存在/查询失败：跳过，该进程走兜底分类
      }
    })
  );

  // 2. 等 systemd 查询全部结束再采样：避免把上面并发拉起的 systemctl 子进程计入进程表
  await systemdTask;

  // 3. 单次遍历 /proc 全部进程差分：perPid 与 totalPct 同源（此后再不单独差分）
  const { perPid, totalPct } = collectAllProcCpu();

  // 4. ps 全量（新增 ppid，去掉 head/tail）：--sort=-rss 保持内存降序。
  //    comm 定宽 16 列（comm:16），解析按位对齐，避免 comm 含空格时列错位（见 PS_LINE_RE）
  let rows: ProcRow[] = [];
  try {
    const out = execSync('ps -eo pid=,ppid=,comm:16=,rss=,pcpu=,args= --sort=-rss', {
      encoding: 'utf-8'
    });
    rows = parsePsOutput(out);
  } catch {
    rows = [];
  }

  // 5. 仅当存在 containerd shim 时才查 docker（一次，3s 超时，失败静默回退 comm）。
  //    放在 ps 之后：docker 自身进程不会被上面的 ps 快照计入。
  const containerMap = rows.some((r) => /^containerd-shim/.test(r.comm))
    ? await collectContainerNames()
    : new Map<string, string>();

  // 5. 截断 + 合计（先用带 rss_kb 的原始行，保证 total_mem_mb 与 ps 实测同口径），
  //    再对保留下来的行做命名 + CPU 覆盖 + 子树合计
  const { processes: kept, count, truncated, total_mem_mb } = summarizeProcesses(rows, MAX_PROCESS_ROWS);
  const named: Array<Omit<ProcNode, 'subtree_mem_mb' | 'subtree_cpu'>> = kept.map((r) => ({
    name: resolveProcessName(r, pidToService, containerMap),
    pid: r.pid,
    ppid: r.ppid,
    mem_mb: r.mem_mb,
    cpu: perPid.has(r.pid) ? (perPid.get(r.pid) as number) : r.cpu
  }));

  return {
    processes: buildProcessTree(named),
    count,
    truncated,
    total_mem_mb,
    total_cpu: totalPct
  };
}

module.exports = {
  collectProcesses,
  parsePsOutput,
  resolveProcessName,
  extractShimContainerId,
  parseDockerPs,
  matchContainerName,
  summarizeProcesses,
  buildProcessTree,
  MAX_PROCESS_ROWS
};
