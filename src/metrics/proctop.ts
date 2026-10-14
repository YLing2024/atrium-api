'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:child_process';

/**
 * 进程排行：全量进程 + 瞬时 CPU（与系统卡片同一套 /proc 差分与 EMA 平滑）。
 * 2026-10-13 改造：不再截断成「内存 TOP15」，改为返回全部进程，单行补 ppid 与
 *   subtree_mem_mb / subtree_cpu（该节点含全部后代的和），供前端构树。
 * 2026-10-14 修正：
 *   - 硬上限 500 → 2000，并支持 ADMIN_PROC_MAX_ROWS 覆盖（非法值回退默认）；
 *   - 新增解析计数（parsed_count / skipped_count），解析失败不再静默丢弃；
 *   - 单行新增 subtree_count（服务端算好，前端不再自己数）与 cgroup_mem_mb
 *     （仅 systemd 单位主进程行有值，取该单位 cgroup 真值，取不到为 null）；
 *   - 顶层新增 total_cgroup_mb（system.slice 的 cgroup 真值）。
 * 2026-10-14 第二轮：
 *   - 单行新增 thread_count（该进程线程数，读 /proc/<pid>/task 条目数，读不到为 null），
 *     顶层新增 total_threads（全部进程线程数之和，截断前口径）——面板进程数与 htop/btop
 *     的线程数口径差异需要并列给用户看，两者不得混算。
 */

const { exec, execSync } = require('child_process') as typeof import('child_process');
const { promisify } = require('util') as typeof import('util');
const fs = require('fs') as typeof import('fs');

const execAsync = promisify(exec);

// 注意：collectAllProcCpu（probe/system.ts）与 SYSTEMD_SERVICES（probe/services.ts）在模块顶层
// require 会连带加载 state.ts，进而在 import 时就建立 Redis 连接（测试进程会因此挂住）。
// 为让本模块可被单测安全 import（纯函数不触碰 ps/docker/Redis），这两个依赖延迟到 collectProcesses
// 内首次调用时再 require（CJS require 有缓存，重复调用无额外开销）。

// 安全上限默认值：全量进程正常规模在数百条，硬上限兜底极端环境下响应体过大。
// 2026-10-14 由 500 提升到 2000（500 曾把极端环境下的全量进程截断，用户会以为「漏进程」）。
const DEFAULT_MAX_PROCESS_ROWS = 2000;

// 解析 ADMIN_PROC_MAX_ROWS：只接受纯正整数字符串（'0' / '-1' / '12abc' / 空 均视为非法），
// 非法或未设置一律回退 fallback。抽成纯函数以便单测（环境变量是外部输入，绝不采信）。
function resolveMaxProcessRows(raw: unknown, fallback = DEFAULT_MAX_PROCESS_ROWS): number {
  const s = String(raw == null ? '' : raw).trim();
  if (!/^\d+$/.test(s)) return fallback;
  const n = Number(s);
  return Number.isSafeInteger(n) && n > 0 ? n : fallback;
}

const MAX_PROCESS_ROWS = resolveMaxProcessRows(process.env.ADMIN_PROC_MAX_ROWS);

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

// 对外响应的一行：内存自身 RSS / CPU 自身，子树字段为含全部后代的和。
// cgroup_mem_mb 仅当该行是 systemd 单位主进程时为该单位 cgroup 真值，否则 null
// （口径见 docs/API.md：cgroup 含页缓存，与 RSS 不可比）。
type ProcNode = {
  name: string;
  pid: number;
  ppid: number;
  mem_mb: number;
  cpu: number;
  subtree_mem_mb: number;
  subtree_cpu: number;
  subtree_count: number;
  cgroup_mem_mb: number | null;
  // 该进程线程数（/proc/<pid>/task 条目数）；进程已退出 / 读不到为 null（绝不猜 0）。
  thread_count: number | null;
};

/* ============ 纯函数（供单测直接调用，不触碰真实 ps / docker） ============ */

// ps 文本 → 行数组。列序 pid,ppid,comm,rss,pcpu,args，其中 comm 定宽 16 列（见 PS_LINE_RE）。
// rss 单位 kB → mem_mb 取整；pcpu 直接作为 cpu 兜底（collectProcesses 再用 /proc 差分结果覆盖）。
// 解析计数：空行不计；非空但格式不符的行计入 skipped_count（此前是静默丢弃，无法自证完整）。
function parsePsOutputWithStats(text: string): {
  rows: ProcRow[];
  parsed_count: number;
  skipped_count: number;
} {
  const rows: ProcRow[] = [];
  let skipped_count = 0;
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    const m = PS_LINE_RE.exec(line);
    if (!m) {
      skipped_count += 1;
      continue;
    }
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
  return { rows, parsed_count: rows.length, skipped_count };
}

// 兼容入口：只返回行数组（既有调用方与单测语义不变）
function parsePsOutput(text: string): ProcRow[] {
  return parsePsOutputWithStats(text).rows;
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

// cgroup 内存真值解析：cgroup v2 memory.current / systemctl MemoryCurrent 都是十进制字节。
// → MB 整数；空、'[not set]'、'infinity'、负数、超出安全整数的哨兵值一律 null（绝不猜）。
function parseCgroupBytesToMb(raw: unknown): number | null {
  const s = String(raw == null ? '' : raw).trim();
  if (!s || s === '[not set]') return null;
  const n = Number(s);
  if (!Number.isFinite(n) || n < 0 || n > Number.MAX_SAFE_INTEGER) return null;
  return Math.round(n / 1024 / 1024);
}

// systemd 单元名规范化：裸名（如 'admin-server'）补 '.service'；已带已知后缀的保持原样。
function serviceUnitName(name: unknown): string {
  const s = String(name == null ? '' : name).trim();
  if (!s) return s;
  return /\.(service|socket|slice|target|mount|timer|path|scope|device)$/.test(s)
    ? s
    : s + '.service';
}

// 单元 cgroup 内存文件路径：优先 cgroup v2 真值文件。
// 服务单元 → /sys/fs/cgroup/system.slice/<unit>.service/memory.current；
// slice 自身 → /sys/fs/cgroup/<slice>/memory.current。
function cgroupMemoryPath(name: unknown, slice = 'system.slice'): string {
  const unit = serviceUnitName(name);
  if (unit.endsWith('.slice')) return `/sys/fs/cgroup/${unit}/memory.current`;
  return `/sys/fs/cgroup/${slice}/${unit}/memory.current`;
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
// 节点子树合计 = 自身 + 全部后代之和；subtree_count = 含自身的后代进程数。
// 对异常环路做保护（回边直接跳过），保证绝不无限递归。
function buildProcessTree<T extends { pid: number; ppid: number; mem_mb: number; cpu: number }>(
  rows: T[]
): Array<T & { subtree_mem_mb: number; subtree_cpu: number; subtree_count: number }> {
  const nodes = rows.map((r) => ({
    ...r,
    subtree_mem_mb: r.mem_mb,
    subtree_cpu: r.cpu,
    subtree_count: 1
  }));
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
    let count = 1;
    for (const c of children.get(pid) || []) {
      const child = visit(c);
      if (child) {
        mem += child.subtree_mem_mb;
        cpu += child.subtree_cpu;
        count += child.subtree_count;
      }
    }
    n.subtree_mem_mb = mem;
    n.subtree_cpu = Math.round(cpu * 10) / 10;
    n.subtree_count = count;
    mark.set(pid, 2);
    return n;
  };
  for (const n of nodes) visit(n.pid);
  return nodes;
}

// /proc/<pid>/task 的目录条目 → 该进程线程数。条目名即 tid（数字）；非数字项（异常/竞态残留）不计。
// 读到目录（哪怕是空目录）返回条目数；entries 非数组（目录不存在 / 权限不足 / 进程已退出）→ null，
// 绝不猜 0——0 线程的进程不存在，猜 0 会让总数偏小且无法自证。
function parseThreadCount(entries: unknown): number | null {
  if (!Array.isArray(entries)) return null;
  let n = 0;
  for (const e of entries) if (/^\d+$/.test(String(e))) n += 1;
  return n;
}

// 顶层线程总数：各行 thread_count 之和；null（读不到）的行跳过，不按 0 计入（保证总数只少不多、不被污染）。
function sumThreads(rows: ReadonlyArray<{ thread_count?: number | null }>): number {
  let n = 0;
  for (const r of rows) if (typeof r.thread_count === 'number') n += r.thread_count;
  return n;
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

// 读一个 systemd 单位的 cgroup 内存真值（bytes→MB）：优先 cgroup v2 真值文件，
// 回退 `systemctl show <unit> -p MemoryCurrent --value`；任何失败 → null（绝不猜）。
async function readCgroupMb(name: string): Promise<number | null> {
  try {
    const mb = parseCgroupBytesToMb(fs.readFileSync(cgroupMemoryPath(name), 'utf-8'));
    if (mb != null) return mb;
  } catch (e: any) {
    // 文件缺失/不可读 → 走 systemctl 回退
  }
  try {
    const { stdout } = await execAsync(
      `systemctl show ${serviceUnitName(name)} -p MemoryCurrent --value`,
      { encoding: 'utf-8', timeout: 3000 }
    );
    return parseCgroupBytesToMb(stdout);
  } catch {
    return null;
  }
}

// 读一个进程的线程数（/proc/<pid>/task 条目数）：进程已退出 / 权限不足 / 目录不存在 → null（绝不猜）。
function readThreadCount(pid: number): number | null {
  try {
    return parseThreadCount(fs.readdirSync('/proc/' + pid + '/task'));
  } catch {
    return null;
  }
}

// 采集全部进程（不再截断为 TOP15）：
// - 命名：pid 命中 systemd 主进程映射 → 服务名；containerd shim → 容器名（前缀匹配，失败回退 comm）；
//   其余按 comm/args 兜底分类。
// - CPU：统一走 collectAllProcCpu() 的单次 /proc 全量遍历，各进程 cpu 取 perPid.get(pid)、
//   total_cpu 取 totalPct，同一请求内同源同差分基准；pid 缺失时用 ps pcpu 兜底。
// - 安全上限（默认 2000，可用 ADMIN_PROC_MAX_ROWS 覆盖）：按内存降序截断并标 truncated；
//   count / total_mem_mb 均为截断前全量口径。
// - cgroup 真值：仅对「主 PID 保留在结果里」的 systemd 单位逐单位取（并发），取不到为 null。
// 返回 { processes, count, truncated, total_mem_mb, total_cpu, parsed_count, skipped_count, total_cgroup_mb, total_threads }。
async function collectProcesses(): Promise<{
  processes: ProcNode[];
  count: number;
  truncated: boolean;
  total_mem_mb: number;
  total_cpu: number;
  parsed_count: number;
  skipped_count: number;
  total_cgroup_mb: number | null;
  total_threads: number;
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
  let parsedCount = 0;
  let skippedCount = 0;
  try {
    const out = execSync('ps -eo pid=,ppid=,comm:16=,rss=,pcpu=,args= --sort=-rss', {
      encoding: 'utf-8'
    });
    const parsed = parsePsOutputWithStats(out);
    rows = parsed.rows;
    parsedCount = parsed.parsed_count;
    skippedCount = parsed.skipped_count;
  } catch {
    rows = [];
  }

  // 5. 线程数：读 /proc/<pid>/task 条目数。覆盖 ps 解析出的**全量**行（截断前），
  //    使 total_threads 与 `ps -eLf | wc -l` 同口径；读不到记 null。放在截断之前，
  //    这样被截断掉的行也计入线程总数（与 count / total_mem_mb 同为截断前口径）。
  const threadByPid = new Map<number, number | null>();
  for (const r of rows) threadByPid.set(r.pid, readThreadCount(r.pid));
  const total_threads = sumThreads(rows.map((r) => ({ thread_count: threadByPid.get(r.pid) ?? null })));

  // 6. 仅当存在 containerd shim 时才查 docker（一次，3s 超时，失败静默回退 comm）。
  //    放在 ps 之后：docker 自身进程不会被上面的 ps 快照计入。
  const containerMap = rows.some((r) => /^containerd-shim/.test(r.comm))
    ? await collectContainerNames()
    : new Map<string, string>();

  // 7. 截断 + 合计（先用带 rss_kb 的原始行，保证 total_mem_mb 与 ps 实测同口径）
  const { processes: kept, count, truncated, total_mem_mb } = summarizeProcesses(rows, MAX_PROCESS_ROWS);

  // 8. cgroup 真值：只对「主 PID 仍在 kept 里」的单位取（非主进程行不取，保持 null）。
  //    total_cgroup_mb 取 system.slice 整片真值。全部并发，任一失败 → null，绝不影响主响应。
  const keptPids = new Set(kept.map((r) => r.pid));
  const serviceUnits = [...pidToService.entries()].filter(([pid]) => keptPids.has(pid));
  const [totalCgroup, ...unitCgroups] = await Promise.all([
    readCgroupMb('system.slice'),
    ...serviceUnits.map(([, unit]) => readCgroupMb(unit))
  ]);
  const cgroupByPid = new Map<number, number | null>();
  serviceUnits.forEach(([pid], i) => cgroupByPid.set(pid, unitCgroups[i]));

  // 9. 命名 + CPU 覆盖 + cgroup/线程归属 → 构树（buildProcessTree 补 subtree_* / subtree_count）
  const named: Array<Omit<ProcNode, 'subtree_mem_mb' | 'subtree_cpu' | 'subtree_count'>> = kept.map(
    (r) => ({
      name: resolveProcessName(r, pidToService, containerMap),
      pid: r.pid,
      ppid: r.ppid,
      mem_mb: r.mem_mb,
      cpu: perPid.has(r.pid) ? (perPid.get(r.pid) as number) : r.cpu,
      cgroup_mem_mb: pidToService.has(r.pid) ? cgroupByPid.get(r.pid) ?? null : null,
      thread_count: threadByPid.get(r.pid) ?? null
    })
  );

  return {
    processes: buildProcessTree(named),
    count,
    truncated,
    total_mem_mb,
    total_cpu: totalPct,
    parsed_count: parsedCount,
    skipped_count: skippedCount,
    total_cgroup_mb: totalCgroup,
    total_threads
  };
}

module.exports = {
  collectProcesses,
  parsePsOutput,
  parsePsOutputWithStats,
  resolveProcessName,
  extractShimContainerId,
  parseDockerPs,
  matchContainerName,
  summarizeProcesses,
  buildProcessTree,
  parseCgroupBytesToMb,
  serviceUnitName,
  cgroupMemoryPath,
  resolveMaxProcessRows,
  parseThreadCount,
  sumThreads,
  DEFAULT_MAX_PROCESS_ROWS,
  MAX_PROCESS_ROWS
};
