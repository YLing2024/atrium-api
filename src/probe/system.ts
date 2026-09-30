'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:os';

/**
 * 主机系统采样：CPU / 内存 / 磁盘 / 网络 / 磁盘 I/O / PSI / 进程瞬时 CPU。
 * 是 /system 与 /system/stream 的数据源；采样状态统一从 state.ts 读取。
 */

const fs = require('fs') as typeof import('fs');
const os = require('os') as typeof import('os');
const { execSync } = require('child_process') as typeof import('child_process');

const { ema } = require('../util.ts') as {
  ema: (prev: number | null | undefined, current: number, alpha: number) => number;
};
const state = require('../state.ts') as {
  netState: { ts: number; rx: number; tx: number };
  diskioState: { ts: number; read: number; write: number };
  samplerState: {
    cpuPerCoreState: Record<number, { total: number; idle: number }> | null;
    totalEmaPrev: number | null;
  };
  procCpuSample: Map<number, { cpu: number; total: number }>;
  procCpuEma: Map<number, number>;
  CPU_EMA_ALPHA: number;
};

/* ============ 系统信息采集 ============ */

// CPU 采样：累加各核 times
function cpuSample() {
  let idle = 0;
  let total = 0;
  for (const cpu of os.cpus()) {
    for (const t of Object.values(cpu.times)) total += t;
    idle += cpu.times.idle;
  }
  return { idle, total };
}

// 每核 CPU 展示上限：最多返回 MAX_CORES 项（超出截断；cores 字段仍报真实核数）
const MAX_CORES = 8;

// 每核 CPU 占用：读 /proc/stat 的 cpuN 行，累加 user/nice/system/idle/iowait/irq/softirq/steal，
// 与上次采样做差按 (Δtotal − Δidle) / Δtotal × 100 计算（内核口径，含内核与 IO 等待时间）。
// 读取失败时返回空数组，不影响接口。
function cpuPerCoreSample() {
  const cores = [];
  try {
    const lines = fs.readFileSync('/proc/stat', 'utf-8').split('\n');
    const cur = [];
    for (const line of lines) {
      if (!/^cpu\d+\s/.test(line)) continue;
      const cols = line.trim().split(/\s+/);
      const fields = cols.slice(1).map((v) => parseInt(v, 10) || 0);
      if (fields.length < 8) continue;
      cur.push({
        id: parseInt(cols[0].slice(3), 10),
        total: fields.slice(0, 8).reduce((a, b) => a + b, 0),
        idle: fields[3] + fields[4] // idle + iowait
      });
    }
    for (const c of cur.slice(0, MAX_CORES)) {
      let usage = 0;
      const prev = state.samplerState.cpuPerCoreState && state.samplerState.cpuPerCoreState[c.id];
      const dt = prev ? c.total - prev.total : 0;
      if (dt > 0) usage = ((dt - (c.idle - prev!.idle)) / dt) * 100;
      usage = Math.max(0, Math.min(100, usage));
      cores.push({ id: c.id, usage_percent: Math.round(usage * 10) / 10 });
    }
    state.samplerState.cpuPerCoreState = {};
    for (const c of cur) state.samplerState.cpuPerCoreState[c.id] = c;
  } catch (e: any) {
    // /proc/stat 读取失败时返回空数组
    return [];
  }
  return cores;
}

// 系统卡片 CPU = 全部进程瞬时 CPU 合计（进程合计占用，不含内核/IO），与进程排行同一套算法
function getCpuInfo() {
  const cpus = os.cpus();
  const { totalPct } = collectAllProcCpu();
  return {
    model: cpus[0] ? cpus[0].model.trim() : 'unknown',
    usage_percent: totalPct,
    cores: cpus.length,
    per_core: cpuPerCoreSample(),
    loadavg: os.loadavg()
  };
}

// 磁盘（多盘）：解析 df -kP，返回所有真实挂载的设备盘（filesystem 以 /dev/ 开头，
// 排除 tmpfs/udev/overlay 等伪文件系统），跳过 /boot、/boot/efi 系统分区；
// 单位字节，df 失败时返回空数组。
function getDisks() {
  const disks = [];
  try {
    const out = execSync('df -kP', { encoding: 'utf-8' }).trim().split('\n');
    for (const line of out.slice(1)) {
      const cols = line.split(/\s+/);
      if (cols.length < 6) continue;
      const filesystem = cols[0];
      const mount = cols.slice(5).join(' '); // 挂载点可能含空格
      if (!filesystem.startsWith('/dev/')) continue;
      if (mount === '/boot' || mount === '/boot/efi') continue;
      disks.push({
        filesystem,
        mount,
        total: parseInt(cols[1], 10) * 1024,
        used: parseInt(cols[2], 10) * 1024,
        free: parseInt(cols[3], 10) * 1024,
        percent: parseInt(String(cols[4]).replace('%', ''), 10) || 0
      });
    }
  } catch (e: any) {
    // df 失败时返回空数组
  }

  return disks;
}

// 磁盘（单盘兼容）：旧字段 disk 只取挂载点为 '/' 的盘，内部复用 getDisks()，
// 找不到时保持全 0（该字段/形状可能被前端旧代码与其它分支引用）。
function getDisk() {
  const disk = { total: 0, used: 0, free: 0, percent: 0 };
  const root = getDisks().find((d) => d.mount === '/');
  if (root) {
    disk.total = root.total;
    disk.used = root.used;
    disk.free = root.free;
    disk.percent = root.percent;
  }
  return disk;
}

// 网速采样：累加 /proc/net/dev 所有接口的 rx_bytes / tx_bytes
function netSample() {
  let rx = 0;
  let tx = 0;
  try {
    const lines = fs.readFileSync('/proc/net/dev', 'utf-8').trim().split('\n');
    for (const line of lines.slice(2)) {
      const idx = line.indexOf(':');
      if (idx === -1) continue;
      const stats = line.slice(idx + 1).trim().split(/\s+/);
      if (stats.length < 9) continue;
      rx += parseInt(stats[0], 10) || 0;
      tx += parseInt(stats[8], 10) || 0;
    }
  } catch (e: any) {
    // /proc/net/dev 读取失败时保留 0
  }
  return { rx, tx };
}

// 磁盘 I/O 采样：读 /proc/diskstats，取主盘设备（sda/vda 等，不含分区），
// 扇区读/写字段（第 6、10 列）×512 得字节
function diskioSample() {
  let read = 0;
  let write = 0;
  try {
    const lines = fs.readFileSync('/proc/diskstats', 'utf-8').trim().split('\n');
    for (const line of lines) {
      const cols = line.trim().split(/\s+/);
      if (cols.length < 11) continue;
      const name = cols[2];
      // 主盘设备名形如 sd[a-z]/vd[a-z]/hd[a-z]（无分区数字后缀），分区 minor > 0 排除
      if (!/^(sd[a-z]|vd[a-z]|hd[a-z])$/.test(name)) continue;
      if (parseInt(cols[1], 10) !== 0) continue;
      read += parseInt(cols[5], 10) * 512 || 0;
      write += parseInt(cols[9], 10) * 512 || 0;
    }
  } catch (e: any) {
    // /proc/diskstats 读取失败时保留 0
  }
  return { read, write };
}

// 进程数：解析 /proc/loadavg 第 4 列 running/total
function getProcesses() {
  const proc = { running: 0, total: 0 };
  try {
    const cols = fs.readFileSync('/proc/loadavg', 'utf-8').trim().split(/\s+/);
    if (cols.length >= 4) {
      const m = cols[3].split('/');
      proc.running = parseInt(m[0], 10) || 0;
      proc.total = parseInt(m[1], 10) || 0;
    }
  } catch (e: any) {
    // 读取失败时保留 0
  }
  return proc;
}

// 网络：本次采样与上次采样做差，按时间差换算字节/秒；首次请求速率返回 0
function getNetInfo() {
  const cur = netSample();
  const now = Date.now();
  const dt = (now - state.netState.ts) / 1000;
  const info = {
    rx_bytes: cur.rx,
    tx_bytes: cur.tx,
    rx_rate: 0,
    tx_rate: 0
  };
  if (state.netState.ts && dt > 0) {
    info.rx_rate = Math.max(0, (cur.rx - state.netState.rx) / dt);
    info.tx_rate = Math.max(0, (cur.tx - state.netState.tx) / dt);
  }
  state.netState.ts = now;
  state.netState.rx = cur.rx;
  state.netState.tx = cur.tx;
  return info;
}

// 磁盘 I/O：同上，返回读/写速率（字节/秒）
function getDiskIoInfo() {
  const cur = diskioSample();
  const now = Date.now();
  const dt = (now - state.diskioState.ts) / 1000;
  const info = {
    read_bytes: cur.read,
    write_bytes: cur.write,
    read_rate: 0,
    write_rate: 0
  };
  if (state.diskioState.ts && dt > 0) {
    info.read_rate = Math.max(0, (cur.read - state.diskioState.read) / dt);
    info.write_rate = Math.max(0, (cur.write - state.diskioState.write) / dt);
  }
  state.diskioState.ts = now;
  state.diskioState.read = cur.read;
  state.diskioState.write = cur.write;
  return info;
}

// 解析 /proc/meminfo（单位 kB → bytes）。任一字段缺失回退 os.*，整体失败回退全部 os.*。
// 现文件若干函数直接读 /proc，此处同样直接读文件（fs.existsSync + try/catch 容错，代价可忽略）。
// 返回 { total, used, free, available, buffCache, swapTotal, swapUsed, swapFree, swapPercent }
// 其中 used = 真实占用（= total − available），不含内核可回收的页缓存/缓冲；
// 过去用的 total − free 会把页缓存算成已用，导致面板虚高（本机实测 90% vs 真实 71%）。
function readMeminfo() {
  let info: Record<string, number> = {};
  try {
    if (fs.existsSync('/proc/meminfo')) {
      const text = fs.readFileSync('/proc/meminfo', 'utf-8');
      for (const line of text.split('\n')) {
        const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
        if (m) info[m[1]] = parseInt(m[2], 10) * 1024;
      }
    }
  } catch (e: any) {
    info = {};
  }
  const fallbackTotal = os.totalmem();
  const fallbackFree = os.freemem();
  const total = info.MemTotal || fallbackTotal;
  const free = info.MemFree != null ? info.MemFree : fallbackFree;
  const available = info.MemAvailable != null ? info.MemAvailable : null;
  const buffCache =
    info.Buffers != null && info.Cached != null ? info.Buffers + info.Cached : null;
  const swapTotal = info.SwapTotal != null ? info.SwapTotal : 0;
  const swapFree = info.SwapFree != null ? info.SwapFree : 0;
  // used 优先取 total − MemAvailable：MemAvailable 已扣除可回收的页缓存/缓冲，
  // 是内核给出的"还能给新进程用多少"的估算；缺失时回退旧口径 total − free。
  const used = available != null ? total - available : total - free;
  const swapUsed = swapTotal - swapFree;
  return {
    total,
    used,
    free,
    available,
    buffCache,
    swapTotal,
    swapUsed,
    swapFree,
    swapPercent: swapTotal > 0 ? Math.round((swapUsed / swapTotal) * 1000) / 10 : 0
  };
}

// zram 明细：扫描 /sys/block/zram*，磁盘挂 zram 设备时返回首选压缩设备（zram0），
// 其余（zram1/zram2…）仅并入总 swap（来自 /proc/meminfo）。无 zram 返回 null，不影响主流程。
function getZram() {
  try {
    const blocks = fs.readdirSync('/sys/block');
    const zramDevs = blocks.filter((name) => /^zram\d+$/.test(name)).sort();
    if (!zramDevs.length) return null;

    const comp = zramDevs[0]; // 主压缩设备（zram0）
    const readInt = (f: string): number => {
      try {
        return parseInt(fs.readFileSync(`/sys/block/${comp}/${f}`, 'utf-8').trim(), 10) || 0;
      } catch (e: any) {
        return 0;
      }
    };
    let algorithm = null;
    try {
      const raw = fs
        .readFileSync(`/sys/block/${comp}/comp_algorithm`, 'utf-8')
        .trim();
      const mm = raw.match(/\[([^\]]+)\]/);
      algorithm = (mm ? mm[1] : raw.trim()) || null;
    } catch (e: any) {
      // 读取失败则 algorithm 保持 null
    }
    // mm_stat 的列定义（Linux zram 文档）：orig_data_size compr_data_size mem_used_total mem_limit
    // mem_used_limit mem_used_max same_pages pages_compacted huge_pages。内核版本差异时 try/catch 兜底为 0。
    let orig = 0;
    let compr = 0;
    let used = 0;
    try {
      const cols = fs.readFileSync(`/sys/block/${comp}/mm_stat`, 'utf-8').trim().split(/\s+/);
      if (cols.length >= 3) {
        orig = parseInt(cols[0], 10) || 0;
        compr = parseInt(cols[1], 10) || 0;
        used = parseInt(cols[2], 10) || 0;
      }
    } catch (e: any) {
      orig = 0;
      compr = 0;
      used = 0;
    }
    // comprSize：有 mm_stat 用 compr_data_size；老内核无该文件时回退 mem_used_total（含元数据，近似值）
    const comprSize = compr || readInt('mem_used_total') || used;
    return {
      total: readInt('disksize') || 0,
      used,
      origSize: orig || 0,
      comprSize,
      algorithm
    };
  } catch (e: any) {
    return null;
  }
}

// 解析单个 /proc/pressure/<type> 文件（格式：`some avg10=.. avg60=.. avg300=.. total=..` + full 行）。
// 文件不存在/解析失败（老内核或容器无 PSI）返回 null，不影响主流程。
function parsePressureFile(type: string) {
  try {
    if (!fs.existsSync(`/proc/pressure/${type}`)) return null;
    const text = fs.readFileSync(`/proc/pressure/${type}`, 'utf-8');
    const res: Record<string, { avg10: number; avg60: number; avg300: number; total: number }> = {};
    for (const line of text.split('\n')) {
      const m = line
        .trim()
        .match(/^(some|full)\s+avg10=([\d.]+)\s+avg60=([\d.]+)\s+avg300=([\d.]+)\s+total=(\d+)/);
      if (!m) continue;
      res[m[1]] = {
        avg10: parseFloat(m[2]),
        avg60: parseFloat(m[3]),
        avg300: parseFloat(m[4]),
        total: parseInt(m[5], 10)
      };
    }
    return res.some && res.full ? res : null;
  } catch (e: any) {
    return null;
  }
}

// PSI（Pressure Stall Information）：进程因等内存/CPU/IO 被 stall 的时间占比。
// some=至少一个任务被 stall，full=所有任务都被 stall（更严重）；avg 为滑动平均百分比，total 为累计微秒。
// 返回 { memory, cpu, io }，各自 { some, full } 或 null（无 PSI 的资源）
function readPressure() {
  return {
    memory: parsePressureFile('memory'),
    cpu: parsePressureFile('cpu'),
    io: parsePressureFile('io')
  };
}

// 采集系统信息（CPU 需 ~1s 双采样）
async function collectSystem() {
  const mem = readMeminfo();
  // 内存 percent = 真实占用 (total − available) / total，口径与 free -h 的 available 一致，
  // 不再把可回收的页缓存算成已用；历史曲线会因此整体下移（预期变化）。
  const percent = mem.total > 0 ? Math.round((mem.used / mem.total) * 1000) / 10 : 0;
  return {
    cpu: getCpuInfo(),
    memory: {
      total: mem.total,
      used: mem.used,
      free: mem.free,
      percent,
      buffCache: mem.buffCache,
      available: mem.available,
      swapTotal: mem.swapTotal,
      swapUsed: mem.swapUsed,
      swapFree: mem.swapFree,
      swapPercent: mem.swapPercent,
      zram: getZram()
    },
    disk: getDisk(),
    disks: getDisks(),
    network: getNetInfo(),
    disk_io: getDiskIoInfo(),
    processes: getProcesses(),
    psi: readPressure(),
    uptime: os.uptime(),
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    hostname: os.hostname()
  };
}

/* ============ 历史采样用到的原始量 ============ */

// 内存使用率（百分比，一位小数）—— 真实占用口径：total − MemAvailable
// 与 collectSystem()/free -h 的 available 一致（不含可回收的页缓存）
function memPercent() {
  try {
    const text = fs.readFileSync('/proc/meminfo', 'utf-8');
    const kv: Record<string, number> = {};
    for (const line of text.split('\n')) {
      const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
      if (m) kv[m[1]] = parseInt(m[2], 10) * 1024;
    }
    if (kv.MemTotal > 0 && kv.MemAvailable != null) {
      return Math.round(((kv.MemTotal - kv.MemAvailable) / kv.MemTotal) * 1000) / 10;
    }
  } catch (e: any) {
    // /proc/meminfo 不可读时走下面回退
  }
  const total = os.totalmem();
  if (total <= 0) return 0;
  return Math.round(((total - os.freemem()) / total) * 1000) / 10;
}

// swap 使用率（百分比，一位小数）：/proc/meminfo SwapTotal/SwapFree（含 zram+file+分区）；
// 解析失败或总 swap 为 0 返回 0，不影响历史采样
function swapPercent() {
  try {
    const info: Record<string, number> = {};
    const text = fs.readFileSync('/proc/meminfo', 'utf-8');
    for (const line of text.split('\n')) {
      const m = line.match(/^(\w+):\s+(\d+)\s*kB/);
      if (m) info[m[1]] = parseInt(m[2], 10) * 1024;
    }
    const total = info.SwapTotal || 0;
    const free = info.SwapFree != null ? info.SwapFree : 0;
    if (total <= 0) return 0;
    return Math.round(((total - free) / total) * 1000) / 10;
  } catch (e: any) {
    return 0;
  }
}

// PSI 历史取值：memory/cpu/io 的 some avg10（percent，native 已是滑动均值）
function psiHistPoint() {
  const p = readPressure();
  const avg = (o: Record<string, { avg10: number }> | null) => (o && o.some && Number.isFinite(o.some.avg10) ? o.some.avg10 : null);
  return { psi_mem_avg10: avg(p.memory), psi_cpu_avg10: avg(p.cpu), psi_io_avg10: avg(p.io) };
}

/* ============ 进程瞬时 CPU（系统卡片与进程排行共用） ============ */

// 读 /proc/<pid>/stat，返回进程已用 CPU ticks（utime+stime，字段 14/15）；
// 进程名可能含空格，取最后一个 ')' 后的字段再按空格分割，字段 3 起偏移 3
function procCpuTicks(pid: number): number | null {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf-8');
    const close = stat.lastIndexOf(')');
    if (close === -1) return null;
    const rest = stat.slice(close + 1).trim().split(/\s+/);
    // rest[0]=字段3(state)，字段14 utime → rest[11]，字段15 stime → rest[12]
    const utime = parseInt(rest[11], 10) || 0;
    const stime = parseInt(rest[12], 10) || 0;
    return utime + stime;
  } catch (e: any) {
    return null; // /proc/<pid> 不存在或读取失败
  }
}

// 读 /proc/stat 第一行（cpu 开头），字段 2-5 user+nice+system+idle 求和为系统总时间
function procTotalTicks() {
  try {
    const first = fs.readFileSync('/proc/stat', 'utf-8').split('\n')[0];
    const cols = first.trim().split(/\s+/);
    if (cols[0] !== 'cpu' || cols.length < 5) return null;
    return (
      (parseInt(cols[1], 10) || 0) +
      (parseInt(cols[2], 10) || 0) +
      (parseInt(cols[3], 10) || 0) +
      (parseInt(cols[4], 10) || 0)
    );
  } catch (e: any) {
    return null;
  }
}

// 单次遍历 /proc/[pid]（仅数字目录），对每个 pid 用 procCpuSample Map 做差分（复用
// procCpuTicks/procTotalTicks）得到原始瞬时值后，perPid 与 totalPct 均走统一 EMA 平滑
// （ema(prev,current,CPU_EMA_ALPHA)），输出保留一位小数，避免 0/100 跳变。
// 首次采样（pid 无上一轮状态）无差值：pct 记为 0（collectProcesses 对不在遍历结果内的
// pid 再用 ps pcpu 兜底）。返回值 { perPid: Map<pid, pct>, totalPct }。
function collectAllProcCpu() {
  const curTotal = procTotalTicks();
  const perPid = new Map();
  if (curTotal === null) return { perPid, totalPct: 0 };
  let names;
  try {
    names = fs.readdirSync('/proc');
  } catch (e: any) {
    return { perPid, totalPct: 0 };
  }
  let sumTicks = 0;
  let dTotal = 0;
  let hasPrev = false;
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue; // 仅数字目录（进程 pid）
    const pid = parseInt(name, 10);
    const curCpu = procCpuTicks(pid);
    if (curCpu === null) {
      state.procCpuSample.delete(pid); // 进程已退出：清采样与平滑缓存
      state.procCpuEma.delete(pid);
      continue;
    }
    const last = state.procCpuSample.get(pid);
    let pct = 0;
    if (last && curTotal > last.total) {
      const dCpu = curCpu - last.cpu;
      if (dCpu >= 0) {
        sumTicks += dCpu;
        if (!dTotal) dTotal = curTotal - last.total; // 系统总时间差值，本轮全局一致
        pct = (dCpu / dTotal) * 100; // 原始瞬时占用（未舍入）
        hasPrev = true;
      }
    }
    state.procCpuSample.set(pid, { cpu: curCpu, total: curTotal });
    // 每个 pid 走统一 EMA 平滑（同函数同 alpha），输出保留一位小数
    const smoothed = ema(state.procCpuEma.get(pid), pct, state.CPU_EMA_ALPHA);
    state.procCpuEma.set(pid, smoothed);
    perPid.set(pid, Math.round(smoothed * 10) / 10);
  }
  let totalPct = 0;
  if (hasPrev && dTotal > 0) {
    // 总占用走统一 EMA（对原始瞬时总占用平滑，与各进程同函数同 alpha）
    const smoothed = ema(state.samplerState.totalEmaPrev, (sumTicks / dTotal) * 100, state.CPU_EMA_ALPHA);
    state.samplerState.totalEmaPrev = smoothed;
    totalPct = Math.round(smoothed * 10) / 10;
  }
  return { perPid, totalPct };
}

module.exports = {
  cpuSample,
  cpuPerCoreSample,
  getCpuInfo,
  getDisks,
  getDisk,
  netSample,
  diskioSample,
  getProcesses,
  getNetInfo,
  getDiskIoInfo,
  readMeminfo,
  getZram,
  readPressure,
  collectSystem,
  memPercent,
  swapPercent,
  psiHistPoint,
  collectAllProcCpu
};
