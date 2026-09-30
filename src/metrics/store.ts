'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { MetricPoint } from '../state.ts';

/**
 * 长期留样写入 + 内存历史环形 buffer 与采样器生命周期。
 * 内存 buffer 落盘供多实例共享；写库失败只 warn，绝不拖累 SSE 与内存采样。
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const os = require('os') as typeof import('os');

const { ema } = require('../util.ts') as {
  ema: (prev: number | null | undefined, current: number, alpha: number) => number;
};
const state = require('../state.ts') as {
  historyBuffer: import('../state.ts').HistoryPoint[];
  HISTORY_MAX: number;
  HISTORY_INTERVAL_MS: number;
  CPU_EMA_ALPHA: number;
  samplerState: {
    histCpuPrev: { ts: number; idle: number; total: number } | null;
    histCpuEma: number | null;
    histNetPrev: { ts: number; rx: number; tx: number } | null;
    histDiskioPrev: { ts: number; read: number; write: number } | null;
  };
};
const probe = require('../probe/system.ts') as {
  cpuSample: () => { idle: number; total: number };
  netSample: () => { rx: number; tx: number };
  diskioSample: () => { read: number; write: number };
  readMeminfo: () => { used: number; total: number };
  memPercent: () => number;
  swapPercent: () => number;
  psiHistPoint: () => { psi_mem_avg10: number | null; psi_cpu_avg10: number | null; psi_io_avg10: number | null };
};
const db = require('../db.ts') as {
  openMetricsDb: () => import('node:sqlite').DatabaseSync | null;
  METRICS_RETENTION_SECONDS: number;
};
const { startAggregationScheduler } = require('../metrics/aggregate.ts') as {
  startAggregationScheduler: () => void;
};

/* ============ 历史采样（模块级环形 buffer） ============ */

// 历史数据落盘：多实例共享同一份数据（见 acquireSamplerLock），路由统一读文件返回
const HISTORY_FILE =
  process.env.ADMIN_HISTORY_FILE || path.join(os.tmpdir(), 'admin-server-history.json');

// 采样器锁文件：多个 admin-server 实例共存时只允许一个实例持有采样器，避免重复采样
const SAMPLER_LOCK_FILE =
  process.env.ADMIN_SAMPLER_LOCK || path.join(os.tmpdir(), 'admin-server-sampler.lock');

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: any) {
    return !!(e && e.code === 'EPERM'); // 进程存在但当前用户无权限探测
  }
}

// 尝试获取采样器独占锁（返回是否持有）。锁文件记录持有者 pid，
// 若 pid 已失效（进程退出/崩溃遗留的陈旧锁）则视为可抢占
function acquireSamplerLock() {
  try {
    if (fs.existsSync(SAMPLER_LOCK_FILE)) {
      const holder = parseInt(fs.readFileSync(SAMPLER_LOCK_FILE, 'utf-8').trim(), 10);
      if (holder && holder !== process.pid && isPidAlive(holder)) {
        return false; // 已有活跃实例持有采样器
      }
    }
    fs.writeFileSync(SAMPLER_LOCK_FILE, String(process.pid));
    return true;
  } catch (e: any) {
    return false;
  }
}

// 原子写历史文件（先写临时文件再 rename，避免读端读到半截内容）
function persistHistory() {
  try {
    const tmp = HISTORY_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(state.historyBuffer));
    fs.renameSync(tmp, HISTORY_FILE);
  } catch (e: any) {
    // 落盘失败不影响内存 buffer
  }
}

// 读取历史：优先从文件（多实例共享），文件不可用则退回本进程内存 buffer
function readHistory() {
  try {
    const raw = fs.readFileSync(HISTORY_FILE, 'utf-8');
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) return arr.slice(-state.HISTORY_MAX);
  } catch (e: any) {
    // 文件尚未生成/不可读：退回内存 buffer
  }
  return state.historyBuffer.slice(-state.HISTORY_MAX);
}

/* ============ 长期留样写入 ============ */

// 写入一个 raw 采样点（ts 用 epoch 秒）。任何异常只 warn，不抛出：
// 写库失败不能拖累现有 SSE 与内存采样。
function persistMetricPoint(point: MetricPoint): void {
  const conn = db.openMetricsDb();
  if (!conn) return;
  try {
    conn.prepare(
      'INSERT OR REPLACE INTO metrics (' +
        'ts, cpu, mem_percent, mem_used, mem_total, swap_percent,' +
        'psi_mem_avg10, psi_cpu_avg10, psi_io_avg10,' +
        'net_rx_rate, net_tx_rate, disk_io_read, disk_io_write' +
        ') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(
      Math.floor(point.ts / 1000),
      point.cpu,
      point.mem_percent,
      point.mem_used,
      point.mem_total,
      point.swap_percent,
      point.psi_mem_avg10,
      point.psi_cpu_avg10,
      point.psi_io_avg10,
      point.net_rx_rate,
      point.net_tx_rate,
      point.disk_io_read,
      point.disk_io_write
    );
    // 保留策略：每次写入顺手清理超过 3 天的 raw 点（ts 是主键，走 rowid 顺序，代价极低）
    conn.prepare('DELETE FROM metrics WHERE ts < ?').run(
      Math.floor(Date.now() / 1000) - db.METRICS_RETENTION_SECONDS
    );
  } catch (e: any) {
    console.warn('[admin-server] metrics.db 写入失败:', e.message);
  }
}

/* ============ 采样器 ============ */

// 每次采样：CPU/内存为百分比，网速与磁盘 I/O 为两次采样差值换算的速率（字节/秒）。
// 直接读原始计数（cpuSample/netSample/diskioSample），不扰动 /api/admin/system 的独立采样状态
function sampleHistory() {
  const now = Date.now();
  const cpu = probe.cpuSample();
  const net = probe.netSample();
  const io = probe.diskioSample();

  let cpuPercent = 0;
  if (state.samplerState.histCpuPrev && now > state.samplerState.histCpuPrev.ts) {
    const totalDiff = cpu.total - state.samplerState.histCpuPrev.total;
    const idleDiff = cpu.idle - state.samplerState.histCpuPrev.idle;
    const raw = totalDiff > 0 ? ((totalDiff - idleDiff) / totalDiff) * 100 : 0;
    // history 采样同样走统一 EMA 平滑，避免趋势图跳变
    state.samplerState.histCpuEma = ema(state.samplerState.histCpuEma, raw, state.CPU_EMA_ALPHA);
    cpuPercent = Math.round((state.samplerState.histCpuEma as number) * 10) / 10;
  }

  const dtNet = state.samplerState.histNetPrev ? (now - state.samplerState.histNetPrev.ts) / 1000 : 0;
  const dtIo = state.samplerState.histDiskioPrev ? (now - state.samplerState.histDiskioPrev.ts) / 1000 : 0;
  const netRxRate = state.samplerState.histNetPrev && dtNet > 0 ? Math.max(0, (net.rx - state.samplerState.histNetPrev.rx) / dtNet) : 0;
  const netTxRate = state.samplerState.histNetPrev && dtNet > 0 ? Math.max(0, (net.tx - state.samplerState.histNetPrev.tx) / dtNet) : 0;
  const ioReadRate =
    state.samplerState.histDiskioPrev && dtIo > 0 ? Math.max(0, (io.read - state.samplerState.histDiskioPrev.read) / dtIo) : 0;
  const ioWriteRate =
    state.samplerState.histDiskioPrev && dtIo > 0 ? Math.max(0, (io.write - state.samplerState.histDiskioPrev.write) / dtIo) : 0;

  state.samplerState.histCpuPrev = { ts: now, idle: cpu.idle, total: cpu.total };
  state.samplerState.histNetPrev = { ts: now, rx: net.rx, tx: net.tx };
  state.samplerState.histDiskioPrev = { ts: now, read: io.read, write: io.write };

  const psi = probe.psiHistPoint();
  const mem = probe.readMeminfo(); // 长期留样额外记录内存绝对量（mem_used / mem_total）

  // 内存 buffer / 旧 history 接口的结构保持不变（不加任何新键）
  const point = {
    ts: now,
    cpu: cpuPercent,
    mem_percent: probe.memPercent(),
    swap_percent: probe.swapPercent(),
    psi_mem_avg10: psi.psi_mem_avg10,
    psi_cpu_avg10: psi.psi_cpu_avg10,
    psi_io_avg10: psi.psi_io_avg10,
    net_rx_rate: Math.round(netRxRate),
    net_tx_rate: Math.round(netTxRate),
    disk_io_read: Math.round(ioReadRate),
    disk_io_write: Math.round(ioWriteRate)
  };

  state.historyBuffer.push(point);
  if (state.historyBuffer.length > state.HISTORY_MAX) state.historyBuffer.shift();

  persistHistory();
  // 同步长期留样（写库失败只 warn，不影响上面的内存 buffer 与 SSE）
  persistMetricPoint({ ...point, mem_used: mem.used, mem_total: mem.total });
}

// 启动采样器：仅在持有锁的实例上运行（避免多实例重复采样）。
// 启动时立即采一次，之后每 HISTORY_INTERVAL_MS 采一次；聚合调度与采样器同锁。
function startSampler() {
  if (!acquireSamplerLock()) return;
  sampleHistory();
  const historyTimer = setInterval(sampleHistory, state.HISTORY_INTERVAL_MS);
  historyTimer.unref?.();
  process.on('exit', () => {
    try {
      fs.unlinkSync(SAMPLER_LOCK_FILE);
    } catch (e: any) {
      // 忽略清理失败
    }
  });
  console.log(`[admin-server] 历史采样器已启动（每 ${state.HISTORY_INTERVAL_MS / 1000}s 一次，最多 ${state.HISTORY_MAX} 点）`);
  // 聚合调度与采样器同锁：仅主实例补算/物化聚合表，失败只 warn，绝不拖累采样与 SSE
  startAggregationScheduler();
}

module.exports = { sampleHistory, readHistory, persistMetricPoint, startSampler };
