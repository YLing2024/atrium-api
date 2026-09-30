'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Redis as RedisClient } from 'ioredis';

/**
 * 模块级可变状态集中地：Redis 客户端单例 + 各采样状态。
 * 全进程唯一，任何模块都只能从这里引用，禁止在别处复制。
 */

const Redis = require('ioredis') as { new (url: string): RedisClient };

// 内存历史采样点（缓冲区结构，原样 JSON 序列化）
export type HistoryPoint = {
  ts: number;
  cpu: number;
  mem_percent: number;
  swap_percent: number;
  psi_mem_avg10: number | null;
  psi_cpu_avg10: number | null;
  psi_io_avg10: number | null;
  net_rx_rate: number;
  net_tx_rate: number;
  disk_io_read: number;
  disk_io_write: number;
};

// 长期留样写入点：历史点 + 内存绝对量
export type MetricPoint = HistoryPoint & { mem_used: number; mem_total: number };

// Redis 连接，失败时启动报错退出（唯一实例）
const redis = new Redis('redis://127.0.0.1:6379');
redis.on('error', (err) => {
  console.error('[admin-server] Redis 连接失败:', err.message);
  process.exit(1);
});

const HISTORY_MAX = 120; // 最多保留 120 个采样点
const HISTORY_INTERVAL_MS = 5000; // 每 5 秒采样一次
const historyBuffer: HistoryPoint[] = [];

// 统一 EMA 平滑系数：系统卡片 / 进程排行 / 历史趋势全走同一函数同一参数
const CPU_EMA_ALPHA = 0.4;

// 需要整体重新赋值的采样状态：CommonJS 导出是值拷贝，统一放进容器对象保证跨模块读写同一份
const samplerState: {
  cpuPerCoreState: Record<number, { total: number; idle: number }> | null;
  histCpuPrev: { ts: number; idle: number; total: number } | null;
  histCpuEma: number | null;
  histNetPrev: { ts: number; rx: number; tx: number } | null;
  histDiskioPrev: { ts: number; read: number; write: number } | null;
  totalEmaPrev: number | null;
} = {
  cpuPerCoreState: null,
  histCpuPrev: null,
  histCpuEma: null,
  histNetPrev: null,
  histDiskioPrev: null,
  totalEmaPrev: null
};

// 原地可变状态：网络 / 磁盘 I/O 上次采样累计值
const netState = { ts: 0, rx: 0, tx: 0 };
const diskioState = { ts: 0, read: 0, write: 0 };

// 进程瞬时 CPU 采样状态：pid -> 上次 /proc 采样值（单位 clock ticks）与 EMA 平滑值
const procCpuSample = new Map<number, { cpu: number; total: number }>();
const procCpuEma = new Map<number, number>();

module.exports = {
  redis,
  HISTORY_MAX,
  HISTORY_INTERVAL_MS,
  historyBuffer,
  CPU_EMA_ALPHA,
  samplerState,
  netState,
  diskioState,
  procCpuSample,
  procCpuEma
};
