'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';

/**
 * 数据库单例：metrics.db（长期留样）与 notifications.db（通知中心）的打开、PRAGMA、建表。
 * 懒加载 + 单例，打开/建表失败只降级、绝不抛出到调用方。
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');

/* ============ metrics.db ============ */

// 长期留样数据库：独立文件，绝不与 Hermes 的 state.db 混用（ADMIN_METRICS_DB 可覆盖，便于测试隔离）
const METRICS_DB_FILE =
  process.env.ADMIN_METRICS_DB || path.join(__dirname, '..', 'data', 'metrics.db');
const METRICS_RETENTION_SECONDS = 30 * 24 * 3600; // raw 5s 点保留 30 天（用户规则：30 天前数据不保留）
const METRICS_1M_RETENTION_SECONDS = 90 * 24 * 3600; // 分钟桶保留 90 天
// 小时桶 / 天桶长期保留：不随 raw 过期而删除（超 30 天、raw 已删的桶直接用物化值）

// 留样点与旧 history 点同构（键名沿用采样器现有键名，保证前端图表无需改结构）
const METRIC_KEYS = [
  'cpu',
  'mem_percent',
  'mem_used',
  'mem_total',
  'swap_percent',
  'psi_mem_avg10',
  'psi_cpu_avg10',
  'psi_io_avg10',
  'net_rx_rate',
  'net_tx_rate',
  'disk_io_read',
  'disk_io_write'
];

// 物化聚合档位定义
export type AggDef = {
  table: string;
  stepSec: number;
  retentionSec: number | null;
  pct: number;
  label: string;
};

// 物化聚合表：每行 = 该桶内 raw 5s 样本按档位口径（分钟 Max / 小时 P90 / 天 P99）计算的值，
// 绝不是对下层聚合结果再聚合。
// - metrics_1m 分钟桶（保留 90 天）；metrics_1h 小时桶 / metrics_1d 天桶（长期保留）
// - 三者都直接从 raw `metrics` 计算：1h / 1d 严禁由 1m 递归聚合
// 分档口径（用户 2026-09-18 定稿）：分钟 = Max（峰值）、小时 = P90、天 = P99。
// pct = 100 时取桶内最大值（等价 Max）；其余为最近秩分位 ceil(pct/100 * N)。
const AGG_TABLES: Record<string, AggDef> = {
  '1m': { table: 'metrics_1m', stepSec: 60, retentionSec: METRICS_1M_RETENTION_SECONDS, pct: 100, label: 'max' },
  '1h': { table: 'metrics_1h', stepSec: 3600, retentionSec: null, pct: 90, label: 'p90' },
  '1d': { table: 'metrics_1d', stepSec: 86400, retentionSec: null, pct: 99, label: 'p99' }
};
const AGG_TABLE_LIST = Object.values(AGG_TABLES);

// 物化值的小数位：与旧 AVG 查询保持一致，前端展示不变
const METRIC_ROUND: Record<string, number> = {
  cpu: 1,
  mem_percent: 1,
  mem_used: 0,
  mem_total: 0,
  swap_percent: 1,
  psi_mem_avg10: 2,
  psi_cpu_avg10: 2,
  psi_io_avg10: 2,
  net_rx_rate: 0,
  net_tx_rate: 0,
  disk_io_read: 0,
  disk_io_write: 0
};
const AGG_COLUMNS = METRIC_KEYS.join(', ');
const AGG_COLUMNS_CREATE = METRIC_KEYS.map((k) => `${k} REAL`).join(', ');

// 可写打开 node:sqlite（懒加载 + 单例）。打开/建表失败只降级为「无长期留样」，
// 绝不抛出到调用方，避免影响内存采样与 SSE。
let metricsDb: SqliteDatabase | null = null;
function openMetricsDb() {
  if (metricsDb) return metricsDb;
  try {
    fs.mkdirSync(path.dirname(METRICS_DB_FILE), { recursive: true });
    const db = new DatabaseSync(METRICS_DB_FILE);
    // 并发保护：采样每 5s 写一次，聚合补算会连续写大量分片。
    // 不开 WAL / busy_timeout 时两者相撞会直接 SQLITE_BUSY（"database is locked"）导致整批聚合放弃。
    try {
      db.exec('PRAGMA journal_mode=WAL');
      db.exec('PRAGMA busy_timeout=8000');
      db.exec('PRAGMA synchronous=NORMAL');
    } catch (e: any) {
      console.warn('[admin-server] metrics.db PRAGMA 设置失败（继续运行）:', e.message);
    }
    db.exec(
      'CREATE TABLE IF NOT EXISTS metrics (' +
        'ts INTEGER PRIMARY KEY,' +
        'cpu REAL, mem_percent REAL, mem_used REAL, mem_total REAL, swap_percent REAL,' +
        'psi_mem_avg10 REAL, psi_cpu_avg10 REAL, psi_io_avg10 REAL,' +
        'net_rx_rate REAL, net_tx_rate REAL, disk_io_read REAL, disk_io_write REAL' +
        ')'
    );
    // 物化聚合表：字段与 raw 一致 + bucket_start(Unix 秒) / sample_count / updated_at
    for (const t of AGG_TABLE_LIST) {
      db.exec(
        'CREATE TABLE IF NOT EXISTS ' + t.table + ' (' +
          'bucket_start INTEGER PRIMARY KEY,' +
          AGG_COLUMNS_CREATE + ',' +
          'sample_count INTEGER,' +
          'updated_at INTEGER' +
          ')'
      );
    }
    metricsDb = db;
  } catch (e: any) {
    console.warn('[admin-server] metrics.db 打开失败，长期留样停用:', e.message);
    metricsDb = null;
  }
  return metricsDb;
}

/* ============ notifications.db ============ */

const NOTIFICATIONS_DB_FILE =
  process.env.ADMIN_NOTIFICATIONS_DB || path.join(__dirname, '..', 'data', 'notifications.db');
const NOTIFICATIONS_RETENTION_SECONDS = 30 * 24 * 3600; // 保留 30 天（与日志保留策略一致）
const NOTIFICATIONS_DEDUP_WINDOW_SECONDS = 10 * 60; // 同一 dedupKey 10 分钟内只保留一条
const NOTIFICATIONS_HEARTBEAT_MS = 25000; // SSE 心跳 25s（需求区间 20~30s）
const NOTIFICATION_LEVELS = new Set(['urgent', 'normal', 'digest']);

// 可写打开 node:sqlite（懒加载 + 单例）。打开/建表失败只降级，绝不抛到调用方。
let notificationsDb: SqliteDatabase | null = null;
function openNotificationsDb() {
  if (notificationsDb) return notificationsDb;
  try {
    fs.mkdirSync(path.dirname(NOTIFICATIONS_DB_FILE), { recursive: true });
    const db = new DatabaseSync(NOTIFICATIONS_DB_FILE);
    // 与 metrics.db 同样的并发保护：写入与清理可能交叉
    try {
      db.exec('PRAGMA journal_mode=WAL');
      db.exec('PRAGMA busy_timeout=8000');
      db.exec('PRAGMA synchronous=NORMAL');
    } catch (e: any) {
      console.warn('[admin-server] notifications.db PRAGMA 设置失败（继续运行）:', e.message);
    }
    db.exec(
      'CREATE TABLE IF NOT EXISTS notifications (' +
        'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
        'ts INTEGER NOT NULL,' +
        'level TEXT NOT NULL,' +
        'source TEXT NOT NULL,' +
        'title TEXT NOT NULL,' +
        'body TEXT,' +
        'link TEXT,' +
        'dedup_key TEXT,' +
        'read_at INTEGER' +
        ')'
    );
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_ts ON notifications(ts DESC)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_read_at ON notifications(read_at)');
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_dedup_key ON notifications(dedup_key)');
    // 统计/按来源筛选用（仅加索引，不改列）
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_source ON notifications(source)');
    // 通知类别注册表：类别由服务端定义，客户端只拉取渲染（客户端不得内置任何类别清单）。
    // 软删用 archived_at（不物理删除，避免历史通知失去归属）。
    db.exec(
      'CREATE TABLE IF NOT EXISTS notification_types (' +
        'key TEXT PRIMARY KEY,' +
        'label TEXT NOT NULL,' +
        'description TEXT,' +
        'default_level TEXT,' +
        'sort INTEGER DEFAULT 0,' +
        'enabled INTEGER DEFAULT 1,' +
        'archived_at INTEGER' +
        ')'
    );
    // 通知行增加类别列：历史库没有该列 → 加列；旧行按「type 缺省用 source」回填，
    // 保证旧数据也能按类别查到（不改 source 语义）。
    const notifCols = db.prepare('PRAGMA table_info(notifications)').all();
    if (!notifCols.some((c) => c.name === 'type')) {
      db.exec('ALTER TABLE notifications ADD COLUMN type TEXT');
      db.exec('UPDATE notifications SET type = source WHERE type IS NULL');
    }
    db.exec('CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type)');
    // 预置类别（仅缺省时插入，绝不覆盖后台已改的 label / 排序 / 停用状态）：
    // watchdog=看门狗、monitor=站点监控、cron=定时播报、hermes=Hermes、admin=管理后台。
    const seedType = db.prepare(
      'INSERT OR IGNORE INTO notification_types (key, label, description, default_level, sort, enabled, archived_at) ' +
        'VALUES (?, ?, NULL, ?, ?, 1, NULL)'
    );
    seedType.run('watchdog', '看门狗', 'urgent', 10);
    seedType.run('monitor', '站点监控', 'normal', 20);
    seedType.run('cron', '定时播报', 'normal', 30);
    seedType.run('hermes', 'Hermes', 'normal', 40);
    seedType.run('admin', '管理后台', 'normal', 50);
    notificationsDb = db;
  } catch (e: any) {
    console.warn('[admin-server] notifications.db 打开失败，通知中心停用:', e.message);
    notificationsDb = null;
  }
  return notificationsDb;
}

module.exports = {
  openMetricsDb,
  openNotificationsDb,
  METRICS_DB_FILE,
  METRICS_RETENTION_SECONDS,
  METRICS_1M_RETENTION_SECONDS,
  METRIC_KEYS,
  AGG_TABLES,
  AGG_TABLE_LIST,
  METRIC_ROUND,
  AGG_COLUMNS,
  AGG_COLUMNS_CREATE,
  NOTIFICATIONS_DB_FILE,
  NOTIFICATIONS_RETENTION_SECONDS,
  NOTIFICATIONS_DEDUP_WINDOW_SECONDS,
  NOTIFICATIONS_HEARTBEAT_MS,
  NOTIFICATION_LEVELS
};
