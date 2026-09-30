'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';
import type { AggDef } from '../db.ts';

/**
 * 长期留样的分档聚合：raw 采样点的 P99/Max 物化、启动补算与调度、粒度查询。
 * 所有桶一律直接从 raw metrics 计算，严禁由细粒度桶递归聚合。
 */

const db = require('../db.ts') as {
  openMetricsDb: () => SqliteDatabase | null;
  METRIC_KEYS: string[];
  AGG_TABLES: Record<string, AggDef>;
  METRIC_ROUND: Record<string, number>;
  AGG_COLUMNS: string;
};
const { openMetricsDb, METRIC_KEYS, AGG_TABLES, METRIC_ROUND, AGG_COLUMNS } = db;

// 聚合查询行：bucket + 12 个指标 + 样本数
type AggRow = { bucket: number; sample_count: number } & Record<string, number | null>;

// 粒度/区间白名单：未知参数回退默认（range=1d & step=1m），并正常返回 200
const METRICS_STEP_SECONDS: Record<string, number> = { '1m': 60, '5m': 300, '1h': 3600, '1d': 86400 };
const METRICS_RANGE_SECONDS: Record<string, number> = {
  '1h': 3600,
  '6h': 6 * 3600,
  '1d': 86400,
  '7d': 7 * 86400,
  '30d': 30 * 86400
};

// 分档分位分桶（窗口函数，绝不把 raw 全量拉进 Node）：桶内 12 个指标各自独立排序，
// 取「最近秩」第 ceil(pct/100 * N) 个样本（整数除法实现）；pct=100 即桶内最大值（Max）。
// 分钟桶 pct=100、小时桶 pct=90、天桶 pct=99 —— 三者全部直接来自 raw，绝不递归。
// 返回 [{bucket, sample_count, <metrics>}]。
function computeAggRows(stepSec: number, pct: number, sinceSec: number, untilSec: number): AggRow[] {
  const d = openMetricsDb();
  if (!d) return [];
  const rank = `(${pct} * cnt + 99) / 100`;
  const rowNums = METRIC_KEYS.map(
    (k) => `ROW_NUMBER() OVER (PARTITION BY bucket ORDER BY ${k}) AS r_${k}`
  ).join(', ');
  const p99 = METRIC_KEYS.map(
    (k) => `ROUND(MAX(CASE WHEN r_${k} = ${rank} THEN ${k} END), ${METRIC_ROUND[k]}) AS ${k}`
  ).join(', ');
  const sql =
    'WITH base AS (' +
      'SELECT CAST(ts / ? AS INTEGER) * ? AS bucket, ' + AGG_COLUMNS + ' ' +
      'FROM metrics WHERE ts >= ? AND ts < ?' +
    '), ranked AS (' +
      'SELECT bucket, COUNT(*) OVER (PARTITION BY bucket) AS cnt, ' + rowNums + ', ' + AGG_COLUMNS + ' ' +
      'FROM base' +
    ') SELECT bucket, MAX(cnt) AS sample_count, ' + p99 + ' FROM ranked GROUP BY bucket ORDER BY bucket';
  return d.prepare(sql).all(stepSec, stepSec, sinceSec, untilSec) as AggRow[];
}

// 物化表 upsert（INSERT OR REPLACE，幂等：已存在的桶覆盖更新）
const aggStmtCache = new Map<string, ReturnType<SqliteDatabase['prepare']>>();
function aggUpsertStmt(d: SqliteDatabase, table: string) {
  let stmt = aggStmtCache.get(table);
  if (stmt) return stmt;
  const placeholders = ['?', ...METRIC_KEYS.map(() => '?'), '?', '?'].join(', ');
  stmt = d.prepare(
    'INSERT OR REPLACE INTO ' + table +
      ' (bucket_start, ' + AGG_COLUMNS + ', sample_count, updated_at) VALUES (' + placeholders + ')'
  );
  aggStmtCache.set(table, stmt);
  return stmt;
}

// 计算并写入 [sinceSec, untilSec) 内的完整桶（必须与 step 对齐）
function materializeRange(key: string, sinceSec: number, untilSec: number): number {
  const def = AGG_TABLES[key];
  if (!def || untilSec <= sinceSec) return 0;
  const rows = computeAggRows(def.stepSec, def.pct, sinceSec, untilSec);
  if (!rows.length) return 0;
  const d = openMetricsDb();
  if (!d) return 0;
  const stmt = aggUpsertStmt(d, def.table);
  const now = Math.floor(Date.now() / 1000);
  for (const r of rows) {
    stmt.run(r.bucket, ...METRIC_KEYS.map((k) => r[k]), r.sample_count, now);
  }
  return rows.length;
}

// 补算「最近 N 个完整桶」（默认 1 个）。周期性任务回看多个桶实现自愈：
// 幂等 upsert，重复计算代价极低；某次失败留下的空洞会在下一次回看时自动补上。
function aggregateLastComplete(key: string, lookback = 1): number {
  const def = AGG_TABLES[key];
  const nowSec = Math.floor(Date.now() / 1000);
  const end = Math.floor(nowSec / def.stepSec) * def.stepSec; // 当前桶起点 = 完整桶上界（不含）
  const start = Math.max(0, end - def.stepSec * Math.max(1, lookback));
  if (end <= 0 || end <= start) return 0;
  return materializeRange(key, start, end);
}

// 分钟桶过期清理（小时/天桶长期保留，不清理）
function cleanupExpiredAggregates() {
  const def = AGG_TABLES['1m'];
  const d = openMetricsDb();
  if (!d) return;
  d.prepare('DELETE FROM ' + def.table + ' WHERE bucket_start < ?').run(
    Math.floor(Date.now() / 1000) - (def.retentionSec as number)
  );
}

// 启动补齐规划：只挑「raw 有数据但聚合表缺失」的桶，按连续区间分片；
// 已有的桶一律跳过，绝不在启动时全表重算。
const BACKFILL_CHUNK_BUCKETS = 512;
type BackfillJob = { key: string; start: number; end: number };
function planBackfillJobs(): BackfillJob[] {
  const jobs: BackfillJob[] = [];
  const d = openMetricsDb();
  if (!d) return jobs;
  const raw = d.prepare('SELECT MIN(ts) mn FROM metrics').get() as { mn: number | null } | undefined;
  if (!raw || raw.mn == null) return jobs;
  const nowSec = Math.floor(Date.now() / 1000);
  for (const [key, def] of Object.entries(AGG_TABLES)) {
    try {
      const end = Math.floor(nowSec / def.stepSec) * def.stepSec; // 完整桶上界（不含）
      const floorStart = Math.floor(raw.mn / def.stepSec) * def.stepSec;
      if (floorStart >= end) continue;
      const have = new Set(
        (d
          .prepare('SELECT bucket_start FROM ' + def.table + ' WHERE bucket_start >= ? AND bucket_start < ?')
          .all(floorStart, end) as { bucket_start: number }[])
          .map((r) => r.bucket_start)
      );
      const rawBuckets = d
        .prepare(
          'SELECT DISTINCT CAST(ts / ? AS INTEGER) * ? AS b FROM metrics ' +
            'WHERE ts >= ? AND ts < ? ORDER BY b'
        )
        .all(def.stepSec, def.stepSec, floorStart, end) as { b: number }[];
      const ranges: Array<[number, number]> = [];
      let rangeStart: number | null = null;
      let prev: number | null = null;
      for (const r of rawBuckets) {
        const b = r.b;
        if (have.has(b)) {
          if (rangeStart != null) {
            ranges.push([rangeStart, prev!]);
            rangeStart = null;
          }
          continue;
        }
        if (rangeStart == null) rangeStart = b;
        else if (b !== prev! + def.stepSec) {
          ranges.push([rangeStart, prev!]);
          rangeStart = b;
        }
        prev = b;
      }
      if (rangeStart != null) ranges.push([rangeStart, prev!]);
      const chunk = def.stepSec * BACKFILL_CHUNK_BUCKETS;
      for (const [rs, re] of ranges) {
        for (let s = rs; s <= re; s += chunk) {
          jobs.push({ key, start: s, end: Math.min(re + def.stepSec, s + chunk) });
        }
      }
    } catch (e: any) {
      console.warn('[admin-server] 聚合补算规划失败(' + key + '):', e.message);
    }
  }
  return jobs;
}

// 分片执行补算：每片之间 setImmediate 让出事件循环，避免长时间阻塞采样/SSE
function runBackfill(jobs: BackfillJob[], idx: number): void {
  if (idx >= jobs.length) {
    if (jobs.length) console.log('[admin-server] 聚合启动补算完成，共 ' + jobs.length + ' 个分片');
    return;
  }
  const job = jobs[idx];
  try {
    materializeRange(job.key, job.start, job.end);
  } catch (e: any) {
    console.warn('[admin-server] 聚合补算失败(' + job.key + '):', e.message);
  }
  setImmediate(() => runBackfill(jobs, idx + 1));
}

// 聚合调度（仅在持有采样锁的实例上启动）：
// - 启动补齐缺失桶（幂等，只补缺的）
// - 每分钟补上一个完整分钟桶；每小时/每天各补一个完整桶（均直接读 raw 算 P99）
// 每次聚合最外层 try/catch + warn，失败绝不影响采样与 SSE
let aggregationScheduled = false;
function startAggregationScheduler() {
  if (aggregationScheduled) return;
  aggregationScheduled = true;
  setTimeout(() => {
    try {
      runBackfill(planBackfillJobs(), 0);
    } catch (e: any) {
      console.warn('[admin-server] 聚合启动补算失败，不影响采样/SSE:', e.message);
    }
  }, 1500).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1m', 10); // 回看 10 个分钟桶：单次失败留下的空洞下次自动补上
      cleanupExpiredAggregates();
    } catch (e: any) {
      console.warn('[admin-server] 分钟桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 60 * 1000).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1h', 3); // 回看 3 个小时桶
    } catch (e: any) {
      console.warn('[admin-server] 小时桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 60 * 60 * 1000).unref?.();
  setInterval(() => {
    try {
      aggregateLastComplete('1d', 2); // 回看 2 个天桶
    } catch (e: any) {
      console.warn('[admin-server] 天桶聚合失败，不影响采样/SSE:', e.message);
    }
  }, 24 * 60 * 60 * 1000).unref?.();
}

// 粒度查询：1m/1h/1d 读对应物化聚合表；5m 未物化，退回查询时对 raw 现算 P99（兼容旧参数）。
// points 与旧 /history 同构；无数据返回空数组 + 完整 meta，绝不抛 500、绝不返回 null。
function queryMetricPoints(range: string, step: string) {
  const stepSec = METRICS_STEP_SECONDS[step];
  const rangeSec = METRICS_RANGE_SECONDS[range];
  const nowSec = Math.floor(Date.now() / 1000);
  const since = nowSec - rangeSec;
  const d = openMetricsDb();
  const meta: { step: string; range: string; bucketCount: number; firstBucket: number | null; lastBucket: number | null; recordedSeconds: number } = { step, range, bucketCount: 0, firstBucket: null, lastBucket: null, recordedSeconds: 0 };
  if (!d) return { points: [], meta };
  const def = AGG_TABLES[step];
  const rows = (def
    ? d
        .prepare(
          'SELECT bucket_start AS bucket, ' + AGG_COLUMNS + ' FROM ' + def.table +
            ' WHERE bucket_start >= ? ORDER BY bucket_start'
        )
        .all(since)
    : computeAggRows(stepSec, 95, since, nowSec + 1)) as AggRow[]; // 未物化的档位（如 5m）现算，口径取 P95
  const points = rows.map((r) => {
    const p: { ts: number } & Record<string, number | null> = { ts: r.bucket * 1000 };
    for (const k of METRIC_KEYS) p[k] = r[k];
    return p;
  });
  const raw = d.prepare('SELECT MIN(ts) mn FROM metrics').get() as { mn: number | null } | undefined;
  if (raw && raw.mn != null) meta.recordedSeconds = Math.max(0, nowSec - raw.mn);
  meta.bucketCount = points.length;
  meta.firstBucket = points.length ? points[0].ts : null;
  meta.lastBucket = points.length ? points[points.length - 1].ts : null;
  return { points, meta };
}

module.exports = {
  METRICS_STEP_SECONDS,
  METRICS_RANGE_SECONDS,
  startAggregationScheduler,
  queryMetricPoints
};
