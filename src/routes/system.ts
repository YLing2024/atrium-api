'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 系统信息 / 服务状态 / 历史与聚合查询 / SSE 实时流 路由。
 * 薄壳：只做参数解析与响应组装，采集与查询逻辑在 probe / metrics 服务里。
 */

const express = require('express') as typeof import('express');

const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};
const { collectSystem } = require('../probe/system.ts') as {
  collectSystem: () => Promise<Record<string, unknown>>;
};
const { collectServices } = require('../probe/services.ts') as {
  collectServices: () => Promise<Array<{ name: string; status: string; pid: number | null }>>;
};
const { collectProcesses } = require('../metrics/proctop.ts') as {
  collectProcesses: () => Promise<{
    processes: unknown[];
    count: number;
    truncated: boolean;
    total_mem_mb: number;
    total_cpu: number;
    parsed_count: number;
    skipped_count: number;
    total_cgroup_mb: number | null;
  }>;
};
const { sampleHistory, readHistory } = require('../metrics/store.ts') as {
  sampleHistory: () => void;
  readHistory: () => unknown[];
};
const { queryMetricPoints, METRICS_STEP_SECONDS, METRICS_RANGE_SECONDS } = require('../metrics/aggregate.ts') as {
  queryMetricPoints: (range: string, step: string) => { points: unknown[]; meta: Record<string, unknown> };
  METRICS_STEP_SECONDS: Record<string, number>;
  METRICS_RANGE_SECONDS: Record<string, number>;
};

const router = express.Router();

router.get('/', (req, res) => {
  res.json({ name: 'admin-server', status: 'ok' });
});

// 组装系统信息（REST 端点与 SSE 快照共用）：实时采集系统信息，
// 请求驱动同步写入历史 buffer，保证趋势图与上方实时数据同源
async function buildSystemPayload() {
  const data = await collectSystem();
  try {
    sampleHistory();
  } catch {
    /* 采样失败不影响主响应 */
  }
  return data;
}

// 组装服务状态（REST /api/admin/services 专用）：服务列表 + 全量进程树 +
// count / truncated / total_mem_mb / total_cpu + 解析计数 parsed_count / skipped_count +
// cgroup 真值 total_cgroup_mb。SSE 帧不再携带进程明细，见下方 stream 路由。
async function buildServicesPayload() {
  const [services, result] = await Promise.all([collectServices(), collectProcesses()]);
  return {
    services,
    processes: result.processes,
    count: result.count,
    truncated: result.truncated,
    total_mem_mb: result.total_mem_mb,
    total_cpu: result.total_cpu,
    parsed_count: result.parsed_count,
    skipped_count: result.skipped_count,
    total_cgroup_mb: result.total_cgroup_mb
  };
}

// 系统信息（需鉴权）。每次请求实时采集，无缓存
router.get('/api/admin/system', authRequired, async (req, res) => {
  try {
    res.json(await buildSystemPayload());
  } catch (e: any) {
    res.status(500).json({ error: '获取系统信息失败: ' + e.message });
  }
});

// 历史采样（需鉴权）。返回环形 buffer 中的采样点（最多 120 点），多实例共享。
// 行为保持不变：只读内存/文件 buffer，不涉及新增的 metrics.db。
router.get('/api/admin/system/history', authRequired, (req, res) => {
  res.json(readHistory());
});

// 粒度聚合（需鉴权）：1m/1h/1d 分别读物化聚合表（桶内 raw 5s 样本 P99），
// points 与旧 /history 同构；额外返回 meta。未知 range/step 回退默认（1d/1m）并返回 200；
// 无数据/单点也返回结构完整的 200（points 可为空、可为单点），绝不 500。
router.get('/api/admin/system/metrics', authRequired, (req, res) => {
  const range = METRICS_RANGE_SECONDS[req.query.range as string] ? String(req.query.range) : '1d';
  const step = METRICS_STEP_SECONDS[req.query.step as string] ? String(req.query.step) : '1m';
  let points: ReturnType<typeof queryMetricPoints>['points'] = [];
  let meta: ReturnType<typeof queryMetricPoints>['meta'] = { step, range, bucketCount: 0, firstBucket: null, lastBucket: null, recordedSeconds: 0 };
  try {
    const r = queryMetricPoints(range, step);
    points = r.points;
    meta = r.meta;
  } catch (e: any) {
    // 查询失败不 500：降级为空数组 + 完整 meta，前端保持上一帧，不影响页面其余部分
    console.warn('[admin-server] metrics 查询失败:', e.message);
  }
  res.json({ step, range, points, meta });
});

// SSE 实时快照（需鉴权）：系统信息 + 服务状态 + 历史采样合并推送。
// 前端「系统」Tab 激活时才建连、切走即断开（req close 停表），替代前端三组 1s 轮询。
router.get('/api/admin/system/stream', authRequired, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no' // 禁 nginx 缓冲，保证实时
  });
  res.flushHeaders();

  let tick = 0;
  let pushing = false;

  // 单条 snapshot：system / services / history 一次组装推送。
  // 2026-10-13 起 SSE 不再携带进程明细（321 行 × 1s 会白烧带宽 + 前端每秒重渲染），
  // 帧结构保持 { system, services: { services, total_cpu }, history }；进程树改由 REST /services 提供。
  // pushing 防抖避免采集慢于推送间隔时 setInterval 重叠堆积
  async function push() {
    if (pushing) return;
    pushing = true;
    try {
      const [system, services, history] = await Promise.all([
        buildSystemPayload(),
        collectServices(),
        Promise.resolve(readHistory())
      ]);
      // total_cpu 语义不变（collectAllProcCpu 的系统总占用）；同帧直接复用 system.cpu.usage_percent
      // （同一 tick 内只做一次 /proc 差分，避免二次遍历把 EMA 拉偏）
      const sysCpu = (system as { cpu?: { usage_percent?: number } }).cpu;
      const total_cpu = sysCpu && typeof sysCpu.usage_percent === 'number' ? sysCpu.usage_percent : 0;
      res.write(
        'event: snapshot\ndata: ' +
          JSON.stringify({ system, services: { services, total_cpu }, history }) +
          '\n\n'
      );
      tick += 1;
      // 每 10 tick（约 30s）补一条注释行，防代理超时
      if (tick % 10 === 0) res.write(': ping\n\n');
    } catch (e: any) {
      // 单次采集失败不中断流，下个 tick 重试
    } finally {
      pushing = false;
    }
  }

  // 连接建立后立即推送第一条，之后每 1s 推送
  push();
  const timer = setInterval(push, 1000);

  // 客户端断开 / 切走 Tab：停表，不再推送
  req.on('close', () => clearInterval(timer));
});

// 服务状态（需鉴权）。返回各服务 [{ name, status: up/down, pid? }]、
// 全量进程树 processes（单行含 ppid、subtree_mem_mb / subtree_cpu / subtree_count 与
// cgroup_mem_mb）、count / truncated / total_mem_mb、全部进程瞬时 CPU 合计 total_cpu
// （与系统卡片同口径）、解析计数 parsed_count / skipped_count 与 cgroup 真值 total_cgroup_mb。
// collectProcesses 内部做单次 /proc 全量遍历，进程 cpu 与 total_cpu 同源同基准
router.get('/api/admin/services', authRequired, async (req, res) => {
  try {
    res.json(await buildServicesPayload());
  } catch (e: any) {
    res.status(500).json({ error: '获取服务状态失败: ' + e.message });
  }
});

module.exports = router;
