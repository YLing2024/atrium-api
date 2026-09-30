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
  collectProcesses: () => Promise<{ processes: unknown[]; total_cpu: number }>;
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

// 组装服务状态（REST 端点与 SSE 快照共用）
async function buildServicesPayload() {
  const [services, result] = await Promise.all([collectServices(), collectProcesses()]);
  return { services, processes: result.processes, total_cpu: result.total_cpu };
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

  // 单条 snapshot：system / services / history 一次组装推送；
  // pushing 防抖避免采集慢于推送间隔时 setInterval 重叠堆积
  async function push() {
    if (pushing) return;
    pushing = true;
    try {
      const [system, services, history] = await Promise.all([
        buildSystemPayload(),
        buildServicesPayload(),
        Promise.resolve(readHistory())
      ]);
      res.write(
        'event: snapshot\ndata: ' + JSON.stringify({ system, services, history }) + '\n\n'
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
// 进程排行 TOP15 与全部进程瞬时 CPU 合计 total_cpu（与系统卡片同口径）。
// collectProcesses 内部做单次 /proc 全量遍历，进程 cpu 与 total_cpu 同源同基准
router.get('/api/admin/services', authRequired, async (req, res) => {
  try {
    res.json(await buildServicesPayload());
  } catch (e: any) {
    res.status(500).json({ error: '获取服务状态失败: ' + e.message });
  }
});

module.exports = router;
