'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 通知中心路由：写入（回环/可写令牌）/ 列表 / 类别 / 已读 / 删除 / 批量删除 / 统计 / SSE。
 * 薄壳：校验与响应；SQL 与语义在 notifications/store.ts，广播在 notifications/sse.ts。
 */

const express = require('express') as typeof import('express');

const { openNotificationsDb, NOTIFICATION_LEVELS, NOTIFICATIONS_HEARTBEAT_MS } = require('../db.ts') as {
  openNotificationsDb: () => import('node:sqlite').DatabaseSync | null;
  NOTIFICATION_LEVELS: Set<string>;
  NOTIFICATIONS_HEARTBEAT_MS: number;
};
const store = require('../notifications/store.ts') as {
  writeNotification: (db: import('node:sqlite').DatabaseSync, input: {
    levelInput: string; source: string; typeKey: string; title: string;
    body: string | null; link: string | null; dedupKey: string | null;
  }) => { id: number; ts: number; level: string; deduped: boolean; item: import('../notifications/store.ts').NotificationItem };
  listNotifications: (db: import('node:sqlite').DatabaseSync, f: {
    limit: number; before: number | null; level: string | null; source: string | null; type: string | null; unreadOnly: boolean;
  }) => { items: unknown[]; unread: number; total: number };
  listNotificationTypes: (db: import('node:sqlite').DatabaseSync) => { types: unknown[] };
  updateNotificationType: (db: import('node:sqlite').DatabaseSync, key: string, patch: {
    label?: string; description?: string; defaultLevel?: string | null; sort?: number; enabled?: 0 | 1;
  }) => number;
  markNotificationRead: (db: import('node:sqlite').DatabaseSync, id: number) => void;
  markAllNotificationsRead: (db: import('node:sqlite').DatabaseSync) => number;
  deleteNotification: (db: import('node:sqlite').DatabaseSync, id: number) => void;
  bulkDeleteNotifications: (db: import('node:sqlite').DatabaseSync, f: {
    level: string | null; source: string | null; unreadOnly: boolean; readOnly: boolean;
  }, dryRun: boolean) => number;
  notificationStats: (db: import('node:sqlite').DatabaseSync) => { total: number; unread: number; sources: unknown[] };
};
const { notificationClients, broadcastNotification } = require('../notifications/sse.ts') as {
  notificationClients: Set<import('express').Response>;
  broadcastNotification: (item: import('../notifications/store.ts').NotificationItem) => void;
};
const { authRequired, notificationsWriteAuth } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
  notificationsWriteAuth: import('express').RequestHandler;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
};

const router = express.Router();

// 写入通知（本机脚本免 SSO；其余来源走 authRequired）。
// body: { level?, type?, source, title, body?, link?, dedupKey? } → 201 { id, ts }
// - type 可选；缺省用 source 当类别键（兼容既有写入方）。
// - type 未注册 → 自动注册（key 当 label、enabled=1）；enabled=0 的类别仍接受写入。
// - level 缺省 → 用该类别的 default_level，再没有则 normal。
router.post('/api/admin/notifications', notificationsWriteAuth, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const ip = clientIp(req);
  const b = req.body || {};
  const levelInput = typeof b.level === 'string' ? b.level.trim() : '';
  const source = typeof b.source === 'string' ? b.source.trim() : '';
  const typeInput = typeof b.type === 'string' ? b.type.trim() : '';
  const typeKey = typeInput || source; // 缺省用 source 兼容既有写入方
  const title = typeof b.title === 'string' ? b.title.trim() : '';
  const body = typeof b.body === 'string' && b.body !== '' ? b.body : null;
  const link = typeof b.link === 'string' && b.link !== '' ? b.link : null;
  const dedupKey = typeof b.dedupKey === 'string' && b.dedupKey !== '' ? b.dedupKey : null;
  if (levelInput && !NOTIFICATION_LEVELS.has(levelInput)) {
    return res.status(400).json({ error: 'level 必须是 urgent / normal / digest' });
  }
  if (!source || !title) {
    return res.status(400).json({ error: 'source 与 title 不能为空' });
  }
  try {
    const r = store.writeNotification(db, { levelInput, source, typeKey, title, body, link, dedupKey });
    broadcastNotification(r.item);
    if (r.deduped) {
      auditLog('notification_write', ip, true, `dedup id=${r.id} level=${r.level} source=${source} type=${typeKey}`);
    } else {
      auditLog('notification_write', ip, true, `id=${r.id} level=${r.level} source=${source} type=${typeKey}`);
    }
    return res.status(201).json({ id: r.id, ts: r.ts });
  } catch (e: any) {
    auditLog('notification_write', ip, false, e.message);
    return res.status(500).json({ error: '写入通知失败' });
  }
});

// 列表（需鉴权）：支持 limit / before / level / source / type / unread；unread 与 total 为全库计数
// type 为类别维度（命中该类别下全部通知），与 source 并存、互不替代。
router.get('/api/admin/notifications', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const limitRaw = parseInt(req.query.limit as string, 10);
    const limit = Number.isFinite(limitRaw) ? Math.min(200, Math.max(1, limitRaw)) : 50;
    const beforeRaw = parseInt(req.query.before as string, 10);
    const before = Number.isFinite(beforeRaw) ? beforeRaw : null;
    const level = NOTIFICATION_LEVELS.has(String(req.query.level || ''))
      ? String(req.query.level)
      : null;
    const source =
      req.query.source && String(req.query.source).trim() ? String(req.query.source).trim() : null;
    const type = req.query.type && String(req.query.type).trim() ? String(req.query.type).trim() : null;
    const unreadOnly = String(req.query.unread || '') === '1';

    res.json(store.listNotifications(db, { limit, before, level, source, type, unreadOnly }));
  } catch (e: any) {
    res.status(500).json({ error: '获取通知失败' });
  }
});

// 通知类别列表（需鉴权）：类别由服务端定义，客户端据此动态渲染筛选器（不得内置清单）。
// 返回 count/unread 为当前库内统计（仅供参考）；按 sort、label 排序；软删（archived_at）的不返回。
router.get('/api/admin/notifications/types', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    res.json(store.listNotificationTypes(db));
  } catch (e: any) {
    res.status(500).json({ error: '获取通知类别失败' });
  }
});

// 修改通知类别（需鉴权）：body { label?, description?, defaultLevel?, sort?, enabled? } → { ok: true }
// 表即配置；只有传入的字段被更新，未传字段保持原值。
router.patch('/api/admin/notifications/types/:key', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const key = String(req.params.key || '').trim();
  if (!key) return res.status(400).json({ error: '无效的类别' });
  const b = req.body || {};
  const patch: { label?: string; description?: string; defaultLevel?: string | null; sort?: number; enabled?: 0 | 1 } = {};
  if (typeof b.label === 'string') {
    const label = b.label.trim();
    if (!label) return res.status(400).json({ error: 'label 不能为空' });
    patch.label = label;
  }
  if (typeof b.description === 'string') {
    patch.description = b.description;
  }
  if (typeof b.defaultLevel === 'string') {
    const dl = b.defaultLevel.trim();
    if (dl && !NOTIFICATION_LEVELS.has(dl)) {
      return res.status(400).json({ error: 'defaultLevel 必须是 urgent / normal / digest' });
    }
    patch.defaultLevel = dl || null;
  }
  if (b.sort !== undefined && b.sort !== null && b.sort !== '') {
    const s = parseInt(b.sort, 10);
    if (!Number.isFinite(s)) return res.status(400).json({ error: 'sort 必须是整数' });
    patch.sort = s;
  }
  if (b.enabled !== undefined && b.enabled !== null) {
    patch.enabled = b.enabled === true || b.enabled === 1 || b.enabled === '1' ? 1 : 0;
  }
  if (!Object.keys(patch).length) return res.status(400).json({ error: '没有可修改的字段' });
  try {
    const changes = store.updateNotificationType(db, key, patch);
    if (changes === 0) return res.status(404).json({ error: '类别不存在' });
    auditLog('notification_type_update', clientIp(req), true, `key=${key} fields=${Object.keys(patch).length}`);
    res.json({ ok: true });
  } catch (e: any) {
    return res.status(500).json({ error: '修改通知类别失败' });
  }
});

// 单条已读（需鉴权）
router.post('/api/admin/notifications/:id/read', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: '无效的 id' });
  try {
    store.markNotificationRead(db, id);
    auditLog('notification_read', clientIp(req), true, `id=${id}`);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: '标记已读失败' });
  }
});

// 全部已读（需鉴权）→ { ok: true, count: N }
router.post('/api/admin/notifications/read-all', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    const count = store.markAllNotificationsRead(db);
    auditLog('notification_read_all', clientIp(req), true, `count=${count}`);
    res.json({ ok: true, count });
  } catch (e: any) {
    res.status(500).json({ error: '全部已读失败' });
  }
});

// 删除（需鉴权）
router.delete('/api/admin/notifications/:id', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const id = parseInt(req.params.id, 10);
  if (!Number.isFinite(id)) return res.status(400).json({ error: '无效的 id' });
  try {
    store.deleteNotification(db, id);
    auditLog('notification_delete', clientIp(req), true, `id=${id}`);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: '删除通知失败' });
  }
});

// 批量删除（需鉴权）：按筛选一次删除多条。
// body: { level?, source?, unreadOnly?, readOnly?, dryRun? } → { ok: true, count: N }
// dryRun=true 只统计、不删除，供前端二次确认时拿到准确条数（新增可选字段）。
// 注意：不带任何条件即「全部删除」；审计只记条数与筛选，绝不记 body。
router.post('/api/admin/notifications/bulk-delete', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  const b = req.body || {};
  const level = NOTIFICATION_LEVELS.has(String(b.level || '')) ? String(b.level) : null;
  const source = typeof b.source === 'string' && b.source.trim() ? b.source.trim() : null;
  const unreadOnly = b.unreadOnly === true;
  const readOnly = b.readOnly === true;
  const dryRun = b.dryRun === true;
  // 未读与已读互斥：同时给出时不匹配任何行，避免误删
  if (unreadOnly && readOnly) return res.json({ ok: true, count: 0 });
  try {
    const count = store.bulkDeleteNotifications(db, { level, source, unreadOnly, readOnly }, dryRun);
    if (!dryRun) {
      auditLog(
        'notification_bulk_delete',
        clientIp(req),
        true,
        `count=${count} level=${level || '-'} source=${source || '-'} unreadOnly=${unreadOnly} readOnly=${readOnly}`
      );
    }
    res.json({ ok: true, count });
  } catch (e: any) {
    auditLog('notification_bulk_delete', clientIp(req), false, e.message);
    res.status(500).json({ error: '批量删除失败' });
  }
});

// 统计（需鉴权）→ { total, unread, sources: [{ source, count }] }
// sources 按条数降序（来源相同时按字典序），前端只展示 Top 5。
router.get('/api/admin/notifications/stats', authRequired, (req, res) => {
  const db = openNotificationsDb();
  if (!db) return res.status(503).json({ error: '通知库暂不可用' });
  try {
    res.json(store.notificationStats(db));
  } catch (e: any) {
    res.status(500).json({ error: '获取通知统计失败' });
  }
});

// SSE 实时流（需鉴权）：另开一条，绝不复用系统指标 /system/stream。
// event: notification（新通知 item） / heartbeat（每 25s）
router.get('/api/admin/notifications/stream', authRequired, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.flushHeaders();
  res.write('retry: 5000\n\n');

  notificationClients.add(res);
  // 广播时可能遇到已断开的 socket，兜底吞掉 error，避免进程级未捕获异常
  res.on('error', () => notificationClients.delete(res));
  const hb = setInterval(() => {
    try {
      res.write('event: heartbeat\ndata: ' + JSON.stringify({ ts: Math.floor(Date.now() / 1000) }) + '\n\n');
    } catch (e: any) {
      notificationClients.delete(res);
    }
  }, NOTIFICATIONS_HEARTBEAT_MS);
  hb.unref?.();

  // 客户端断开：停心跳并移除订阅者，不泄漏监听器
  req.on('close', () => {
    clearInterval(hb);
    notificationClients.delete(res);
  });
});

module.exports = router;
