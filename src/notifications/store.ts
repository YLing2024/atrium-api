'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';

/**
 * 通知库读写（notifications.db）：行→接口视图映射、类别注册/默认级别、
 * 写入去重、列表/统计/已读/删除、保留期清理。
 * 表结构（建表）在 db.ts；本模块只做数据读写与语义映射。
 */

const { openNotificationsDb, NOTIFICATION_LEVELS, NOTIFICATIONS_RETENTION_SECONDS, NOTIFICATIONS_DEDUP_WINDOW_SECONDS } = require('../db.ts') as {
  openNotificationsDb: () => SqliteDatabase | null;
  NOTIFICATION_LEVELS: Set<string>;
  NOTIFICATIONS_RETENTION_SECONDS: number;
  NOTIFICATIONS_DEDUP_WINDOW_SECONDS: number;
};

// 通知行（库内原始行，字段名与表结构一致）
export type NotificationRow = {
  id: number | bigint;
  ts: number | bigint;
  level: string;
  source: string;
  type?: string | null;
  title: string;
  body: string | null;
  link: string | null;
  read_at: number | bigint | null;
};

// 通知接口契约 item（字段名严格固定；dedup_key 不外泄）
export type NotificationItem = {
  id: number;
  ts: number;
  level: string;
  source: string;
  type: string;
  title: string;
  body: string | null;
  link: string | null;
  readAt: number | null;
};

// 库内行 → 接口契约 item（字段名严格固定；dedup_key 不外泄）
// type 为类别维度（可历史缺失，回退 source），source 字段保留不变，既有客户端不受影响。
function notificationView(row: NotificationRow): NotificationItem {
  return {
    id: Number(row.id),
    ts: Number(row.ts),
    level: row.level,
    source: row.source,
    type: row.type || row.source,
    title: row.title,
    body: row.body,
    link: row.link,
    readAt: row.read_at == null ? null : Number(row.read_at)
  };
}

// 未注册类别自动注册：key 当 label、enabled=1。任何新写入方第一次发通知就自动出现在筛选器里。
// 失败只 warn，绝不阻断写入（注册表出问题也不能丢通知）。
function ensureNotificationType(db: SqliteDatabase, key: string): void {
  if (!key) return;
  try {
    db.prepare(
      'INSERT OR IGNORE INTO notification_types (key, label, description, default_level, sort, enabled, archived_at) ' +
        'VALUES (?, ?, NULL, NULL, 0, 1, NULL)'
    ).run(key, key);
  } catch (e: any) {
    console.warn('[admin-server] 通知类别自动注册失败（不影响写入）:', e.message);
  }
}

// 取类别默认级别：default_level 合法才用，否则 normal（写入方显式给级别时不走这里）。
function notificationDefaultLevel(db: SqliteDatabase, key: string): string {
  try {
    const row = db.prepare('SELECT default_level FROM notification_types WHERE key = ?').get(key) as { default_level: string | null } | undefined;
    const lvl = row && row.default_level;
    return NOTIFICATION_LEVELS.has(lvl as string) ? (lvl as string) : 'normal';
  } catch (e: any) {
    return 'normal';
  }
}

// 写入通知（含 dedupKey 去重）：同一 dedupKey 10 分钟内更新该行并置未读，不新增。
// level 已由调用方校验；缺省时取类别默认级别。
type WriteNotificationInput = {
  levelInput: string;
  source: string;
  typeKey: string;
  title: string;
  body: string | null;
  link: string | null;
  dedupKey: string | null;
};

function writeNotification(
  db: SqliteDatabase,
  input: WriteNotificationInput
): { id: number; ts: number; level: string; deduped: boolean; item: NotificationItem } {
  const now = Math.floor(Date.now() / 1000);
  // 未注册类别自动注册；已注册（含 enabled=0）不动，照常接受写入
  ensureNotificationType(db, input.typeKey);
  const level = input.levelInput || notificationDefaultLevel(db, input.typeKey);
  if (input.dedupKey) {
    // 同一 dedupKey 10 分钟内只保留一条：更新 ts 与内容，不新增；重新置为未读
    const existing = db
      .prepare(
        'SELECT id FROM notifications WHERE dedup_key = ? AND ts >= ? ORDER BY id DESC LIMIT 1'
      )
      .get(input.dedupKey, now - NOTIFICATIONS_DEDUP_WINDOW_SECONDS) as { id: number } | undefined;
    if (existing) {
      db.prepare(
        'UPDATE notifications SET ts=?, level=?, source=?, type=?, title=?, body=?, link=?, read_at=NULL WHERE id=?'
      ).run(now, level, input.source, input.typeKey, input.title, input.body, input.link, existing.id);
      const item = notificationView(
        db.prepare('SELECT * FROM notifications WHERE id = ?').get(existing.id) as NotificationRow
      );
      return { id: Number(existing.id), ts: now, level, deduped: true, item };
    }
  }
  const info = db
    .prepare(
      'INSERT INTO notifications (ts, level, source, type, title, body, link, dedup_key, read_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)'
    )
    .run(now, level, input.source, input.typeKey, input.title, input.body, input.link, input.dedupKey);
  const id = Number(info.lastInsertRowid);
  const item = notificationView(db.prepare('SELECT * FROM notifications WHERE id = ?').get(id) as NotificationRow);
  return { id, ts: now, level, deduped: false, item };
}

// 列表：支持 limit / before / level / source / type / unread；unread 与 total 为全库计数
type ListNotificationFilters = {
  limit: number;
  before: number | null;
  level: string | null;
  source: string | null;
  type: string | null;
  unreadOnly: boolean;
};

function listNotifications(db: SqliteDatabase, f: ListNotificationFilters) {
  const where = [];
  const args = [];
  if (f.level) {
    where.push('level = ?');
    args.push(f.level);
  }
  if (f.source) {
    where.push('source = ?');
    args.push(f.source);
  }
  if (f.type) {
    where.push('type = ?');
    args.push(f.type);
  }
  if (f.before != null) {
    where.push('id < ?');
    args.push(f.before);
  }
  if (f.unreadOnly) where.push('read_at IS NULL');
  const sql =
    'SELECT * FROM notifications' +
    (where.length ? ' WHERE ' + where.join(' AND ') : '') +
    ' ORDER BY id DESC LIMIT ?';
  args.push(f.limit);
  const items = (db.prepare(sql).all(...args) as NotificationRow[]).map(notificationView);
  const unread = Number(
    (db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL').get() as { n: number }).n
  );
  const total = Number((db.prepare('SELECT COUNT(*) AS n FROM notifications').get() as { n: number }).n);
  return { items, unread, total };
}

// 类别列表：类别由服务端定义，客户端据此动态渲染筛选器（不得内置清单）。
// 返回 count/unread 为当前库内统计（仅供参考）；按 sort、label 排序；软删（archived_at）的不返回。
function listNotificationTypes(db: SqliteDatabase) {
  const rows = db
    .prepare(
      'SELECT t.key, t.label, t.description, t.default_level, t.sort, t.enabled, ' +
        '(SELECT COUNT(*) FROM notifications n WHERE n.type = t.key) AS count, ' +
        '(SELECT COUNT(*) FROM notifications n WHERE n.type = t.key AND n.read_at IS NULL) AS unread ' +
        'FROM notification_types t WHERE t.archived_at IS NULL ' +
        'ORDER BY t.sort ASC, t.label ASC'
    )
    .all();
  const types = rows.map((r) => ({
    key: r.key,
    label: r.label,
    description: r.description,
    defaultLevel: r.default_level,
    sort: Number(r.sort) || 0,
    enabled: Number(r.enabled) === 1 ? 1 : 0,
    count: Number(r.count) || 0,
    unread: Number(r.unread) || 0
  }));
  return { types };
}

// 修改类别（表即配置）：只有传入的字段被更新，未传字段保持原值。
type NotificationTypePatch = {
  label?: string;
  description?: string;
  defaultLevel?: string | null;
  sort?: number;
  enabled?: 0 | 1;
};

function updateNotificationType(db: SqliteDatabase, key: string, patch: NotificationTypePatch): number {
  const sets = [];
  const args = [];
  if (patch.label !== undefined) {
    sets.push('label = ?');
    args.push(patch.label);
  }
  if (patch.description !== undefined) {
    sets.push('description = ?');
    args.push(patch.description);
  }
  if (patch.defaultLevel !== undefined) {
    sets.push('default_level = ?');
    args.push(patch.defaultLevel);
  }
  if (patch.sort !== undefined) {
    sets.push('sort = ?');
    args.push(patch.sort);
  }
  if (patch.enabled !== undefined) {
    sets.push('enabled = ?');
    args.push(patch.enabled);
  }
  if (!sets.length) return 0;
  const info = db
    .prepare('UPDATE notification_types SET ' + sets.join(', ') + ' WHERE key = ?')
    .run(...args, key);
  return Number(info.changes);
}

// 单条已读
function markNotificationRead(db: SqliteDatabase, id: number): void {
  db.prepare('UPDATE notifications SET read_at = ? WHERE id = ? AND read_at IS NULL').run(
    Math.floor(Date.now() / 1000),
    id
  );
}

// 全部已读 → 影响条数
function markAllNotificationsRead(db: SqliteDatabase): number {
  const info = db
    .prepare('UPDATE notifications SET read_at = ? WHERE read_at IS NULL')
    .run(Math.floor(Date.now() / 1000));
  return Number(info.changes);
}

// 删除单条
function deleteNotification(db: SqliteDatabase, id: number): void {
  db.prepare('DELETE FROM notifications WHERE id = ?').run(id);
}

// 批量删除：按筛选统计/删除；未读与已读互斥由调用方保证
type BulkDeleteFilters = {
  level: string | null;
  source: string | null;
  unreadOnly: boolean;
  readOnly: boolean;
};

function bulkDeleteNotifications(db: SqliteDatabase, f: BulkDeleteFilters, dryRun: boolean): number {
  const where = [];
  const args = [];
  if (f.level) {
    where.push('level = ?');
    args.push(f.level);
  }
  if (f.source) {
    where.push('source = ?');
    args.push(f.source);
  }
  if (f.unreadOnly) where.push('read_at IS NULL');
  if (f.readOnly) where.push('read_at IS NOT NULL');
  const whereSql = where.length ? ' WHERE ' + where.join(' AND ') : '';
  if (dryRun) {
    return Number((db.prepare('SELECT COUNT(*) AS n FROM notifications' + whereSql).get(...args) as { n: number }).n);
  }
  const info = db.prepare('DELETE FROM notifications' + whereSql).run(...args);
  return Number(info.changes);
}

// 统计 → { total, unread, sources: [{ source, count }] }，sources 按条数降序（同数按字典序）
function notificationStats(db: SqliteDatabase) {
  const total = Number((db.prepare('SELECT COUNT(*) AS n FROM notifications').get() as { n: number }).n);
  const unread = Number(
    (db.prepare('SELECT COUNT(*) AS n FROM notifications WHERE read_at IS NULL').get() as { n: number }).n
  );
  const sources = db
    .prepare(
      'SELECT source, COUNT(*) AS count FROM notifications GROUP BY source ORDER BY count DESC, source ASC'
    )
    .all()
    .map((r) => ({ source: r.source, count: Number(r.count) }));
  return { total, unread, sources };
}

// 清理 30 天前的通知。启动时一次 + 每小时一次；失败只 warn，不影响其它接口。
function cleanupNotifications() {
  const db = openNotificationsDb();
  if (!db) return;
  try {
    const cutoff = Math.floor(Date.now() / 1000) - NOTIFICATIONS_RETENTION_SECONDS;
    db.prepare('DELETE FROM notifications WHERE ts < ?').run(cutoff);
  } catch (e: any) {
    console.warn('[admin-server] 通知清理失败（不影响其它接口）:', e.message);
  }
}

function startNotificationMaintenance() {
  cleanupNotifications();
  const timer = setInterval(cleanupNotifications, 60 * 60 * 1000);
  timer.unref?.();
}

module.exports = {
  notificationView,
  ensureNotificationType,
  notificationDefaultLevel,
  writeNotification,
  listNotifications,
  listNotificationTypes,
  updateNotificationType,
  markNotificationRead,
  markAllNotificationsRead,
  deleteNotification,
  bulkDeleteNotifications,
  notificationStats,
  cleanupNotifications,
  startNotificationMaintenance
};
