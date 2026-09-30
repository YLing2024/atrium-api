'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';
import type {} from 'node:os';

/**
 * 历史记录只读浏览路由：数据源为 Hermes state.db（每次请求独立 open → query → close）。
 */

const express = require('express') as typeof import('express');
const os = require('os') as typeof import('os');
const path = require('path') as typeof import('path');
const { DatabaseSync } = require('node:sqlite') as typeof import('node:sqlite');

const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
};

const router = express.Router();

// Hermes 会话数据库（只读浏览历史记录用）；默认取本机 Hermes state.db，可被环境变量覆盖（测试实例隔离）
const HERMES_STATE_DB =
  process.env.HERMES_STATE_DB || path.join(os.homedir(), '.hermes', 'state.db');

// 只读历史会话列表：数据源为 Hermes state.db（以 readOnly 打开），
// 每次请求独立 open → query → close，避免长期占用 WAL 锁（Hermes 网关并发写同一库）。
// 数据库不可用仅影响本接口，不影响其它接口与进程启动
router.get('/api/admin/history', authRequired, (req, res) => {
  const ip = clientIp(req);
  let db: SqliteDatabase | undefined;
  try {
    db = new DatabaseSync(HERMES_STATE_DB, { readOnly: true });
  } catch (e: any) {
    auditLog('history_list', ip, false, '数据库不可用: ' + e.message);
    return res.status(503).json({ error: '历史记录暂不可用' });
  }
  try {
    const rows = db
      .prepare(
        `SELECT id, title, display_name, started_at, last_activity_at, message_count, session_key
         FROM sessions ORDER BY last_activity_at DESC`
      )
      .all() as Array<{ id: string; title: string | null; display_name: string | null; started_at: number | null; last_activity_at: number | null; message_count: number }>;
    const sessions = rows.map((r) => {
      const title = r.title || r.display_name || r.id;
      const raw = r.last_activity_at != null ? r.last_activity_at : r.started_at;
      return {
        id: r.id,
        title,
        time: raw != null ? Math.round(raw * 1000) : null,
        message_count: r.message_count
      };
    });
    auditLog('history_list', ip, true, `sessions=${sessions.length}`);
    res.json({ sessions });
  } catch (e: any) {
    auditLog('history_list', ip, false, e.message);
    res.status(500).json({ error: '获取历史会话失败' });
  } finally {
    try {
      db.close();
    } catch (e: any) {
      // 关闭失败忽略
    }
  }
});

// 只读单个会话消息：仅保留 user/assistant 角色，按 id 升序
router.get('/api/admin/history/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  let db: SqliteDatabase | undefined;
  try {
    db = new DatabaseSync(HERMES_STATE_DB, { readOnly: true });
  } catch (e: any) {
    auditLog('history_messages', ip, false, '数据库不可用: ' + e.message);
    return res.status(503).json({ error: '历史记录暂不可用' });
  }
  try {
    const session = db
      .prepare(`SELECT id, title, display_name FROM sessions WHERE id = ?`)
      .get(id) as { id: string; title: string | null; display_name: string | null } | undefined;
    if (!session) {
      auditLog('history_messages', ip, false, '会话不存在: ' + id);
      return res.status(404).json({ error: '会话不存在' });
    }
    const rows = db
      .prepare(
        `SELECT role, content, timestamp FROM messages
         WHERE session_id = ? AND role IN ('user','assistant') ORDER BY id ASC`
      )
      .all(id) as Array<{ role: string; content: string; timestamp: number | null }>;
    const messages = rows.map((r) => ({
      role: r.role,
      content: r.content,
      ts: r.timestamp != null ? Math.round(r.timestamp * 1000) : null
    }));
    auditLog('history_messages', ip, true, `session=${id} messages=${messages.length}`);
    res.json({
      session: { id: session.id, title: session.title || session.display_name || session.id },
      messages
    });
  } catch (e: any) {
    auditLog('history_messages', ip, false, e.message);
    res.status(500).json({ error: '获取会话消息失败' });
  } finally {
    try {
      db.close();
    } catch (e: any) {
      // 关闭失败忽略
    }
  }
});

module.exports = router;
