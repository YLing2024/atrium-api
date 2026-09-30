'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'node:child_process';

/**
 * Web 终端路由：口令二次验证 → 票据签发 / 票据校验（仅本机）/ tmux 会话列表与关闭。
 */

const express = require('express') as typeof import('express');
const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const os = require('os') as typeof import('os');
const crypto = require('crypto') as typeof import('crypto');
const { execSync } = require('child_process') as typeof import('child_process');

const { redis } = require('../state.ts') as { redis: import('ioredis').Redis };
const { auditLog, clientIp, sha256hex } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
  sha256hex: (str: unknown) => string;
};
const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};

const router = express.Router();

/* ---------- Web 终端会话（ttyd + tmux） ---------- */
// 会话名白名单：term- 前缀 + 小写字母/数字/短横，长度受限 —— 杜绝 tmux 命令注入
const TERM_SESSION_RE = /^term-[a-z0-9][a-z0-9-]{0,31}$/;

// 列出 ttyd/tmux 的终端会话（只暴露本系统创建的 term-* 会话）
function listTermSessions() {
  const out = execSync(
    "tmux list-sessions -F '#{session_name}|#{session_attached}|#{session_activity}' 2>/dev/null || true",
    { encoding: 'utf-8' }
  );
  return out
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [name, attached, activity] = line.split('|');
      return { name, attached: attached === '1', activity: Number(activity) || 0 };
    })
    .filter((s) => TERM_SESSION_RE.test(s.name));
}

/* ---------- 终端二次验证（口令 → 短期票） ---------- */
// 口令只存哈希：/root/.hermes/term_password 内容 "sha256$<salt>$<hash>"（600，不入库）
const TERM_PW_FILE = process.env.ADMIN_TERM_PW_FILE || path.join(os.homedir(), '.hermes', 'term_password');
const TERM_TICKET_PREFIX = 'term:ticket:';
const TERM_TICKET_TTL = 12 * 3600; // 12 小时
const TERM_UNLOCK_MAX_FAILS = 5;
const TERM_UNLOCK_LOCKOUT_MS = 10 * 60 * 1000; // 连续失败 5 次锁 10 分钟
const termUnlockState = new Map<string, { fails: number; until: number }>(); // ip -> { fails, until }

function termPasswordOk(pw: string): boolean {
  try {
    const raw = fs.readFileSync(TERM_PW_FILE, 'utf-8').trim();
    const [algo, salt, hash] = raw.split('$');
    if (algo !== 'sha256' || !salt || !hash) return false;
    const got = crypto.createHash('sha256').update(salt + ':' + String(pw)).digest('hex');
    const a = Buffer.from(got, 'hex');
    const b = Buffer.from(hash, 'hex');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  } catch (e: any) {
    return false; // 文件缺失/损坏一律拒绝
  }
}

// 终端口令校验 → 下发短期票（前端拿票去开终端会话）
router.post('/api/admin/term/unlock', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const st = termUnlockState.get(ip) || { fails: 0, until: 0 };
  const now = Date.now();
  if (st.until > now) {
    return res.status(429).json({ error: '尝试过多，请稍后再试', retryAfter: Math.ceil((st.until - now) / 1000) });
  }
  const pw = String((req.body && req.body.password) || '');
  if (!termPasswordOk(pw)) {
    st.fails += 1;
    if (st.fails >= TERM_UNLOCK_MAX_FAILS) {
      st.until = now + TERM_UNLOCK_LOCKOUT_MS;
      st.fails = 0;
    }
    termUnlockState.set(ip, st);
    auditLog('term_unlock_fail', ip, false, `fails=${st.fails}`);
    return res.status(401).json({ error: '口令不正确' });
  }
  termUnlockState.set(ip, { fails: 0, until: 0 });
  const ticket = crypto.randomBytes(32).toString('hex');
  try {
    await redis.set(TERM_TICKET_PREFIX + sha256hex(ticket), '1', 'EX', TERM_TICKET_TTL);
  } catch (e: any) {
    return res.status(500).json({ error: '票据存储失败: ' + e.message });
  }
  auditLog('term_unlock_ok', ip, true, '');
  res.json({ ticket, expiresIn: TERM_TICKET_TTL });
});

// 票据校验（供服务端 wrapper 起 shell 前调用；只允许本机）
router.get('/api/admin/term/verify', async (req, res) => {
  const ip = clientIp(req);
  if (!(ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1')) {
    return res.status(403).json({ ok: false });
  }
  const ticket = String((req.query && req.query.ticket) || '');
  if (!ticket) return res.status(400).json({ ok: false });
  try {
    const v = await redis.get(TERM_TICKET_PREFIX + sha256hex(ticket));
    if (!v) return res.status(401).json({ ok: false });
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ ok: false });
  }
});

// 终端会话列表（需鉴权）
router.get('/api/admin/term/sessions', authRequired, (req, res) => {
  try {
    res.json({ sessions: listTermSessions() });
  } catch (e: any) {
    res.status(500).json({ error: '读取终端会话失败: ' + e.message });
  }
});

// 批量关闭终端会话（需鉴权）：浏览器关窗/关标签时前端用 sendBeacon 调用，
// 避免会话与连接残留在服务端。names 不在白名单内的一律忽略（不做注入面）。
router.post('/api/admin/term/sessions/close', authRequired, (req, res) => {
  const body = req.body || {};
  const names = Array.isArray(body.names) ? body.names : [];
  const killed = [];
  for (const raw of names.slice(0, 32)) {
    const name = String(raw || '');
    if (!TERM_SESSION_RE.test(name)) continue;
    try {
      execSync(`tmux kill-session -t '${name}' 2>/dev/null || true`, { encoding: 'utf-8' });
      killed.push(name);
    } catch (e: any) {
      /* 单个失败不影响整体 */
    }
  }
  if (killed.length) auditLog('term_sessions_close', clientIp(req), true, killed.join(','));
  res.json({ ok: true, killed });
});

// 关闭指定终端会话（需鉴权）：admin 里关掉标签页时调用
router.delete('/api/admin/term/sessions/:name', authRequired, (req, res) => {
  const name = String(req.params.name || '');
  if (!TERM_SESSION_RE.test(name)) return res.status(400).json({ error: '非法会话名' });
  try {
    execSync(`tmux kill-session -t '${name}' 2>/dev/null || true`, { encoding: 'utf-8' });
    auditLog('term_session_kill', clientIp(req), true, name);
    res.json({ ok: true });
  } catch (e: any) {
    res.status(500).json({ error: '关闭终端会话失败: ' + e.message });
  }
});

module.exports = router;
