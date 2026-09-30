'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Request } from 'express';

/**
 * 文件区临时链接（限时分享）路由：创建 / 列表 / 改期 / 撤销 / 删除，以及公开下载 /s/:token。
 * 账本为本地 JSON；status 不落盘，读取时按 revokedAt / expiresAt 推导。
 */

const express = require('express') as typeof import('express');
const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const crypto = require('crypto') as typeof import('crypto');

const { PORT } = require('../config.ts') as { PORT: number };
const { FILE_DIR, resolveFileRel, isProtectedPath, relFromFull } = require('./files.ts') as {
  FILE_DIR: string;
  resolveFileRel: (rel: unknown) => string | null;
  isProtectedPath: (full: string) => boolean;
  relFromFull: (full: string) => string;
};
const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: Request) => string;
};

const router = express.Router();

/* ============ 文件区 · 临时链接（限时分享 /s/:token） ============ */
// 语义对齐 v2link（server/src/lib/expiry.ts、services/linkService.ts）：
//   · expiresAt === 0 为「永久有效」哨兵（单字段表达，不引入第二个 permanent 布尔列）；
//   · 状态机 active → expired | revoked；revoked 不可逆，仅 active 可改期；
//   · 改期改的是「过期时刻」本身（不是"延长 N 小时"），过去时刻一律 400，立即失效走 revoked。
// 账本为本地 JSON（data/file-shares.json，可用 ADMIN_SHARE_FILE 覆盖）；status 不落盘，
// 读取时按 revokedAt / expiresAt 推导，避免两份事实。

const SHARE_FILE =
  process.env.ADMIN_SHARE_FILE || path.join(__dirname, '..', '..', 'data', 'file-shares.json');
// 分享链接基址：优先环境变量（去掉末尾斜杠）；未设置时按请求头推导（见 shareBaseUrl）
const SHARE_BASE_URL = String(process.env.ADMIN_SHARE_BASE_URL || '').replace(/\/+$/, '');
const SHARE_PERMANENT = 0; // expiresAt 哨兵：永久有效
const SHARE_DEFAULT_TTL_HOURS = 24;
const SHARE_MIN_TTL_HOURS = 1;
const SHARE_MAX_TTL_HOURS = 8760; // 365 天
const SHARE_REVOKED_KEEP_MS = 30 * 24 * 3600 * 1000; // revoked 记录保留 30 天
const SHARE_EXPIRED_KEEP_MS = 90 * 24 * 3600 * 1000; // expired 记录保留 90 天

// 分享账本记录（data/file-shares.json 数组元素；字段由本模块写入，读取时宽松校验）
type ShareRecord = {
  id: string;
  token: string;
  relPath: string;
  size?: number;
  note?: string;
  createdAt?: number;
  expiresAt: number;
  revokedAt?: number | null;
  downloads?: number;
  lastAccessAt?: number | null;
  lastAccessIp?: string | null;
};

// 是否永久有效（expiresAt 为哨兵 0）；所有比较/展示统一走此函数，禁止裸写 === 0
function isPermanentExpiry(expiresAt: unknown): boolean {
  return Number(expiresAt) === SHARE_PERMANENT;
}

// 状态推导（不落盘）：revoked 优先，其次永久，其次按到期时刻判定
function shareStatus(rec: ShareRecord, now: number): string {
  if (rec && rec.revokedAt) return 'revoked';
  if (isPermanentExpiry(rec && rec.expiresAt)) return 'active';
  return Number(rec && rec.expiresAt) <= now ? 'expired' : 'active';
}

// 读取账本原始数组：文件不存在视为空，损坏则回退空（不阻断服务）
function readSharesRaw(): ShareRecord[] {
  try {
    const raw = fs.readFileSync(SHARE_FILE, 'utf-8');
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? (arr as ShareRecord[]) : [];
  } catch (e: any) {
    return [];
  }
}

// 原子写账本（临时文件 + rename，避免读端读到半截内容；与 persistHistory 写法一致）
function writeShares(list: ShareRecord[]): void {
  try {
    fs.mkdirSync(path.dirname(SHARE_FILE), { recursive: true });
    const tmp = SHARE_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(list, null, 2));
    fs.renameSync(tmp, SHARE_FILE);
  } catch (e: any) {
    console.error('[admin-server] 分享账本写入失败:', e.message);
  }
}

// 读取账本并惰性清理：revoked 超 30 天 / expired 超 90 天自动删除（有变化才写回）
function readShares() {
  const now = Date.now();
  const list = readSharesRaw();
  const kept = list.filter((rec) => {
    if (!rec || typeof rec !== 'object') return false;
    const st = shareStatus(rec, now);
    if (st === 'revoked') {
      return !(rec.revokedAt && now - rec.revokedAt > SHARE_REVOKED_KEEP_MS);
    }
    if (st === 'expired') {
      const exp = Number(rec.expiresAt);
      return !(exp > 0 && now - exp > SHARE_EXPIRED_KEEP_MS);
    }
    return true;
  });
  if (kept.length !== list.length) writeShares(kept);
  return kept;
}

// 分享基址：环境变量优先；否则 X-Forwarded-Proto + Host 推导（禁止硬编码域名）
function shareBaseUrl(req: Request): string {
  if (SHARE_BASE_URL) return SHARE_BASE_URL;
  const proto =
    String(((req.headers['x-forwarded-proto'] as string) || '').split(',')[0].trim()) || 'http';
  const host =
    String(req.headers['x-forwarded-host'] || req.headers.host || '')
      .split(',')[0]
      .trim() || `127.0.0.1:${PORT}`;
  return `${proto}://${host}`;
}

// 分享路径规范化：仅接受 FILE_DIR 内的相对路径（绝对路径 / 越界 / 含 .. 一律拒绝）
// 创建入参用此函数（内部复用现有 resolveFileRel），账本已存 relPath 用 shareFullFromRel 还原
function resolveSharePath(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;
  let decoded;
  try {
    decoded = decodeURIComponent(trimmed);
  } catch (e: any) {
    return null;
  }
  // 绝对路径（/etc/passwd、C:\...）一律拒绝：文件区路径只允许相对 FILE_DIR
  if (/^[/\\]/.test(decoded) || /^[a-zA-Z]:[\\/]/.test(decoded)) return null;
  if (decoded.split(/[\\/]/).some((seg) => seg === '..')) return null;
  const full = resolveFileRel(trimmed);
  if (!full || full === FILE_DIR) return null;
  return full;
}

// 账本 relPath（不含 URL 编码）→ 绝对路径；越界返回 null（防账本被篡改）
function shareFullFromRel(rel: unknown): string | null {
  if (typeof rel !== 'string' || !rel) return null;
  const full = path.resolve(FILE_DIR, rel);
  if (full !== FILE_DIR && !full.startsWith(FILE_DIR + path.sep)) return null;
  return full;
}

// lstat 判定：file / dir / other（符号链接等特殊文件）/ missing
function shareFileInfo(full: string | null): { kind: string; size: number } {
  if (!full) return { kind: 'missing', size: 0 };
  try {
    const st = fs.lstatSync(full);
    if (st.isFile()) return { kind: 'file', size: st.size };
    if (st.isDirectory()) return { kind: 'dir', size: 0 };
    return { kind: 'other', size: 0 };
  } catch (e: any) {
    return { kind: 'missing', size: 0 };
  }
}

// 记录 → 列表视图（存储字段 + 计算字段 url / status / remainingMs / fileExists）
function toShareView(rec: ShareRecord, req: Request, now: number) {
  const status = shareStatus(rec, now);
  const remainingMs =
    status === 'active'
      ? isPermanentExpiry(rec.expiresAt)
        ? null
        : Math.max(0, Number(rec.expiresAt) - now)
      : 0;
  const full = shareFullFromRel(rec.relPath);
  return {
    id: rec.id,
    token: rec.token,
    relPath: rec.relPath,
    size: rec.size,
    note: rec.note || '',
    createdAt: rec.createdAt,
    expiresAt: rec.expiresAt,
    revokedAt: rec.revokedAt || null,
    downloads: rec.downloads || 0,
    lastAccessAt: rec.lastAccessAt || null,
    lastAccessIp: rec.lastAccessIp || null,
    url: `${shareBaseUrl(req)}/s/${rec.token}`,
    status,
    remainingMs,
    fileExists: shareFileInfo(full).kind === 'file'
  };
}

// 创建临时链接：body { path, expiresAt? | ttlHours?, note? }
//   path      —— 文件区相对路径（必须是普通文件、非受保护路径）
//   expiresAt —— 绝对到期 epoch ms；0 = 永久；必须为将来时刻，二选一优先于 ttlHours
//   ttlHours  —— 相对时长（夹紧 1~8760 小时）；都不给默认 24 小时
router.post('/api/admin/files/shares', authRequired, (req, res) => {
  const ip = clientIp(req);
  const body = req.body || {};
  const full = resolveSharePath(body.path);
  if (!full) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) {
    return res.status(403).json({ error: '该文件受保护，不允许分享' });
  }
  const info = shareFileInfo(full);
  if (info.kind === 'missing') return res.status(404).json({ error: '文件不存在' });
  if (info.kind === 'dir') return res.status(400).json({ error: '暂不支持分享目录' });
  if (info.kind !== 'file') return res.status(400).json({ error: '不是普通文件' });

  const now = Date.now();
  let expiresAt;
  const hasAbs =
    body.expiresAt !== undefined && body.expiresAt !== null && body.expiresAt !== '';
  if (hasAbs) {
    const at = Number(body.expiresAt);
    if (!Number.isFinite(at) || !Number.isInteger(at) || at < 0) {
      return res.status(400).json({ error: 'expiresAt 须为 epoch 毫秒整数（0 表示永久）' });
    }
    if (at !== SHARE_PERMANENT && at <= now) {
      return res
        .status(400)
        .json({ error: 'expiresAt 须为将来时刻（0 表示永久；立即失效请用撤销）' });
    }
    expiresAt = at;
  } else if (body.ttlHours !== undefined && body.ttlHours !== null && body.ttlHours !== '') {
    const h = Number(body.ttlHours);
    if (!Number.isFinite(h)) return res.status(400).json({ error: 'ttlHours 须为数字' });
    const clamped = Math.min(SHARE_MAX_TTL_HOURS, Math.max(SHARE_MIN_TTL_HOURS, h));
    expiresAt = now + clamped * 3600 * 1000;
  } else {
    expiresAt = now + SHARE_DEFAULT_TTL_HOURS * 3600 * 1000;
  }

  const note = typeof body.note === 'string' ? body.note.trim().slice(0, 500) : '';
  const rec = {
    id: crypto.randomBytes(6).toString('base64url'), // 随机 8 位短 id
    token: crypto.randomBytes(24).toString('base64url'),
    relPath: relFromFull(full), // 相对 FILE_DIR，用 / 分隔
    size: info.size,
    note,
    createdAt: now,
    expiresAt,
    revokedAt: null,
    downloads: 0,
    lastAccessAt: null,
    lastAccessIp: null
  };
  const list = readShares();
  list.push(rec);
  writeShares(list);
  auditLog(
    'share-create',
    ip,
    true,
    `id=${rec.id} path=${rec.relPath} expiresAt=${rec.expiresAt}`
  );
  res.status(201).json(toShareView(rec, req, now));
});

// 临时链接列表：按 createdAt 倒序，含计算字段（url / status / remainingMs / fileExists）
router.get('/api/admin/files/shares', authRequired, (req, res) => {
  const now = Date.now();
  const list = readShares().sort((a, b) => (Number(b.createdAt) || 0) - (Number(a.createdAt) || 0));
  res.json({ shares: list.map((r) => toShareView(r, req, now)) });
});

// 改期 / 转永久 / 改备注 / 撤销：body { expiresAt?, note?, revoked? }
//   expiresAt: 0 → 转永久；>0 → 直接设为该绝对到期时刻（须为将来时刻）
//   revoked: true → 撤销（不可逆）；仅 active 记录可操作
router.patch('/api/admin/files/shares/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  const body = req.body || {};
  const now = Date.now();

  const list = readShares();
  const idx = list.findIndex((r) => r && r.id === id);
  if (idx === -1) return res.status(404).json({ error: '链接不存在' });
  const rec = list[idx];

  if (body.revoked !== undefined && typeof body.revoked !== 'boolean') {
    return res.status(400).json({ error: 'revoked 须为布尔值' });
  }
  if (body.revoked === false) {
    return res.status(400).json({ error: '撤销不可逆，无法恢复' });
  }
  const wantsRevoke = body.revoked === true;
  const hasExpiry =
    body.expiresAt !== undefined && body.expiresAt !== null && body.expiresAt !== '';
  const hasNote = body.note !== undefined;
  if (!wantsRevoke && !hasExpiry && !hasNote) {
    return res.status(400).json({ error: '没有可更新的字段' });
  }

  // 状态机：仅 active 可改期 / 撤销（expired / revoked 不可再操作）
  const status = shareStatus(rec, now);
  if (status !== 'active') {
    return res.status(400).json({ error: `仅有效链接可操作（当前 ${status}）` });
  }

  if (wantsRevoke) rec.revokedAt = now;
  if (hasExpiry) {
    const at = Number(body.expiresAt);
    if (!Number.isFinite(at) || !Number.isInteger(at) || at < 0) {
      return res.status(400).json({ error: 'expiresAt 须为 epoch 毫秒整数（0 表示永久）' });
    }
    if (at !== SHARE_PERMANENT && at <= now) {
      return res
        .status(400)
        .json({ error: 'expiresAt 须为将来时刻（0 表示永久；立即失效请用撤销）' });
    }
    rec.expiresAt = at;
  }
  if (hasNote) {
    rec.note = typeof body.note === 'string' ? body.note.trim().slice(0, 500) : '';
  }

  list[idx] = rec;
  writeShares(list);
  auditLog(
    'share-update',
    ip,
    true,
    `id=${id} revoked=${wantsRevoke ? 1 : 0} expiresAt=${rec.expiresAt}`
  );
  res.json(toShareView(rec, req, now));
});

// 删除记录（不动磁盘文件）
router.delete('/api/admin/files/shares/:id', authRequired, (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  const list = readShares();
  const idx = list.findIndex((r) => r && r.id === id);
  if (idx === -1) return res.status(404).json({ error: '链接不存在' });
  const removed = list.splice(idx, 1)[0];
  writeShares(list);
  auditLog('share-delete', ip, true, `id=${id} path=${removed.relPath}`);
  res.json({ ok: true });
});

// 公开下载（免鉴权）：只认 token，不接受任何路径参数，不做目录列举。
//   命中且 active → 流式返回附件（文件名按 RFC 5987 编码，见 res.download）
//   token 不存在 / 文件已删 → 404；已撤销 / 已过期 → 410 Gone
//   三个失败分支共用同一张极简 HTML 提示页，不回显服务器路径
router.get('/s/:token', (req, res) => {
  const ip = clientIp(req);
  const now = Date.now();
  const fail = (status: number, text: string) => {
    res
      .status(status)
      .type('html')
      .send(
        '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">' +
          '<meta name="viewport" content="width=device-width,initial-scale=1">' +
          `<title>${text}</title></head>` +
          '<body style="margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;' +
          'font-family:system-ui,-apple-system,\'Segoe UI\',sans-serif;background:#0f1115;color:#c9d1d9">' +
          `<main style="text-align:center"><p style="font-size:15px;letter-spacing:.05em">${text}</p></main>` +
          '</body></html>'
      );
  };

  const token = String(req.params.token || '');
  if (!token) return fail(404, '链接不存在');

  const list = readShares();
  const rec = list.find((r) => r && r.token === token);
  if (!rec) return fail(404, '链接不存在');

  const status = shareStatus(rec, now);
  if (status === 'revoked' || status === 'expired') return fail(410, '链接已失效');

  const full = shareFullFromRel(rec.relPath);
  const info = shareFileInfo(full);
  if (info.kind !== 'file') return fail(404, '链接不存在');

  // 成功下载：计数 + 记录最后访问（IP 用 clientIp），并写审计
  rec.downloads = (rec.downloads || 0) + 1;
  rec.lastAccessAt = now;
  rec.lastAccessIp = ip;
  writeShares(list);
  auditLog('share-download', ip, true, rec.relPath);
  res.download(full as string, path.basename(full as string), (err) => {
    if (err && !res.headersSent) {
      console.error('[admin-server] 分享下载失败:', err.message);
    }
  });
});

module.exports = router;
