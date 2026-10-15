'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { DatabaseSync as SqliteDatabase } from 'node:sqlite';

/**
 * 通知附件：base64 校验/安全化命名/落盘/元信息入库/读取/清理。
 *
 * 设计要点：
 * - 文件本体落盘在 notification-files/<id>/<safeName>（目录 0700、文件 0600）；
 *   元信息（name/mime/size）入库 notification_attachments，供列表/详情/下载回 mime。
 * - 客户端给的 name 一律只取 basename 并做字符白名单替换，绝不用客户端路径。
 * - 附件写入失败不影响通知本身：调用方自行吞掉 warnings，只 warn 一行。
 * - 删除通知（单条/批量/保留期清理）时先删目录与元信息行，再删通知行。
 */

const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');

const { NOTIFICATIONS_DB_FILE } = require('../db.ts') as { NOTIFICATIONS_DB_FILE: string };

// 附件根目录：默认与通知库同级的 notification-files/，可用 ADMIN_NOTIFICATION_FILES_DIR 覆盖。
const NOTIFICATION_FILES_DIR =
  process.env.ADMIN_NOTIFICATION_FILES_DIR ||
  path.join(path.dirname(NOTIFICATIONS_DB_FILE), 'notification-files');

const ATTACHMENT_MAX_COUNT = 4;
const ATTACHMENT_MAX_FILE_BYTES = 8 * 1024 * 1024; // 单个解码后 ≤ 8 MB
const ATTACHMENT_MAX_TOTAL_BYTES = 20 * 1024 * 1024; // 合计 ≤ 20 MB

// 允许的 mime 白名单（其它一律 400）。
// text/html 供「归档报告网页」：正文应是可阅读的真实网页，而不是网页截图。
const ALLOWED_ATTACHMENT_MIMES = new Set([
  'image/png',
  'image/jpeg',
  'image/webp',
  'image/gif',
  'application/pdf',
  'text/markdown',
  'text/plain',
  'text/html'
]);

export type AttachmentMeta = { name: string; mime: string; size: number };
export type AttachmentView = AttachmentMeta & { url: string };
export type PreparedAttachment = { name: string; mime: string; data: Buffer };
export type ParseAttachmentsResult =
  | { ok: true; items: PreparedAttachment[] }
  | { ok: false; status: number; error: string };

/** 附件目录（notification-files/<id>） */
function attachmentDir(id: number): string {
  return path.join(NOTIFICATION_FILES_DIR, String(id));
}

/**
 * 安全化附件名：仅保留 basename，非法字符替换为 `_`，长度 ≤ 80，去首部 `.`。
 * 结果绝不含路径分隔符，空名回退 `file`。
 */
function sanitizeAttachmentName(rawName: unknown): string {
  let name = typeof rawName === 'string' ? rawName : '';
  // 反斜杠先归一为 `/`，再取 basename，杜绝 Windows 路径参与
  name = name.replace(/\\/g, '/');
  const base = name.split('/').pop() || '';
  let safe = base.replace(/[^A-Za-z0-9._-]/g, '_');
  safe = safe.slice(0, 80).replace(/^\.+/, '');
  return safe || 'file';
}

// 同一通知内重名：在扩展名前插入 `-2`、`-3`…（保留扩展名，便于下载/预览识别类型）。
// 加后缀后仍须满足长度 ≤ 80 的不变量，故按后缀长度回缩主名。
function dedupeName(name: string, used: Set<string>): string {
  if (!used.has(name)) return name;
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  let n = 2;
  let candidate = '';
  do {
    const suffix = `-${n}`;
    const room = Math.max(1, 80 - suffix.length - ext.length);
    candidate = stem.slice(0, room) + suffix + ext;
    n += 1;
  } while (used.has(candidate));
  return candidate;
}

// 去掉可能的 data URL 前缀（`data:image/png;base64,`），只留纯 base64
function stripDataUrlPrefix(s: string): string {
  const idx = s.indexOf('base64,');
  return idx >= 0 ? s.slice(idx + 'base64,'.length) : s;
}

/**
 * 校验并解码请求里的 attachments。
 * 超限（数量/单文件/合计）→ 413 `附件过大`；mime 不在白名单或结构非法 → 400。
 * 返回的 name 已安全化并做请求内去重。
 */
function parseAttachments(input: unknown): ParseAttachmentsResult {
  if (input == null) return { ok: true, items: [] };
  if (!Array.isArray(input)) return { ok: false, status: 400, error: '附件格式无效' };
  if (input.length > ATTACHMENT_MAX_COUNT) return { ok: false, status: 413, error: '附件过大' };
  const used = new Set<string>();
  const items: PreparedAttachment[] = [];
  let total = 0;
  for (const raw of input) {
    if (!raw || typeof raw !== 'object') return { ok: false, status: 400, error: '附件格式无效' };
    const rec = raw as Record<string, unknown>;
    const mime = typeof rec.mime === 'string' ? rec.mime.trim().toLowerCase() : '';
    if (!ALLOWED_ATTACHMENT_MIMES.has(mime)) {
      return { ok: false, status: 400, error: '不支持的附件类型' };
    }
    const dataBase64 = typeof rec.dataBase64 === 'string' ? stripDataUrlPrefix(rec.dataBase64.trim()) : '';
    if (!dataBase64) return { ok: false, status: 400, error: '附件数据无效' };
    let data: Buffer;
    try {
      data = Buffer.from(dataBase64, 'base64');
    } catch (e: any) {
      return { ok: false, status: 400, error: '附件数据无效' };
    }
    if (data.length === 0) return { ok: false, status: 400, error: '附件数据无效' };
    if (data.length > ATTACHMENT_MAX_FILE_BYTES) return { ok: false, status: 413, error: '附件过大' };
    total += data.length;
    if (total > ATTACHMENT_MAX_TOTAL_BYTES) return { ok: false, status: 413, error: '附件过大' };
    const name = dedupeName(sanitizeAttachmentName(rec.name), used);
    used.add(name);
    items.push({ name, mime, data });
  }
  return { ok: true, items };
}

/**
 * 落盘附件并写元信息。同一通知（dedupKey 命中的重复写入）为覆盖式：先清掉旧附件，
 * 避免目录/元信息堆叠历史文件；同批次内重名自动加后缀。
 * 单个附件失败只记 warning，不抛出、不影响其余附件（调用方据此不阻断通知本身）。
 */
function saveNotificationAttachments(
  db: SqliteDatabase,
  id: number,
  items: PreparedAttachment[]
): { metas: AttachmentMeta[]; warnings: string[] } {
  const metas: AttachmentMeta[] = [];
  const warnings: string[] = [];
  if (!items.length) return { metas, warnings };

  // 覆盖式写入：先清空该通知既有附件（元信息行 + 目录），再落本批
  deleteNotificationAttachments(db, [id]);

  const used = new Set<string>();
  const dir = attachmentDir(id);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    fs.chmodSync(dir, 0o700);
  } catch (e: any) {
    warnings.push('附件目录不可写');
    console.warn('[admin-server] 通知附件目录创建失败:', e.message);
    return { metas, warnings };
  }

  for (const item of items) {
    const name = dedupeName(item.name, used);
    used.add(name);
    try {
      fs.writeFileSync(path.join(dir, name), item.data, { mode: 0o600 });
      fs.chmodSync(path.join(dir, name), 0o600);
      db.prepare(
        'INSERT OR REPLACE INTO notification_attachments (notification_id, name, mime, size) VALUES (?, ?, ?, ?)'
      ).run(id, name, item.mime, item.data.length);
      metas.push({ name, mime: item.mime, size: item.data.length });
    } catch (e: any) {
      // 回给客户端的 warning 不含系统路径，细节只进服务端日志
      warnings.push(`附件写入失败: ${name}`);
      console.warn('[admin-server] 通知附件写入失败:', e.message);
    }
  }
  return { metas, warnings };
}

/** 单条通知的附件元信息（按 name 升序） */
function listAttachments(db: SqliteDatabase, id: number): AttachmentMeta[] {
  return (db
    .prepare('SELECT name, mime, size FROM notification_attachments WHERE notification_id = ? ORDER BY name ASC')
    .all(id) as { name: string; mime: string; size: number }[]).map((r) => ({
    name: r.name,
    mime: r.mime,
    size: Number(r.size)
  }));
}

/** 批量取附件元信息（列表页一次查清，避免逐条读盘） */
function attachmentsForIds(db: SqliteDatabase, ids: number[]): Map<number, AttachmentMeta[]> {
  const map = new Map<number, AttachmentMeta[]>();
  if (!ids.length) return map;
  const placeholders = ids.map(() => '?').join(',');
  const rows = db
    .prepare(
      `SELECT notification_id, name, mime, size FROM notification_attachments ` +
        `WHERE notification_id IN (${placeholders}) ORDER BY notification_id ASC, name ASC`
    )
    .all(...ids) as { notification_id: number; name: string; mime: string; size: number }[];
  for (const r of rows) {
    const key = Number(r.notification_id);
    const list = map.get(key) || [];
    list.push({ name: r.name, mime: r.mime, size: Number(r.size) });
    map.set(key, list);
  }
  return map;
}

/** 附件下载地址（同源相对路径；前端直接使用不要再拼） */
function attachmentUrl(id: number, name: string): string {
  return `/api/admin/notifications/${id}/files/${encodeURIComponent(name)}`;
}

/** 元信息 → 接口视图（带 url） */
function toAttachmentViews(id: number, metas: AttachmentMeta[]): AttachmentView[] {
  return metas.map((m) => ({ ...m, url: attachmentUrl(id, m.name) }));
}

/** 是否存在图片附件（前端列表显示图片标记用） */
function hasImageAttachment(metas: AttachmentMeta[]): boolean {
  return metas.some((m) => m.mime.startsWith('image/'));
}

// 归档 HTML 报告以同源页面内嵌进管理端，本机脚本产出的报告无 JS。
// 安全红线：绝不能让归档 HTML 以同源身份执行脚本——CSP 只给 `sandbox`
// （不带 allow-scripts / allow-same-origin），并配 nosniff 禁止 MIME 嗅探。
const HTML_ATTACHMENT_DOWNLOAD_HEADERS: Record<string, string> = {
  'Content-Security-Policy': 'sandbox',
  'X-Content-Type-Options': 'nosniff'
};

/**
 * 附件下载的额外响应头：仅 `text/html` 附加 CSP `sandbox` + `nosniff`。
 * 其它 mime 返回空对象，保持既有下载行为不变。
 */
function attachmentDownloadHeaders(mime: string): Record<string, string> {
  return mime === 'text/html' ? { ...HTML_ATTACHMENT_DOWNLOAD_HEADERS } : {};
}

// 解码 URI（express 已解一层，兼容双重编码）；失败保留原值
function safeDecode(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch (e: any) {
    return raw;
  }
}

/**
 * 定位待下载的附件：name 精确匹配落盘文件名，并做 path.resolve 前缀校验防穿越。
 * 未命中 / 非法 → null。
 */
function findAttachment(
  db: SqliteDatabase,
  id: number,
  rawName: unknown
): { path: string; name: string; mime: string } | null {
  const decoded = safeDecode(String(rawName == null ? '' : rawName));
  const base = path.basename(decoded);
  if (!base || base === '.' || base === '..') return null;
  const dir = path.resolve(attachmentDir(id));
  const resolved = path.resolve(dir, base);
  if (resolved !== path.join(dir, base) || !resolved.startsWith(dir + path.sep)) return null;
  const meta = db
    .prepare('SELECT name, mime FROM notification_attachments WHERE notification_id = ? AND name = ?')
    .get(id, base) as { name: string; mime: string } | undefined;
  if (!meta) return null;
  if (!fs.existsSync(resolved)) return null;
  return { path: resolved, name: base, mime: meta.mime };
}

/**
 * 删除若干通知的附件：先删元信息行，再删整个附件目录。
 * 删目录失败只 warn，不抛出、不阻断删除通知行。
 */
function deleteNotificationAttachments(db: SqliteDatabase, ids: number[]): void {
  if (!ids.length) return;
  const placeholders = ids.map(() => '?').join(',');
  try {
    db.prepare(`DELETE FROM notification_attachments WHERE notification_id IN (${placeholders})`).run(...ids);
  } catch (e: any) {
    console.warn('[admin-server] 删除通知附件元信息失败（不影响删除通知）:', e.message);
  }
  for (const id of ids) {
    try {
      fs.rmSync(attachmentDir(id), { recursive: true, force: true });
    } catch (e: any) {
      console.warn(`[admin-server] 删除通知附件目录失败 id=${id}:`, e.message);
    }
  }
}

module.exports = {
  NOTIFICATION_FILES_DIR,
  ATTACHMENT_MAX_COUNT,
  ATTACHMENT_MAX_FILE_BYTES,
  ATTACHMENT_MAX_TOTAL_BYTES,
  ALLOWED_ATTACHMENT_MIMES,
  sanitizeAttachmentName,
  parseAttachments,
  saveNotificationAttachments,
  listAttachments,
  attachmentsForIds,
  attachmentUrl,
  toAttachmentViews,
  hasImageAttachment,
  attachmentDownloadHeaders,
  findAttachment,
  deleteNotificationAttachments
};
