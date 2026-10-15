'use strict';

// 模块边界标记：让本文件成为 TS 模块（类型导入会被原样剥离，运行时仍是 CommonJS）
import type {} from 'node:test';

// 通知附件/详情/列表/清理单元测试（node:test，零依赖）。
// 关键：必须在 require 之前设置 ADMIN_NOTIFICATIONS_DB / ADMIN_NOTIFICATION_FILES_DIR /
// ADMIN_NOTIFICATION_RETENTION_DAYS —— db.ts 与 attachments.ts 模块加载即解析这些路径。
// 全部落到 os.tmpdir() 临时目录，绝不读写仓库里的真实通知库。

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-notif-'));
const DB_FILE = path.join(tmpDir, 'notifications.db');
const FILES_DIR = path.join(tmpDir, 'notification-files');
process.env.ADMIN_NOTIFICATIONS_DB = DB_FILE;
process.env.ADMIN_NOTIFICATION_FILES_DIR = FILES_DIR;
process.env.ADMIN_NOTIFICATION_RETENTION_DAYS = '180';

const dbMod = require('../src/db.ts');
const store = require('../src/notifications/store.ts');
const attachments = require('../src/notifications/attachments.ts');

const { openNotificationsDb } = dbMod;
const db = openNotificationsDb();
assert.ok(db, '通知库应可打开');

// 1x1 PNG 头字节，仅用于构造合法 base64 负载
const PNG_BYTES = Buffer.from('89504e470d0a1a0a0000000d49484452', 'hex');
const b64 = (buf: Buffer) => buf.toString('base64');

function writeOne(overrides: Record<string, unknown> = {}) {
  return store.writeNotification(db, {
    levelInput: 'normal',
    source: 'cron',
    typeKey: 'cron',
    title: '测试通知',
    body: '## 正文',
    link: null,
    dedupKey: null,
    ...overrides
  });
}

test('sanitizeAttachmentName：取 basename、替换非法字符、去首部点、限长、空名回退', () => {
  assert.equal(attachments.sanitizeAttachmentName('../../etc/passwd'), 'passwd');
  assert.equal(attachments.sanitizeAttachmentName('a/b/c.png'), 'c.png');
  assert.equal(attachments.sanitizeAttachmentName('..\\..\\windows\\x.txt'), 'x.txt');
  assert.equal(attachments.sanitizeAttachmentName('.hidden'), 'hidden');
  assert.equal(attachments.sanitizeAttachmentName('报告 1.png'), '___1.png');
  assert.equal(attachments.sanitizeAttachmentName('x'.repeat(100)), 'x'.repeat(80));
  assert.equal(attachments.sanitizeAttachmentName(''), 'file');
});

test('parseAttachments：mime 白名单、数量上限、单文件上限', () => {
  const bad = attachments.parseAttachments([{ name: 'a.zip', mime: 'application/zip', dataBase64: b64(PNG_BYTES) }]);
  assert.equal(bad.ok, false);
  assert.equal(bad.status, 400);

  const five = Array.from({ length: 5 }, (_, i) => ({ name: `a${i}.png`, mime: 'image/png', dataBase64: b64(PNG_BYTES) }));
  const tooMany = attachments.parseAttachments(five);
  assert.equal(tooMany.ok, false);
  assert.equal(tooMany.status, 413);

  const huge = Buffer.alloc(8 * 1024 * 1024 + 1, 1);
  const tooBig = attachments.parseAttachments([{ name: 'big.png', mime: 'image/png', dataBase64: b64(huge) }]);
  assert.equal(tooBig.ok, false);
  assert.equal(tooBig.status, 413);

  const notArray = attachments.parseAttachments({});
  assert.equal(notArray.ok, false);
  assert.equal(notArray.status, 400);
});

test('parseAttachments：重名自动加后缀（保留扩展名）', () => {
  const parsed = attachments.parseAttachments([
    { name: 'report.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) },
    { name: 'report.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) }
  ]);
  assert.equal(parsed.ok, true);
  assert.deepEqual(
    parsed.items.map((i: { name: string }) => i.name),
    ['report.png', 'report-2.png']
  );
});

test('saveNotificationAttachments：落盘 0600、目录 0700、元信息入库', () => {
  const r = writeOne({ title: '带附件' });
  const parsed = attachments.parseAttachments([
    { name: 'shot.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) },
    { name: 'notes.md', mime: 'text/markdown', dataBase64: b64(Buffer.from('# hi')) }
  ]);
  assert.equal(parsed.ok, true);
  const saved = attachments.saveNotificationAttachments(db, r.id, parsed.items);
  assert.equal(saved.warnings.length, 0);
  assert.equal(saved.metas.length, 2);

  const dir = path.join(FILES_DIR, String(r.id));
  assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
  assert.equal(fs.statSync(path.join(dir, 'shot.png')).mode & 0o777, 0o600);

  const meta = attachments.listAttachments(db, r.id);
  assert.deepEqual(
    meta.map((m: { name: string }) => m.name),
    ['notes.md', 'shot.png']
  );
});

test('parseAttachments：text/html 允许写入并落盘', () => {
  const r = writeOne({ title: '网页报告' });
  const parsed = attachments.parseAttachments([
    { name: 'report.html', mime: 'text/html', dataBase64: b64(Buffer.from('<h1>报告</h1>')) }
  ]);
  assert.equal(parsed.ok, true);
  const saved = attachments.saveNotificationAttachments(db, r.id, parsed.items);
  assert.equal(saved.warnings.length, 0);
  assert.equal(saved.metas[0].mime, 'text/html');
  assert.ok(fs.existsSync(path.join(FILES_DIR, String(r.id), 'report.html')));
  assert.equal(attachments.listAttachments(db, r.id)[0].mime, 'text/html');
});

test('attachmentDownloadHeaders：text/html 附 CSP sandbox + nosniff，其它 mime 不加', () => {
  const html = attachments.attachmentDownloadHeaders('text/html');
  assert.equal(html['Content-Security-Policy'], 'sandbox');
  assert.equal(html['X-Content-Type-Options'], 'nosniff');
  // 红线：不得放开脚本或同源身份
  assert.ok(!html['Content-Security-Policy'].includes('allow-scripts'));
  assert.ok(!html['Content-Security-Policy'].includes('allow-same-origin'));
  assert.deepEqual(attachments.attachmentDownloadHeaders('image/png'), {});
});

test('列表带 attachments + hasImage；详情带附件；下载地址正确', () => {
  const r = writeOne({ title: '列表附件' });
  const parsed = attachments.parseAttachments([
    { name: 'a.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) }
  ]);
  attachments.saveNotificationAttachments(db, r.id, parsed.items);

  const list = store.listNotifications(db, {
    limit: 200,
    before: null,
    level: null,
    source: null,
    type: null,
    unreadOnly: false
  });
  const item = list.items.find((i: { id: number }) => i.id === r.id);
  assert.ok(item);
  assert.equal(item.attachments.length, 1);
  assert.equal(item.hasImage, true);
  assert.equal(item.attachments[0].url, `/api/admin/notifications/${r.id}/files/a.png`);

  const detail = store.getNotification(db, r.id);
  assert.ok(detail);
  assert.equal(detail.attachments.length, 1);
  assert.equal(detail.hasImage, true);

  assert.equal(store.getNotification(db, 999999), null);
});

test('findAttachment：精确匹配 + 防穿越', () => {
  const r = writeOne({ title: '下载' });
  const parsed = attachments.parseAttachments([
    { name: 'doc.pdf', mime: 'application/pdf', dataBase64: b64(PNG_BYTES) }
  ]);
  attachments.saveNotificationAttachments(db, r.id, parsed.items);

  const ok = attachments.findAttachment(db, r.id, 'doc.pdf');
  assert.ok(ok);
  assert.equal(ok.mime, 'application/pdf');
  // basename 归一：带目录的 name 会落到 basename 上的同名文件（防穿越靠 basename + 前缀校验）
  assert.equal(attachments.findAttachment(db, r.id, '../doc.pdf')?.name, 'doc.pdf');
  assert.equal(attachments.findAttachment(db, r.id, '../../etc/passwd'), null);
  assert.equal(attachments.findAttachment(db, r.id, 'missing.pdf'), null);
});

test('deleteNotification：连同附件目录与元信息一并删除', () => {
  const r = writeOne({ title: '待删' });
  const parsed = attachments.parseAttachments([
    { name: 'x.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) }
  ]);
  attachments.saveNotificationAttachments(db, r.id, parsed.items);
  const dir = path.join(FILES_DIR, String(r.id));
  assert.ok(fs.existsSync(dir));

  store.deleteNotification(db, r.id);
  assert.equal(fs.existsSync(dir), false);
  assert.equal(store.getNotification(db, r.id), null);
  assert.equal(attachments.listAttachments(db, r.id).length, 0);
});

test('cleanupNotifications：过期通知行与附件目录一并清理', () => {
  const r = writeOne({ title: '过期' });
  const parsed = attachments.parseAttachments([
    { name: 'old.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) }
  ]);
  attachments.saveNotificationAttachments(db, r.id, parsed.items);
  // 造一条 200 天前的时间（保留期 180 天）
  db.prepare('UPDATE notifications SET ts = ? WHERE id = ?').run(Math.floor(Date.now() / 1000) - 200 * 86400, r.id);
  const dir = path.join(FILES_DIR, String(r.id));
  assert.ok(fs.existsSync(dir));

  store.cleanupNotifications();

  assert.equal(store.getNotification(db, r.id), null);
  assert.equal(fs.existsSync(dir), false);
  assert.equal(attachments.listAttachments(db, r.id).length, 0);
});

test('bulkDeleteNotifications：dryRun 只统计；实删含附件清理', () => {
  const a = writeOne({ title: '批量A', typeKey: 'bulk-a', source: 'bulk-a' });
  const b = writeOne({ title: '批量B', typeKey: 'bulk-b', source: 'bulk-b' });
  const parsed = attachments.parseAttachments([
    { name: 'p.png', mime: 'image/png', dataBase64: b64(PNG_BYTES) }
  ]);
  attachments.saveNotificationAttachments(db, a.id, parsed.items);

  const dry = store.bulkDeleteNotifications(db, {
    level: null, source: 'bulk-a', unreadOnly: false, readOnly: false
  }, true);
  assert.equal(dry, 1);
  assert.ok(store.getNotification(db, a.id), 'dryRun 不应删除');

  const deleted = store.bulkDeleteNotifications(db, {
    level: null, source: 'bulk-a', unreadOnly: false, readOnly: false
  }, false);
  assert.equal(deleted, 1);
  assert.equal(store.getNotification(db, a.id), null);
  assert.equal(fs.existsSync(path.join(FILES_DIR, String(a.id))), false);
  assert.ok(store.getNotification(db, b.id), '其它来源不受影响');
});
