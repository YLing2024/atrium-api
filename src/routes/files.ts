'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 文件上传下载与文件区路由：通用上传 / 下载，文件区目录浏览、上传、新建、重命名、删除。
 * 所有文件区路径严格限制在 FILE_DIR 内；跳过符号链接，防逃逸。
 * 路径与保护名单辅助函数导出给 shares.ts 复用。
 */

const express = require('express') as typeof import('express');
const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const os = require('os') as typeof import('os');
const multer = require('multer') as typeof import('multer');

const { authRequired } = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
};
const { auditLog, clientIp } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
};

const router = express.Router();

// 上传目录：通用 /api/admin/upload 的落点（uploads/）
const UPLOAD_DIR = process.env.ADMIN_UPLOAD_DIR || path.join(__dirname, '..', '..', 'uploads');

// 文件区：admin「文件」Tab 的上传落点。独立于 uploads/，专用于把文件传给 Hermes（保留原始文件名）
const FILE_DIR = process.env.ADMIN_FILE_DIR || '/root/files/download';
const FILE_MAX_BYTES = 500 * 1024 * 1024; // 单文件上限 500MB（与 /api/admin/upload 的 100MB 相互独立）
// 文件区根目录这一层的保护名单，分两类：
//  · FILE_ROOT_PROTECTED —— 系统文件，不展示、也不允许任何写操作命中其整棵子树（swapfile / lost+found / cache）
//  · FILE_ROOT_READONLY  —— 收纳目录，正常展示、可浏览，但「根这一层的那一项」不允许被删/改名/移动，子路径照常读写
// 两者都只作用于根目录这一层：子目录中的同名文件（如 <root>/backup/swapfile）不受影响。
const FILE_ROOT_PROTECTED = new Set(['swapfile', 'lost+found', 'cache']);
const FILE_ROOT_READONLY = new Set(['toolchains', 'apps', 'build', 'www', 'files', 'backups', 'siyuan',
                                      'nextcloud', 'vaultwarden', 'objbox']);
                                      // 2026-09-29 Nextcloud；2026-10-06 Vaultwarden 密码库；2026-10-07 objbox 对象存储
try {
  fs.mkdirSync(FILE_DIR, { recursive: true });
} catch (e: any) {
  console.error('[admin-server] 文件区目录创建失败:', e.message);
}
// 上传目录不存在则自动创建
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

/* ============ 通用上传 / 下载 ============ */

// 上传：保存到 uploads 目录，按时间戳命名，限制单文件 100MB
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '';
    cb(null, `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 100 * 1024 * 1024 } });

router.post('/api/admin/upload', authRequired, upload.single('file'), (req, res) => {
  if (!req.file) {
    auditLog('upload', clientIp(req), false, '未收到文件');
    return res.status(400).json({ error: '未收到文件（字段名应为 file）' });
  }
  auditLog('upload', clientIp(req), true, req.file.path); // 记录落盘路径
  res.json({ path: req.file.path }); // 返回绝对路径，供 image.attach / file.attach 使用
});

/* ============ 文件区（admin「文件」Tab：目录浏览 / 上传 / 下载 / 新建 / 重命名 / 删除） ============ */

// 还原原始文件名：busboy 按 latin1 解码 Content-Disposition，中文名会变乱码；按 latin1→utf8 还原
function decodeOriginalName(raw: unknown): string {
  const name = String(raw || '');
  try {
    const utf8 = Buffer.from(name, 'latin1').toString('utf8');
    if (!utf8.includes('\uFFFD')) return utf8;
  } catch (e: any) {
    // 落到下面的原值
  }
  return name;
}

// 单个文件/目录名：去分隔符与控制字符，拒绝 . / .. / 空
function sanitizeSegment(raw: unknown): string {
  const base = path
    .basename(decodeOriginalName(raw))
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/[\\/]/g, '')
    .trim();
  if (!base || base === '.' || base === '..') return '';
  return base;
}

// 重名不覆盖：notes.7z → notes-2.7z → notes-3.7z
function uniqueFileName(dir: string, raw: unknown): string {
  const name = sanitizeSegment(raw) || 'unnamed';
  if (!fs.existsSync(path.join(dir, name))) return name;
  const ext = path.extname(name);
  const stem = name.slice(0, name.length - ext.length) || 'file';
  for (let i = 2; i < 10000; i += 1) {
    const candidate = `${stem}-${i}${ext}`;
    if (!fs.existsSync(path.join(dir, candidate))) return candidate;
  }
  return `${stem}-${Date.now()}${ext}`;
}

// 外部传入的相对路径 → FILE_DIR 内的绝对路径；越界/非法返回 null
function resolveFileRel(rel: unknown): string | null {
  let decoded;
  try {
    decoded = decodeURIComponent(String(rel == null ? '' : rel));
  } catch (e: any) {
    return null;
  }
  const full = path.resolve(FILE_DIR, decoded.replace(/^\/+/, ''));
  if (full !== FILE_DIR && !full.startsWith(FILE_DIR + path.sep)) return null;
  return full;
}

// 判断一个（已经过 resolveFileRel 的）绝对路径是否命中文件区根目录保护名单。
// 规则：取相对 FILE_DIR 的第一段，命中 FILE_ROOT_PROTECTED 才算保护；根目录自身不受保护。
// 只匹配根目录这一层——真实路径比较，不做字符串模糊匹配（my-swapfile.txt 不会被误伤）。
function isProtectedPath(full: string): boolean {
  if (full === FILE_DIR) return false;
  const rel = path.relative(FILE_DIR, full);
  if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return false;
  const parts = rel.split(path.sep);
  if (FILE_ROOT_PROTECTED.has(parts[0])) return true; // 整棵子树都不可写
  return parts.length === 1 && FILE_ROOT_READONLY.has(parts[0]); // 只挡根这一层那一项
}

// 是否属于「连列表里都不展示」的那一类：只用于列目录过滤，不参与写操作判定
function isHiddenRootPath(full: string): boolean {
  if (full === FILE_DIR) return false;
  const rel = path.relative(FILE_DIR, full);
  if (!rel || rel === '..' || rel.startsWith('..' + path.sep) || path.isAbsolute(rel)) return false;
  return FILE_ROOT_PROTECTED.has(rel.split(path.sep)[0]);
}

// 绝对路径 → 相对 FILE_DIR 的路径（用 / 分隔）；根目录为 ''
function relFromFull(full: string): string {
  const rel = path.relative(FILE_DIR, full);
  return rel === '' ? '' : rel.split(path.sep).join('/');
}

const fileStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = resolveFileRel(req.query && req.query.path);
    // @ts-expect-error: multer 运行时以 error 优先（destination 被忽略），允许只传 error
    if (!dir) return cb(new Error('目标路径非法'));
    // 目标目录不存在时按需创建（拖拽文件夹上传时会带上相对路径）
    try {
      fs.mkdirSync(dir, { recursive: true });
    } catch (e: any) {
      // @ts-expect-error: 同上，error 分支只看第一个参数
      return cb(new Error('创建目标目录失败：' + e.message));
    }
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const dir = resolveFileRel(req.query && req.query.path);
    cb(null, uniqueFileName(dir || FILE_DIR, file.originalname));
  }
});
const fileUpload = multer({ storage: fileStorage, limits: { fileSize: FILE_MAX_BYTES } });

// 上传：错误在本层处理，避免落到底部通用 multer 处理器（那里写死了 100MB 文案）
router.post('/api/admin/files/upload', authRequired, (req, res) => {
  fileUpload.single('file')(req, res, (err) => {
    if (err) {
      const tooLarge = err.code === 'LIMIT_FILE_SIZE';
      const msg = tooLarge
        ? `文件超过 ${Math.round(FILE_MAX_BYTES / 1024 / 1024)}MB 上限`
        : `上传失败：${err.message}`;
      auditLog('upload', clientIp(req), false, msg);
      return res.status(tooLarge ? 413 : 400).json({ error: msg });
    }
    if (!req.file) {
      auditLog('upload', clientIp(req), false, '未收到文件');
      return res.status(400).json({ error: '未收到文件（字段名应为 file）' });
    }
    // 文件区根目录保护名单：multer 已落盘，按最终路径判定；命中则删除已写入文件并拒绝
    if (isProtectedPath(path.resolve(req.file.path))) {
      try {
        fs.rmSync(req.file.path, { force: true });
      } catch (e: any) {
        // 清理失败不影响返回
      }
      auditLog('upload', clientIp(req), false, `${req.file.filename}: 受保护路径`);
      return res.status(403).json({ error: '该文件受保护，不允许操作' });
    }
    auditLog('upload', clientIp(req), true, `${req.file.filename} (${req.file.size}B)`);
    res.json({ name: req.file.filename, size: req.file.size, path: req.file.path });
  });
});

// 列目录：目录在前，同类按名称排序（中文用拼音序）
router.get('/api/admin/files', authRequired, (req, res) => {
  const dir = resolveFileRel(req.query.path);
  if (!dir) return res.status(400).json({ error: '路径非法' });
  let st;
  try {
    st = fs.lstatSync(dir);
  } catch (e: any) {
    return res.status(404).json({ error: '目录不存在' });
  }
  if (!st.isDirectory()) return res.status(400).json({ error: '不是目录' });
  try {
    const entries = fs
      .readdirSync(dir, { withFileTypes: true })
      .map((d) => {
        let s;
        try {
          s = fs.lstatSync(path.join(dir, d.name));
        } catch (e: any) {
          return null;
        }
        const isDir = s.isDirectory();
        // 跳过符号链接与特殊文件（防逃逸）
        if (!isDir && !s.isFile()) return null;
        // 根目录保护名单（swapfile / lost+found / cache）不展示
        if (isHiddenRootPath(path.join(dir, d.name))) return null;
        return {
          name: d.name,
          type: isDir ? 'dir' : 'file',
          size: isDir ? 0 : s.size,
          mtime: s.mtimeMs
        };
      })
      .filter((e): e is { name: string; type: string; size: number; mtime: number } => Boolean(e))
      .sort((a, b) => {
        if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
        return a.name.localeCompare(b.name, 'zh-Hans-CN');
      });
    const rel = relFromFull(dir);
    const parent = rel === '' ? null : rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '';
    res.json({ path: rel, parent, entries });
  } catch (e: any) {
    res.status(500).json({ error: '读取目录失败：' + e.message });
  }
});

// 下载单个文件
router.get('/api/admin/files/download', authRequired, (req, res) => {
  const full = resolveFileRel(req.query.path);
  if (!full) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  let st;
  try {
    st = fs.lstatSync(full);
  } catch (e: any) {
    return res.status(404).json({ error: '文件不存在' });
  }
  if (!st.isFile()) return res.status(400).json({ error: '不是普通文件' });
  res.download(full, path.basename(full));
});

// 新建文件夹
router.post('/api/admin/files/mkdir', authRequired, (req, res) => {
  const dir = resolveFileRel(req.body && req.body.path);
  if (!dir) return res.status(400).json({ error: '路径非法' });
  const name = sanitizeSegment(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称非法' });
  const target = path.join(dir, name);
  if (!target.startsWith(FILE_DIR + path.sep)) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(target)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  if (fs.existsSync(target)) return res.status(409).json({ error: '同名已存在' });
  try {
    fs.mkdirSync(target);
  } catch (e: any) {
    auditLog('mkdir', clientIp(req), false, `${name}: ${e.message}`);
    return res.status(500).json({ error: '创建失败：' + e.message });
  }
  auditLog('mkdir', clientIp(req), true, relFromFull(target));
  res.json({ ok: true, path: relFromFull(target) });
});

// 重命名（文件或目录）
router.post('/api/admin/files/rename', authRequired, (req, res) => {
  const full = resolveFileRel(req.body && req.body.path);
  if (!full || full === FILE_DIR) return res.status(400).json({ error: '路径非法' });
  const name = sanitizeSegment(req.body && req.body.name);
  if (!name) return res.status(400).json({ error: '名称非法' });
  const target = path.join(path.dirname(full), name);
  if (!target.startsWith(FILE_DIR + path.sep)) return res.status(400).json({ error: '路径非法' });
  // 源路径或目标路径命中根目录保护名单都拒绝（防止改名躲过保护 / 改名占位）
  if (isProtectedPath(full) || isProtectedPath(target)) {
    return res.status(403).json({ error: '该文件受保护，不允许操作' });
  }
  if (!fs.existsSync(full)) return res.status(404).json({ error: '文件不存在' });
  if (target !== full && fs.existsSync(target)) return res.status(409).json({ error: '同名已存在' });
  try {
    fs.renameSync(full, target);
  } catch (e: any) {
    auditLog('rename', clientIp(req), false, `${relFromFull(full)}: ${e.message}`);
    return res.status(500).json({ error: '重命名失败：' + e.message });
  }
  auditLog('rename', clientIp(req), true, `${relFromFull(full)} → ${relFromFull(target)}`);
  res.json({ ok: true, path: relFromFull(target) });
});

// 删除（目录递归）
router.delete('/api/admin/files', authRequired, (req, res) => {
  const full = resolveFileRel(req.query.path);
  if (!full || full === FILE_DIR) return res.status(400).json({ error: '路径非法' });
  if (isProtectedPath(full)) return res.status(403).json({ error: '该文件受保护，不允许操作' });
  let st;
  try {
    st = fs.lstatSync(full);
  } catch (e: any) {
    return res.status(404).json({ error: '文件不存在' });
  }
  const rel = relFromFull(full);
  try {
    fs.rmSync(full, { recursive: st.isDirectory(), force: false });
  } catch (e: any) {
    auditLog('delete', clientIp(req), false, `${rel}: ${e.message}`);
    return res.status(500).json({ error: '删除失败：' + e.message });
  }
  auditLog('delete', clientIp(req), true, rel);
  res.json({ ok: true });
});

/* ============ 通用下载（白名单根目录） ============ */

// 下载白名单根目录：AI 回复的文件可能落在 uploads、/root、/tmp、/home、/var/www 等位置
const DOWNLOAD_ALLOWED_BASES = [UPLOAD_DIR, '/root', '/tmp', '/home', '/var/www']
  .map((d) => path.resolve(d))
  .filter((d) => d.startsWith(path.sep));

// 下载：路径 resolve 后必须落在任一白名单目录内，再以附件形式返回
router.get('/api/admin/download', authRequired, (req, res) => {
  const p = req.query.path;
  if (!p || typeof p !== 'string') {
    return res.status(400).json({ error: '缺少 path 参数' });
  }
  // 支持官方 MEDIA:~/path 形态：~ 展开为 home 目录
  const expanded = p.startsWith('~/') ? path.join(os.homedir(), p.slice(2)) : p;
  const resolved = path.resolve(expanded);
  const allowed = DOWNLOAD_ALLOWED_BASES.some(
    (base) => resolved === base || resolved.startsWith(base + path.sep)
  );
  if (!allowed) {
    return res.status(400).json({ error: '路径不在允许范围内' });
  }
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return res.status(404).json({ error: '文件不存在' });
  }
  res.download(resolved);
});

module.exports = router;
module.exports.FILE_DIR = FILE_DIR;
module.exports.UPLOAD_DIR = UPLOAD_DIR;
module.exports.resolveFileRel = resolveFileRel;
module.exports.isProtectedPath = isProtectedPath;
module.exports.relFromFull = relFromFull;
