'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type {} from 'express';

/**
 * 接口令牌（API Token）管理路由：列表 / 生成 / 更新 / 吊销。
 * 与登录设备会话完全隔离；只存哈希，明文仅生成时返回一次。
 */

const express = require('express') as typeof import('express');
const crypto = require('crypto') as typeof import('crypto');

import type { ApiTokenMeta } from '../middleware/auth.ts';

const { redis } = require('../state.ts') as { redis: import('ioredis').Redis };
const { auditLog, clientIp, sha256hex } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: import('express').Request) => string;
  sha256hex: (str: unknown) => string;
};
const {
  authRequired,
  apiTokenKey,
  API_TOKEN_PREFIX,
  API_TOKEN_MAX_DAYS,
  parseApiTokenMeta
} = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
  apiTokenKey: (id: string) => string;
  API_TOKEN_PREFIX: string;
  API_TOKEN_MAX_DAYS: number;
  parseApiTokenMeta: (raw: string | null) => ApiTokenMeta | null;
};

const router = express.Router();

// GET /api/admin/api-tokens —— 列表（绝不含 token 明文），按 createdAt 倒序
router.get('/api/admin/api-tokens', authRequired, async (req, res) => {
  const ip = clientIp(req);
  try {
    const keys = await redis.keys(API_TOKEN_PREFIX + '*');
    const tokens = [];
    for (const key of keys) {
      const meta = parseApiTokenMeta(await redis.get(key));
      if (!meta) continue;
      tokens.push({
        id: meta.id,
        name: meta.name,
        note: meta.note || '',
        createdAt: Number(meta.createdAt) || 0,
        expiresAt: Number(meta.expiresAt) || 0,
        lastUsedAt: Number(meta.lastUsedAt) || 0,
        // 老令牌无此字段 → 只读（false），行为与新增前一致
        canWrite: meta.canWrite === true
      });
    }
    tokens.sort((a, b) => b.createdAt - a.createdAt);
    auditLog('api_tokens_list', ip, true, `count=${tokens.length}`);
    return res.json({ tokens });
  } catch (e: any) {
    auditLog('api_tokens_list', ip, false, e.message);
    return res.status(500).json({ error: '获取接口令牌失败' });
  }
});

// POST /api/admin/api-tokens —— 生成令牌；明文仅此一次返回
router.post('/api/admin/api-tokens', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const name = String((req.body && req.body.name) || '').trim();
  const note = String((req.body && req.body.note) || '').trim();
  const rawDays = req.body && req.body.expiresInDays != null ? req.body.expiresInDays : 30;
  const days = Number(rawDays);
  if (!name) {
    return res.status(400).json({ error: '令牌名称不能为空' });
  }
  if (!Number.isInteger(days) || days < 1 || days > API_TOKEN_MAX_DAYS) {
    return res.status(400).json({ error: '有效期需为 1~365 天的整数' });
  }
  try {
    const token = crypto.randomBytes(32).toString('hex'); // 64 位 hex 明文，仅此一次展示
    const id = sha256hex(token); // id = sha256 全文
    const now = Date.now();
    const expiresAt = now + days * 86400000;
    // canWrite：新增的可写标志（只加字段，不改已有字段）；默认 false = 只读
    const canWrite = req.body && req.body.canWrite === true;
    const meta = { id, name, note, createdAt: now, expiresAt, lastUsedAt: 0, canWrite };
    await redis.set(apiTokenKey(id), JSON.stringify(meta), 'EX', days * 86400); // 固定过期，不滑动
    auditLog('api_tokens_create', ip, true, `id=${id} name=${name} days=${days} canWrite=${canWrite}`);
    return res.json({ id, token, meta });
  } catch (e: any) {
    auditLog('api_tokens_create', ip, false, e.message);
    return res.status(500).json({ error: '生成接口令牌失败' });
  }
});

// PATCH /api/admin/api-tokens/:id —— 改名 / 改备注 / 重设有效期（重设则 TTL 一并刷新）
router.patch('/api/admin/api-tokens/:id', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  try {
    const meta = parseApiTokenMeta(await redis.get(apiTokenKey(id)));
    if (!meta) {
      return res.status(404).json({ error: '接口令牌不存在或已过期' });
    }
    const body = req.body || {};
    if (body.name != null) {
      const name = String(body.name).trim();
      if (!name) return res.status(400).json({ error: '令牌名称不能为空' });
      meta.name = name;
    }
    if (body.note != null) meta.note = String(body.note).trim();
    if (body.canWrite != null) meta.canWrite = body.canWrite === true;
    if (body.expiresInDays != null) {
      const days = Number(body.expiresInDays);
      if (!Number.isInteger(days) || days < 1 || days > API_TOKEN_MAX_DAYS) {
        return res.status(400).json({ error: '有效期需为 1~365 天的整数' });
      }
      meta.expiresAt = Date.now() + days * 86400000; // 重设有效期：expiresAt = now + days
    }
    const ttl = Math.max(1, Math.floor((Number(meta.expiresAt) - Date.now()) / 1000));
    await redis.set(apiTokenKey(id), JSON.stringify(meta), 'EX', ttl);
    auditLog('api_tokens_update', ip, true, `id=${id}`);
    return res.json({
      id: meta.id,
      name: meta.name,
      note: meta.note,
      createdAt: Number(meta.createdAt),
      expiresAt: Number(meta.expiresAt),
      lastUsedAt: Number(meta.lastUsedAt),
      canWrite: meta.canWrite === true
    });
  } catch (e: any) {
    auditLog('api_tokens_update', ip, false, e.message);
    return res.status(500).json({ error: '更新接口令牌失败' });
  }
});

// DELETE /api/admin/api-tokens/:id —— 吊销，立即失效
router.delete('/api/admin/api-tokens/:id', authRequired, async (req, res) => {
  const ip = clientIp(req);
  const id = req.params.id;
  try {
    await redis.del(apiTokenKey(id));
    auditLog('api_tokens_delete', ip, true, `id=${id}`);
    return res.json({ ok: true });
  } catch (e: any) {
    auditLog('api_tokens_delete', ip, false, e.message);
    return res.status(500).json({ error: '吊销接口令牌失败' });
  }
});

module.exports = router;
