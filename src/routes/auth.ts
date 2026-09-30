'use strict';

// 模块边界标记：让本文件成为 TS 模块（CommonJS；类型导入会被原样剥离，无运行时影响）
import type { Request, Response, NextFunction } from 'express';

/**
 * 认证路由：模式探测 / TOTP 登录登出 / 当前身份 / TOTP 重置与设备会话转发 / 修改密码。
 * 薄壳：只做校验与响应，鉴权语义在 middleware/auth.ts。
 */

const express = require('express') as typeof import('express');
const fs = require('fs') as typeof import('fs');
const path = require('path') as typeof import('path');
const crypto = require('crypto') as typeof import('crypto');

const config = require('../config.ts') as import('../config.ts').AdminConfigModule;
const { AUTH_MODE } = config;
const { redis } = require('../state.ts') as { redis: import('ioredis').Redis };
const { auditLog, clientIp, verifyPassword } = require('../util.ts') as {
  auditLog: (action: string, ip: string, ok: unknown, detail?: string) => void;
  clientIp: (req: Request) => string;
  verifyPassword: (input: unknown, stored: unknown) => boolean;
};
const {
  authRequired,
  sessionKey,
  SESSION_KEY_PREFIX,
  SESSION_TTL,
  builtinSessionToken,
  setSessionCookie,
  clearSessionCookie,
  totpAuth
} = require('../middleware/auth.ts') as {
  authRequired: import('express').RequestHandler;
  sessionKey: (token: string) => string;
  SESSION_KEY_PREFIX: string;
  SESSION_TTL: number;
  builtinSessionToken: (req: Request) => string;
  setSessionCookie: (req: Request, res: Response, token: string) => void;
  clearSessionCookie: (res: Response) => void;
  totpAuth: {
    getSecret: () => string | null | undefined;
    verifyCode: (secret: string, code: unknown) => boolean;
    router?: import('express').Router;
  };
};

const router = express.Router();

/* ============ 登录失败锁定（内存 Map 按 IP 计数） ============ */

// 登录失败锁定：内存 Map 按 IP 计数，连续失败 5 次锁 60 秒，锁定期登录返回 429
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_SECONDS = 60;
const loginFails = new Map<string, { count: number; lockUntil: number }>(); // ip -> { count, lockUntil }

// 检查是否处于锁定状态；锁定过期则顺手清理，返回 { locked, remain? }
function loginRateCheck(ip: string): { locked: boolean; remain?: number } {
  const rec = loginFails.get(ip);
  if (rec && rec.lockUntil) {
    if (rec.lockUntil > Date.now()) {
      return { locked: true, remain: Math.ceil((rec.lockUntil - Date.now()) / 1000) };
    }
    loginFails.delete(ip);
  }
  return { locked: false };
}

// 记录一次失败；累计到上限即触发 60s 锁定，返回当前失败计数
function loginRateFail(ip: string) {
  const rec = loginFails.get(ip) || { count: 0, lockUntil: 0 };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_FAILS) {
    rec.lockUntil = Date.now() + LOGIN_LOCK_SECONDS * 1000;
  }
  loginFails.set(ip, rec);
  return rec;
}

// 登录成功清除该 IP 失败记录
function loginRateClear(ip: string): void {
  loginFails.delete(ip);
}

/* ============ 本地登录相关路由 ============ */

// 认证模式探测：免鉴权，只回模式，不泄漏任何其它信息（前端据此决定登录界面/跳转策略）
router.get('/api/admin/auth-mode', (req, res) => {
  res.json({ authMode: AUTH_MODE });
});

// 登录：TOTP 动态验证码比对（复用 totp-auth 模块的 verifyCode），成功后写入 Redis 独立会话并下发会话 cookie。
// sso 模式下不提供本地登录入口 → 404（不要 401/302，避免暴露）。
router.post(
  '/api/admin/login',
  (req, res, next) => {
    if (AUTH_MODE === 'sso') return res.status(404).json({ error: 'Not Found' });
    next();
  },
  async (req, res) => {
    const { code } = req.body || {};
    const ip = clientIp(req);
    try {
      // 首次使用：secret 未配置时引导先设置
      const secret = totpAuth.getSecret();
      if (!secret) {
        auditLog('login', ip, false, 'TOTP 未配置');
        return res
          .status(403)
          .json({ error: '首次使用：请先设置 TOTP', code: 'totp_setup_required' });
      }
      // 锁定检查：同一 IP 连续失败已达上限（60s 锁定内），直接 429 拒绝
      const rate = loginRateCheck(ip);
      if (rate.locked) {
        auditLog('login', ip, false, `锁定中（剩余 ${rate.remain}s）`);
        return res.status(429).json({
          error: `尝试过多，请 ${rate.remain} 秒后再试`,
          code: 'rate_limited',
          retryAfter: rate.remain
        });
      }
      if (!totpAuth.verifyCode(secret, code)) {
        const rec = loginRateFail(ip);
        auditLog('login', ip, false, `验证码错误（第 ${rec.count}/${LOGIN_MAX_FAILS} 次）`);
        return res.status(401).json({ error: '验证码错误' });
      }
      // 登录成功：清除该 IP 失败计数，签发会话；同时下发 HttpOnly 会话 cookie（TTL 与 Redis 会话一致）
      loginRateClear(ip);
      auditLog('login', ip, true, 'ok');
      const token = crypto.randomBytes(32).toString('hex');
      await redis.set(sessionKey(token), token, 'EX', SESSION_TTL);
      setSessionCookie(req, res, token);
      res.json({ token });
    } catch (e: any) {
      auditLog('login', ip, false, '会话服务异常');
      res.status(500).json({ error: '会话服务异常' });
    }
  }
);

// 登出：删除 Redis 会话 + 清 cookie，幂等（未登录也 200）。sso 模式 → 404。
router.post('/api/admin/logout', async (req, res) => {
  if (AUTH_MODE === 'sso') return res.status(404).json({ error: 'Not Found' });
  const token = builtinSessionToken(req);
  if (token) {
    try {
      await redis.del(sessionKey(token));
    } catch (e: any) {
      // 登出幂等：Redis 异常也不阻断，cookie 照清
    }
  }
  clearSessionCookie(res);
  auditLog('logout', clientIp(req), true, 'ok');
  res.json({ ok: true });
});

// 当前登录身份（来自本地会话）。sso 模式 → 404；builtin 未登录 → 401。
router.get(
  '/api/admin/me',
  (req, res, next) => {
    if (AUTH_MODE === 'sso') return res.status(404).json({ error: 'Not Found' });
    next();
  },
  authRequired,
  (req, res) => {
    res.json({ name: req.user!.name, role: req.user!.role });
  }
);

/* ============ 转发认证中心：TOTP 重置 / 设备会话 ============ */

// 认证中心基址：只从环境变量或本地配置（config.json，不入库）读取；
// 源码不硬编码任何私有地址（含回环地址）。未配置时各转发接口返回 502。
function authCenterBaseUrl() {
  const configured =
    process.env.AUTH_CENTER_BASE_URL || (config.get() && config.get().auth_center_base_url);
  return configured ? String(configured).replace(/\/+$/, '') : '';
}

// 认证中心共享内部令牌（0600）：只读，绝不打印、绝不返回给客户端。
const AUTH_CENTER_INTERNAL_TOKEN_FILE =
  process.env.AUTH_CENTER_INTERNAL_TOKEN_FILE ||
  path.join(__dirname, '..', '..', '..', 'auth-server', 'internal-token');

function readInternalToken() {
  return fs.readFileSync(AUTH_CENTER_INTERNAL_TOKEN_FILE, 'utf8').trim();
}

// TOTP 重置 / 确认：身份只取网关注入的 X-Auth-User，带共享内部令牌调用认证中心内部接口
// /api/internal/totp/reset|confirm?sub=<用户名>，**不再转发任何客户端凭证**
// （浏览器通道无 token；App 通道带的是 JWT access_token，认证中心 SSO 会话都认不出，会 401）。
// 两阶段语义（reset 只写 pending → confirm 验证转正）由认证中心内部实现，此处仅透传。
// 认证中心不可达 → 502；内部令牌文件缺失/为空 → 500（日志写明原因），绝不静默成功。
function forwardTotp(action: string) {
  return async (req: Request, res: Response) => {
    const ip = clientIp(req);
    const sub = String((req.user && req.user.name) || req.get('x-auth-user') || '').trim();
    if (!sub) {
      auditLog('totp_' + action, ip, false, '缺少 X-Auth-User');
      return res.status(401).json({ error: '未登录' });
    }
    const base = authCenterBaseUrl();
    if (!base) {
      auditLog('totp_' + action, ip, false, '认证中心地址未配置');
      console.error('[admin-server] AUTH_CENTER_BASE_URL 未配置，无法转发 TOTP 请求');
      return res.status(502).json({ error: '认证中心不可达' });
    }
    let internalToken;
    try {
      internalToken = readInternalToken();
    } catch (e: any) {
      auditLog('totp_' + action, ip, false, '内部令牌文件不可读');
      console.error(
        `[admin-server] 读取认证中心内部令牌失败（${AUTH_CENTER_INTERNAL_TOKEN_FILE}）: ${e.message}`
      );
      return res.status(500).json({ error: '服务未正确配置' });
    }
    if (!internalToken) {
      auditLog('totp_' + action, ip, false, '内部令牌文件为空');
      console.error(`[admin-server] 认证中心内部令牌文件为空: ${AUTH_CENTER_INTERNAL_TOKEN_FILE}`);
      return res.status(500).json({ error: '服务未正确配置' });
    }
    const url = new URL(base + '/api/internal/totp/' + action);
    url.searchParams.set('sub', sub);
    const headers = {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-Internal-Token': internalToken
    };
    try {
      const upstream = await fetch(url, {
        method: 'POST',
        headers,
        body: JSON.stringify(req.body || {}),
        signal: AbortSignal.timeout(5000)
      });
      const data = await upstream.json().catch(() => ({}));
      auditLog('totp_' + action, ip, upstream.ok, '内部接口');
      return res.status(upstream.status).json(data);
    } catch (e: any) {
      auditLog('totp_' + action, ip, false, '认证中心不可达: ' + e.message);
      return res.status(502).json({ error: '认证中心不可达' });
    }
  };
}

router.post('/api/admin/totp/reset', authRequired, forwardTotp('reset'));
router.post('/api/admin/totp/confirm', authRequired, forwardTotp('confirm'));

// 已登录设备管理：用户身份只取网关注入的 X-Auth-User（authRequired 已保证存在），
// 用共享内部令牌（X-Internal-Token）调用认证中心内部接口 /api/internal/sessions*，
// **不再转发任何客户端凭证**（浏览器无 token；App 带的是 JWT access_token，认证中心 SSO 会话认不出）。
// GET 列表 / PUT :id/name 重命名 / DELETE :id 踢下线，路径与语义与旧转发一致。
function forwardSessions(req: Request, res: Response) {
  const ip = clientIp(req);
  const action =
    req.method === 'GET' ? 'list' : req.method === 'PUT' ? 'rename' : req.method === 'DELETE' ? 'delete' : req.method.toLowerCase();
  const sub = (req.user && req.user.name) || req.get('x-auth-user') || '';
  const base = authCenterBaseUrl();
  if (!base) {
    auditLog('sessions_' + action, ip, false, '认证中心地址未配置');
    console.error('[admin-server] AUTH_CENTER_BASE_URL 未配置，无法转发设备会话请求');
    return res.status(502).json({ error: '认证中心不可达' });
  }
  let internalToken;
  try {
    internalToken = readInternalToken();
  } catch (e: any) {
    auditLog('sessions_' + action, ip, false, '内部令牌文件不可读');
    console.error(
      `[admin-server] 读取认证中心内部令牌失败（${AUTH_CENTER_INTERNAL_TOKEN_FILE}）: ${e.message}`
    );
    return res.status(500).json({ error: '服务未正确配置' });
  }
  if (!internalToken) {
    auditLog('sessions_' + action, ip, false, '内部令牌文件为空');
    console.error(`[admin-server] 认证中心内部令牌文件为空: ${AUTH_CENTER_INTERNAL_TOKEN_FILE}`);
    return res.status(500).json({ error: '服务未正确配置' });
  }
  // req.path 在 app.use 挂载点下已是相对路径：GET → '/'，PUT → '/:id/name'，DELETE → '/:id'
  const relPath = req.path === '/' ? '' : req.path;
  const url = new URL(base + '/api/internal/sessions' + relPath);
  url.searchParams.set('sub', String(sub));
  const headers: Record<string, string> = { Accept: 'application/json', 'X-Internal-Token': internalToken };
  const opts: RequestInit = { method: req.method, headers, signal: AbortSignal.timeout(5000) };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(req.body || {});
  }
  fetch(url, opts)
    .then(async (upstream) => {
      const data = await upstream.json().catch(() => ({}));
      auditLog('sessions_' + action, ip, upstream.ok, '内部接口');
      return res.status(upstream.status).json(data);
    })
    .catch((e) => {
      auditLog('sessions_' + action, ip, false, '认证中心不可达: ' + e.message);
      return res.status(502).json({ error: '认证中心不可达' });
    });
}

router.use('/api/admin/sessions', authRequired, forwardSessions);

// TOTP 首次设置：挂载 totp-auth 模块路由（无鉴权，secret 已配置则 409）
// sso 模式下不提供任何本地口令入口 → /setup 一律 404（否则会变成一个免鉴权的密钥签发口，
// 而 sso 模式根本不使用 TOTP，没必要暴露）。/reset 与 /confirm 仍由 authRequired 保护。
router.use('/api/admin/totp', (req: Request, res: Response, next: NextFunction) => {
  if (AUTH_MODE === 'sso' && req.path === '/setup') return res.status(404).json({ error: 'Not Found' });
  const ip = clientIp(req);
  res.on('finish', () => {
    if (req.path === '/setup') {
      auditLog('totp_setup', ip, res.statusCode < 400, 'ok');
    }
  });
  next();
}, totpAuth.router!);

/* ============ 修改密码 ============ */

// 修改密码（需鉴权）：验证旧密码后更新 config.json，并删除 Redis 会话使所有已登录会话失效
router.post('/api/admin/password', authRequired, async (req, res) => {
  const { old_password, new_password } = req.body || {};
  const ip = clientIp(req);
  if (!verifyPassword(old_password || '', config.get().admin_password)) {
    auditLog('password', ip, false, '旧密码错误');
    return res.status(400).json({ error: '旧密码错误' });
  }
  if (typeof new_password !== 'string' || new_password.length < 6) {
    return res.status(400).json({ error: '新密码至少 6 位' });
  }
  try {
    config.setAdminPassword(new_password);
    auditLog('password', ip, true, '修改密码');
    const keys = await redis.keys(SESSION_KEY_PREFIX + '*');
    if (keys.length) await redis.del(...keys);
    res.json({ ok: true, msg: '密码已修改，请重新登录' });
  } catch (e: any) {
    auditLog('password', ip, false, '会话服务异常');
    res.status(500).json({ error: '会话服务异常' });
  }
});

module.exports = router;
