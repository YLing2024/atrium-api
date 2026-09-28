'use strict';

/**
 * 配置模块：读取 /root/proj/admin-server/config.json。
 * 首次运行时自动生成默认配置文件（含初始密码）。
 * 所有密码/密钥均从配置读取，业务代码不硬编码。
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const CONFIG_PATH = process.env.ADMIN_CONFIG_PATH || path.join(__dirname, '..', 'config.json');

const DEFAULT_CONFIG = {
  admin_password: crypto.randomBytes(12).toString('base64url') // 首次运行随机生成（仓库不携带任何固定默认口令）
};

let config = null;

function load() {
  const exists = fs.existsSync(CONFIG_PATH);
  let fileConfig = {};
  if (exists) {
    try {
      fileConfig = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
    } catch (e) {
      console.error('[admin-server] 配置文件解析失败，使用默认配置: ' + e.message);
    }
  }
  config = Object.assign({}, DEFAULT_CONFIG, fileConfig);
  // 首次运行，或缺少 admin_password 时补充并持久化（兼容旧配置文件）
  if (!exists || !fileConfig.admin_password) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
    if (!exists) {
      console.log('[admin-server] 已生成配置文件: ' + CONFIG_PATH + '（含随机初始口令，权限 0600，请妥善保存）');
    }
  }
  // 口令/密钥文件一律 0600（旧文件可能是 0644）
  try { fs.chmodSync(CONFIG_PATH, 0o600); } catch (e) { /* 权限调整失败不影响启动 */ }
  return config;
}

function save() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
  try { fs.chmodSync(CONFIG_PATH, 0o600); } catch (e) { /* 同上 */ }
}

load();

module.exports = {
  get() {
    return config;
  },
  setAdminPassword(password) {
    config.admin_password = password;
    save();
  },
  setTotpSecret(secret) {
    config.totp_secret = secret;
    save();
  },
  getOrCreateJwtSecret() {
    if (!config.jwt_secret) {
      config.jwt_secret = crypto.randomBytes(32).toString('hex');
      save();
    }
    return config.jwt_secret;
  },
  CONFIG_PATH
};
