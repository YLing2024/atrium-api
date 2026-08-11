'use strict';

/**
 * 配置模块：读取 /root/proj/admin-server/config.json。
 * 首次运行时自动生成默认配置文件（含初始密码）。
 * 所有密码/密钥均从配置读取，业务代码不硬编码。
 */

const fs = require('fs');
const path = require('path');

const CONFIG_PATH = process.env.ADMIN_CONFIG_PATH || path.join(__dirname, '..', 'config.json');

const DEFAULT_CONFIG = {
  admin_password: '***REMOVED***' // 初始密码，首次运行自动生成
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
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n');
    if (!exists) {
      console.log('[admin-server] 已生成默认配置文件: ' + CONFIG_PATH);
    }
  }
  return config;
}

function save() {
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n');
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
  CONFIG_PATH
};
