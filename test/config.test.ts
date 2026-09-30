'use strict';

// 模块边界标记：让本文件成为 TS 模块（类型导入会被原样剥离，运行时仍是 CommonJS）
import type {} from 'node:test';

// config.ts 路径与环境变量解析单元测试（node:test，零依赖）
// 关键：必须在设置 ADMIN_CONFIG_PATH 之后再 require —— config.ts 模块加载即执行 load()。
// 全部落到 os.tmpdir() 临时目录，绝不读写仓库里的真实 config.json。

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const REPO_ROOT = path.resolve(__dirname, '..');
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-cfg-'));
const CONFIG_PATH = path.join(tmpDir, 'config.json');
process.env.ADMIN_CONFIG_PATH = CONFIG_PATH;

const config = require('../src/config.ts');

test('CONFIG_PATH：ADMIN_CONFIG_PATH 覆盖生效', () => {
  assert.equal(config.CONFIG_PATH, CONFIG_PATH);
});

test('首次加载：生成配置文件、权限 0600、含随机 admin_password', () => {
  const st = fs.statSync(CONFIG_PATH);
  assert.equal(st.mode & 0o777, 0o600);
  const cfg = config.get();
  assert.equal(typeof cfg.admin_password, 'string');
  assert.ok(cfg.admin_password.length > 0);
});

test('setAdminPassword：同步写回文件', () => {
  config.setAdminPassword('unit-test-password');
  assert.equal(config.get().admin_password, 'unit-test-password');
  const onDisk = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8'));
  assert.equal(onDisk.admin_password, 'unit-test-password');
});

test('getOrCreateJwtSecret：同进程内稳定，且落盘', () => {
  const a = config.getOrCreateJwtSecret();
  const b = config.getOrCreateJwtSecret();
  assert.equal(a, b);
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.equal(JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf-8')).jwt_secret, a);
});

test('默认路径：未设置 ADMIN_CONFIG_PATH 时回退到 <repo>/config.json', () => {
  // 子进程内 patch fs，拦截 load() 的文件读写，避免触碰真实 config.json
  const entry = path.join(REPO_ROOT, 'src', 'config.ts');
  const script = [
    "const fs = require('node:fs');",
    'fs.existsSync = () => false;',
    'fs.writeFileSync = () => {};',
    'fs.chmodSync = () => {};',
    'const cfg = require(' + JSON.stringify(entry) + ');',
    'process.stdout.write(cfg.CONFIG_PATH);'
  ].join('\n');
  const env = { ...process.env };
  delete env.ADMIN_CONFIG_PATH;
  const out = execFileSync(process.execPath, ['-e', script], { env, encoding: 'utf-8' });
  // load() 会在「首次生成」分支打印一行提示，取最后一行再比对
  assert.equal(out.trim().split('\n').pop(), path.join(REPO_ROOT, 'config.json'));
});
