// ESLint 扁平配置（flat config）
// 只开正确性规则，不加任何格式 / 风格规则（不引 stylistic / prettier）。
// 本仓库为 CommonJS 后端：sourceType=commonjs + Node 全局 + 类型感知解析（project）。
import tseslint from 'typescript-eslint';

// Node 全局显式声明（避免为 globals 再引一个依赖）
const nodeGlobals = {
  require: 'readonly',
  module: 'readonly',
  exports: 'writable',
  __dirname: 'readonly',
  __filename: 'readonly',
  process: 'readonly',
  console: 'readonly',
  Buffer: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  setImmediate: 'readonly',
  clearImmediate: 'readonly',
  queueMicrotask: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  TextEncoder: 'readonly',
  TextDecoder: 'readonly',
  fetch: 'readonly',
  AbortController: 'readonly',
  structuredClone: 'readonly',
  global: 'readonly',
  globalThis: 'readonly'
};

export default tseslint.config(
  {
    ignores: ['node_modules/**', 'uploads/**', 'uploads-test/**', 'data/**', '**/*.log']
  },
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      sourceType: 'commonjs',
      parserOptions: { project: true, tsconfigRootDir: import.meta.dirname },
      globals: nodeGlobals
    },
    rules: {
      // 未使用变量保持 warn，不阻断「首次运行 0 error」
      '@typescript-eslint/no-unused-vars': 'warn',
      // 外部登记表 / 第三方回调数据按 any 处理是有意为之，降为 warn
      '@typescript-eslint/no-explicit-any': 'warn',
      // 本仓库是 CommonJS（零构建，生产用 node 直跑 .ts），require 是既定写法
      '@typescript-eslint/no-require-imports': 'off'
    }
  }
);
