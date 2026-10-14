// 「路由 ↔ 文档一致性」机检（零依赖）。
//
// 做法（路由快照法）：从 src/routes/*.ts 提取实际路由清单，与 docs/API.md 里逐条登记的
// 端点标题比对；缺失或多余都以非 0 退出并打印差集。目的：改了路由不改文档 = 机检直接红，
// 不靠人工核对。
//
// 提取规则：
//   - router.<get|post|put|patch|delete|all>('<path>' …) → "<METHOD> <path>"
//     （允许 ( 与字符串之间跨行，覆盖 router.post(\n '/api/admin/login' 这种写法）；
//   - router.use('<prefix>' …) → "ALL <prefix>"（挂载点，如转发到认证中心的 /api/admin/sessions）。
// 文档规则：docs/API.md 中以「### <METHOD> <path>」开头的行即为登记端点，其余行不参与比对。
//
// 用法：node scripts/check-api-docs.mjs        一致性校验
//       node scripts/check-api-docs.mjs --list 只打印源码里的实际路由（供人工维护文档）
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const ROUTES_DIR = join(ROOT, 'src', 'routes');
const DOC_FILE = join(ROOT, 'docs', 'API.md');

const VERBS = 'get|post|put|patch|delete|all';
// router.<verb>(  与引号之间可跨行；只取单引号/双引号字面量路径
const ROUTE_RE = new RegExp(`\\brouter\\.(${VERBS})\\s*\\(\\s*['"]([^'"]+)['"]`, 'g');
const MOUNT_RE = /\brouter\.use\s*\(\s*['"]([^'"]+)['"]/g;

// 提取源码实际路由：Map<"METHOD PATH", "文件:行号">，每键只记首次出现的位置
function extractRoutes() {
  const routes = new Map();
  for (const file of readdirSync(ROUTES_DIR).filter((n) => n.endsWith('.ts')).sort()) {
    const full = join(ROUTES_DIR, file);
    const text = readFileSync(full, 'utf8');
    const lineAt = (idx) => text.slice(0, idx).split('\n').length;
    const record = (key, idx) => {
      if (!routes.has(key)) routes.set(key, `${relative(ROOT, full)}:${lineAt(idx)}`);
    };
    let m;
    ROUTE_RE.lastIndex = 0;
    while ((m = ROUTE_RE.exec(text)) !== null) record(`${m[1].toUpperCase()} ${m[2]}`, m.index);
    MOUNT_RE.lastIndex = 0;
    while ((m = MOUNT_RE.exec(text)) !== null) record(`ALL ${m[1]}`, m.index);
  }
  return routes;
}

// 提取文档登记的端点标题：只认行首三级标题 `### METHOD /path`
function extractDocHeadings() {
  const text = readFileSync(DOC_FILE, 'utf8');
  const set = new Set();
  const re = /^###\s+([A-Z]+)\s+(\S+)\s*$/gm;
  let m;
  while ((m = re.exec(text)) !== null) set.add(`${m[1]} ${m[2]}`);
  return set;
}

function main() {
  const routes = extractRoutes();
  if (process.argv.includes('--list')) {
    for (const key of [...routes.keys()].sort()) console.log(`${key}\t${routes.get(key)}`);
    console.log(`共 ${routes.size} 条实际路由`);
    return;
  }

  const doc = extractDocHeadings();
  const missing = [...routes.keys()].filter((k) => !doc.has(k)).sort();
  const extra = [...doc].filter((k) => !routes.has(k)).sort();

  if (missing.length || extra.length) {
    console.error('路由与 docs/API.md 不一致：');
    for (const k of missing) console.error(`  文档缺失  ${k}  (${routes.get(k)})`);
    for (const k of extra) console.error(`  文档多余  ${k}  (源码无此路由)`);
    console.error(
      `\n源码 ${routes.size} 条 / 文档 ${doc.size} 条；缺失 ${missing.length}、多余 ${extra.length}。`
    );
    process.exit(1);
  }

  console.log(
    `接口文档校验通过：源码 ${routes.size} 条路由与 docs/API.md 完全一致（缺失 0、多余 0）。`
  );
}

main();
