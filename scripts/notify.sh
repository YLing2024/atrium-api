#!/usr/bin/env bash
# 写入一条通知到通知中心（本机脚本免 SSO）。
# 用法：
#   ./scripts/notify.sh "标题" "正文" [level] [source] [link]
#   level: urgent | normal | digest（默认 normal）
#   source: 来源标识（默认 manual）
#   link:   可选跳转地址
# 可选环境变量：
#   ADMIN_NOTIFY_URL        后端地址，默认 http://127.0.0.1:3100
#   ADMIN_NOTIFY_DEDUP_KEY  去重键，同一键 10 分钟内只保留一条
set -euo pipefail

TITLE="${1:-}"
BODY="${2:-}"
LEVEL="${3:-normal}"
SOURCE="${4:-manual}"
LINK="${5:-}"
DEDUP_KEY="${ADMIN_NOTIFY_DEDUP_KEY:-}"
BASE="${ADMIN_NOTIFY_URL:-http://127.0.0.1:3100}"

if [ -z "$TITLE" ]; then
  echo "用法: $0 \"标题\" \"正文\" [level] [source] [link]" >&2
  exit 2
fi

case "$LEVEL" in
  urgent | normal | digest) ;;
  *)
    echo "level 只能是 urgent / normal / digest" >&2
    exit 2
    ;;
esac

# 用 python3 生成 JSON，避免标题/正文里的引号、换行破坏请求体
PAYLOAD="$(
  TITLE="$TITLE" BODY="$BODY" LEVEL="$LEVEL" SOURCE="$SOURCE" LINK="$LINK" DEDUP_KEY="$DEDUP_KEY" \
    python3 -c '
import json, os
d = {"level": os.environ["LEVEL"], "source": os.environ["SOURCE"], "title": os.environ["TITLE"]}
if os.environ.get("BODY"):
    d["body"] = os.environ["BODY"]
if os.environ.get("LINK"):
    d["link"] = os.environ["LINK"]
if os.environ.get("DEDUP_KEY"):
    d["dedupKey"] = os.environ["DEDUP_KEY"]
print(json.dumps(d, ensure_ascii=False))
'
)"

curl -sS -X POST "$BASE/api/admin/notifications" \
  -H 'Content-Type: application/json' \
  --data-binary "$PAYLOAD"
echo
