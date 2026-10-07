#!/usr/bin/env bash
# 并发首注册竞态验证：在全新实例上同时发起 N 个注册请求，
# 无论谁先谁后，最终只能有 1 个账号拿到系统管理员身份。
#
# 前置条件：全新库（还没有任何用户）。默认配置（未开放公开注册）下，
# 应只有 1 个 201，其余全部 409；若 PUBLIC_SIGNUP=true，则 N 个都 201，
# 但其中仍只能有 1 个 sysadmin。
#
# 用法：API=http://127.0.0.1:4000 bash scripts/verify-first-admin-race.sh
# 注意：注册接口按 IP 限流（10 次 / 15 分钟），失败后需等限流窗口过去再重试。
set -euo pipefail

API="${API:-http://127.0.0.1:4000}"
V1="$API/api/v1"
N="${N:-8}"
RUN_ID="$(date +%s)-$RANDOM"
WORK="$(mktemp -d)"

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "== 并发首注册竞态验证 =="
echo "API: $API（并发数 $N，需要全新库）"

pids=()
for i in $(seq 1 "$N"); do
  (
    code=$(curl -sS -o "$WORK/body-$i" -w '%{http_code}' -X POST \
      -H 'Content-Type: application/json' \
      --data "{\"email\":\"race-$RUN_ID-$i@example.com\",\"password\":\"family2026\",\"displayName\":\"并发$i\"}" \
      "$V1/auth/register")
    printf '%s' "$code" > "$WORK/code-$i"
  ) &
  pids+=($!)
done
for p in "${pids[@]}"; do wait "$p"; done

created=0
admins=0
conflicts=0
limited=0
for i in $(seq 1 "$N"); do
  code=$(cat "$WORK/code-$i")
  case "$code" in
    201)
      created=$((created + 1))
      role=$(node -e "const d=JSON.parse(require('fs').readFileSync(process.argv[1],'utf8'));process.stdout.write(d.user?.systemRole ?? '')" "$WORK/body-$i")
      [ "$role" = "sysadmin" ] && admins=$((admins + 1))
      ;;
    409) conflicts=$((conflicts + 1)) ;;
    429) limited=$((limited + 1)) ;;
    *) echo "  · 第 $i 个请求返回意外状态 $code：$(head -c 200 "$WORK/body-$i")" ;;
  esac
done

echo "  · 结果分布：201=$created 409=$conflicts 429=$limited，其中系统管理员 $admins 个"

FAIL=0
if [ "$limited" -gt 0 ]; then
  echo "  ✗ 触发注册限流（429），结果不可信；请等 15 分钟限流窗口过去后重试"
  FAIL=1
fi
if [ "$created" -eq 0 ]; then
  echo "  ✗ 没有任何账号注册成功：本验证需要在全新库上运行（库里已有用户时全部返回 409）"
  FAIL=1
fi
if [ "$admins" -ne 1 ]; then
  echo "  ✗ 出现 $admins 个系统管理员（期望恰好 1 个）：首个账号判定存在竞态"
  FAIL=1
fi

if [ "$FAIL" -gt 0 ]; then exit 1; fi
echo "  ✓ $N 个并发注册只有 1 个获得系统管理员身份"
echo "竞态验证通过。"
