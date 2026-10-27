#!/usr/bin/env bash
# 收尾一次 AI 审核：发本轮总结、更新审核记录，最后把结论写成 PR head 提交上的
# ai-review 和 security-review 状态。由 review.yml 的 finish 任务运行，只有这个任务能写状态。
# 规则见 docs/agent/loop.md 的"AI 审核"。
# 输入环境变量：GH_TOKEN REPO PR HEAD_SHA RUN_URL EVENT_LABEL
#   SCOPE_RESULT CLAUDE_RESULT：scope 和 claude 两个任务的结果；API_STATUS：claude 失败时的 API 状态码；
#   TOKEN_MISSING：review 环境里没有订阅 token 时为 true
#   以及 scope 的输出：ACTION TIER ROUND RUN_AI RUN_SECURITY AI SECURITY RECORD SYNC RECORD_COMMENT_ID
#   claude 的输出：AI_RESULT SECURITY_RESULT（结构化结论）

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off

work="$(mktemp -d)"

mark() {
  for context in ai-review security-review; do
    bash scripts/set-status.sh "$HEAD_SHA" "$context" "$1" "$2"
  done
}
verdict_text() {
  case "$1" in
    pass) echo "通过" ;;
    changes-requested) echo "需要修改" ;;
    *) echo "不适用（非高风险）" ;;
  esac
}
verdict_state() {
  case "$1" in
    pass | n/a) echo success ;;
    *) echo failure ;;
  esac
}
# 结构化结论里报了新问题却给"通过"时，按"需要修改"处理。
verdict_of() {
  jq -r --arg count "$2" 'if (.[$count] // 0) > 0 then "changes-requested" else (.verdict // "") end' <<< "${1:-null}"
}
drop_recheck_label() {
  if [[ "${EVENT_LABEL:-}" == re-review ]]; then
    gh pr edit "$PR" --repo "$REPO" --remove-label re-review > /dev/null || true
  fi
}

if [[ "$SCOPE_RESULT" != success ]]; then
  mark failure "审核准备没跑完，见运行日志"
  exit 0
fi
case "$ACTION" in
  stale | draft | off-main) exit 0 ;;
  stop)
    gh pr edit "$PR" --repo "$REPO" --add-label needs-rethink > /dev/null
    mark failure "已审 3 轮仍未通过：停下复盘，由用户决定是否继续"
    exit 0
    ;;
esac
if [[ "$ACTION" == review && "$CLAUDE_RESULT" != success ]]; then
  if [[ "${TOKEN_MISSING:-}" == true ]]; then
    mark failure "review 环境里没有订阅 token：按 docs/agent/loop.md 设置后重跑失败的任务"
  else
    case "${API_STATUS:-}" in
      429) mark failure "Claude 订阅用量到上限：等重置后，在 Actions 里重跑失败的任务" ;;
      401) mark failure "订阅 token 无效或已过期：按 docs/agent/loop.md 重新生成并设置后重跑" ;;
      "") mark failure "审核没跑完，见运行日志" ;;
      *) mark failure "审核调用 Claude 失败（HTTP $API_STATUS），见运行日志" ;;
    esac
  fi
  drop_recheck_label
  exit 0
fi

ai="$AI"
note_ai="（沿用）"
if [[ "$RUN_AI" == true ]]; then
  ai="$(verdict_of "${AI_RESULT:-}" important)"
  note_ai=""
fi
security="$SECURITY"
note_security="（沿用）"
if [[ "$TIER" != high ]]; then
  security=n/a
  note_security=""
elif [[ "$RUN_SECURITY" == true ]]; then
  security="$(verdict_of "${SECURITY_RESULT:-}" issues)"
  note_security=""
fi
if [[ -z "$ai" || -z "$security" ]] || [[ "$TIER" == high && "$security" == n/a ]]; then
  mark failure "审核没有给出有效结论，见运行日志"
  drop_recheck_label
  echo "::error::审核结论无效：AI=$ai security=$security tier=$TIER"
  exit 1
fi

# 总结里的 HTML 注释会被当成标记，先转义。
if [[ "$RUN_AI" == true || "$RUN_SECURITY" == true ]]; then
  : > "$work/summary.md"
  if [[ "$RUN_AI" == true ]]; then
    jq -r --arg round "$ROUND" --arg verdict "$(verdict_text "$ai")" \
      '"**第 \($round) 轮 AI 审核：\($verdict)**\n本轮新提出：重要 \(.important) 条，小问题 \(.minor) 条，既有问题 \(.existing) 条。\n\n\(.summary | gsub("<!--"; "&lt;!--"))\n"' \
      <<< "$AI_RESULT" >> "$work/summary.md"
  fi
  if [[ "$RUN_SECURITY" == true ]]; then
    jq -r --arg round "$ROUND" --arg verdict "$(verdict_text "$security")" \
      '"**第 \($round) 轮安全审核：\($verdict)**\n本轮新提出 \(.issues) 条。\n\n\(.summary | gsub("<!--"; "&lt;!--"))\n"' \
      <<< "$SECURITY_RESULT" >> "$work/summary.md"
  fi
  gh pr comment "$PR" --repo "$REPO" --body-file "$work/summary.md" > /dev/null
fi

if [[ "$RECORD" == true ]]; then
  : > "$work/record.md"
  if [[ -n "$RECORD_COMMENT_ID" ]]; then
    gh api "repos/$REPO/issues/comments/$RECORD_COMMENT_ID" --jq .body > "$work/record.md"
  fi
  go run ./tools/reviewround record -comment "$work/record.md" -head "$HEAD_SHA" -round "$ROUND" \
    -ai "$ai" -security "$security" -sync="${SYNC:-false}" > "$work/new-record.md"
  if [[ -n "$RECORD_COMMENT_ID" ]]; then
    gh api -X PATCH "repos/$REPO/issues/comments/$RECORD_COMMENT_ID" -F "body=@$work/new-record.md" > /dev/null
  else
    gh pr comment "$PR" --repo "$REPO" --body-file "$work/new-record.md" > /dev/null
  fi
fi

drop_recheck_label
bash scripts/set-status.sh "$HEAD_SHA" ai-review "$(verdict_state "$ai")" "第 $ROUND 轮：$(verdict_text "$ai")$note_ai"
bash scripts/set-status.sh "$HEAD_SHA" security-review "$(verdict_state "$security")" "第 $ROUND 轮：$(verdict_text "$security")$note_security"
