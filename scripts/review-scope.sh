#!/usr/bin/env bash
# 审核的准备：判断这次事件要不要审、审什么；要审时先把两项状态标成审核中。
# 由 .github/workflows/review.yml 的 scope 任务在 main 的检出里运行；PR 的 head 检出在 pr-head/，只当数据读。
# 规则见 docs/agent/loop.md 的"AI 审核"。
# 输入环境变量：GH_TOKEN REPO PR HEAD_SHA BASE_REF DRAFT EVENT_ACTION EVENT_LABEL RUN_URL
# 输出到 $GITHUB_OUTPUT：action（review、reuse、stop、draft、stale、off-main），
#   以及 tier round run_ai run_security ai_scope security_scope since ai security record sync record_comment_id

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off

record_marker='<!-- xdial-review-state '

mark() {
  for context in ai-review security-review; do
    bash scripts/set-status.sh "$HEAD_SHA" "$context" "$1" "$2"
  done
}

if [[ "$BASE_REF" != main ]]; then
  echo "action=off-main" >> "$GITHUB_OUTPUT"
  mark failure "只审核指向 main 的 PR"
  exit 0
fi
current_head="$(gh pr view "$PR" --repo "$REPO" --json headRefOid --jq .headRefOid)"
if [[ "$current_head" != "$HEAD_SHA" ]]; then
  echo "action=stale" >> "$GITHUB_OUTPUT"
  echo "PR 的 head 已经是 $current_head，这次事件过时了"
  exit 0
fi
if [[ "$DRAFT" == true ]]; then
  echo "action=draft" >> "$GITHUB_OUTPUT"
  mark pending "草稿不审，转为可审后再审"
  exit 0
fi

work="$(mktemp -d)"
go build -o "$work/risktier" ./tools/risktier
go build -o "$work/reviewround" ./tools/reviewround

bash scripts/pr-files.sh > "$work/files"
tier="$("$work/risktier" -config .github/risk-tiers.json -v < "$work/files")"
main_sha="$(git -C pr-head rev-parse refs/remotes/origin/main)"

# 审核记录：github-actions[bot] 发的、以标记开头的最早一条评论。
gh api --paginate "repos/$REPO/issues/$PR/comments" |
  jq -c --arg marker "$record_marker" \
    '.[] | select(.user.login == "github-actions[bot]" and (.body | startswith($marker))) | {id, body}' \
    > "$work/records.jsonl"
record_comment_id="$(jq -rs 'first | .id // ""' "$work/records.jsonl")"
jq -rs 'first | .body // ""' "$work/records.jsonl" > "$work/record.md"
last_head="$("$work/reviewround" last -comment "$work/record.md")"

case "$(bash scripts/changes-since.sh pr-head "$last_head" "$HEAD_SHA" "$main_sha")" in
  none) changes=0 ;;
  some*) changes=1 ;;
  *) changes=-1 ;;
esac

allow_more=false
if bash scripts/labeled-by-owner.sh allow-more-rounds; then
  allow_more=true
fi
recheck=false
if [[ "$EVENT_ACTION" == labeled && "$EVENT_LABEL" == re-review ]]; then
  recheck=true
fi

decision="$("$work/reviewround" decide -comment "$work/record.md" -head "$HEAD_SHA" -changes "$changes" \
  -tier "$tier" -allow-more="$allow_more" -recheck="$recheck")"
{
  echo "tier=$tier"
  jq -r 'to_entries[] | "\(.key)=\(.value)"' <<< "$decision"
  echo "record_comment_id=$record_comment_id"
} >> "$GITHUB_OUTPUT"
jq -r --arg tier "$tier" '"风险档 \($tier)，第 \(.round) 轮：\(.action)，AI \(.ai_scope)，安全 \(.security_scope)"' \
  <<< "$decision" >> "$GITHUB_STEP_SUMMARY"

if [[ "$(jq -r .action <<< "$decision")" == review ]]; then
  mark pending "审核中（${HEAD_SHA:0:7}）"
fi
