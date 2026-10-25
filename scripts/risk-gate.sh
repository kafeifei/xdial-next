#!/usr/bin/env bash
# 风险关卡：定档、打标签，维护 PR head 提交上的 risk-gate 状态、批准记录和自动合并。
# 由 .github/workflows/risk.yml 在 main 的检出里运行；PR 的 head 检出在 pr-head/，只当数据读。
# 规则见 docs/agent/loop.md 的"风险档"和"批准"。
# 输入环境变量：GH_TOKEN REPO PR HEAD_SHA BASE_REF EVENT_ACTION EVENT_LABEL SENDER SAME_REPO DRAFT RUN_URL

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off

owner="${REPO%%/*}"
approval_marker='<!-- xdial-approval '
short="${HEAD_SHA:0:7}"

status() { bash scripts/set-status.sh "$HEAD_SHA" risk-gate "$1" "$2"; }
current_labels() { gh pr view "$PR" --repo "$REPO" --json labels --jq '[.labels[].name] | join(",")'; }
has_label() { [[ ",$labels," == *",$1,"* ]]; }
rank() {
  case "$1" in
    low) echo 0 ;;
    medium) echo 1 ;;
    *) echo 2 ;;
  esac
}

if [[ "$SAME_REPO" != true ]]; then
  status failure "外部 fork 的 PR 不自动处理，由用户决定"
  exit 0
fi
if [[ "$BASE_REF" != main ]]; then
  status failure "只处理指向 main 的 PR"
  exit 0
fi
# 事件到达时 PR 可能已经有了更新的 head，那就交给那次事件处理。
current_head="$(gh pr view "$PR" --repo "$REPO" --json headRefOid --jq .headRefOid)"
if [[ "$current_head" != "$HEAD_SHA" ]]; then
  echo "PR 的 head 已经是 $current_head，这次事件过时了"
  exit 0
fi

bash scripts/ensure-labels.sh
work="$(mktemp -d)"
bash scripts/pr-files.sh > "$work/files"
tier="$(go run ./tools/risktier -config .github/risk-tiers.json -v < "$work/files")"
main_sha="$(git -C pr-head rev-parse refs/remotes/origin/main)"
labels="$(current_labels)"

# 批准记录：github-actions[bot] 发的、以标记开头的最早一条评论，记着批准时的提交和风险档。
gh api --paginate "repos/$REPO/issues/$PR/comments" |
  jq -c --arg marker "$approval_marker" \
    '.[] | select(.user.login == "github-actions[bot]" and (.body | startswith($marker))) | {id, body}' \
    > "$work/approvals.jsonl"
approval_id="$(jq -rs 'first | .id // ""' "$work/approvals.jsonl")"
approval="$(jq -cs --arg marker "$approval_marker" \
  'first | (.body // "") | ltrimstr($marker) | split(" -->")[0] | (fromjson? // {})' "$work/approvals.jsonl")"

if [[ "$EVENT_ACTION" == labeled && "$EVENT_LABEL" == owner-approved ]]; then
  if [[ "$SENDER" == "$owner" ]]; then
    approval="$(jq -cn --arg sha "$HEAD_SHA" --arg tier "$tier" '{sha: $sha, tier: $tier}')"
    printf '%s%s -->\n仓库所有者在 %s 上批准了合并（%s 风险）。之后作者再改代码，批准自动失效。由风险工作流维护，请勿编辑。\n' \
      "$approval_marker" "$approval" "$short" "$tier" > "$work/approval.md"
    if [[ -n "$approval_id" ]]; then
      gh api -X PATCH "repos/$REPO/issues/comments/$approval_id" -F "body=@$work/approval.md" > /dev/null
    else
      gh pr comment "$PR" --repo "$REPO" --body-file "$work/approval.md" > /dev/null
    fi
  else
    gh pr edit "$PR" --repo "$REPO" --remove-label owner-approved > /dev/null
    labels="$(current_labels)"
  fi
fi

# 批准只对批准时的代码和风险档有效；每次运行都核对，不依赖事件类型。
approved=false
if has_label owner-approved; then
  approved_sha="$(jq -r '.sha // ""' <<< "$approval")"
  approved_tier="$(jq -r '.tier // "low"' <<< "$approval")"
  changes=unknown
  if [[ -n "$approved_sha" ]]; then
    changes="$(bash scripts/changes-since.sh pr-head "$approved_sha" "$HEAD_SHA" "$main_sha")"
  fi
  # 所有者刚加标签的这次事件以事件里的发送者为准，事件接口可能还查不到这条记录。
  by_owner=false
  if [[ "$EVENT_ACTION" == labeled && "$EVENT_LABEL" == owner-approved && "$SENDER" == "$owner" ]] ||
    bash scripts/labeled-by-owner.sh owner-approved; then
    by_owner=true
  fi
  if [[ "$changes" == none && "$by_owner" == true ]] && (( $(rank "$tier") <= $(rank "$approved_tier") )); then
    approved=true
  else
    gh pr edit "$PR" --repo "$REPO" --remove-label owner-approved > /dev/null
    labels="$(current_labels)"
  fi
fi

for t in low medium high; do
  if [[ "$t" == "$tier" ]]; then
    has_label "risk:$t" || gh pr edit "$PR" --repo "$REPO" --add-label "risk:$t" > /dev/null
  elif has_label "risk:$t"; then
    gh pr edit "$PR" --repo "$REPO" --remove-label "risk:$t" > /dev/null
  fi
done

if [[ "$tier" == low || "$approved" == true ]]; then
  if [[ "$DRAFT" != true ]]; then
    gh pr merge "$PR" --repo "$REPO" --auto --merge ||
      echo "::warning::开不了自动合并，关卡结论不受影响，可以手动合并"
  fi
  if [[ "$tier" == low ]]; then
    status success "低风险：其余关卡通过后自动合并（$short）"
  else
    status success "$tier 风险：仓库所有者已批准（$short）"
  fi
  exit 0
fi

# 中、高风险且没有有效的批准：自动合并必须是关着的，关不掉就失败，不能放行。
gh pr merge "$PR" --repo "$REPO" --disable-auto > /dev/null 2>&1 || true
auto_merge="$(gh pr view "$PR" --repo "$REPO" --json autoMergeRequest --jq '.autoMergeRequest != null')"
if [[ "$auto_merge" != false ]]; then
  status failure "自动合并关不掉，需要用户处理"
  echo "::error::自动合并关不掉"
  exit 1
fi
status pending "$tier 风险：等仓库所有者在 $short 上加 owner-approved"
