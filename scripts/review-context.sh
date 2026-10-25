#!/usr/bin/env bash
# 准备 AI 审核要读的材料，写到 .review/ 下。审核者没有 shell，只能读这些文件和 PR 的检出。
# 只收仓库所有者和审核机器人写的东西；第三方的评论和 issue 不进审核上下文。
# 输入环境变量：GH_TOKEN REPO PR HEAD_SHA PR_DIR ROUND TIER AI_SCOPE SECURITY_SCOPE SINCE

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

owner="${REPO%%/*}"
mkdir -p .review

gh pr view "$PR" --repo "$REPO" --json title,body | jq -r '"# " + .title + "\n\n" + (.body // "")' > .review/pr.md

issue_numbers="$(gh pr view "$PR" --repo "$REPO" --json closingIssuesReferences --jq '.closingIssuesReferences[].number')"
: > .review/issues.md
for number in $issue_numbers; do
  issue="$(gh issue view "$number" --repo "$REPO" --json number,title,body,author)"
  jq -r --arg owner "$owner" 'select(.author.login == $owner) | "## #\(.number) \(.title)\n\n\(.body // "")\n"' \
    <<< "$issue" >> .review/issues.md
done

comments="$(gh api --paginate "repos/$REPO/pulls/$PR/comments")"
jq -c --arg owner "$owner" '.[] | select(.user.login == $owner or .user.login == "github-actions[bot]")
  | {id, in_reply_to_id, user: .user.login, path, line, body}' <<< "$comments" > .review/threads.jsonl

main_sha="$(git -C "$PR_DIR" rev-parse refs/remotes/origin/main)"
fork_point="$(git -C "$PR_DIR" merge-base "$main_sha" "$HEAD_SHA")"
git -C "$PR_DIR" diff "$fork_point" "$HEAD_SHA" > .review/full.patch
git -C "$PR_DIR" diff --name-status "$fork_point" "$HEAD_SHA" > .review/files.txt
git -C "$PR_DIR" log --format='%h %s' "$fork_point..$HEAD_SHA" > .review/commits.txt

since_patch=false
if [[ "$AI_SCOPE" == since || "$SECURITY_SCOPE" == since ]]; then
  changes="$(bash scripts/changes-since.sh "$PR_DIR" "$SINCE" "$HEAD_SHA" "$main_sha")"
  if [[ "$changes" == some* ]]; then
    git -C "$PR_DIR" diff "${changes#some }" "$HEAD_SHA" > .review/since.patch
    since_patch=true
  fi
fi

describe() {
  case "$1" in
    full)
      echo "审整个 PR：.review/full.patch（相对 PR 从 main 分出的位置），以及受它影响的调用方。"
      ;;
    since)
      if [[ "$since_patch" == true ]]; then
        echo "只审上一轮审核（${SINCE:0:7}）之后作者的改动：.review/since.patch，包括合并 main 时手工改动或解冲突的部分。.review/full.patch 只作背景。"
      else
        echo "审整个 PR：.review/full.patch。算不出上一轮之后的改动，所以退回整审。"
      fi
      ;;
    replies)
      echo "代码和上一轮审核时相同。只复核 .review/threads.jsonl 里作者对以往意见的回复：理由成立就接受，不成立就说明。.review/full.patch 只作背景。"
      ;;
  esac
}

for kind in ai security; do
  if [[ "$kind" == ai ]]; then scope="$AI_SCOPE"; else scope="$SECURITY_SCOPE"; fi
  [[ -z "$scope" ]] && continue
  {
    echo "第 $ROUND 轮审核，风险档：$TIER。"
    echo
    echo "范围：$(describe "$scope")"
    echo
    echo "PR head（${HEAD_SHA:0:7}）的文件在 $PR_DIR 下。改动的文件列表在 .review/files.txt，提交列表在 .review/commits.txt。"
  } > ".review/$kind-scope.md"
done
