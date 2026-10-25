#!/usr/bin/env bash
# 列出 PR 改动涉及的全部路径，每行一个：改动后的路径，以及重命名前的旧路径。
# 用 files API 取原始文件名；文件数和 PR 报告的对不上时失败（比如超过 API 的 3000 个上限）。
# 输入环境变量：GH_TOKEN REPO PR

set -euo pipefail

files="$(gh api --paginate "repos/$REPO/pulls/$PR/files?per_page=100" --jq '.[] | {filename, previous_filename}')"
count="$(jq -s 'length' <<< "$files")"
expected="$(gh pr view "$PR" --repo "$REPO" --json changedFiles --jq .changedFiles)"
if [[ "$count" != "$expected" ]]; then
  echo "PR 改了 $expected 个文件，files API 只返回了 $count 个" >&2
  exit 1
fi
if [[ -n "$files" ]]; then
  jq -r '.filename, (.previous_filename // empty)' <<< "$files"
fi
