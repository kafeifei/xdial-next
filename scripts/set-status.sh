#!/usr/bin/env bash
# 在提交上写一个状态，供 main 的分支保护检查：
#   set-status.sh <sha> <context> <pending|success|failure> <说明>
# 输入环境变量：GH_TOKEN REPO；RUN_URL 可选，作为状态的链接。

set -euo pipefail

sha=$1 context=$2 state=$3 description=$4
args=(-f "state=$state" -f "context=$context" -f "description=$description")
if [[ -n "${RUN_URL:-}" ]]; then
  args+=(-f "target_url=$RUN_URL")
fi
gh api "repos/$REPO/statuses/$sha" "${args[@]}" > /dev/null
