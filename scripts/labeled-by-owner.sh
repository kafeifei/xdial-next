#!/usr/bin/env bash
# 标签在 PR 上，并且最近一次是仓库所有者本人加的（不是机器人）时退出码为 0。
#   labeled-by-owner.sh <标签>
# 输入环境变量：GH_TOKEN REPO PR

set -euo pipefail

label=$1
owner="${REPO%%/*}"

labels="$(gh pr view "$PR" --repo "$REPO" --json labels --jq '[.labels[].name] | join(",")')"
if [[ ",$labels," != *",$label,"* ]]; then
  exit 1
fi

events="$(gh api --paginate "repos/$REPO/issues/$PR/events")"
actor="$(jq -rs --arg label "$label" \
  '[.[][] | select(.event == "labeled" and .label.name == $label)] | last | "\(.actor.login // "") \(.actor.type // "")"' \
  <<< "$events")"
[[ "$actor" == "$owner User" ]]
