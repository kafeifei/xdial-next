#!/usr/bin/env bash
# 审核步骤失败时，从 claude-code-action 的执行记录里取出 API 状态码和结果文本。
# 这个 action 不打印失败原因；用订阅 token 时最常见的是用量到上限（429），表现为
# 初始化后立刻结束、零成本、只有一轮。见 anthropics/claude-code-action#1720。
# 输出到 $GITHUB_OUTPUT：api_status（例如 429；取不到时为空）

set -euo pipefail

file="${RUNNER_TEMP:?}/claude-execution-output.json"
if [[ ! -s "$file" ]]; then
  echo "api_status=" >> "$GITHUB_OUTPUT"
  echo "::error::审核失败，而且没有执行记录"
  exit 0
fi

result="$(jq -c '[.[] | select(.type == "result")] | last // {}' "$file")"
status="$(jq -r '.api_error_status // empty' <<< "$result")"
# 结果文本来自 Claude 和 API，不可信：只截一段，去掉换行，免得在日志里拼出工作流命令。
excerpt="$(jq -r '(.result // "") | .[0:300]' <<< "$result" | tr '\r\n' '  ')"

echo "api_status=$status" >> "$GITHUB_OUTPUT"
echo "::error::审核失败：API 状态 ${status:-未知}；结果摘录（不可信）：$excerpt"
