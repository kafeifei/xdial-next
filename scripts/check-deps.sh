#!/usr/bin/env bash
# 依赖门禁：go.mod 必须和代码一致（go mod tidy -diff 为空，直接依赖不能标成 // indirect），
# 直接依赖都在 .github/deps-allowlist.txt 里；不能有 replace 和 go.work，
# 也不能有补丁目录或 vendored 上游源码。见 AGENTS.md。

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off

allowlist=.github/deps-allowlist.txt
failed=0

for file in go.work go.work.sum; do
  if [[ -e "$file" ]]; then
    echo "不能有 $file：单模块仓库，依赖只由 go.mod 决定" >&2
    failed=1
  fi
done

for dir in patches third_party vendor; do
  if [[ -e "$dir" ]]; then
    echo "不能有 $dir/：不打补丁，不 vendor 上游源码" >&2
    failed=1
  fi
done

if ! tidy_diff="$(go mod tidy -diff 2>&1)"; then
  echo "go.mod / go.sum 和代码对不上，先跑 go mod tidy：" >&2
  echo "$tidy_diff" >&2
  failed=1
fi

module_json="$(go mod edit -json)"
if [[ "$(jq '.Replace // [] | length' <<< "$module_json")" != 0 ]]; then
  echo "go.mod 不能有 replace：上游模块必须原样使用" >&2
  failed=1
fi

allowed="$(grep -v -E '^[[:space:]]*(#|$)' "$allowlist" | awk '{print $1}')"
while IFS= read -r module; do
  [[ -z "$module" ]] && continue
  if ! grep -qxF "$module" <<< "$allowed"; then
    echo "直接依赖不在 $allowlist 里：$module（新增依赖要先经用户批准）" >&2
    failed=1
  fi
done < <(jq -r '.Require // [] | .[] | select(.Indirect != true) | .Path' <<< "$module_json")

if (( failed )); then
  exit 1
fi
echo "dependency gate passed"
