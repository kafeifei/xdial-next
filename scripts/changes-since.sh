#!/usr/bin/env bash
# 判断 PR head 相对一个旧提交有没有作者自己的改动。只同步 main（自动合并、没有手工改动）不算。
#   changes-since.sh <PR 的 git 目录> <旧提交> <head> <main 的最新提交>
# 输出一行：
#   none        只同步了 main：旧提交自动合并 head 所含的 main 后，树和 head 完全相同
#   some <树>   有改动；<树> 是那次自动合并的结果，`git diff <树> <head>` 就是作者的改动（含解冲突）
#   unknown     旧提交为空、不是 head 的祖先（比如强推过），或自动合并有冲突

set -euo pipefail

dir=$1 since=$2 head=$3 main=$4

if [[ -z "$since" ]] || ! git -C "$dir" cat-file -e "$since^{commit}" 2> /dev/null ||
  ! git -C "$dir" merge-base --is-ancestor "$since" "$head"; then
  echo unknown
  exit 0
fi

synced="$(git -C "$dir" merge-base "$head" "$main")"
if ! merged="$(git -C "$dir" merge-tree --write-tree "$since" "$synced" 2> /dev/null)"; then
  echo unknown
  exit 0
fi
merged="$(printf '%s\n' "$merged" | head -n 1)"

if [[ "$merged" == "$(git -C "$dir" rev-parse "$head^{tree}")" ]]; then
  echo none
else
  echo "some $merged"
fi
