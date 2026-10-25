#!/usr/bin/env bash
# 公开内容门禁：仓库是公开的，已跟踪的文件里不能出现私有配置和不该公开的说法。
# 规则沿用 kafeifei/XDial 的 scripts/check-public-content.sh。

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Keep the deny-list assembled at runtime so this guard does not contain the
# strings it is responsible for rejecting.
policy_term='g''fw'
policy_list="${policy_term}"'list'
policy_geo='geosite-'"${policy_term}"
community_source='lyc''8503'
enterprise_domain='xin''dong''\.com'
enterprise_address='139''\.196\.60\.210'
# macOS 自带的 bash 3.2 不支持 Unicode 码点转义，下面三个词用 UTF-8 字节写。
restricted_phrase=$'\xe8\xa2\xab\xe5\xa2\x99'
misleading_phrase=$'\xe5\xa2\x99\xe7\xbb\x99'
ambiguous_phrase=$'\xe6\xb1\xa1\xe6\x9f\x93'

forbidden_regex="${policy_term}|${policy_list}|${policy_geo}|${community_source}|${enterprise_domain}|${enterprise_address}|${restricted_phrase}|${misleading_phrase}|${ambiguous_phrase}"

set +e
matched_files="$(git grep -I -l -i -E -e "$forbidden_regex" -- .)"
grep_status=$?
set -e
if (( grep_status > 1 )); then
  echo "public-content gate could not scan tracked files" >&2
  exit "$grep_status"
fi
if [[ -n "$matched_files" ]]; then
  echo "public-content gate rejected tracked content in:" >&2
  printf '%s\n' "$matched_files" >&2
  exit 1
fi

set +e
# 关掉 core.quotePath，中文路径按原样输出，否则会被转义成八进制、匹配不上。
private_regex='(^|/)PrivateConfig(/|$)'
tracked_paths="$(git -c core.quotePath=false ls-files)"
private_paths="$(LC_ALL=C grep -i -E "$private_regex" <<< "$tracked_paths")"
private_status=$?
set -e
if (( private_status > 1 )); then
  echo "public-content gate could not inspect tracked paths" >&2
  exit "$private_status"
fi
if [[ -n "$private_paths" ]] || LC_ALL=C grep -q -i -E -e "$forbidden_regex" <<< "$tracked_paths"; then
  echo "public-content gate rejected a tracked path" >&2
  exit 1
fi

# 这段历史会随合并提交进入公开历史，所以也查其中新增的行（含合并提交带进来的）、
# 改动过的路径、提交说明，以及作者和提交者的名字与邮箱。
if [[ -n "${PUBLIC_CONTENT_RANGE:-}" ]]; then
  history="$(mktemp)"
  git log --format='%an %ae %cn %ce%n%B' "$PUBLIC_CONTENT_RANGE" > "$history"
  history_paths="$(git -c core.quotePath=false log --name-only --diff-merges=first-parent --format= "$PUBLIC_CONTENT_RANGE")"
  if LC_ALL=C grep -q -i -E "$private_regex" <<< "$history_paths"; then
    echo "public-content gate rejected private configuration in $PUBLIC_CONTENT_RANGE" >&2
    exit 1
  fi
  printf '%s\n' "$history_paths" >> "$history"
  git log -p --diff-merges=first-parent --format= "$PUBLIC_CONTENT_RANGE" |
    LC_ALL=C grep '^+' | LC_ALL=C grep -v '^+++' >> "$history" || true
  if LC_ALL=C grep -q -i -E -e "$forbidden_regex" "$history"; then
    echo "public-content gate rejected history in $PUBLIC_CONTENT_RANGE" >&2
    exit 1
  fi
fi

echo "public-content gate passed"
