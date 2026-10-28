#!/usr/bin/env bash
# 在测试虚拟机里执行的 e2e 用例，每个用例输出一行 JSON：{"case", "ok", "detail"}。
# scripts/e2e-vm.sh 经只读共享目录把它和 xdial 二进制放在同一目录。

set -uo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
cp "$dir/xdial" "$work/xdial"
xdial="$work/xdial"
failed=0

report() {
  jq -cn --arg case "$1" --argjson ok "$2" --arg detail "$3" '{case: $case, ok: $ok, detail: $detail}'
  [[ "$2" == true ]] || failed=1
}

report environment true "macOS $(sw_vers -productVersion) $(uname -m)"

if out="$("$xdial" version --json 2>&1)" && jq -e '.schema == "xdial.version/v1" and .ok and .result.os == "darwin" and .result.arch == "arm64"' <<< "$out" > /dev/null; then
  report version-json true "$out"
else
  report version-json false "$out"
fi

# 离线检查要在真正的 macOS 上通过：编译出的配置含 TUN 和 openconnect，box.New 在子进程里跑。
cat > "$work/config.jsonc" << 'EOF'
{
  "version": 1,
  "mixed": { "port": 17890, "username": "e2e", "password": { "secret": "mixed" } },
  "lines": [
    { "id": "hk", "type": "trojan", "server": "hk.example.com", "server_port": 443,
      "password": { "secret": "hk" }, "tls": { "enabled": true, "server_name": "hk.example.com" } },
    { "id": "corp", "type": "openconnect", "flavor": "anyconnect", "server": "https://vpn.corp.example",
      "username": "e2e", "password": { "secret": "corp" } }
  ],
  "rule_sets": [{ "id": "corp", "type": "inline", "rules": [{ "domain_suffix": ["corp.example"] }] }],
  "scenarios": [{ "id": "office", "rules": [{ "rule_set": "corp", "line": "corp" }], "final": "hk" }]
}
EOF
if out="$("$xdial" config check "$work/config.jsonc" --json 2>&1)" && jq -e '.ok and .result.scenarios == ["office"]' <<< "$out" > /dev/null; then
  report config-check true "$(jq -c '.result.pending' <<< "$out")"
else
  report config-check false "$out"
fi

exit "$failed"
