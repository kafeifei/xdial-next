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

# --- M2：daemon、本地 API、TUN 和系统 DNS -----------------------------------
id="com.kafeifei.xdial.debug"
data="/Library/Application Support/$id"

facts() {
  local utun route resolver dns http
  utun="$(ifconfig -l | tr ' ' '\n' | grep -c '^utun')"
  route="$(route -n get 1.1.1.1 2> /dev/null | awk '/interface:/{print $2}')"
  resolver="$(scutil --dns | awk '/^resolver #1/{f=1} f&&/nameserver\[0\]/{print $3; exit}')"
  dns="$(dscacheutil -q host -a name www.apple.com 2> /dev/null | awk '/ip_address/{print $2; exit}')"
  http="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://www.apple.com 2> /dev/null)"
  jq -cn --arg utun "$utun" --arg route "$route" --arg resolver "$resolver" --arg dns "$dns" --arg http "$http" \
    '{utun: $utun, route: $route, resolver: $resolver, dns: $dns, http: $http}'
}
base="$(facts)"
report m2-baseline true "$base console=$(stat -f %Su /dev/console) me=$(id -un)"
restored() {
  jq -e --argjson b "$base" '.utun == $b.utun and .route == $b.route and .resolver == $b.resolver and .dns != "" and .http != "000" and .http != ""' <<< "$1" > /dev/null
}
check() { if eval "$2"; then report "$1" true "$3"; else report "$1" false "$3"; fi; }
key="State:/Network/Service/$id/DNS"
has_key() { printf 'show %s\n' "$key" | scutil | grep -c ServerAddresses; }
service="$(networksetup -listallnetworkservices | sed -n 2p)"

out="$(sudo "$xdial" daemon install --json 2>&1)"
check m2-install "jq -e .ok <<< '$out' > /dev/null" "$out"
perms="$(stat -f '%Sp %Su:%Sg' "/var/run/$id" "/var/run/$id/api.sock" "$data/private" "$data/bin/xdial" 2> /dev/null | tr '\n' ';')"
check m2-permissions '[[ "$perms" == "drwxr-xr-x root:wheel;srw-rw-rw- root:wheel;drwx------ root:wheel;-rwxr-xr-x root:wheel;" ]]' "$perms"
# 不是控制台用户、也不是 root 的调用方被拒，拿到 api.permission。
cp "$xdial" /tmp/xdial-other && chmod 755 /tmp/xdial-other
out="$(cd /tmp && sudo -u nobody /tmp/xdial-other status --json 2>&1)"
check m2-other-user-refused "jq -e '.error.code == \"api.permission\"' <<< '$out' > /dev/null" "$out"

cat > "$work/m2.jsonc" << 'EOF'
{
  "version": 1,
  "mixed": { "port": 17890, "username": "e2e", "password": { "secret": "mixed" } },
  "rule_sets": [{ "id": "apple", "type": "inline", "rules": [{ "domain_suffix": ["apple.com"] }] }],
  "scenarios": [{ "id": "s", "rules": [{ "rule_set": "apple", "line": "direct" }], "final": "direct" }]
}
EOF
# 控制台用户不用 sudo 就能调用 daemon。
out="$("$xdial" config apply "$work/m2.jsonc" --json 2>&1)"
check m2-apply "jq -e '.ok and .result.applied' <<< '$out' > /dev/null" "$out"
out="$(printf 'mixed-pass\n' | "$xdial" secret set mixed --json 2>&1)"
check m2-secret "jq -e '.ok and .result.set' <<< '$out' > /dev/null" "$out"
out="$("$xdial" connect --scenario s --json 2>&1)"
if ! jq -e '.ok' <<< "$out" > /dev/null 2>&1; then
  out="$out | engine.log: $(sudo tail -n 15 "$data/private/engine.log" 2> /dev/null | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-200 | tr '\n' ';') | daemon.log: $(sudo tail -n 5 "$data/private/daemon.log" 2> /dev/null | tr '\n' ';')"
fi
check m2-connect "jq -e '.ok and .result.state == \"connected\" and .result.system_dns and (.result.physical_dns | length) > 0' <<< '${out%% |*}' > /dev/null" "$out"
sleep 2
during="$(facts)"
check m2-connected-facts "jq -e --argjson b '$base' '.utun != \$b.utun and (.route | startswith(\"utun\")) and .resolver == \"172.19.0.2\" and .dns != \"\" and .http == \"200\"' <<< '$during' > /dev/null" "$during"
dns_seen="$(sudo grep -c 'dns: exchange' "$data/private/engine.log" 2> /dev/null)"
check m2-dns-in-singbox '[[ "${dns_seen:-0}" -gt 0 ]]' "dns exchange lines: $dns_seen"
probes="udp=$(dig +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1) tcp=$(dig +tcp +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1) ddr=$(dig +time=3 +tries=1 @172.19.0.2 _dns.resolver.arpa SVCB 2>&1 | awk '/status:/{print $6}') canary=$(dig +time=3 +tries=1 @172.19.0.2 use-application-dns.net A 2>&1 | awk '/status:/{print $6}')"
check m2-dns-udp-tcp '[[ "$probes" =~ udp=[0-9] && "$probes" =~ tcp=[0-9] && "$probes" == *"ddr=NXDOMAIN,"* && "$probes" == *"canary=NXDOMAIN,"* ]]' "$probes"
leak="$(sudo grep -c 'mixed-pass' "$data/private/engine.log" "$data/private/events.jsonl" 2> /dev/null | awk -F: '{s+=$2} END{print s+0}')"
check m2-no-secret-in-logs '[[ "$leak" == 0 ]]' "lines with the secret: $leak"
noauth="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:17890 https://www.apple.com 2>&1 | tail -c 80)"
withauth="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -x http://e2e:mixed-pass@127.0.0.1:17890 https://www.apple.com 2>&1)"
check m2-mixed-auth '[[ "$noauth" != "200" && "$withauth" == "200" ]]' "without auth: $noauth; with auth: $withauth"

# 手动改物理网络的 DNS：daemon 用新的服务器重载引擎，系统解析器仍是 172.19.0.2。
pid0="$("$xdial" status --json | jq -r .result.engine_pid)"
sudo networksetup -setdnsservers "$service" 1.1.1.1
for _ in $(seq 1 30); do
  sleep 1
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.state == "connected" and .result.physical_dns == ["1.1.1.1"]' <<< "$st" > /dev/null 2>&1 && break
done
changed="$(facts)"
check m2-physical-dns-reload "jq -e --arg p '$pid0' '.result.state == \"connected\" and .result.physical_dns == [\"1.1.1.1\"] and (.result.engine_pid | tostring) != \$p' <<< '$st' > /dev/null && jq -e '.resolver == \"172.19.0.2\" and .http == \"200\"' <<< '$changed' > /dev/null" "$(jq -c '.result | {state, physical_dns, engine_pid}' <<< "$st") $changed"
sudo networksetup -setdnsservers "$service" empty
sleep 3

out="$("$xdial" disconnect --json 2>&1)"
sleep 2
after="$(facts)"
check m2-disconnect-restored "restored '$after' && [[ \"\$(has_key)\" == 0 ]]" "$after"

# 连接中强杀 daemon：临时键随它的会话立刻消失；launchd 拉起新的，旧引擎自己退出，新 daemon 恢复连接，只有一个 TUN。
"$xdial" connect --scenario s --json > /dev/null 2>&1
sleep 2
dpid="$(pgrep -f "$data/bin/xdial daemon run" | head -1)"
sudo kill -9 "$dpid"
sleep 0.5
gone="$(has_key)"
for _ in $(seq 1 60); do
  sleep 0.5
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.ok and .result.state == "connected"' <<< "$st" > /dev/null 2>&1 && break
done
sleep 2
engines="$(pgrep -f "xdial __engine" | wc -l | tr -d ' ')"
resumed="$(facts)"
check m2-daemon-killed-resumes "[[ '$gone' == 0 ]] && jq -e '.ok and .result.state == \"connected\"' <<< '$st' > /dev/null && [[ '$engines' == 1 ]] && jq -e --argjson b '$base' '(.utun | tonumber) == ((\$b.utun | tonumber) + 1) and .resolver == \"172.19.0.2\" and .http == \"200\"' <<< '$resumed' > /dev/null" "key_after_kill=$gone engines=$engines $resumed"

# 引擎崩溃：重连之前系统 DNS 先撤掉（放行直连），之后恢复。
epid="$("$xdial" status --json | jq -r .result.engine_pid)"
sudo kill -9 "$epid"
sleep 0.3
during_gap="$(has_key)"
for _ in $(seq 1 40); do
  sleep 0.5
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e --arg p "$epid" '.result.state == "connected" and (.result.engine_pid | tostring) != $p' <<< "$st" > /dev/null 2>&1 && break
done
check m2-engine-crash "[[ '$during_gap' == 0 ]] && jq -e '.result.state == \"connected\" and .result.system_dns' <<< '$st' > /dev/null" "key_during_gap=$during_gap $(jq -c '.result | {state, engine_pid, system_dns}' <<< "$st")"

# 连接中重装：先断开，换掉二进制，新 daemon 恢复连接。
out="$(sudo "$xdial" daemon install --json 2>&1)"
for _ in $(seq 1 40); do
  sleep 0.5
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.state == "connected"' <<< "$st" > /dev/null 2>&1 && break
done
check m2-reinstall-resumes "jq -e .ok <<< '$out' > /dev/null && jq -e '.result.state == \"connected\" and .result.system_dns' <<< '$st' > /dev/null" "$(jq -c '.ok' <<< "$out") $(jq -c '.result | {state, system_dns}' <<< "$st")"

out="$(sudo "$xdial" daemon uninstall --purge --json 2>&1)"
sleep 2
final="$(facts)"
left="$(ls -d "/Library/LaunchDaemons/$id.plist" "$data" "/var/run/$id" /var/run/com.kafeifei.xdial.shared 2> /dev/null | tr '\n' ';')$(pgrep -f 'xdial (daemon|__engine)' | tr '\n' ',')"
check m2-uninstall-clean "jq -e .ok <<< '$out' > /dev/null && restored '$final' && [[ -z '$left' && \"\$(has_key)\" == 0 ]]" "left=[$left] $final"

exit "$failed"
