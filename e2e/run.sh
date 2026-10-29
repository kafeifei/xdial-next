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
  local tun route resolver dns http
  # 只数带 XDial TUN 地址的接口：系统服务自己的 utun 个数会在开机后变化。
  tun="$(ifconfig | grep -c 'inet 172\.19\.0\.1 ')"
  route="$(route -n get 1.1.1.1 2> /dev/null | awk '/interface:/{print $2}')"
  resolver="$(scutil --dns | awk '/^resolver #1/{f=1} f&&/nameserver\[0\]/{print $3; exit}')"
  dns="$(dscacheutil -q host -a name www.apple.com 2> /dev/null | awk '/ip_address/{print $2; exit}')"
  http="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://www.apple.com 2> /dev/null)"
  jq -cn --arg tun "$tun" --arg route "$route" --arg resolver "$resolver" --arg dns "$dns" --arg http "$http" \
    '{tun: $tun, route: $route, resolver: $resolver, dns: $dns, http: $http}'
}
base="$(facts)"
report m2-baseline true "$base console=$(stat -f %Su /dev/console) me=$(id -un)"
restored() {
  jq -e --argjson b "$base" '.tun == "0" and .route == $b.route and .resolver == $b.resolver and .dns != "" and .http != "000" and .http != ""' <<< "$1" > /dev/null
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
  "scenarios": [{ "id": "s", "rules": [{ "rule_set": "apple", "line": "direct" }], "final": "direct" },
                { "id": "t", "rules": [], "final": "direct" }]
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
check m2-connected-facts "jq -e --argjson b '$base' '.tun == \"1\" and (.route | startswith(\"utun\")) and .resolver == \"172.19.0.2\" and .dns != \"\" and .http == \"200\"' <<< '$during' > /dev/null" "$during"
# 发一次系统查询，在引擎日志里看到它的应答，才算系统查询进了 sing-box。sing-box 在 info 级别只记有
# 应答记录的查询，所以用一个真实存在、虚拟机平时不会查的名字，比较查询前后日志里它出现的行数。
probe_name="example.org"
before_probe="$(sudo grep -c "$probe_name" "$data/private/engine.log" 2> /dev/null)"
dscacheutil -flushcache
dscacheutil -q host -a name "$probe_name" > /dev/null 2>&1
sleep 1
after_probe="$(sudo grep -c "$probe_name" "$data/private/engine.log" 2> /dev/null)"
check m2-dns-in-singbox '[[ "${after_probe:-0}" -gt "${before_probe:-0}" ]]' "lines with $probe_name: $before_probe -> $after_probe"
probes="udp=$(dig +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1) tcp=$(dig +tcp +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1) ddr=$(dig +time=3 +tries=1 @172.19.0.2 _dns.resolver.arpa SVCB 2>&1 | awk '/status:/{print $6}') canary=$(dig +time=3 +tries=1 @172.19.0.2 use-application-dns.net A 2>&1 | awk '/status:/{print $6}')"
check m2-dns-udp-tcp '[[ "$probes" =~ udp=[0-9] && "$probes" =~ tcp=[0-9] && "$probes" == *"ddr=NXDOMAIN,"* && "$probes" == *"canary=NXDOMAIN,"* ]]' "$probes"
leak="$(sudo grep -c 'mixed-pass' "$data/private/engine.log" "$data/private/events.jsonl" 2> /dev/null | awk -F: '{s+=$2} END{print s+0}')"
check m2-no-secret-in-logs '[[ "$leak" == 0 ]]' "lines with the secret: $leak"
noauth="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -x http://127.0.0.1:17890 https://www.apple.com 2>&1 | tail -c 80)"
withauth="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' -x http://e2e:mixed-pass@127.0.0.1:17890 https://www.apple.com 2>&1)"
check m2-mixed-auth '[[ "$noauth" != "200" && "$withauth" == "200" ]]' "without auth: $noauth; with auth: $withauth"

# 连接中切场景、连接中 apply：都是重载，连接锁不放开，不会撞上 engine.busy。
out="$("$xdial" scenario use t --json 2>&1)"
check m2-reload-scenario "jq -e '.ok and .result.state == \"connected\" and .result.scenario == \"t\" and .result.system_dns' <<< '$out' > /dev/null" "$out"
sed 's/"apple.com"/"apple.com", "icloud.com"/' "$work/m2.jsonc" > "$work/m2b.jsonc"
out="$("$xdial" config apply "$work/m2b.jsonc" --json 2>&1)"
check m2-reload-apply "jq -e '.ok and .result.applied and .result.reloaded' <<< '$out' > /dev/null" "$out"
out="$("$xdial" scenario use s --json 2>&1)"
st="$("$xdial" status --json 2>&1)"
check m2-reload-back "jq -e '.ok and .result.scenario == \"s\"' <<< '$out' > /dev/null && jq -e '.result.state == \"connected\" and .result.last_error == \"\"' <<< '$st' > /dev/null" "$out | $st"

# 只杀掉持有临时键的 scutil 会话：daemon 开新会话补回，引擎不动。
epid="$("$xdial" status --json | jq -r .result.engine_pid)"
sudo pkill -9 -x scutil
for _ in $(seq 1 20); do
  sleep 0.5
  [[ "$(has_key)" == 1 ]] && break
done
st="$("$xdial" status --json 2>&1)"
restarted="$("$xdial" logs --lines 50 --json 2>&1 | grep -c dns_session_restarted)"
check m2-session-replaced "[[ '$restarted' -ge 1 && \"\$(has_key)\" == 1 ]] && jq -e --arg p '$epid' '.result.state == \"connected\" and .result.system_dns and (.result.engine_pid | tostring) == \$p' <<< '$st' > /dev/null" "restarted=$restarted $(jq -c '.result | {state, system_dns, engine_pid}' <<< "$st")"

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
check m2-daemon-killed-resumes "[[ '$gone' == 0 ]] && jq -e '.ok and .result.state == \"connected\"' <<< '$st' > /dev/null && [[ '$engines' == 1 ]] && jq -e --argjson b '$base' '.tun == \"1\" and .resolver == \"172.19.0.2\" and .http == \"200\"' <<< '$resumed' > /dev/null" "key_after_kill=$gone engines=$engines $resumed"

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

# --- M3：远程规则集下载（#10）----------------------------------------------
# 用公网上真实的规则集。代理线路连虚拟机里的测试服务端（e2e/testserver），它自己也绑物理接口，
# 所以经它下载同样不经过 TUN：引擎日志里不该出现规则集的主机名。
iface="$(printf 'show State:/Network/Global/IPv4\n' | scutil | awk '/PrimaryInterface/{print $3}')"
lan="$(ipconfig getifaddr "$iface")"
cat > "$work/ts.json" << EOF
{
  "log": { "level": "info", "output": "$work/ts.log" },
  "dns": { "servers": [{ "type": "udp", "tag": "d", "server": "1.1.1.1" }], "final": "d" },
  "inbounds": [{ "type": "shadowsocks", "tag": "ss-in", "listen": "0.0.0.0", "listen_port": 18388,
                 "method": "aes-128-gcm", "password": "e2e-ss-pass" },
               { "type": "vless", "tag": "vless-in", "listen": "0.0.0.0", "listen_port": 18389,
                 "users": [{ "uuid": "1386f85e-657b-4d6e-9d56-78badb75e1fd" }] }],
  "outbounds": [{ "type": "direct", "tag": "direct" }],
  "route": { "default_interface": "$iface", "default_domain_resolver": "d" }
}
EOF
# 共享目录不能直接执行，和 xdial 一样先拷到工作目录。
cp "$dir/testserver" "$work/testserver"
"$work/testserver" "$work/ts.json" > "$work/ts.out" 2>&1 &
tspid=$!
sleep 1
cat > "$work/m3.jsonc" << EOF
{
  "version": 1,
  "mixed": { "port": 17890, "username": "e2e", "password": { "secret": "mixed" } },
  "lines": [{ "id": "ss", "type": "shadowsocks", "server": "$lan", "server_port": 18388,
              "method": "aes-128-gcm", "password": { "secret": "ss" } }],
  "rule_sets": [
    { "id": "apple", "type": "remote", "format": "source",
      "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/apple.json" },
    { "id": "cn-ip", "type": "remote", "format": "binary", "download_via": "ss",
      "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs" },
    { "id": "local", "type": "remote", "format": "source", "url": "https://localtest.me/rules.json" },
    { "id": "to-http", "type": "remote", "format": "source",
      "url": "https://httpbingo.org/redirect-to?url=http%3A%2F%2Fexample.com%2F" }
  ],
  "scenarios": [
    { "id": "s", "rules": [{ "rule_set": "apple", "line": "direct" }, { "rule_set": "cn-ip", "line": "direct" }], "final": "direct" },
    { "id": "t", "rules": [], "final": "direct" },
    { "id": "u", "rules": [{ "rule_set": "local", "line": "direct" }], "final": "direct" }
  ]
}
EOF
printf 'e2e-ss-pass\n' | "$xdial" secret set ss --json > /dev/null 2>&1
before_gh="$(sudo grep -c raw.githubusercontent.com "$data/private/engine.log" 2> /dev/null)"
# 连着场景 s 时 apply：两个规则集都没缓存，重载前先下载，一个经 direct、一个经代理线路。
out="$("$xdial" config apply "$work/m3.jsonc" --json 2>&1)"
check m3-apply-downloads "jq -e '.ok and .result.applied and .result.reloaded' <<< '$out' > /dev/null" "iface=$iface lan=$lan testserver=[$(head -c 300 "$work/ts.out" | tr '\n' ';')] $out"
list="$("$xdial" rule-set list --json 2>&1)"
check m3-rule-set-list "jq -e '[.result.rule_sets[] | select(.id == \"apple\" or .id == \"cn-ip\") | select(.cached and .rules > 0)] | length == 2' <<< '$list' > /dev/null" "$(jq -c '[.result.rule_sets[] | {id, cached, rules, last_error: .last_error.code}]' <<< "$list")"
via="$(grep -c raw.githubusercontent.com "$work/ts.log" 2> /dev/null)"
after_gh="$(sudo grep -c raw.githubusercontent.com "$data/private/engine.log" 2> /dev/null)"
check m3-download-via-line-and-around-tun '[[ "${via:-0}" -ge 1 && "${after_gh:-0}" == "${before_gh:-0}" ]]' "via test server: $via; engine log lines: $before_gh -> $after_gh"
perm="$(sudo sh -c "stat -f '%Sp %Su' '$data/private/resources/rule-sets/'apple.*.json" 2> /dev/null)"
check m3-cache-private '[[ "$perm" == "-rw------- root" ]]' "$perm"
out="$("$xdial" rule-set update apple --json 2>&1)"
check m3-update-not-modified "jq -e '.ok and .result.updated[0].changed == false and .result.updated[0].rules > 0' <<< '$out' > /dev/null" "$out"
out="$("$xdial" rule-set update local --json 2>&1)"
check m3-refuses-loopback "jq -e '.error.code == \"resource.blocked\"' <<< '$out' > /dev/null" "$out"
out="$("$xdial" rule-set update to-http --json 2>&1)"
check m3-refuses-http-redirect "jq -e '.error.code == \"resource.blocked\"' <<< '$out' > /dev/null" "$out"
# 场景 u 的规则集下载不了：切场景失败，现有连接不变。
out="$("$xdial" scenario use u --json 2>&1)"
st="$("$xdial" status --json 2>&1)"
check m3-missing-keeps-connection "jq -e '.error.code == \"resource.blocked\"' <<< '$out' > /dev/null && jq -e '.result.state == \"connected\" and .result.scenario == \"s\"' <<< '$st' > /dev/null" "$out | $(jq -c '.result | {state, scenario}' <<< "$st")"
out="$("$xdial" scenario use t --json 2>&1)" && out2="$("$xdial" scenario use s --json 2>&1)"
check m3-switch-from-cache "jq -e '.ok and .result.scenario == \"s\" and .result.state == \"connected\"' <<< '$out2' > /dev/null" "$out2"

# --- M3：订阅（#11）-----------------------------------------------------------
# 现场拼一个 Clash 订阅：节点指向测试服务端，规则把 example.org 交给 Proxy 策略。经公网的 echo 服务
# （httpbingo.org/base64）下载，所以走的是真实的下载路径。组只选 vless 节点，场景按策略名映射。
sub_yaml="proxies:
  - {name: \"e2e ss\", type: ss, server: $lan, port: 18388, cipher: aes-128-gcm, password: e2e-ss-pass}
  - {name: \"e2e vless\", type: vless, server: $lan, port: 18389, uuid: 1386f85e-657b-4d6e-9d56-78badb75e1fd}
  - {name: \"e2e hy2\", type: hysteria2, server: $lan, port: 1, password: x}
rules:
  - DOMAIN-SUFFIX,example.org,Proxy
  - DOMAIN-SUFFIX,apple.com,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy
"
sub_url="https://httpbingo.org/base64/$(printf '%s' "$sub_yaml" | base64 | tr '+/' '-_' | tr -d '=\n')"
cat > "$work/m3sub.jsonc" << 'EOF'
{
  "version": 1,
  "groups": [{ "id": "proxy", "type": "selector", "outbounds": [{ "subscription": "air", "filter": "vless" }] }],
  "subscriptions": [{ "id": "air", "url": { "secret": "air-url" } }],
  "scenarios": [{ "id": "sub", "rules": [{ "subscription": "air", "policies": { "Proxy": "proxy", "DIRECT": "direct" } }],
                  "final": "direct" }]
}
EOF
"$xdial" disconnect --json > /dev/null 2>&1
printf '%s\n' "$sub_url" | "$xdial" secret set air-url --json > /dev/null 2>&1
out="$("$xdial" config apply "$work/m3sub.jsonc" --json 2>&1)"
out2="$("$xdial" connect --scenario sub --json 2>&1)"
check m3-subscription-connect "jq -e '.ok' <<< '$out' > /dev/null && jq -e '.ok and .result.state == \"connected\"' <<< '$out2' > /dev/null" "$(jq -c '.ok' <<< "$out") $out2"
list="$("$xdial" subscription list --json 2>&1)"
check m3-subscription-list "jq -e '.result.subscriptions[0] | .cached and .format == \"clash\" and .nodes == 2 and .rules == 2 and .unsupported[\"node:hysteria2\"] == 1 and .unsupported[\"rule:geoip\"] == 1 and ([.policies[].name] == [\"Proxy\", \"DIRECT\"])' <<< '$list' > /dev/null" "$(jq -c '.result.subscriptions[0] | {cached, format, nodes, rules, unsupported, policies}' <<< "$list")"
show="$("$xdial" subscription show air --json 2>&1)"
check m3-subscription-show-no-secrets "jq -e '.ok and (.result.nodes | length) == 2' <<< '$show' > /dev/null && ! grep -q e2e-ss-pass <<< '$show'" "$(jq -c '.result.nodes' <<< "$show")"
# 经 TUN 进来的连接交给节点时带的是 IP，测试服务端日志里看不到域名：比较 vless 入站的连接数。
# example.org 按订阅规则走 proxy 组（vless 节点）；它的 DNS 也经这个组，是发往 1.1.1.1 的 DoH，
# 不算在内，只数发往其他地址的连接。apple.com 走 direct，不该增加。
vless_count() { grep 'vless-in' "$work/ts.log" 2> /dev/null | grep 'inbound connection to' | grep -vc 'to 1\.1\.1\.1:'; }
c0="$(vless_count)"
code_org="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' https://example.org 2>&1)"
sleep 1
c1="$(vless_count)"
code_apple="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' https://www.apple.com 2>&1)"
sleep 1
c2="$(vless_count)"
check m3-subscription-rules-route '[[ "$code_org" == 200 && "$code_apple" == 200 && "${c1:-0}" -gt "${c0:-0}" && "${c2:-0}" == "${c1:-0}" ]]' "example.org=$code_org apple=$code_apple vless connections: $c0 -> $c1 -> $c2"
"$xdial" disconnect --json > /dev/null 2>&1
"$xdial" config apply "$work/m3.jsonc" --json > /dev/null 2>&1
"$xdial" connect --scenario s --json > /dev/null 2>&1
kill "$tspid" 2> /dev/null

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
left="$(ls -d "/Library/LaunchDaemons/$id.plist" "$data" "/var/run/$id" "/Library/Application Support/com.kafeifei.xdial.shared" 2> /dev/null | tr '\n' ';')$(pgrep -f 'xdial (daemon|__engine)' | tr '\n' ',')"
check m2-uninstall-clean "jq -e .ok <<< '$out' > /dev/null && restored '$final' && [[ -z '$left' && \"\$(has_key)\" == 0 ]]" "left=[$left] $final"

exit "$failed"
