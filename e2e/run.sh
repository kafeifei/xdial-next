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

# --- M3：AnyConnect 线路的状态（#12）------------------------------------------
# 虚拟机里没有 AnyConnect 服务器：线路指向一个不是 AnyConnect 的公网 https 服务。连接照常建立，
# 走这条线路的流量不通、其余不受影响，status 里能看到这条 VPN 连不上，事件日志有记录。
cat > "$work/m3vpn.jsonc" << 'EOF'
{
  "version": 1,
  "lines": [{ "id": "corp", "type": "openconnect", "flavor": "anyconnect", "server": "https://example.com",
              "username": "e2e", "password": { "secret": "corp" } }],
  "rule_sets": [{ "id": "corp-domains", "type": "inline", "rules": [{ "domain_suffix": ["corp.example"] }] }],
  "scenarios": [{ "id": "vpn", "rules": [{ "rule_set": "corp-domains", "line": "corp" }], "final": "direct" }]
}
EOF
"$xdial" disconnect --json > /dev/null 2>&1
printf 'not-a-real-password\n' | "$xdial" secret set corp --json > /dev/null 2>&1
"$xdial" config apply "$work/m3vpn.jsonc" --json > /dev/null 2>&1
out="$("$xdial" connect --scenario vpn --json 2>&1)"
for _ in $(seq 1 40); do
  sleep 1
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.endpoints.corp.state == "failed" or .result.endpoints.corp.state == "auth_required"' <<< "$st" > /dev/null 2>&1 && break
done
http="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' https://www.apple.com 2>&1)"
events="$("$xdial" logs --lines 100 --json 2>&1 | grep -c '"endpoint_state"')"
text="$("$xdial" status 2>&1 | grep 'corp' | head -1)"
check m3-anyconnect-status "jq -e '.ok and .result.state == \"connected\"' <<< '$out' > /dev/null && jq -e '.result.state == \"connected\" and .result.endpoints.corp.type == \"openconnect\" and .result.endpoints.corp.state != \"connected\"' <<< '$st' > /dev/null && [[ '$http' == 200 && '$events' -ge 1 ]]" "$(jq -c '.result.endpoints' <<< "$st") http=$http events=$events text=[$text]"

# --- M3：Tailscale（#13）-----------------------------------------------------
# 用用户给的临时 auth key（可复用、ephemeral、tag:xdial-e2e）让虚拟机入网：登录后到 connected，
# 自己的 Tailnet 名字经系统 DNS 解析到自己的地址，日志里没有 key，登出后等新的登录。
if [[ -s "$dir/ts-authkey" ]]; then
  ts_host="xdial-e2e-$(date +%s)"
  cat > "$work/m3ts.jsonc" << EOF
{
  "version": 1,
  "lines": [{ "id": "tailnet", "type": "tailscale", "hostname": "$ts_host", "ephemeral": true }],
  "rule_sets": [{ "id": "tailnet-names", "type": "inline", "rules": [{ "domain_suffix": ["ts.net"] }, { "ip_cidr": ["100.64.0.0/10"] }] }],
  "scenarios": [{ "id": "ts", "rules": [{ "rule_set": "tailnet-names", "line": "tailnet" }], "final": "direct" }]
}
EOF
  "$xdial" disconnect --json > /dev/null 2>&1
  "$xdial" config apply "$work/m3ts.jsonc" --json > /dev/null 2>&1
  "$xdial" connect --scenario ts --json > /dev/null 2>&1
  out="$("$xdial" tailscale login tailnet --auth-key --json < "$dir/ts-authkey" 2>&1)"
  for _ in $(seq 1 60); do
    st="$("$xdial" status --json 2> /dev/null)"
    jq -e '.result.endpoints.tailnet.state == "connected" and (.result.endpoints.tailnet.self | length) > 0' <<< "$st" > /dev/null 2>&1 && break
    sleep 1
  done
  ts_name="$(jq -r '.result.endpoints.tailnet.dns_name // ""' <<< "$st")"
  ts_ip="$(jq -r '[.result.endpoints.tailnet.self[] | select(startswith("100."))][0] // ""' <<< "$st")"
  check m3-tailscale-login "jq -e '.result.endpoints.tailnet.state == \"connected\" and .result.endpoints.tailnet.tailnet != \"\"' <<< '$st' > /dev/null && [[ -n '$ts_ip' ]]" "login=$(jq -c '.ok' <<< "$out") $(jq -c '.result.endpoints.tailnet | {state, tailnet, dns_name, self, peers}' <<< "$st")"
  dscacheutil -flushcache
  resolved="$(dscacheutil -q host -a name "${ts_name%.}" 2> /dev/null | awk '/ip_address/{print $2; exit}')"
  check m3-tailscale-dns '[[ -n "$ts_ip" && "$resolved" == "$ts_ip" ]]' "${ts_name%.} -> $resolved (self $ts_ip)"
  key_leak="$(sudo grep -c -F -f "$dir/ts-authkey" "$data/private/engine.log" "$data/private/events.jsonl" 2> /dev/null | awk -F: '{s+=$2} END{print s+0}')"
  check m3-tailscale-key-not-logged '[[ "$key_leak" == 0 ]]' "lines with the auth key: $key_leak"
  out="$("$xdial" tailscale logout tailnet --json 2>&1)"
  check m3-tailscale-logout "jq -e '.ok and .result.state == \"auth_required\"' <<< '$out' > /dev/null" "$(jq -c '.result | {state, auth_url: (.auth_url != null)}' <<< "$out" 2> /dev/null || echo "$out")"
else
  report m3-tailscale true "跳过：本机钥匙串里没有 xdial-e2e-tailscale-authkey"
fi

# --- M4：线路组在运行中（#16）------------------------------------------------
# selector 组的两个成员分别连测试服务端的 shadowsocks 和 vless 入口：手选之后流量换到另一个入口，
# 引擎不重启；测速对两个成员都有结果。这个场景的 final 就是这个组，虚拟机的后台流量也走它，
# 所以只数发往一个固定地址（1.0.0.1）的连接。
cat > "$work/m4g.jsonc" << EOF
{
  "version": 1,
  "lines": [
    { "id": "ss", "type": "shadowsocks", "server": "$lan", "server_port": 18388, "method": "aes-128-gcm", "password": { "secret": "ss" } },
    { "id": "vl", "type": "vless", "server": "$lan", "server_port": 18389, "uuid": { "secret": "vl" } }
  ],
  "groups": [{ "id": "pick", "type": "selector", "outbounds": ["ss", "vl"] }],
  "scenarios": [{ "id": "g", "rules": [], "final": "pick" }]
}
EOF
"$xdial" disconnect --json > /dev/null 2>&1
printf '1386f85e-657b-4d6e-9d56-78badb75e1fd\n' | "$xdial" secret set vl --json > /dev/null 2>&1
"$xdial" config apply "$work/m4g.jsonc" --json > /dev/null 2>&1
st0="$("$xdial" connect --scenario g --json 2>&1)"
inbound_count() { grep "$1" "$work/ts.log" 2> /dev/null | grep -c 'inbound connection to 1\.0\.0\.1:443'; }
s0="$(inbound_count ss-in)"; v0="$(inbound_count vless-in)"
curl -sS -m 15 -o /dev/null https://1.0.0.1 2> /dev/null; sleep 1
s1="$(inbound_count ss-in)"; v1="$(inbound_count vless-in)"
sel="$("$xdial" group select pick vl --json 2>&1)"
curl -sS -m 15 -o /dev/null https://1.0.0.1 2> /dev/null; sleep 1
s2="$(inbound_count ss-in)"; v2="$(inbound_count vless-in)"
st1="$("$xdial" status --json 2>&1)"
check m4-group-select "jq -e '.result.applied' <<< '$sel' > /dev/null && [[ \$(jq -r .result.engine_pid <<< '$st0') == \$(jq -r .result.engine_pid <<< '$st1') ]] && jq -e '.result.groups.pick.now == \"vl\"' <<< '$st1' > /dev/null && (( s1 > s0 && v1 == v0 && v2 > v1 ))" "ss $s0->$s1->$s2 vless $v0->$v1->$v2 $(jq -c '.result.groups.pick.now' <<< "$st1") lines: $(grep 'to 1\.0\.0\.1:443' "$work/ts.log" | tail -4 | cut -c1-120 | tr '\n' ';')"
tst="$("$xdial" line test pick --json 2>&1)"
check m4-line-test "jq -e '.result.results.ss.delay_ms > 0 and .result.results.vl.delay_ms > 0' <<< '$tst' > /dev/null" "$tst"
"$xdial" disconnect --json > /dev/null 2>&1
"$xdial" config apply "$work/m3.jsonc" --json > /dev/null 2>&1
"$xdial" connect --scenario s --json > /dev/null 2>&1
kill "$tspid" 2> /dev/null

# --- M4：explain（#17）-------------------------------------------------------
# 连着场景 s：apple.com 命中远程规则集 apple（第 1 条）；1.0.1.1 在 geoip-cn 里（第 2 条）；
# example.com 没有规则命中，走 final。离线对配置文件判断，远程规则集按不匹配算。
e1="$("$xdial" explain https://www.apple.com --json 2>&1)"
e2="$("$xdial" explain 1.0.1.1 --json 2>&1)"
e3="$("$xdial" explain https://example.com --json 2>&1)"
e4="$("$xdial" explain https://www.apple.com --config "$work/m3.jsonc" --json 2>&1)"
check m4-explain "jq -e '.result.rule.rule_set == \"apple\" and .result.line == \"direct\" and .result.dns.server == \"physical\"' <<< '$e1' > /dev/null && jq -e '.result.rule.rule_set == \"cn-ip\"' <<< '$e2' > /dev/null && jq -e '.result.rule == null and .result.line == \"direct\"' <<< '$e3' > /dev/null && jq -e '.result.rule == null and (.result.notes | length) > 0' <<< '$e4' > /dev/null" "$(jq -c '.result | {rule, line, dns: .dns.server}' <<< "$e1") $(jq -c '.result.rule' <<< "$e2") $(jq -c '.result.rule' <<< "$e3") offline=$(jq -c '.result.rule' <<< "$e4")"

# --- M4：doctor（#18）--------------------------------------------------------
# 连着场景 s。前面杀过引擎，规则集 local 下载被拒：doctor 都要指出来，其余几项正常。
"$xdial" rule-set update local --json > /dev/null 2>&1
d1="$("$xdial" doctor --json 2>&1)"
check m4-doctor-faults "jq -e '[.result.checks[] | {(.name): .status}] | add | .connection == \"ok\" and .system_dns == \"ok\" and .physical_dns == \"ok\" and .engine == \"warn\" and .resources == \"fail\"' <<< '$d1' > /dev/null && jq -e '[.result.checks[] | select(.name == \"engine\") | .detail[] | select(startswith(\"engine_exited\"))] | length == 1' <<< '$d1' > /dev/null && jq -e '[.result.checks[] | select(.name == \"resources\") | .detail[] | select(contains(\"local\"))] | length == 1' <<< '$d1' > /dev/null" "$(jq -c '[.result.checks[] | {name, status, summary}]' <<< "$d1")"
# 物理网络的 DNS 换成不通的地址：连接还在（探测只到 sing-box），doctor 的上游检查指出来。
sudo networksetup -setdnsservers "$service" 192.0.2.1
for _ in $(seq 1 30); do
  sleep 1
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.state == "connected" and .result.physical_dns == ["192.0.2.1"]' <<< "$st" > /dev/null 2>&1 && break
done
d2="$("$xdial" doctor --json 2>&1)"
t2="$("$xdial" doctor 2>&1)"
code=$?
check m4-doctor-physical-dns "jq -e '.result.checks[] | select(.name == \"physical_dns\") | .status == \"fail\" and (.summary | contains(\"192.0.2.1\"))' <<< '$d2' > /dev/null && [[ '$code' == 0 && \"\$(grep -c '^\[有问题\] physical_dns' <<< '$t2')\" == 1 ]]" "$(jq -c '.result.checks[] | select(.name == "physical_dns")' <<< "$d2") exit=$code"
sudo networksetup -setdnsservers "$service" empty
for _ in $(seq 1 30); do
  sleep 1
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.state == "connected" and .result.physical_dns != ["192.0.2.1"] and .result.system_dns' <<< "$st" > /dev/null 2>&1 && break
done

# daemon restart（6.1）：App 升级后用它换上新的二进制。daemon 答复后退出，launchd 拉起新进程，连接恢复。
dpid0="$(pgrep -f "$data/bin/xdial daemon run" | head -1)"
out="$("$xdial" daemon restart --json 2>&1)"
dpid1=""
for _ in $(seq 1 60); do
  sleep 0.5
  st="$("$xdial" status --json 2> /dev/null)"
  dpid1="$(pgrep -f "$data/bin/xdial daemon run" | head -1)"
  [ -n "$dpid1" ] && [ "$dpid1" != "$dpid0" ] && jq -e '.ok and .result.state == "connected" and .result.system_dns' <<< "$st" > /dev/null 2>&1 && break
done
check m5-daemon-restart "jq -e '.ok and .result.restarting' <<< '$out' > /dev/null && [[ -n '$dpid1' && '$dpid1' != '$dpid0' ]] && jq -e '.result.state == \"connected\" and .result.system_dns' <<< '$st' > /dev/null" "pid $dpid0 -> $dpid1 $(jq -c '.result | {state, system_dns}' <<< "$st" 2> /dev/null) $(head -c 200 <<< "$out")"

# 连接中重装：先断开，换掉二进制，新 daemon 恢复连接。
pre="$("$xdial" status --json 2>&1 | jq -c '.result | {state, last_error, physical_dns}' 2>&1)"
out="$(sudo "$xdial" daemon install --json 2>&1)"
for _ in $(seq 1 40); do
  sleep 0.5
  st="$("$xdial" status --json 2> /dev/null)"
  jq -e '.result.state == "connected"' <<< "$st" > /dev/null 2>&1 && break
done
check m2-reinstall-resumes "jq -e .ok <<< '$out' > /dev/null && jq -e '.result.state == \"connected\" and .result.system_dns' <<< '$st' > /dev/null" "$(head -c 800 <<< "$out" | tr '\n' ' ') | $(head -c 400 <<< "$st" | tr '\n' ' ') | before=$(head -c 300 <<< "$pre" | tr '\n' ' ')"

out="$(sudo "$xdial" daemon uninstall --purge --json 2>&1)"
sleep 2
final="$(facts)"
left="$(ls -d "/Library/LaunchDaemons/$id.plist" "$data" "/var/run/$id" "/Library/Application Support/com.kafeifei.xdial.shared" 2> /dev/null | tr '\n' ';')$(pgrep -f 'xdial (daemon|__engine)' | tr '\n' ',')"
check m2-uninstall-clean "jq -e .ok <<< '$out' > /dev/null && restored '$final' && [[ -z '$left' && \"\$(has_key)\" == 0 ]]" "left=[$left] $final"

exit "$failed"
