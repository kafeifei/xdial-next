#!/usr/bin/env bash
# M2 系统 DNS 的实验，结果记在 docs/verification/m2-system-dns.md。
# 运行：XDIAL_E2E_CASES=e2e/experiments/system-dns.sh make e2e（约 15 分钟，大部分在等超时）。
# 每一项都只报告观测到的事实（ok 恒为 true），结论由人对照记录。
set -uo pipefail
dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
cp "$dir/xdial" "$work/xdial"
xdial="$work/xdial"
id="com.kafeifei.xdial.debug"
data="/Library/Application Support/$id"

report() { jq -cn --arg case "$1" --argjson ok "${2:-true}" --arg detail "$3" '{case: $case, ok: $ok, detail: $detail}'; }
first_resolver() { scutil --dns | awk '/^resolver #1/{f=1} f&&/nameserver\[0\]/{print $3; exit}'; }
global_dns() { printf 'show State:/Network/Global/DNS\n' | scutil | tr -s ' \n' ' '; }

report env true "macOS $(sw_vers -productVersion) global=$(global_dns) first=$(first_resolver)"

# E1 临时键：会话活着时存在，会话结束（stdin EOF / 被杀）后消失。
key="State:/Network/Service/xdial-exp/DNS"
fifo="$work/holder.in"
mkfifo "$fifo"
sudo scutil < "$fifo" > "$work/holder.out" 2>&1 &
holder=$!
exec 7> "$fifo"
printf 'd.init\nd.add ServerAddresses * 192.0.2.53\nd.add SupplementalMatchDomains * xdial-exp.invalid\nadd %s temporary\n' "$key" >&7
sleep 1
has() { printf 'show %s\n' "$key" | scutil | grep -c ServerAddresses; }
alive="$(has)"
# E2 通知：同一会话里 n.add + n.watch，另一个会话改一个被监视的键，看 holder 的 stdout。
wkey="State:/Network/Service/xdial-exp-watch/DNS"
printf 'n.add %s\nn.add State:/Network/Global/DNS\nn.watch\n' "$wkey" >&7
sleep 1
printf 'd.init\nd.add ServerAddresses * 192.0.2.54\nset %s\n' "$wkey" | sudo scutil
sleep 1
printf 'remove %s\n' "$wkey" | sudo scutil
sleep 1
# 通知开着之后，同一会话还能不能继续执行命令：再加一个临时键。
key2="State:/Network/Service/xdial-exp2/DNS"
printf 'd.init\nd.add ServerAddresses * 192.0.2.55\nadd %s temporary\n' "$key2" >&7
sleep 1
alive2="$(printf 'show %s\n' "$key2" | scutil | grep -c ServerAddresses)"
watch_out="$(tr '\n' '|' < "$work/holder.out" | cut -c1-600)"
exec 7>&-
sleep 1.5
after_eof="$(has)"
report e1-temporary-key true "alive=$alive key2_after_watch=$alive2 after_eof=$after_eof holder_exit=$(kill -0 $holder 2> /dev/null && echo running || echo exited)"
report e2-watch true "$watch_out"

# E1b：被 kill -9 的会话也会回收临时键。
mkfifo "$work/h2.in"
sudo scutil < "$work/h2.in" > /dev/null 2>&1 &
exec 8> "$work/h2.in"
printf 'd.init\nd.add ServerAddresses * 192.0.2.53\nd.add SupplementalMatchDomains * xdial-exp.invalid\nadd %s temporary\n' "$key" >&8
sleep 1
before_kill="$(has)"
sudo pkill -9 -x scutil
sleep 1.5
after_kill="$(has)"
exec 8>&-
report e1b-temporary-killed true "before=$before_kill after_kill9=$after_kill"

# E3：匹配所有域名的临时键会不会改动 State:/Network/Global/DNS；它是不是第一解析器。
mkfifo "$work/h3.in"
sudo scutil < "$work/h3.in" > /dev/null 2>&1 &
exec 9> "$work/h3.in"
g0="$(global_dns)"
printf 'd.init\nd.add ServerAddresses * 172.19.0.2\nd.add SupplementalMatchDomains * ""\nd.add SearchOrder # 1\nadd State:/Network/Service/xdial-exp3/DNS temporary\n' >&9
sleep 1
g1="$(global_dns)"
f1="$(first_resolver)"
exec 9>&-
sleep 1.5
report e3-global-dns true "before=[$g0] with_key=[$g1] first=$f1 after=$(first_resolver)"

# E4：final 线路不可达时，系统查询会不会回落到物理网络的 DNS。
sudo "$xdial" daemon install --json > /dev/null 2>&1
cat > "$work/dead.jsonc" << 'EOF'
{ "version": 1,
  "lines": [{ "id": "dead", "type": "trojan", "server": "127.0.0.1", "server_port": 9, "password": { "secret": "dead" } }],
  "scenarios": [{ "id": "dead", "rules": [], "final": "dead" }, { "id": "ok", "rules": [], "final": "direct" }] }
EOF
"$xdial" config apply "$work/dead.jsonc" --json > /dev/null 2>&1
printf 'x\n' | "$xdial" secret set dead --json > /dev/null 2>&1
out="$("$xdial" connect --scenario dead --json 2>&1)"
report e4-connect "$(jq -e .ok <<< "$out" > /dev/null 2>&1 && echo true || echo false)" "$(jq -c '.result.state // .error' <<< "$out" 2> /dev/null)"
gw="$(route -n get default 2> /dev/null | awk '/gateway:/{print $2}')"
sudo tcpdump -i en0 -n -l "udp port 53 or tcp port 53" > "$work/en0.txt" 2> /dev/null &
td=$!
sleep 1
results=""
for i in 1 2 3 4 5 6; do
  name="probe$i-$RANDOM.example.org"
  t0=$(date +%s)
  r="$(dscacheutil -q host -a name "$name" 2> /dev/null | awk '/ip_address/{print $2; exit}')"
  results="$results $name=${r:-none}/$(( $(date +%s) - t0 ))s"
done
apple="$(dscacheutil -q host -a name www.apple.com 2> /dev/null | awk '/ip_address/{print $2; exit}')"
sleep 1
sudo kill $td 2> /dev/null
sleep 0.5
q_en0="$(grep -c 'probe' "$work/en0.txt")"
report e4-fallback true "gw=$gw first=$(first_resolver) results:$results apple=${apple:-none} en0_probe_pkts=$q_en0 sample=$(grep probe "$work/en0.txt" | head -3 | tr '\n' '|' | cut -c1-400)"

# E5：健康场景下 UDP 和 TCP 直接问 172.19.0.2；DDR 和 Firefox canary。
"$xdial" scenario use ok --json > /dev/null 2>&1
sleep 2
udp="$(dig +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1)"
tcp="$(dig +tcp +time=3 +tries=1 @172.19.0.2 www.apple.com A +short 2>&1 | tail -1)"
ddr="$(dig +time=3 +tries=1 @172.19.0.2 _dns.resolver.arpa SVCB 2>&1 | awk '/status:/{print $6}')"
ddr_tcp="$(dig +tcp +time=3 +tries=1 @172.19.0.2 _dns.resolver.arpa SVCB 2>&1 | awk '/status:/{print $6}')"
canary="$(dig +time=3 +tries=1 @172.19.0.2 use-application-dns.net A 2>&1 | awk '/status:/{print $6}')"
route172="$(route -n get 172.19.0.2 | awk '/interface:/{print $2}')"
report e5-tcp-udp true "udp=$udp tcp=$tcp ddr=$ddr ddr_tcp=$ddr_tcp canary=$canary route=$route172 global=$(global_dns)"

# E6：引擎在场景 dead 下拿系统解析器时（local 回退）会不会自环：看引擎日志里的 local 错误。
"$xdial" scenario use dead --json > /dev/null 2>&1
sleep 1
d="$(dscacheutil -q host -a name www.example.com 2> /dev/null | awk '/ip_address/{print $2; exit}')"
report e6-engine-log true "$(sudo tail -n 12 "$data/private/engine.log" 2> /dev/null | sed 's/\x1b\[[0-9;]*m//g' | cut -c1-160 | tr '\n' '|')"

"$xdial" disconnect --json > /dev/null 2>&1
sudo "$xdial" daemon uninstall --purge --json > /dev/null 2>&1
report done true "first=$(first_resolver)"
