#!/usr/bin/env bash
# 在 mbp64k 的测试虚拟机里跑 e2e：从 xdial-base 克隆一台一次性虚拟机，
# 把 darwin/arm64 构建和 e2e/ 用例经只读共享目录交给它，跑完删除。
# 用法和约束见 docs/agent/e2e.md。结果写到 build/e2e/<run>/results.jsonl，原始输出在 output.log。

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
export GOWORK=off

host="${XDIAL_E2E_HOST:-kafeifei_bot@192.168.1.3}"
base_vm="${XDIAL_E2E_BASE_VM:-xdial-base}"
run_id="$(date -u +%Y%m%d-%H%M%S)-$$"
vm="xdial-e2e-$run_id"
out_dir="build/e2e/$run_id"
remote_dir="xdial-e2e/$run_id"
ssh_opts=(-o BatchMode=yes -o ConnectTimeout=10)

mkdir -p "$out_dir/share"
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$out_dir/share/xdial" ./cmd/xdial
# 只给 e2e 用的 sing-box 服务端，代理线路和订阅连它，不进产品。
GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -o "$out_dir/share/testserver" ./e2e/testserver
# Go 不给 git worktree 里构建的二进制写 VCS 信息，这里自己记下构建时的提交，结果才对得上代码。
commit="$(git rev-parse HEAD)$(git diff --quiet HEAD -- || echo -dirty)"
echo "$commit" > "$out_dir/commit"
# 默认跑 e2e/run.sh；XDIAL_E2E_CASES 可以换成别的用例文件，例如 e2e/experiments/ 下的实验。
cp "${XDIAL_E2E_CASES:-e2e/run.sh}" "$out_dir/share/run.sh"

# 远端脚本自己负责清理和释放锁；这里只再兜一次底，删掉虚拟机和文件，不碰锁。
cleanup() {
  ssh "${ssh_opts[@]}" "$host" bash -s -- "$vm" "$remote_dir" > /dev/null 2>&1 << 'EOF' || true
L=~/.local/bin/lume
"$L" stop "$1" --force
"$L" delete "$1" --force
rm -rf ~/"$2"
true
EOF
}
trap cleanup EXIT

ssh "${ssh_opts[@]}" "$host" "mkdir -p ~/$remote_dir"
scp -q "${ssh_opts[@]}" "$out_dir"/share/* "$host:$remote_dir/"
# Tailscale 的用例要一个可复用、ephemeral、带 tag:xdial-e2e 的 auth key，用户放在本机钥匙串的
# xdial-e2e-tailscale-authkey 里。它只经临时文件传过去，不留在 build/ 下；远端目录随虚拟机一起删掉。
if key="$(security find-generic-password -s xdial-e2e-tailscale-authkey -w 2> /dev/null)" && [[ -n "$key" ]]; then
  key_file="$(mktemp)"
  printf '%s' "$key" > "$key_file"
  scp -q "${ssh_opts[@]}" "$key_file" "$host:$remote_dir/ts-authkey"
  rm -f "$key_file"
fi
unset key

echo "e2e: $vm（基于 $base_vm）" >&2
status=0
ssh "${ssh_opts[@]}" "$host" bash -s -- "$vm" "$base_vm" "$remote_dir" > "$out_dir/output.log" 2>&1 << 'EOF' || status=$?
set -euo pipefail
vm=$1 base=$2 dir=$3
L=~/.local/bin/lume
lock=~/xdial-e2e/.lock
mutex=~/xdial-e2e/.lock-mutex

# 一台 Mac 最多同时跑两台 macOS 虚拟机，vm4 已占一台，所以 e2e 一次只跑一个。
# 拿锁、接管过期锁、释放锁都在 .lock-mutex 这把互斥锁里进行，免得两个运行互相删掉对方的锁。
# 一次运行最长约 20 分钟，超过 25 分钟的锁算作异常退出留下的：先删掉锁里记的那台虚拟机，再接管。
age() { echo $(( $(date +%s) - $(stat -f %m "$1" 2> /dev/null || date +%s) )); }
with_mutex() {
  local status
  for _ in $(seq 1 60); do
    if mkdir "$mutex" 2> /dev/null; then
      status=0
      "$@" || status=$?
      rm -rf "$mutex"
      return "$status"
    fi
    if (( $(age "$mutex") > 300 )); then
      rm -rf "$mutex"
    fi
    sleep 1
  done
  return 1
}
try_acquire() {
  if [ -d "$lock" ]; then
    if (( $(age "$lock") <= 1500 )); then
      return 1
    fi
    stale="$(cat "$lock/owner" 2> /dev/null || true)"
    if [ -n "$stale" ]; then
      "$L" stop "$stale" --force > /dev/null 2>&1 || true
      "$L" delete "$stale" --force > /dev/null 2>&1 || true
    fi
    rm -rf "$lock"
  fi
  mkdir "$lock" && echo "$vm" > "$lock/owner"
}
release() {
  if [ "$(cat "$lock/owner" 2> /dev/null)" = "$vm" ]; then
    rm -rf "$lock"
  fi
}

# 发起端断线或被杀时，这里写输出会失败而退出，收到 HUP、INT、TERM 也会退出；无论怎么退出都删掉这台虚拟机并释放锁。
cleanup() {
  "$L" stop "$vm" --force > /dev/null 2>&1 || true
  "$L" delete "$vm" --force > /dev/null 2>&1 || true
  rm -rf ~/"$dir"
  with_mutex release || true
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

acquired=false
for _ in $(seq 1 180); do
  if with_mutex try_acquire; then
    acquired=true
    break
  fi
  sleep 10
done
if [ "$acquired" != true ]; then
  echo "等不到 e2e 锁" >&2
  exit 1
fi

"$L" clone "$base" "$vm" > /dev/null
"$L" run "$vm" --detach --no-display --vnc disabled --shared-dir "$HOME/$dir:ro" > /dev/null
for _ in $(seq 1 36); do
  "$L" ssh "$vm" --timeout 10 true > /dev/null 2>&1 && break
  sleep 5
done
# 共享目录挂在 /Volumes/My Shared Files 下，每个共享一个子目录，开机后稍晚才出现。
"$L" ssh "$vm" --timeout 900 'for _ in $(seq 1 30); do
  f="$(find "/Volumes/My Shared Files" -maxdepth 2 -name run.sh 2> /dev/null | head -1)"
  [ -n "$f" ] && exec bash "$f"
  sleep 2
done
echo "虚拟机里找不到共享的 e2e 用例" >&2
exit 1'
EOF

# lume ssh 会把虚拟机里的 stderr 并进 stdout，这里只留用例输出的 JSON 行。
jq -R -c 'fromjson? | select(type == "object" and has("case"))' "$out_dir/output.log" > "$out_dir/results.jsonl"
cat "$out_dir/results.jsonl"
passed="$(jq -s '[.[] | select(.ok)] | length' "$out_dir/results.jsonl")"
total="$(jq -s 'length' "$out_dir/results.jsonl")"
echo "e2e: $passed/$total 通过（提交 $commit），结果在 $out_dir/results.jsonl，原始输出在 $out_dir/output.log" >&2
if (( status == 0 && (total == 0 || passed != total) )); then
  status=1
fi
exit "$status"
