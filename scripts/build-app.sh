#!/usr/bin/env bash
# 组装菜单栏 App（ARCHITECTURE.md 6.1）：App 本体、xdial 和 SMAppService 用的 launchd 配置放进一个包，再签名。
# 用法：scripts/build-app.sh [debug|release]
# 签名身份取 XDIAL_SIGN_IDENTITY；不给就用临时签名（"-"），这样的包 SMAppService 注册不了，只能看结构。
# 只在测试虚拟机里装：App 注册 daemon 后会接管这台机器的网络。
set -euo pipefail

channel="${1:-debug}"
case "$channel" in
  debug) id=com.kafeifei.xdial.debug name="XDial Debug" ;;
  release) id=com.kafeifei.xdial name="XDial" ;;
  *) echo "用法：$0 [debug|release]" >&2; exit 2 ;;
esac
root="$(cd "$(dirname "$0")/.." && pwd)"
# 没给版本时带上提交，App 才分得出两个开发构建（6.1）；Go 在 git worktree 里不一定记下提交。
version="${XDIAL_VERSION:-dev-$(git -C "$root" rev-parse --short HEAD)$(git -C "$root" diff --quiet HEAD -- || echo -dirty)}"
sign="${XDIAL_SIGN_IDENTITY:--}"
out="$root/build/app"
app="$out/$name.app"

tags="$(grep -v '^#' "$root/.github/build-tags.txt" | tr '\n' ',')"
mkdir -p "$out"
(cd "$root" && GOWORK=off go build -tags "$tags" \
  -ldflags "-X github.com/kafeifei/xdial-next/internal/buildinfo.Identity=$id -X github.com/kafeifei/xdial-next/internal/buildinfo.Version=$version" \
  -o "$out/xdial-$channel" ./cmd/xdial)
(cd "$root/macos" && swift build -c release --product XDial > /dev/null)
bin="$(cd "$root/macos" && swift build -c release --show-bin-path)"

# 包里 daemon 的构建：App 拿它和运行中的 daemon 比，不一样就让 daemon 重启（6.1）。
# 只运行刚编出来的 xdial 的 version，不碰网络和 daemon。
build="$("$out/xdial-$channel" version --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"]["build"])')"

rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Library/LaunchDaemons"
cp "$bin/XDial" "$app/Contents/MacOS/XDial"
cp "$out/xdial-$channel" "$app/Contents/MacOS/xdial"

cat > "$app/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleIdentifier</key>
	<string>$id</string>
	<key>CFBundleName</key>
	<string>$name</string>
	<key>CFBundleExecutable</key>
	<string>XDial</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>${version#v}</string>
	<key>CFBundleVersion</key>
	<string>${version#v}</string>
	<key>LSMinimumSystemVersion</key>
	<string>14.0</string>
	<key>LSUIElement</key>
	<true/>
	<key>XDialDaemonBuild</key>
	<string>$build</string>
</dict>
</plist>
EOF

# 和命令行安装写的 launchd 配置一样（cmd/xdial/daemon.go 的 plistTemplate），只是程序在包里，
# 不写日志路径：daemon 自己把输出接到日志（6.5）。
cat > "$app/Contents/Library/LaunchDaemons/$id.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>$id</string>
	<key>BundleProgram</key>
	<string>Contents/MacOS/xdial</string>
	<key>ProgramArguments</key>
	<array>
		<string>xdial</string>
		<string>daemon</string>
		<string>run</string>
	</array>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>$id</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>AbandonProcessGroup</key>
	<false/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>ExitTimeOut</key>
	<integer>20</integer>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
EOF

codesign -f -s "$sign" --options runtime -i "$id.daemon" "$app/Contents/MacOS/xdial"
codesign -f -s "$sign" --options runtime "$app"
codesign --verify --strict --deep "$app"
echo "$app（daemon 构建 $build，签名 $sign）"
