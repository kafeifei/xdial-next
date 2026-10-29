// swift-tools-version: 5.10
import PackageDescription

// The menu bar App, ARCHITECTURE.md 6.1 and 6.2: a client of the local API
// that registers the daemon with SMAppService. scripts/build-app.sh puts it
// in a bundle with the xdial binary and the launchd job.
let package = Package(
    name: "XDial",
    platforms: [.macOS(.v14)],
    targets: [
        .executableTarget(name: "XDial", path: "Sources/XDial"),
        .testTarget(name: "XDialTests", dependencies: ["XDial"], path: "Tests/XDialTests"),
    ]
)
