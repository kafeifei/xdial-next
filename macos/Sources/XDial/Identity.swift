import Foundation

/// Which daemon this App belongs to: the release identity or Debug, by the
/// App's bundle identifier, ARCHITECTURE.md 6.1. The two never share a
/// socket, a configuration or a launchd job.
struct Identity {
    let id: String

    static let release = "com.kafeifei.xdial"
    static let debug = "com.kafeifei.xdial.debug"

    static var current: Identity {
        let bundle = Bundle.main.bundleIdentifier ?? debug
        return Identity(id: bundle == release ? release : debug)
    }

    var socket: String { "/var/run/\(id)/api.sock" }
    /// The launchd job in the App's bundle, Contents/Library/LaunchDaemons.
    var plistName: String { "\(id).plist" }
    /// Where `sudo xdial daemon install` puts its job; the two cannot both be.
    var commandLinePlist: String { "/Library/LaunchDaemons/\(id).plist" }
    /// The build of the xdial binary in this bundle, written by the build.
    var bundledBuild: String? { Bundle.main.object(forInfoDictionaryKey: "XDialDaemonBuild") as? String }
}
