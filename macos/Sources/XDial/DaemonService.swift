import Foundation
import ServiceManagement

/// Registers the daemon with SMAppService and keeps it on the build this
/// App carries, ARCHITECTURE.md 6.1.
@MainActor
final class DaemonService: ObservableObject {
    enum Phase: Equatable {
        /// `sudo xdial daemon install` put its own job there: same label.
        case commandLineInstalled
        case notRegistered
        case requiresApproval
        case enabled
        case failed(String)
    }

    @Published private(set) var phase: Phase = .notRegistered

    let identity: Identity
    private let service: SMAppService

    init(identity: Identity = .current) {
        self.identity = identity
        service = SMAppService.daemon(plistName: identity.plistName)
        refresh()
    }

    func refresh() {
        if FileManager.default.fileExists(atPath: identity.commandLinePlist) {
            phase = .commandLineInstalled
            return
        }
        switch service.status {
        case .enabled: phase = .enabled
        case .requiresApproval: phase = .requiresApproval
        case .notRegistered: phase = .notRegistered
        case .notFound: phase = .failed("App 包里没有 daemon 的 launchd 配置")
        @unknown default: phase = .failed("系统给了不认识的状态")
        }
    }

    /// Registers the daemon; macOS then asks for approval in System Settings.
    func register() {
        refresh()
        guard phase == .notRegistered || phase == .requiresApproval else { return }
        do {
            try service.register()
        } catch {
            // Registering before approval reports that approval is needed.
            refresh()
            if phase != .requiresApproval {
                phase = .failed(error.localizedDescription)
                return
            }
        }
        refresh()
        if phase == .requiresApproval {
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    func openSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    /// After an update the daemon running is still the old binary: it is
    /// asked to restart, and launchd starts the one in this bundle.
    func ensureCurrentBuild(using api: APIClient) async {
        guard phase == .enabled, let bundled = identity.bundledBuild,
              let running = try? await api.call("version")["build"] as? String,
              running != bundled else { return }
        _ = try? await api.call("daemon.restart")
    }
}
