import SwiftUI

/// The menu bar App. This is the skeleton the confirmed design (#25) grows
/// from: it registers the daemon and shows and changes the connection, all
/// through the local API.
@main
struct XDialApp: App {
    @StateObject private var daemon = DaemonService()
    @StateObject private var model = PanelModel(api: APIClient(socket: Identity.current.socket))

    var body: some Scene {
        MenuBarExtra {
            Panel(daemon: daemon, model: model)
        } label: {
            Image(systemName: model.connected ? "circle.circle.fill" : "circle.circle")
                .accessibilityLabel(model.connected ? "XDial 已连接" : "XDial 未连接")
        }
        .menuBarExtraStyle(.window)
    }
}

@MainActor
final class PanelModel: ObservableObject {
    @Published private(set) var state = "disconnected"
    @Published private(set) var scenario = ""
    @Published private(set) var lastError = ""
    @Published private(set) var problem: APIError?

    let api: APIClient
    var connected: Bool { state == "connected" }

    init(api: APIClient) { self.api = api }

    func refresh() async {
        await run { try await self.api.call("status") }
    }

    func toggle() async {
        let method = state == "connected" || state == "connecting" ? "disconnect" : "connect"
        await run { try await self.api.call(method) }
    }

    /// Calls the API and takes the status it answers with.
    private func run(_ call: () async throws -> [String: Any]) async {
        do {
            let status = try await call()
            state = status["state"] as? String ?? "disconnected"
            scenario = status["scenario"] as? String ?? ""
            lastError = status["last_error"] as? String ?? ""
            problem = nil
        } catch let error as APIError {
            problem = error
        } catch {
            problem = APIError(code: "internal", message: error.localizedDescription, hint: nil)
        }
    }
}

struct Panel: View {
    @ObservedObject var daemon: DaemonService
    @ObservedObject var model: PanelModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            switch daemon.phase {
            case .enabled:
                connection
            case .commandLineInstalled:
                Text("这台 Mac 上的 daemon 是用命令行装的。要改由 App 管理，先在终端运行：")
                Text("sudo xdial daemon uninstall").font(.system(.body, design: .monospaced)).textSelection(.enabled)
            case .notRegistered:
                Text("XDial 用一个后台服务接管网络，要在系统设置里批准一次。")
                Button("开始") { daemon.register() }.buttonStyle(.borderedProminent)
            case .requiresApproval:
                Text("在 系统设置 › 通用 › 登录项与扩展 里打开 XDial，回到这里会自动继续。")
                Button("打开系统设置") { daemon.openSettings() }
            case let .failed(message):
                Text("后台服务没装好：\(message)").foregroundStyle(.red)
            }
            Divider()
            HStack {
                Spacer()
                Button("退出") { NSApplication.shared.terminate(nil) }
            }
        }
        .padding(16)
        .frame(width: 340)
        .task {
            daemon.refresh()
            await daemon.ensureCurrentBuild(using: model.api)
            await model.refresh()
        }
    }

    private var connection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Circle().fill(model.connected ? Color.green : Color.secondary).frame(width: 10, height: 10)
                    .accessibilityHidden(true)
                Text(model.connected ? "已连接 · \(model.scenario)" : model.state)
                    .font(.headline)
                Spacer()
                Button(model.connected ? "断开" : "连接") { Task { await model.toggle() } }
            }
            if !model.lastError.isEmpty {
                Text(model.lastError).font(.caption).foregroundStyle(.secondary)
            }
            if let problem = model.problem {
                Text(problem.message).font(.caption).foregroundStyle(.red)
            }
        }
    }
}
