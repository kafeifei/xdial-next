import Darwin
import Foundation

/// An error the daemon answered with, or one reaching it: the code is the
/// same set the CLI prints, ARCHITECTURE.md 5.
struct APIError: Error, Equatable {
    let code: String
    let message: String
    let hint: String?

    static func unreachable(_ why: String) -> APIError {
        APIError(code: "daemon.unreachable", message: "连不上 daemon：\(why)", hint: nil)
    }
}

/// Calls the daemon's local API, ARCHITECTURE.md 6.2: one JSON line out and
/// one back over the daemon's socket, once the one listening is known to be
/// root. The App never reads the daemon's files.
struct APIClient {
    let socket: String
    /// Who must be listening: root, except in tests.
    var server: uid_t = 0

    static let maxResponse = 64 << 20

    func call(_ method: String, _ params: [String: Any] = [:]) async throws -> [String: Any] {
        let client = self
        return try await Task.detached { try client.callBlocking(method, params) }.value
    }

    func callBlocking(_ method: String, _ params: [String: Any]) throws -> [String: Any] {
        let fd = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw APIError.unreachable(String(cString: strerror(errno))) }
        defer { close(fd) }
        // A daemon that went away fails the write instead of killing the App.
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(socket.utf8CString)
        guard path.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw APIError.unreachable("socket 路径太长") }
        withUnsafeMutableBytes(of: &address.sun_path) { target in
            path.withUnsafeBytes { target.copyMemory(from: $0) }
        }
        let connected = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else { throw APIError.unreachable(String(cString: strerror(errno))) }
        // A socket someone else put at that path would see the requests.
        var credentials = xucred()
        var length = socklen_t(MemoryLayout<xucred>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, &credentials, &length) == 0, credentials.cr_uid == server else {
            throw APIError.unreachable("监听的不是 daemon")
        }
        var request: [String: Any] = ["v": 1, "id": 1, "method": method]
        if !params.isEmpty { request["params"] = params }
        var line = try JSONSerialization.data(withJSONObject: request)
        line.append(0x0a)
        try line.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let written = write(fd, bytes.baseAddress! + offset, bytes.count - offset)
                guard written > 0 else { throw APIError.unreachable("写不进去") }
                offset += written
            }
        }
        var response = Data()
        var buffer = [UInt8](repeating: 0, count: 64 << 10)
        while response.firstIndex(of: 0x0a) == nil {
            let count = read(fd, &buffer, buffer.count)
            guard count > 0 else { throw APIError.unreachable("连接断了") }
            response.append(buffer, count: count)
            guard response.count <= Self.maxResponse else {
                throw APIError(code: "internal", message: "回复超过 \(Self.maxResponse) 字节", hint: nil)
            }
        }
        let first = response.prefix(upTo: response.firstIndex(of: 0x0a)!)
        guard let reply = try JSONSerialization.jsonObject(with: first) as? [String: Any] else {
            throw APIError(code: "internal", message: "回复不是 JSON 对象", hint: nil)
        }
        if reply["ok"] as? Bool == true {
            return reply["result"] as? [String: Any] ?? [:]
        }
        let error = reply["error"] as? [String: Any] ?? [:]
        throw APIError(code: error["code"] as? String ?? "internal",
                       message: error["message"] as? String ?? "",
                       hint: error["hint"] as? String)
    }
}
