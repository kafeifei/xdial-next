import Darwin
import Foundation
import XCTest
@testable import XDial

/// A one-shot server on a Unix socket that answers each line with reply.
private final class LineServer {
    let path: String
    private let fd: Int32
    private(set) var received = ""

    init(reply: String) throws {
        path = NSTemporaryDirectory() + "xd-\(UUID().uuidString.prefix(8)).sock"
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        withUnsafeMutableBytes(of: &address.sun_path) { target in bytes.withUnsafeBytes { target.copyMemory(from: $0) } }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        XCTAssertEqual(bound, 0)
        listen(fd, 1)
        let listener = fd
        Thread.detachNewThread { [weak self] in
            let conn = accept(listener, nil, nil)
            var on: Int32 = 1
            setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
            var buffer = [UInt8](repeating: 0, count: 4096)
            let count = read(conn, &buffer, buffer.count)
            self?.received = String(decoding: buffer.prefix(max(count, 0)), as: UTF8.self)
            let line = Array((reply + "\n").utf8)
            _ = line.withUnsafeBytes { write(conn, $0.baseAddress, $0.count) }
            close(conn)
        }
    }

    deinit {
        close(fd)
        unlink(path)
    }
}

final class APIClientTests: XCTestCase {
    func testAnswerIsTheResult() throws {
        let server = try LineServer(reply: #"{"id":1,"schema":"xdial.status/v1","ok":true,"result":{"state":"connected"}}"#)
        let client = APIClient(socket: server.path, server: getuid())
        let result = try client.callBlocking("status", [:])
        XCTAssertEqual(result["state"] as? String, "connected")
        XCTAssertTrue(server.received.contains(#""method":"status""#))
    }

    func testErrorCarriesTheCode() throws {
        let server = try LineServer(reply: #"{"id":1,"schema":"xdial.error/v1","ok":false,"error":{"code":"config.conflict","message":"不存在","hint":"看看"}}"#)
        let client = APIClient(socket: server.path, server: getuid())
        XCTAssertThrowsError(try client.callBlocking("scenario.use", ["id": "x"])) { error in
            XCTAssertEqual(error as? APIError, APIError(code: "config.conflict", message: "不存在", hint: "看看"))
        }
    }

    func testOnlyTheExpectedOwnerIsTalkedTo() throws {
        let server = try LineServer(reply: #"{"ok":true}"#)
        // In a test the listener is this user, not root.
        let client = APIClient(socket: server.path)
        XCTAssertThrowsError(try client.callBlocking("status", [:])) { error in
            XCTAssertEqual((error as? APIError)?.code, "daemon.unreachable")
        }
    }
}
