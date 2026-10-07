import Foundation
import VPNGateCore

/// Byte stream under the SoftEther protocol. The real one is TLS over NWConnection; tests use an in-memory fake.
protocol ByteStream: AnyObject {
    var buffer: ByteBuffer { get set }
    func start() async throws
    func send(_ data: Data) async throws
    /// Reads whatever the transport has next (at least 1 byte) or throws.
    func readChunk() async throws -> Data
    func cancel()
}

extension ByteStream {
    func recv(_ n: Int) async throws -> Data {
        while buffer.count < n { buffer.append(try await readChunk()) }
        return Data(buffer.take(n)!)
    }

    func recvU32() async throws -> UInt32 {
        rd32([UInt8](try await recv(4)), 0)
    }

    func recvHTTPHead() async throws -> HTTPHead {
        while true {
            if let head = buffer.take(upTo: HTTPHead.terminator) { return HTTPHead.parse(head) }
            if buffer.count > HTTPHead.maxSize { throw StreamError.protocolError("HTTP header too large") }
            buffer.append(try await readChunk())
        }
    }
}

typealias StreamFactory = (_ host: String, _ port: UInt16, _ proxy: ProxySettings) -> ByteStream

/// An established-or-establishing link to a VPN Gate relay, as seen by the session.
protocol VPNTransport: AnyObject {
    var onFrame: (([UInt8]) -> Void)? { get set }
    var onClose: ((Error?) -> Void)? { get set }
    var bytesIn: UInt64 { get }
    var bytesOut: UInt64 { get }
    func connect(log: (String) -> Void) async throws -> Welcome
    func sendFrame(_ frame: [UInt8])
    func close(_ error: Error?)
}

extension VPNTransport {
    func close() { close(nil) }
}

protocol TunDevice: AnyObject {
    var name: String { get }
    var onPacket: (([UInt8]) -> Void)? { get set }
    func startReading()
    func write(ipv4 packet: [UInt8])
    func close()
}

protocol CommandRunner {
    @discardableResult
    func run(_ path: String, _ args: [String]) -> (status: Int32, out: String)
}

protocol DNSConfigurator {
    /// Makes the tunnel the primary DNS resolver while connected.
    func set(servers: [String], iface: String, address: String, router: String) -> Bool
    func remove()
}

protocol NetConfiguring: AnyObject {
    func apply(iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool) throws
    func teardown()
}

/// What the IPC layer needs from a session.
protocol SessionControlling: AnyObject {
    var emit: ((HelperEvent) -> Void)? { get set }
    var snapshot: HelperEvent { get }
    func connect(host: String, port: Int?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool)
    func disconnect()
}
