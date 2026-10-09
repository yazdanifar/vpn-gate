import Foundation
import Network
import Security

public enum StreamError: Error, LocalizedError {
    case closed, timeout, protocolError(String)
    public var errorDescription: String? {
        switch self {
        case .closed: return "Connection closed"
        case .timeout: return "Timed out"
        case .protocolError(let m): return m
        }
    }
}

/// Byte stream under the SoftEther protocol.
public protocol ByteStream: AnyObject {
    var buffer: ByteBuffer { get set }
    func start() async throws
    func send(_ data: Data) async throws
    /// Reads whatever the transport has next (at least 1 byte) or throws.
    func readChunk() async throws -> Data
    func cancel()
    /// IPv4 address the connection really went to (after `start()`), when the transport can tell; nil otherwise.
    var remoteIPv4: String? { get }
}

public extension ByteStream {
    var remoteIPv4: String? { nil }

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

public typealias StreamFactory = (_ host: String, _ port: UInt16, _ proxy: ProxySettings) -> ByteStream

/// Remembers why the verify block refused the server, so `start()` can report it instead of a bare TLS error.
final class TLSVerifyFailure {
    private let lock = NSLock()
    private var _reason: String?
    var reason: String? { lock.lock(); defer { lock.unlock() }; return _reason }
    func set(_ r: String) { lock.lock(); _reason = r; lock.unlock() }
}

/// TLS stream over NWConnection. By default it accepts the self-signed certificates VPN Gate relays use;
/// `policy` can pin the leaf certificate's SHA-1/SHA-256 fingerprint or require system trust.
public final class TLSStream: ByteStream {
    private let conn: NWConnection
    private let verifyFailure = TLSVerifyFailure()
    public var buffer = ByteBuffer()
    public var connState: NWConnection.State { conn.state }

    public init(host: String, port: UInt16, proxy: ProxySettings, policy: ServerCertPolicy = .acceptAny) {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        let failure = verifyFailure
        sec_protocol_options_set_verify_block(sec, { metadata, trust, complete in
            var leaf: Data?
            sec_protocol_metadata_access_peer_certificate_chain(metadata) { cert in
                if leaf == nil { leaf = SecCertificateCopyData(sec_certificate_copy_ref(cert).takeRetainedValue()) as Data }
            }
            if let why = policy.rejection(leafDER: leaf) { failure.set(why); complete(false); return }
            if policy == .systemTrust {
                var err: CFError?
                if !SecTrustEvaluateWithError(sec_trust_copy_ref(trust).takeRetainedValue(), &err) {
                    failure.set("Server certificate is not trusted: \(err.map { CFErrorCopyDescription($0) as String } ?? "unknown reason")")
                    complete(false); return
                }
            }
            complete(true)
        }, .global())
        sec_protocol_options_set_min_tls_protocol_version(sec, .TLSv12)
        if host.contains(where: { $0.isLetter && $0 != "." }) && IPv4Address(host) == nil {
            sec_protocol_options_set_tls_server_name(sec, host)
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        tcp.enableKeepalive = true
        let params = NWParameters(tls: tls, tcp: tcp)

        if proxy.kind != .none, !proxy.host.isEmpty, let p = NWEndpoint.Port(rawValue: UInt16(clamping: proxy.port)) {
            let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(proxy.host), port: p)
            let cfg = proxy.kind == .http
                ? ProxyConfiguration(httpCONNECTProxy: ep)
                : ProxyConfiguration(socksv5Proxy: ep)
            if let u = proxy.username, let pw = proxy.password, !u.isEmpty { cfg.applyCredential(username: u, password: pw) }
            params.preferNoProxies = false
            let ctx = NWParameters.PrivacyContext(description: "vpngate-proxy")
            ctx.proxyConfigurations = [cfg]
            params.setPrivacyContext(ctx)
        }
        conn = NWConnection(host: NWEndpoint.Host(host),
                            port: NWEndpoint.Port(rawValue: port) ?? 443, using: params)
    }

    public func start() async throws { try await start(timeout: 15) }

    public func start(timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            let once = OnceFlag()
            @Sendable func finish(_ r: Result<Void, Error>) {
                guard once.claim() else { return }
                // A failed or timed-out attempt must not keep retrying in the background.
                if case .failure = r { self.conn.cancel() }
                if case .failure = r, let why = self.verifyFailure.reason { c.resume(throwing: StreamError.protocolError(why)); return }
                c.resume(with: r)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready: finish(.success(()))
                case .failed(let e): finish(.failure(e))
                case .waiting(let e): finish(.failure(e))   // no route / refused: fail fast
                case .cancelled: finish(.failure(StreamError.closed))
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                finish(.failure(StreamError.timeout))
            }
        }
    }

    public func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err = err { c.resume(throwing: err) } else { c.resume() }
            })
        }
    }

    public func readChunk() async throws -> Data {
        try await withCheckedThrowingContinuation { c in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, err in
                if let err = err { c.resume(throwing: err) }
                else if let data = data, !data.isEmpty { c.resume(returning: data) }
                else if isComplete { c.resume(throwing: StreamError.closed) }
                else { c.resume(returning: Data()) }
            }
        }
    }

    /// The peer of the ready connection: the address the hostname resolved to, or the proxy's address behind a proxy.
    public var remoteIPv4: String? {
        guard case .hostPort(let host, _)? = conn.currentPath?.remoteEndpoint, case .ipv4(let a) = host else { return nil }
        return a.rawValue.map(String.init).joined(separator: ".")
    }

    public func cancel() { conn.cancel() }
}

/// Thread-safe "first caller wins" flag, shared by the state handler and the timeout of a connection attempt.
private final class OnceFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false
    /// True exactly once, for the first caller.
    func claim() -> Bool { lock.withLock { if claimed { return false }; claimed = true; return true } }
}
