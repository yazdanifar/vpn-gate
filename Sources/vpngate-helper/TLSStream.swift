import Foundation
import Network
import VPNGateCore

enum StreamError: Error, LocalizedError {
    case closed, timeout, protocolError(String)
    var errorDescription: String? {
        switch self {
        case .closed: return "Connection closed"
        case .timeout: return "Timed out"
        case .protocolError(let m): return m
        }
    }
}

/// TLS stream over NWConnection that accepts the self-signed certificates VPN Gate relays use.
final class TLSStream: ByteStream {
    private let conn: NWConnection
    var buffer = ByteBuffer()
    var connState: NWConnection.State { conn.state }

    init(host: String, port: UInt16, proxy: ProxySettings) {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        sec_protocol_options_set_verify_block(sec, { _, _, complete in complete(true) }, .global())
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

    func start() async throws { try await start(timeout: 15) }

    func start(timeout: TimeInterval) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            let lock = NSLock()
            var done = false
            @Sendable func finish(_ r: Result<Void, Error>) {
                lock.lock(); defer { lock.unlock() }
                if done { return }
                done = true
                // A failed or timed-out attempt must not keep retrying in the background.
                if case .failure = r { self.conn.cancel() }
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

    func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            conn.send(content: data, completion: .contentProcessed { err in
                if let err = err { c.resume(throwing: err) } else { c.resume() }
            })
        }
    }

    func readChunk() async throws -> Data {
        try await withCheckedThrowingContinuation { c in
            conn.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, isComplete, err in
                if let err = err { c.resume(throwing: err) }
                else if let data = data, !data.isEmpty { c.resume(returning: data) }
                else if isComplete { c.resume(throwing: StreamError.closed) }
                else { c.resume(returning: Data()) }
            }
        }
    }

    func cancel() { conn.cancel() }
}
