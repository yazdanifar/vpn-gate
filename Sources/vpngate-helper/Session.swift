import Foundation
import VPNGateCore

struct SessionDependencies {
    var makeTransport: (_ host: String, _ port: UInt16, _ proxy: ProxySettings) -> VPNTransport = {
        SoftEtherClient(host: $0, port: $1, proxy: $2)
    }
    var makeTun: () throws -> TunDevice = { try Utun() }
    var makeNet: () -> NetConfiguring = { NetConfig() }
}

struct SessionTiming {
    var reconnectDelay: Double = 3
    var maxAttempts = 8
    var minRenewSeconds: Double = 60
    var bridge = BridgeTiming()
}

/// One-shot async signal: `wait()` returns once `fire()` has been called (from any thread, any number of times).
final class AsyncSignal {
    private let lock = NSLock()
    private var fired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func fire() {
        lock.lock(); fired = true; let w = waiters; waiters = []; lock.unlock()
        w.forEach { $0.resume() }
    }

    func wait() async {
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in
            lock.lock()
            if fired { lock.unlock(); c.resume() } else { waiters.append(c); lock.unlock() }
        }
    }
}

/// Everything one connection attempt owns. Released exactly once by `VPNSession.release`.
private final class Resources {
    let gen: Int
    let linkDown = AsyncSignal()
    var client: VPNTransport?
    var tun: TunDevice?
    var net: NetConfiguring?
    /// Strongly owned here: the tun/transport callbacks only hold it weakly.
    var bridge: EthernetBridge?
    var timer: DispatchSourceTimer?
    var renew: Task<Void, Never>?
    init(gen: Int) { self.gen = gen }
}

/// Owns one VPN connection: SoftEther session + bridge + utun + routes, with optional auto-reconnect.
///
/// Every `connect()`/`disconnect()` bumps a generation number. Work started for an older generation
/// never publishes state and never keeps resources: after each `await` it checks `isCurrent(gen)`.
final class VPNSession: SessionControlling {
    private let deps: SessionDependencies
    private let timing: SessionTiming
    private let lock = NSLock()
    private var generation = 0
    private var activeRuns = 0
    private var runTask: Task<Void, Never>?
    private var current = HelperEvent(state: .disconnected)
    private var res: Resources?

    var emit: ((HelperEvent) -> Void)?

    init(deps: SessionDependencies = SessionDependencies(), timing: SessionTiming = SessionTiming()) {
        self.deps = deps; self.timing = timing
        current.helperVersion = helperVersion          // present in every snapshot, even before the first event
    }

    var snapshot: HelperEvent { lock.lock(); defer { lock.unlock() }; return current }

    /// True once every connect() task has run to completion (used by tests and shutdown).
    func waitUntilIdle(timeout: Double) async -> Bool {
        let end = Date().addingTimeInterval(timeout)
        while Date() < end {
            lock.lock(); let n = activeRuns; lock.unlock()
            if n == 0 { return true }
            try? await Task.sleep(nanoseconds: 20_000_000)
        }
        return false
    }

    private func isCurrent(_ gen: Int) -> Bool { lock.lock(); defer { lock.unlock() }; return generation == gen }

    /// Publishes a state change; ignored if `gen` has been superseded.
    private func set(_ gen: Int, _ state: ConnectionState, server: String? = nil, ip: String? = nil,
                     log: String? = nil, error: String? = nil) {
        lock.lock()
        guard generation == gen else { lock.unlock(); return }
        publishLocked(state, server: server, ip: ip, log: log, error: error)
    }

    /// Caller holds `lock`; releases it before emitting.
    private func publishLocked(_ state: ConnectionState, server: String?, ip: String?, log: String?, error: String?) {
        current.state = state
        if state == .disconnected { current.server = nil; current.virtualIP = nil }
        if let s = server { current.server = s }
        if let i = ip { current.virtualIP = i }
        current.log = log
        current.error = error
        current.helperVersion = helperVersion
        let e = current
        lock.unlock()
        emit?(e)
    }

    // MARK: control

    func connect(host: String, port: Int?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool) {
        connect(host: host, port: port, ports: nil, proxy: proxy, autoReconnect: autoReconnect, blockIPv6: blockIPv6)
    }

    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool) {
        lock.lock()
        generation += 1
        let gen = generation
        let old = res; res = nil
        let oldTask = runTask
        activeRuns += 1
        lock.unlock()
        oldTask?.cancel()
        if let old = old { release(old) }
        runTask = Task.detached { [weak self] in
            await self?.run(gen, host: host, preferredPort: port, preferredPorts: ports, proxy: proxy,
                            autoReconnect: autoReconnect, blockIPv6: blockIPv6)
            if let self = self { self.lock.lock(); self.activeRuns -= 1; self.lock.unlock() }
        }
    }

    func disconnect() {
        lock.lock()
        generation += 1
        let old = res; res = nil
        let task = runTask; runTask = nil
        lock.unlock()
        task?.cancel()
        if let old = old { release(old) }
        lock.lock()
        publishLocked(.disconnected, server: nil, ip: nil, log: nil, error: nil)
    }

    // MARK: run loop

    private func run(_ gen: Int, host: String, preferredPort: Int?, preferredPorts: [Int]?, proxy: ProxySettings,
                     autoReconnect: Bool, blockIPv6: Bool) async {
        var attempt = 0
        while isCurrent(gen) && !Task.isCancelled {
            set(gen, attempt == 0 ? .connecting : .reconnecting, server: host)
            let r = Resources(gen: gen)
            lock.lock()
            guard generation == gen else { lock.unlock(); return }
            res = r
            lock.unlock()

            var failure: Error?
            do {
                try await establish(r, host: host, preferredPort: preferredPort, preferredPorts: preferredPorts, proxy: proxy,
                                    autoReconnect: autoReconnect, blockIPv6: blockIPv6)
                attempt = 0
                await r.linkDown.wait()
            } catch { failure = error }

            // Release only if nobody else already did (disconnect/connect hand resources over themselves).
            lock.lock()
            if res === r { res = nil }
            lock.unlock()
            release(r)
            if !isCurrent(gen) || Task.isCancelled { return }

            if let failure = failure, !(failure is CancellationError) {
                if !autoReconnect { set(gen, .disconnected, error: failure.localizedDescription); return }
            } else if !autoReconnect {
                set(gen, .disconnected, error: "Connection lost"); return
            }
            guard attempt < timing.maxAttempts else {
                set(gen, .disconnected, error: "Gave up reconnecting"); return
            }
            attempt += 1
            set(gen, .reconnecting, server: host, log: "Reconnecting in \(Int(timing.reconnectDelay.rounded(.up)))s (attempt \(attempt))",
                error: failure?.localizedDescription)
            try? await Task.sleep(nanoseconds: UInt64(timing.reconnectDelay * 1_000_000_000))
        }
    }

    /// Runs `body` on `r` only if its generation is still current.
    private func withResources(_ r: Resources, _ body: (Resources) -> Void) -> Bool {
        lock.lock(); defer { lock.unlock() }
        guard generation == r.gen else { return false }
        body(r)
        return true
    }

    private func establish(_ r: Resources, host: String, preferredPort: Int?, preferredPorts: [Int]?, proxy: ProxySettings,
                           autoReconnect: Bool, blockIPv6: Bool) async throws {
        let gen = r.gen
        var ports = [Int]()
        if let preferredPorts = preferredPorts {
            for p in preferredPorts where InputValidation.isValidPort(p) && !ports.contains(p) {
                ports.append(p)
            }
        }
        for p in [preferredPort ?? 0, 443, 992, 5555, 1194] where InputValidation.isValidPort(p) && !ports.contains(p) {
            ports.append(p)
        }

        var client: VPNTransport?
        var lastError: Error = StreamError.closed
        for port in ports {
            try Task.checkCancellation()
            guard isCurrent(gen) else { throw CancellationError() }
            let c = deps.makeTransport(host, UInt16(port), proxy)
            // Registered before connecting so that a disconnect() during the handshake can reach it.
            guard withResources(r, { $0.client = c }) else { c.close(); throw CancellationError() }
            do {
                set(gen, .authenticating, server: host, log: "Connecting to \(host):\(port)")
                _ = try await c.connect { [weak self] m in self?.set(gen, .authenticating, log: m) }
                guard isCurrent(gen) else { throw CancellationError() }
                client = c; break
            } catch {
                c.close(); lastError = error
                _ = withResources(r) { if $0.client === c { $0.client = nil } }
                if error is CancellationError || !isCurrent(gen) { throw CancellationError() }
                set(gen, .connecting, log: "Port \(port) failed: \(error.localizedDescription)")
            }
        }
        guard let client = client else { throw lastError }

        let tun = try deps.makeTun()
        guard withResources(r, { $0.tun = tun }) else { tun.close(); throw CancellationError() }
        let bridge = EthernetBridge(timing: timing.bridge)
        guard withResources(r, { $0.bridge = bridge }) else { throw CancellationError() }
        bridge.sendFrame = { [weak client] in client?.sendFrame($0) }
        bridge.deliverIPv4 = { [weak tun] in tun?.write(ipv4: $0) }
        bridge.onLeaseChanged = { [weak client] _ in client?.close(StreamError.protocolError("DHCP address changed")) }
        bridge.onLeaseLost = { [weak client] in client?.close(StreamError.protocolError("DHCP lease lost")) }
        client.onFrame = { [weak bridge] in bridge?.fromHub($0) }
        tun.onPacket = { [weak bridge] in bridge?.fromHost($0) }
        client.onClose = { [weak self] err in
            if let err = err, autoReconnect, self?.isCurrent(gen) == true {
                self?.set(gen, .reconnecting, log: "Link closed: \(err.localizedDescription)")
            }
            r.linkDown.fire()
        }

        set(gen, .dhcp, log: "Requesting address on \(tun.name)")
        let lease = try await bridge.acquireLease()
        guard isCurrent(gen) else { throw CancellationError() }
        bridge.gratuitousARP()
        let net = deps.makeNet()
        guard withResources(r, { $0.net = net }) else { throw CancellationError() }
        try net.apply(iface: tun.name, lease: lease,
                      bypassHost: proxy.kind == .none ? host : proxy.host, blockIPv6: blockIPv6)
        tun.startReading()

        set(gen, .connected, ip: ipString(lease.ip), log: "Connected via \(tun.name), gateway \(ipString(lease.router))")
        let timer = makeCounterTimer(r, client)
        let wait = max(Double(lease.seconds) / 2, timing.minRenewSeconds)
        let renew = Task.detached { [weak bridge] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
                if Task.isCancelled { return }
                await bridge?.renew()
            }
        }
        if !withResources(r, { $0.timer = timer; $0.renew = renew }) { timer.cancel(); renew.cancel(); throw CancellationError() }
    }

    private func makeCounterTimer(_ r: Resources, _ c: VPNTransport) -> DispatchSourceTimer {
        let gen = r.gen
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self, weak c] in
            guard let self = self, let c = c else { return }
            self.lock.lock()
            guard self.generation == gen else { self.lock.unlock(); return }
            self.current.bytesIn = c.bytesIn; self.current.bytesOut = c.bytesOut
            self.current.log = nil; self.current.error = nil
            let e = self.current
            self.lock.unlock()
            self.emit?(e)
        }
        t.resume()
        return t
    }

    /// Stops traffic first, then removes routes, then closes the tun. Safe to call more than once.
    private func release(_ r: Resources) {
        lock.lock()
        let (c, n, t, timer, renew) = (r.client, r.net, r.tun, r.timer, r.renew)
        r.client = nil; r.net = nil; r.tun = nil; r.timer = nil; r.renew = nil; r.bridge = nil
        lock.unlock()
        timer?.cancel(); renew?.cancel()
        c?.onClose = nil
        c?.close()
        r.linkDown.fire()
        n?.teardown()
        t?.close()
    }
}
