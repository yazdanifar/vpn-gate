import Foundation
import Darwin

enum UtunError: Error, LocalizedError {
    case failed(String)
    var errorDescription: String? { if case .failed(let m) = self { return m }; return nil }
}

/// Reads utun-framed packets (4-byte address-family header + IP packet) from a file descriptor.
/// Separate from `Utun` so it can be tested with a socketpair.
///
/// The reader thread is the only one that ever polls/reads the descriptor, and `close()` waits for it to
/// stop before closing the descriptor, so a recycled fd number can never be read by a stale thread.
final class FDPacketReader {
    private let lock = NSLock()
    private var fd: Int32
    private var running = false
    private var stopped = DispatchSemaphore(value: 0)
    private var wake: (read: Int32, write: Int32) = (-1, -1)
    var onPacket: (([UInt8]) -> Void)?

    init(fd: Int32) { self.fd = fd }

    func startReading() {
        var p: [Int32] = [0, 0]
        guard pipe(&p) == 0 else { return }
        lock.lock()
        guard fd >= 0, !running else { lock.unlock(); Darwin.close(p[0]); Darwin.close(p[1]); return }
        running = true; wake = (p[0], p[1])
        let fd = self.fd
        lock.unlock()
        Thread.detachNewThread { [weak self] in
            var buf = [UInt8](repeating: 0, count: 65536)
            loop: while true {
                var fds = [pollfd(fd: fd, events: Int16(POLLIN), revents: 0),
                           pollfd(fd: p[0], events: Int16(POLLIN), revents: 0)]
                let r = poll(&fds, 2, -1)
                if r < 0 { if errno == EINTR { continue }; break }
                if fds[1].revents != 0 { break }                       // close() asked us to stop
                if fds[0].revents & Int16(POLLIN) == 0 { if fds[0].revents != 0 { break }; continue }
                let n = read(fd, &buf, buf.count)
                if n < 0 { if errno == EAGAIN || errno == EINTR { continue }; break loop }
                if n <= 4 { continue }
                // header is the AF; only forward IPv4
                if buf[3] == 2, let self = self { self.onPacket?(Array(buf[4..<n])) }
            }
            self?.stopped.signal()
        }
    }

    func write(ipv4 packet: [UInt8]) {
        lock.lock(); defer { lock.unlock() }
        guard fd >= 0 else { return }
        let out: [UInt8] = [0, 0, 0, 2] + packet
        _ = out.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, out.count) }
    }

    func close() {
        lock.lock()
        let wasRunning = running, w = wake
        running = false
        lock.unlock()
        if wasRunning {
            var b: UInt8 = 1
            _ = Darwin.write(w.write, &b, 1)
            _ = stopped.wait(timeout: .now() + 2)
            Darwin.close(w.read); Darwin.close(w.write)
        }
        lock.lock()
        let f = fd; fd = -1
        lock.unlock()
        if f >= 0 { Darwin.close(f) }
    }
}

/// macOS utun device (L3).
final class Utun: TunDevice {
    private(set) var name = ""
    private var reader: FDPacketReader!
    var onPacket: (([UInt8]) -> Void)? {
        get { reader.onPacket }
        set { reader.onPacket = newValue }
    }

    init() throws {
        let s = socket(32 /*PF_SYSTEM*/, SOCK_DGRAM, 2 /*SYSPROTO_CONTROL*/)
        guard s >= 0 else { throw UtunError.failed("socket: \(String(cString: strerror(errno)))") }

        // struct ctl_info { u32 ctl_id; char ctl_name[96]; }
        var info = [UInt8](repeating: 0, count: 100)
        let ctlName = Array("com.apple.net.utun_control".utf8)
        info.replaceSubrange(4..<(4 + ctlName.count), with: ctlName)
        let CTLIOCGINFO: UInt = 0xc064_4e03
        guard ioctl(s, CTLIOCGINFO, &info) == 0 else {
            Darwin.close(s); throw UtunError.failed("CTLIOCGINFO: \(String(cString: strerror(errno)))")
        }
        let ctlID = info[0..<4].withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }

        // struct sockaddr_ctl { u8 len; u8 family; u16 sysaddr; u32 id; u32 unit; u32 reserved[5]; }
        var addr = [UInt8](repeating: 0, count: 32)
        addr[0] = 32; addr[1] = 32            // sc_len, AF_SYSTEM
        addr[2] = 2                           // AF_SYS_CONTROL (little endian u16)
        withUnsafeBytes(of: ctlID) { addr.replaceSubrange(4..<8, with: $0) }
        // sc_unit = 0 lets the kernel pick the next free utunN
        let rc = addr.withUnsafeBytes { connect(s, $0.baseAddress!.assumingMemoryBound(to: sockaddr.self), 32) }
        guard rc == 0 else {
            Darwin.close(s); throw UtunError.failed("connect utun (need root): \(String(cString: strerror(errno)))")
        }
        var nameBuf = [CChar](repeating: 0, count: 32)
        var len = socklen_t(nameBuf.count)
        guard getsockopt(s, 2, 2 /*UTUN_OPT_IFNAME*/, &nameBuf, &len) == 0 else {
            Darwin.close(s); throw UtunError.failed("UTUN_OPT_IFNAME")
        }
        name = String(cString: nameBuf)
        _ = fcntl(s, F_SETFL, O_NONBLOCK)
        reader = FDPacketReader(fd: s)
    }

    func startReading() { reader.startReading() }
    func write(ipv4 packet: [UInt8]) { reader.write(ipv4: packet) }
    func close() { reader.close() }
}
