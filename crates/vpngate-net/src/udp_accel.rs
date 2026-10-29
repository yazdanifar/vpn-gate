//! SoftEther UDP Acceleration (version 2.0, ChaCha20-Poly1305). Reference: SoftEther src/Cedar/UdpAccel.c, UdpAccel.h
//! (the port of `UdpAccel.swift`).
//!
//! Two-phase life cycle: [`UdpAccel::bind`] opens the local socket early (its port is advertised in the login pack),
//! and [`UdpAccel::configure`] supplies the server's endpoint, cookies and key once the welcome arrives.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Range;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use vpngate_core::data_phase;
use vpngate_core::udp_accel::{self as packet, UdpAccelFields, IV_SIZE};

use crate::connection_pool::{ByteCountFn, FrameFn};
use crate::entropy::{Entropy, SystemEntropy};

// UdpAccel.h: KEEPALIVE_INTERVAL_MIN/MAX/TIMEOUT (legacy) and the *_FAST variants, WINDOW_SIZE_MSEC. The interval is
// `rand() % (max - min) + min` (UdpAccel.c:285 area), so the maximum is exclusive.
pub const KEEP_ALIVE_INTERVAL_MS: Range<u64> = 1000..3000;
pub const KEEP_ALIVE_INTERVAL_FAST_MS: Range<u64> = 500..1000;
pub const KEEP_ALIVE_TIMEOUT_MS: u64 = 9000;
pub const KEEP_ALIVE_TIMEOUT_FAST_MS: u64 = 2100;
pub const WINDOW_MS: u64 = 30_000;
/// How long packets must arrive without a gap before UDP carries data: UDP_ACCELERATION_REQUIRE_CONTINUOUS
/// (UdpAccel.h:123, confirmed in the Windows client as `FirstStableReceiveTick + 10000 <= Now`).
pub const STABLE_RECEIVE_MS: u64 = 10_000;
/// Upstream max_size passed to UdpAccelSend: 1000 for keep-alives (UdpAccel.c:285), MaxUdpPacketSize = 1454 - 20 - 8
/// for data (UdpAccel.c:1170-1186). It only bounds the random zero padding.
const KEEP_ALIVE_MAX_SIZE: usize = 1000;
const DATA_MAX_SIZE: usize = 1454 - 20 - 8;
const MAX_INFLATED_SIZE: usize = 4096;

pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn monotonic_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

/// What the welcome tells the client about the server side of the UDP channel.
#[derive(Debug, Clone)]
pub struct UdpAccelConfig {
    pub server_ip: String,
    pub server_port: u16,
    pub my_cookie: u32,
    pub your_cookie: u32,
    pub your_key_v2: Vec<u8>,
    pub fast_disconnect: bool,
    /// The session negotiated `use_compress`: data goes out zlib-compressed, flag 1.
    pub use_compress: bool,
    /// `udp_acceleration_use_encryption == false`: no IV/AEAD/MAC.
    pub plaintext: bool,
    /// The TCP peer IP (upstream YourIp2); keep-alives also go there while UDP is not usable.
    pub secondary_ip: Option<String>,
}

#[derive(Default)]
struct Callbacks {
    on_frame: Option<FrameFn>,
    on_byte_count: Option<ByteCountFn>,
}

struct State {
    socket: Option<Arc<UdpSocket>>,
    /// A second handle on the same socket for sending: `try_send_to` on the Tokio socket reports `WouldBlock` until
    /// the reactor has delivered its first readiness event, which a datagram send must not wait for.
    sender: Option<Arc<std::net::UdpSocket>>,
    your_key: Vec<u8>,
    my_cookie: u32,
    your_cookie: u32,
    dest: SocketAddrV4,
    dest2: Option<SocketAddrV4>,
    use_compress: bool,
    plain_mode: bool,
    configured: bool,
    fast_disconnect: bool,
    started: bool,
    closed: bool,
    next_iv: Vec<u8>,
    /// When the last valid packet arrived (local clock).
    last_recv_tick: u64,
    /// Highest of our own ticks the peer echoed back.
    last_recv_my_tick: u64,
    /// Highest peer tick seen; echoed in everything we send.
    last_recv_your_tick: u64,
    first_stable_receive_tick: u64,
    tasks: Vec<JoinHandle<()>>,
}

impl State {
    fn timeout_ms(&self) -> u64 {
        if self.fast_disconnect {
            KEEP_ALIVE_TIMEOUT_FAST_MS
        } else {
            KEEP_ALIVE_TIMEOUT_MS
        }
    }

    /// UdpAccelIsSendReady(a, true): dead when `LastRecvTick + timeout < Now` (a gap resets the stable run).
    fn usable(&mut self, now: u64) -> bool {
        if self.closed || !self.configured || self.last_recv_tick == 0 || self.first_stable_receive_tick == 0 {
            return false;
        }
        if now < self.last_recv_tick || now - self.last_recv_tick > self.timeout_ms() {
            self.first_stable_receive_tick = 0;
            return false;
        }
        now >= self.first_stable_receive_tick && now - self.first_stable_receive_tick >= STABLE_RECEIVE_MS
    }
}

struct Inner {
    my_key_v2: Vec<u8>,
    state: Mutex<State>,
    callbacks: Mutex<Callbacks>,
    clock: Mutex<Clock>,
}

impl Inner {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("udp accel state")
    }

    fn now(&self) -> u64 {
        let clock = self.clock.lock().expect("udp accel clock").clone();
        clock()
    }

    fn stop(&self) {
        let tasks = {
            let mut st = self.state();
            if st.closed {
                return;
            }
            st.closed = true;
            st.socket = None;
            st.sender = None;
            std::mem::take(&mut st.tasks)
        };
        tasks.iter().for_each(JoinHandle::abort);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Handle to one UDP acceleration channel; clones share the channel. The channel stops when `stop` is called or the
/// last handle is dropped.
#[derive(Clone)]
pub struct UdpAccel {
    inner: Arc<Inner>,
}

fn parse_peer(ip: &str, port: u16) -> Option<SocketAddrV4> {
    let ip: Ipv4Addr = ip.parse().ok()?;
    (!ip.is_unspecified()).then(|| SocketAddrV4::new(ip, port))
}

impl UdpAccel {
    /// Binds the local socket (any interface, any port). Needs a Tokio runtime. `my_key_v2` is the 128-byte client key
    /// from the login pack, of which the first 32 bytes are used.
    pub fn bind(my_key_v2: &[u8]) -> std::io::Result<UdpAccel> {
        let std_socket = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // The UDP endpoint is the relay: its datagrams must not enter the tunnel.
            vpngate_platform::protect::protect(std_socket.as_raw_fd())?;
        }
        std_socket.set_nonblocking(true)?;
        let sender = std_socket.try_clone()?;
        let socket = UdpSocket::from_std(std_socket)?;
        let iv = SystemEntropy.bytes(IV_SIZE);
        Ok(UdpAccel {
            inner: Arc::new(Inner {
                my_key_v2: my_key_v2.to_vec(),
                state: Mutex::new(State {
                    socket: Some(Arc::new(socket)),
                    sender: Some(Arc::new(sender)),
                    your_key: Vec::new(),
                    my_cookie: 0,
                    your_cookie: 0,
                    dest: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
                    dest2: None,
                    use_compress: false,
                    plain_mode: false,
                    configured: false,
                    fast_disconnect: false,
                    started: false,
                    closed: false,
                    next_iv: iv,
                    last_recv_tick: 0,
                    last_recv_my_tick: 0,
                    last_recv_your_tick: 0,
                    first_stable_receive_tick: 0,
                    tasks: Vec::new(),
                }),
                callbacks: Mutex::new(Callbacks::default()),
                clock: Mutex::new(Arc::new(monotonic_ms)),
            }),
        })
    }

    /// Replaces the time source (milliseconds); tests use it.
    pub fn set_clock(&self, clock: Clock) {
        *self.inner.clock.lock().expect("udp accel clock") = clock;
    }

    /// Frames received over UDP and the byte counts (in, out). Set before `start`.
    pub fn set_callbacks(&self, on_frame: FrameFn, on_byte_count: ByteCountFn) {
        let mut cb = self.inner.callbacks.lock().expect("udp accel callbacks");
        cb.on_frame = Some(on_frame);
        cb.on_byte_count = Some(on_byte_count);
    }

    /// The bound local port, 0 once the socket is closed.
    pub fn local_port(&self) -> u16 {
        let st = self.inner.state();
        st.socket.as_ref().and_then(|s| s.local_addr().ok()).map_or(0, |a| a.port())
    }

    /// Highest peer tick accepted so far (diagnostics and tests).
    pub fn last_peer_tick(&self) -> u64 {
        self.inner.state().last_recv_your_tick
    }

    /// The port we currently send to (diagnostics and tests).
    pub fn peer_port(&self) -> u16 {
        self.inner.state().dest.port()
    }

    pub fn is_socket_closed(&self) -> bool {
        self.inner.state().socket.is_none()
    }

    /// Supplies the server side. Fails (UDP stays off, TCP carries on) for a non-IPv4-literal or unspecified address,
    /// port 0, or (unless `plaintext`) a key shorter than 32 bytes.
    pub fn configure(&self, c: UdpAccelConfig) -> bool {
        if c.server_port == 0 || !(c.plaintext || c.your_key_v2.len() >= 32) {
            return false;
        }
        let Some(dest) = parse_peer(&c.server_ip, c.server_port) else { return false };
        let dest2 = c.secondary_ip.as_deref().and_then(|ip| parse_peer(ip, c.server_port));
        let mut st = self.inner.state();
        if st.closed {
            return false;
        }
        st.dest = dest;
        st.dest2 = dest2;
        st.use_compress = c.use_compress;
        st.plain_mode = c.plaintext;
        st.my_cookie = c.my_cookie;
        st.your_cookie = c.your_cookie;
        st.your_key = c.your_key_v2;
        st.fast_disconnect = c.fast_disconnect;
        st.configured = true;
        true
    }

    /// True when the peer has been sending continuously for the stable period and recently enough to trust the path.
    pub fn is_usable(&self) -> bool {
        let now = self.inner.now();
        self.inner.state().usable(now)
    }

    /// Starts the receive and keep-alive tasks. Needs a Tokio runtime.
    pub fn start(&self) {
        let socket = {
            let mut st = self.inner.state();
            if !st.configured || st.closed || st.started {
                return;
            }
            st.started = true;
            st.socket.clone().expect("open socket")
        };
        let weak = Arc::downgrade(&self.inner);
        let tasks = vec![tokio::spawn(receive_loop(weak.clone(), socket)), tokio::spawn(keep_alive_loop(weak))];
        let mut st = self.inner.state();
        if st.closed {
            tasks.iter().for_each(JoinHandle::abort);
        } else {
            st.tasks = tasks;
        }
    }

    /// Closes the socket and ends both tasks.
    pub fn stop(&self) {
        self.inner.stop();
    }

    /// Sends one Ethernet frame. `false` when UDP is not usable (or the send failed): the caller falls back to TCP.
    pub fn send_frame(&self, frame: &[u8]) -> bool {
        if !self.is_usable() {
            return false;
        }
        let compress = self.inner.state().use_compress;
        if compress {
            // Session UseCompress: every block is zlib-compressed and flagged (Session.c:517, UdpAccel.c:353).
            let Ok(z) = data_phase::compress_frame(frame) else { return false };
            return self.send_packet(true, &z, DATA_MAX_SIZE);
        }
        self.send_packet(false, frame, DATA_MAX_SIZE)
    }

    fn send_packet(&self, compressed: bool, payload: &[u8], max_size: usize) -> bool {
        let now = self.inner.now();
        let sent = {
            // The whole encrypt+send runs under the lock: the IV chain must never hand the same nonce to two senders.
            let mut st = self.inner.state();
            let Some(socket) = st.sender.clone().filter(|_| !st.closed && st.configured) else { return false };
            let padding = packet::padding_size(payload.len(), max_size, |n| SystemEntropy.below(n));
            let fields = UdpAccelFields {
                cookie: st.your_cookie,
                my_tick: now,
                your_tick: st.last_recv_your_tick,
                compressed,
                payload,
                padding,
            };
            let Ok((wire, next_iv)) = packet::encode(&self.inner.my_key_v2, &st.next_iv, &fields, st.plain_mode) else {
                return false;
            };
            st.next_iv = next_iv;
            let sent = socket.send_to(&wire, st.dest).is_ok();
            // Keep-alive while UDP is not usable: the peer may sit behind a NAT, so also try the TCP peer IP
            // (UdpAccel.c:625-651).
            if let Some(other) = st.dest2 {
                if payload.is_empty() && other.ip() != st.dest.ip() && !st.usable(now) {
                    let _ = socket.send_to(&wire, SocketAddrV4::new(*other.ip(), st.dest.port()));
                }
            }
            sent
        };
        if sent {
            self.count_bytes(0, payload.len());
        }
        sent
    }

    fn count_bytes(&self, bytes_in: usize, bytes_out: usize) {
        let cb = self.inner.callbacks.lock().expect("udp accel callbacks").on_byte_count.clone();
        if let Some(cb) = cb {
            cb(bytes_in, bytes_out);
        }
    }

    /// Validates one received datagram (AEAD tag, cookie, tick window) and delivers its payload.
    pub fn handle_datagram(&self, raw: &[u8], from: SocketAddrV4) {
        let (key, expected_cookie, plain) = {
            let st = self.inner.state();
            if st.closed || !st.configured {
                return;
            }
            (st.your_key.clone(), st.my_cookie, st.plain_mode)
        };
        let min = if plain { packet::MIN_PLAINTEXT_SIZE } else { packet::MIN_PACKET_SIZE };
        if raw.len() < min {
            return;
        }
        let Ok(decoded) = packet::decode(raw, &key, plain) else { return };
        if decoded.header.cookie != expected_cookie {
            return;
        }
        let h = &decoded.header;

        {
            let now = self.inner.now();
            let mut st = self.inner.state();
            // Upstream drops a packet whose tick is a full window older than the newest peer tick seen.
            if h.my_tick < st.last_recv_your_tick && st.last_recv_your_tick - h.my_tick >= WINDOW_MS {
                return;
            }
            if st.last_recv_tick != 0 && now >= st.last_recv_tick && now - st.last_recv_tick > st.timeout_ms() {
                st.first_stable_receive_tick = 0; // gap: stability restarts
            }
            // Strictly newer: replaying the latest packet from elsewhere must not move the peer.
            let newest = h.my_tick > st.last_recv_your_tick;
            st.last_recv_my_tick = st.last_recv_my_tick.max(h.your_tick);
            st.last_recv_your_tick = st.last_recv_your_tick.max(h.my_tick);
            if newest {
                st.dest = from; // the peer (or its NAT mapping) moved: follow authenticated packets only
            }
            if st.last_recv_my_tick != 0 && now >= st.last_recv_my_tick && now - st.last_recv_my_tick < WINDOW_MS {
                st.last_recv_tick = now;
                if st.first_stable_receive_tick == 0 {
                    st.first_stable_receive_tick = now;
                }
            }
        }

        // Every non-empty payload is data; an empty one is a keep-alive. A nonzero flag means zlib (Connection.c:2845).
        if decoded.payload.is_empty() {
            return;
        }
        self.count_bytes(decoded.payload.len(), 0);
        let frame = if h.compressed {
            match data_phase::uncompress_frame(&decoded.payload, MAX_INFLATED_SIZE) {
                Ok(f) if !f.is_empty() => f,
                _ => return,
            }
        } else {
            decoded.payload
        };
        let on_frame = self.inner.callbacks.lock().expect("udp accel callbacks").on_frame.clone();
        if let Some(f) = on_frame {
            f(frame);
        }
    }
}

async fn receive_loop(weak: Weak<Inner>, socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 2048];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, SocketAddr::V4(from))) => {
                let Some(inner) = weak.upgrade() else { return };
                UdpAccel { inner }.handle_datagram(&buf[..n], from);
            }
            Ok(_) => {}
            // Windows reports an ICMP port-unreachable for an earlier send as a receive error; keep listening.
            Err(_) => {
                if weak.upgrade().is_none_or(|i| i.state().closed) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }
}

async fn keep_alive_loop(weak: Weak<Inner>) {
    loop {
        let Some(inner) = weak.upgrade() else { return };
        let udp = UdpAccel { inner };
        udp.send_packet(false, &[], KEEP_ALIVE_MAX_SIZE);
        let range =
            if udp.inner.state().fast_disconnect { KEEP_ALIVE_INTERVAL_FAST_MS } else { KEEP_ALIVE_INTERVAL_MS };
        drop(udp);
        let wait = range.start + SystemEntropy.below((range.end - range.start) as usize) as u64;
        tokio::time::sleep(Duration::from_millis(wait)).await;
    }
}

#[cfg(test)]
mod tests;
