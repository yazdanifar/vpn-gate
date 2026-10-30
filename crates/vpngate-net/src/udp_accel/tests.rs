use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

use super::*;

const MINE: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = i as u8;
        i += 1;
    }
    k
};
const PEER: [u8; 32] = {
    let mut k = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        k[i] = 100 + i as u8;
        i += 1;
    }
    k
};

fn z_plain() -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..8 {
        v.extend(0u8..16);
    }
    v.extend_from_slice(b"hello hello hello hello");
    v
}

/// `python zlib.compress(z_plain())`.
const Z_BLOCK: &str = "789c6360646266616563e7e0e4e2e6e1e5e367a0333f233527275f01830400a6120c71";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn loopback(port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)
}

fn clock(start: u64) -> (Arc<AtomicU64>, Clock) {
    let t = Arc::new(AtomicU64::new(start));
    let t2 = t.clone();
    (t, Arc::new(move || t2.load(Ordering::SeqCst)))
}

struct Opts {
    fast: bool,
    server_port: u16,
    server_ip: &'static str,
    compress: bool,
    plaintext: bool,
    secondary_ip: Option<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            fast: false,
            server_port: 9,
            server_ip: "127.0.0.1",
            compress: false,
            plaintext: false,
            secondary_ip: None,
        }
    }
}

fn make_udp(o: Opts, start: u64) -> (UdpAccel, Arc<AtomicU64>) {
    let mut key = MINE.to_vec();
    key.extend([0u8; 96]);
    let u = UdpAccel::bind(&key).unwrap();
    assert!(u.configure(UdpAccelConfig {
        server_ip: o.server_ip.into(),
        server_port: o.server_port,
        my_cookie: 7,
        your_cookie: 9,
        your_key_v2: PEER.to_vec(),
        fast_disconnect: o.fast,
        use_compress: o.compress,
        plaintext: o.plaintext,
        secondary_ip: o.secondary_ip.map(Into::into),
    }));
    let (t, c) = clock(start);
    u.set_clock(c);
    (u, t)
}

static IV_COUNTER: AtomicU64 = AtomicU64::new(0);

fn peer_packet(
    my_tick: u64,
    your_tick: u64,
    cookie: u32,
    compressed: bool,
    payload: &[u8],
    plaintext: bool,
) -> Vec<u8> {
    let n = IV_COUNTER.fetch_add(1, Ordering::SeqCst) as u8 + 1;
    let f = UdpAccelFields { cookie, my_tick, your_tick, compressed, payload, padding: 0 };
    packet::encode(&PEER, &[n; 12], &f, plaintext).unwrap().0
}

fn pp(my_tick: u64, your_tick: u64, payload: &[u8]) -> Vec<u8> {
    peer_packet(my_tick, your_tick, 7, false, payload, false)
}

/// Drives a channel to "usable" with the fake clock (packets 2 s apart for 10 s, all echoing our ticks).
fn make_usable(u: &UdpAccel, t: &AtomicU64, from: SocketAddrV4) {
    for step in 0..=5u64 {
        t.store(100_000 + step * 2000, Ordering::SeqCst);
        u.handle_datagram(&pp(1000 + step * 2000, t.load(Ordering::SeqCst) - 100, &[]), from);
    }
}

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

fn collect(u: &UdpAccel) -> Frames {
    let frames: Frames = Arc::default();
    let f = frames.clone();
    u.set_callbacks(Arc::new(move |fr| f.lock().unwrap().push(fr)), Arc::new(|_, _| {}));
    frames
}

fn count(frames: &Frames) -> usize {
    frames.lock().unwrap().len()
}

/// A plain UDP socket standing in for the VPN server.
struct LoopbackUdp {
    socket: UdpSocket,
    port: u16,
}

impl LoopbackUdp {
    async fn new() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        LoopbackUdp { socket, port }
    }

    async fn recv(&self, secs: f64) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 2048];
        let r = tokio::time::timeout(Duration::from_secs_f64(secs), self.socket.recv_from(&mut buf)).await;
        r.ok().and_then(Result::ok).map(|(n, _)| buf[..n].to_vec())
    }
}

#[tokio::test]
async fn stale_ticks_dropped_and_last_peer_tick_is_monotonic() {
    let (u, _) = make_udp(Opts::default(), 100_000);
    let frames = collect(&u);
    let from = loopback(5000);
    u.handle_datagram(&pp(50_000, 99_000, &[1, 2, 3]), from);
    assert_eq!((count(&frames), u.last_peer_tick()), (1, 50_000));
    u.handle_datagram(&pp(90_000, 99_500, &[1, 2, 3]), from);
    assert_eq!((count(&frames), u.last_peer_tick()), (2, 90_000));
    u.handle_datagram(&pp(50_000, 99_500, &[1, 2, 3]), from); // 40 s behind: replay of old traffic
    assert_eq!((count(&frames), u.last_peer_tick()), (2, 90_000));
    u.handle_datagram(&pp(70_000, 99_500, &[1, 2, 3]), from); // 20 s behind: inside the window
    assert_eq!((count(&frames), u.last_peer_tick()), (3, 90_000));
}

#[tokio::test]
async fn wrong_cookie_and_tampered_packets_are_ignored() {
    let (u, _) = make_udp(Opts::default(), 100_000);
    let frames = collect(&u);
    u.handle_datagram(&peer_packet(10, 99_000, 8, false, &[1, 2, 3], false), loopback(5000));
    let mut bad = pp(10, 99_000, &[1, 2, 3]);
    *bad.last_mut().unwrap() ^= 1;
    u.handle_datagram(&bad, loopback(5000));
    u.handle_datagram(&[1, 2, 3], loopback(5000));
    assert_eq!((count(&frames), u.last_peer_tick()), (0, 0));
}

#[tokio::test]
async fn needs_a_stable_receive_period_and_times_out() {
    let (u, t) = make_udp(Opts::default(), 100_000);
    assert!(!u.is_usable(), "nothing received yet");
    u.handle_datagram(&pp(1000, 99_900, &[]), loopback(5000));
    assert!(!u.is_usable(), "first packet alone is not a stable period");
    // keep the run alive with a packet every 2 s (inside the 9 s timeout) for just under 10 s
    for step in 1..=4u64 {
        t.store(100_000 + step * 2000, Ordering::SeqCst);
        u.handle_datagram(&pp(1000 + step * 2000, t.load(Ordering::SeqCst) - 100, &[]), loopback(5000));
    }
    t.store(109_999, Ordering::SeqCst);
    assert!(!u.is_usable(), "9.999 s since the first packet is not 10 s");
    t.store(110_000, Ordering::SeqCst);
    u.handle_datagram(&pp(11_000, 109_900, &[]), loopback(5000));
    assert!(u.is_usable(), "10 s of continuous traffic (UDP_ACCELERATION_REQUIRE_CONTINUOUS)");
    t.store(110_000 + 9_000, Ordering::SeqCst);
    assert!(u.is_usable(), "legacy timeout is 9 s: still alive at exactly 9 s (LastRecvTick + timeout < Now)");
    t.store(110_000 + 9_001, Ordering::SeqCst);
    assert!(!u.is_usable(), "silent for more than 9 s");
}

#[tokio::test]
async fn gap_longer_than_the_timeout_restarts_the_stable_run() {
    let (u, t) = make_udp(Opts::default(), 100_000);
    u.handle_datagram(&pp(1000, 99_900, &[]), loopback(5000));
    t.store(105_000, Ordering::SeqCst);
    u.handle_datagram(&pp(6000, 104_900, &[]), loopback(5000));
    t.store(114_001, Ordering::SeqCst); // 9.001 s of silence
    u.handle_datagram(&pp(15_000, 113_900, &[]), loopback(5000));
    assert!(!u.is_usable(), "14 s after the first packet but the run restarted at 114.001");
    t.store(119_000, Ordering::SeqCst);
    u.handle_datagram(&pp(20_000, 118_900, &[]), loopback(5000));
    assert!(!u.is_usable(), "5 s after the restart");
    t.store(124_001, Ordering::SeqCst);
    u.handle_datagram(&pp(25_000, 123_900, &[]), loopback(5000));
    assert!(u.is_usable(), "10 s after the restart");
}

#[tokio::test]
async fn packet_that_does_not_echo_our_tick_is_not_live() {
    let (u, t) = make_udp(Opts::default(), 100_000);
    u.handle_datagram(&pp(1000, 0, &[]), loopback(5000)); // never heard us
    t.store(111_000, Ordering::SeqCst);
    u.handle_datagram(&pp(12_000, 60_000, &[]), loopback(5000)); // echo is 51 s old
    assert!(!u.is_usable(), "no round trip inside the 30 s window");
}

#[tokio::test]
async fn fast_disconnect_mode_uses_the_short_timeout() {
    let (u, t) = make_udp(Opts { fast: true, ..Opts::default() }, 100_000);
    u.handle_datagram(&pp(1000, 99_900, &[]), loopback(5000));
    for step in 1..=5u64 {
        t.store(100_000 + step * 2000, Ordering::SeqCst);
        u.handle_datagram(&pp(1000 + step * 2000, t.load(Ordering::SeqCst) - 100, &[]), loopback(5000));
    }
    assert!(u.is_usable());
    t.store(110_000 + 2_100, Ordering::SeqCst);
    assert!(u.is_usable());
    t.store(110_000 + 2_101, Ordering::SeqCst);
    assert!(!u.is_usable(), "fast mode drops after 2.1 s");
}

#[tokio::test]
async fn peer_address_follows_newest_authenticated_packet_only() {
    let (u, _) = make_udp(Opts { server_port: 4000, ..Opts::default() }, 100_000);
    assert_eq!(u.peer_port(), 4000);
    u.handle_datagram(&pp(100, 99_000, &[1, 2, 3]), loopback(5000));
    assert_eq!(u.peer_port(), 5000);
    u.handle_datagram(&pp(100, 99_000, &[1, 2, 3]), loopback(6666)); // same tick from elsewhere
    assert_eq!(u.peer_port(), 5000, "a replayed/equal tick must not redirect traffic");
    u.handle_datagram(&pp(200, 99_000, &[1, 2, 3]), loopback(5001));
    assert_eq!(u.peer_port(), 5001);
}

#[tokio::test]
async fn configure_rejects_bad_endpoints() {
    let u = UdpAccel::bind(&MINE).unwrap();
    let cfg = |ip: &str, port: u16, key: &[u8]| UdpAccelConfig {
        server_ip: ip.into(),
        server_port: port,
        my_cookie: 1,
        your_cookie: 2,
        your_key_v2: key.to_vec(),
        fast_disconnect: false,
        use_compress: false,
        plaintext: false,
        secondary_ip: None,
    };
    assert!(!u.configure(cfg("vpn.example.com", 4000, &PEER)), "hostname");
    assert!(!u.configure(cfg("0.0.0.0", 4000, &PEER)), "unspecified");
    assert!(!u.configure(cfg("1.2.3.4", 0, &PEER)), "port 0");
    assert!(!u.configure(cfg("1.2.3.4", 4000, &[1, 2, 3])), "short key");
    assert!(u.configure(cfg("1.2.3.4", 4000, &PEER)));
}

#[tokio::test]
async fn stop_closes_the_socket_and_ends_the_tasks() {
    let lb = LoopbackUdp::new().await;
    let (u, _) = make_udp(Opts { server_port: lb.port, ..Opts::default() }, 1);
    assert!(u.local_port() > 0);
    u.start();
    assert!(lb.recv(3.0).await.is_some(), "first keep-alive proves the loops are running");
    u.stop();
    assert!(u.is_socket_closed());
    assert_eq!(u.local_port(), 0);
    assert!(!u.send_frame(&[1]), "no send after stop");
    // never started: stop closes immediately too
    let (idle, _) = make_udp(Opts::default(), 1);
    idle.stop();
    assert!(idle.is_socket_closed());
}

#[tokio::test]
async fn dropping_the_last_handle_closes_the_socket() {
    let (u, _) = make_udp(Opts::default(), 1);
    u.start();
    let weak = Arc::downgrade(&u.inner);
    drop(u);
    for _ in 0..50 {
        if weak.upgrade().is_none() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the channel outlived its last handle");
}

#[tokio::test]
async fn keepalives_use_negotiated_peer_cookie_and_key() {
    let lb = LoopbackUdp::new().await;
    let (u, _) = make_udp(Opts { server_port: lb.port, ..Opts::default() }, 5000);
    u.start();
    let raw = lb.recv(3.0).await.expect("keep-alive datagram");
    let d = packet::decode(&raw, &MINE, false).unwrap();
    assert_eq!(d.header.cookie, 9);
    assert!(!d.header.compressed);
    assert!(d.payload.is_empty());
    assert_eq!(d.header.my_tick, 5000);
    u.stop();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_senders_never_reuse_a_nonce() {
    let lb = LoopbackUdp::new().await;
    let (u, t) = make_udp(Opts { server_port: lb.port, ..Opts::default() }, 100_000);
    make_usable(&u, &t, loopback(lb.port));
    assert!(u.is_usable());
    let (threads, each) = (4, 40);
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let u = u.clone();
            tokio::task::spawn_blocking(move || {
                for i in 0..each {
                    let _ = u.send_frame(&[i as u8]);
                }
            })
        })
        .collect();
    for h in handles {
        h.await.unwrap();
    }
    let (mut ivs, mut n) = (HashSet::new(), 0);
    while let Some(p) = lb.recv(0.3).await {
        ivs.insert(p[..12].to_vec());
        n += 1;
    }
    assert!(n >= threads * each / 2, "received {n}");
    assert_eq!(ivs.len(), n, "every datagram needs a unique nonce");
    u.stop();
}

#[tokio::test]
async fn compressed_flag_payload_is_inflated_and_delivered() {
    let (u, _) = make_udp(Opts::default(), 100_000);
    let frames = collect(&u);
    let from = loopback(5000);
    let z = unhex(Z_BLOCK);
    u.handle_datagram(&peer_packet(1000, 99_900, 7, true, &z, false), from);
    assert_eq!(*frames.lock().unwrap(), vec![z_plain()], "flag 1 = zlib payload, must not be dropped as a keep-alive");
    u.handle_datagram(&peer_packet(1100, 99_900, 7, false, &[9, 8, 7], false), from);
    assert_eq!(frames.lock().unwrap()[1], [9, 8, 7]);
    u.handle_datagram(&peer_packet(1200, 99_900, 7, true, &[1, 2, 3, 4], false), from); // not zlib
    u.handle_datagram(&peer_packet(1300, 99_900, 7, true, &z[..10], false), from); // truncated
    assert_eq!(count(&frames), 2, "undecodable compressed payloads are dropped");
    // inflation is bounded: a 1 MB zero run compresses to ~1 KB and must not be delivered
    let bomb = data_phase::compress_frame(&vec![0u8; 1 << 20]).unwrap();
    u.handle_datagram(&peer_packet(1400, 99_900, 7, true, &bomb, false), from);
    assert_eq!(count(&frames), 2, "zip bomb dropped");
}

#[tokio::test]
async fn keepalive_is_empty_payload_and_delivers_nothing() {
    let (u, _) = make_udp(Opts::default(), 100_000);
    let frames = collect(&u);
    u.handle_datagram(&peer_packet(1000, 99_900, 7, true, &[], false), loopback(5000));
    u.handle_datagram(&peer_packet(1100, 99_900, 7, false, &[], false), loopback(5000));
    assert_eq!(count(&frames), 0);
}

#[tokio::test]
async fn negotiated_compression_sends_zlib_with_flag_1_and_padding_below_32() {
    let lb = LoopbackUdp::new().await;
    let (u, t) = make_udp(Opts { server_port: lb.port, compress: true, ..Opts::default() }, 100_000);
    make_usable(&u, &t, loopback(lb.port));
    assert!(u.is_usable());
    assert!(u.send_frame(&z_plain()));
    let raw = lb.recv(3.0).await.expect("data datagram");
    let d = packet::decode(&raw, &MINE, false).unwrap();
    assert!(d.header.compressed);
    assert_eq!(data_phase::uncompress_frame(&d.payload, 4096).unwrap(), z_plain());
    let pad = raw.len() - (packet::MIN_PACKET_SIZE + d.payload.len());
    assert!(pad <= 31, "padding {pad}");
}

#[tokio::test]
async fn uncompressed_session_sends_raw_frames_with_flag_0() {
    let lb = LoopbackUdp::new().await;
    let (u, t) = make_udp(Opts { server_port: lb.port, ..Opts::default() }, 100_000);
    make_usable(&u, &t, loopback(lb.port));
    assert!(u.send_frame(&[5, 6, 7, 8]));
    let raw = lb.recv(3.0).await.expect("data datagram");
    let d = packet::decode(&raw, &MINE, false).unwrap();
    assert!(!d.header.compressed);
    assert_eq!(d.payload, [5, 6, 7, 8]);
}

#[tokio::test]
async fn plaintext_mode_has_no_iv_no_mac_and_no_padding() {
    let lb = LoopbackUdp::new().await;
    let (u, _) = make_udp(Opts { server_port: lb.port, plaintext: true, ..Opts::default() }, 100_000);
    let frames = collect(&u);
    // peer -> us: bare cookie(4) tick(8) tick(8) size(2) flag(1) data
    let wire = peer_packet(1000, 99_900, 7, false, &[1, 2, 3], true);
    let mut expected = unhex("00000007");
    expected.extend(unhex("00000000000003e8"));
    expected.extend(unhex("000000000001863c"));
    expected.extend(unhex("0003"));
    expected.extend([0, 1, 2, 3]);
    assert_eq!(wire, expected);
    u.handle_datagram(&wire, loopback(lb.port));
    assert_eq!(*frames.lock().unwrap(), vec![vec![1, 2, 3]]);
    u.handle_datagram(&pp(1100, 99_900, &[4]), loopback(5000)); // an encrypted packet is garbage here
    assert_eq!(count(&frames), 1);
    // us -> peer
    u.start();
    let raw = lb.recv(3.0).await.expect("keep-alive");
    assert_eq!(raw.len(), 23, "plaintext keep-alive: 23 header bytes, nothing else");
    assert_eq!(raw[..4], unhex("00000009")[..]);
    u.stop();
}

#[tokio::test]
async fn keepalive_also_goes_to_tcp_peer_ip_until_udp_is_usable() {
    // primary 127.0.0.2 (nobody listens), secondary 127.0.0.1 (the test socket)
    let lb = LoopbackUdp::new().await;
    let opts =
        Opts { server_port: lb.port, server_ip: "127.0.0.2", secondary_ip: Some("127.0.0.1"), ..Opts::default() };
    let (u, _) = make_udp(opts, 100_000);
    u.start();
    let raw = lb.recv(3.0).await.expect("keep-alive must reach the second IP");
    let d = packet::decode(&raw, &MINE, false).unwrap();
    assert!(d.payload.is_empty());
    assert_eq!(d.header.cookie, 9);
    u.stop();

    // once usable the second IP is left alone
    let lb2 = LoopbackUdp::new().await;
    let opts =
        Opts { server_port: lb2.port, server_ip: "127.0.0.2", secondary_ip: Some("127.0.0.1"), ..Opts::default() };
    let (u2, t2) = make_udp(opts, 100_000);
    make_usable(&u2, &t2, SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), lb2.port));
    assert!(u2.is_usable());
    u2.start();
    assert!(lb2.recv(0.6).await.is_none(), "no second-IP keep-alive while UDP is usable");
    u2.stop();
}

#[test]
fn keepalive_interval_maximum_is_exclusive() {
    assert!(KEEP_ALIVE_INTERVAL_MS.contains(&1000) && !KEEP_ALIVE_INTERVAL_MS.contains(&3000));
    assert!(KEEP_ALIVE_INTERVAL_FAST_MS.contains(&500) && !KEEP_ALIVE_INTERVAL_FAST_MS.contains(&1000));
    assert_eq!(STABLE_RECEIVE_MS, 10_000);
}

#[tokio::test]
async fn byte_counts_report_data_but_not_keepalives() {
    let lb = LoopbackUdp::new().await;
    let (u, t) = make_udp(Opts { server_port: lb.port, ..Opts::default() }, 100_000);
    let (bytes_in, bytes_out) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let (i, o) = (bytes_in.clone(), bytes_out.clone());
    u.set_callbacks(
        Arc::new(|_| {}),
        Arc::new(move |a, b| {
            i.fetch_add(a, Ordering::SeqCst);
            o.fetch_add(b, Ordering::SeqCst);
        }),
    );
    make_usable(&u, &t, loopback(lb.port));
    u.handle_datagram(&pp(50_000, 99_900, &[1, 2, 3, 4, 5]), loopback(lb.port));
    assert!(u.send_frame(&[1, 2, 3]));
    assert_eq!((bytes_in.load(Ordering::SeqCst), bytes_out.load(Ordering::SeqCst)), (5, 3));
}

// Timing under Tokio's paused clock: virtual time, so the 1-3 s / 0.5-1 s jitter windows are asserted exactly.
async fn keepalive_gaps(fast: bool, packets: usize) -> Vec<Duration> {
    let lb = LoopbackUdp::new().await;
    let (u, _) = make_udp(Opts { server_port: lb.port, fast, ..Opts::default() }, 5000);
    u.start();
    let mut gaps = Vec::new();
    let mut prev = None;
    for _ in 0..packets {
        lb.recv(10.0).await.expect("keep-alive datagram");
        let now = tokio::time::Instant::now();
        if let Some(p) = prev {
            gaps.push(now - p);
        }
        prev = Some(now);
    }
    u.stop();
    gaps
}

#[tokio::test(start_paused = true)]
async fn keepalives_repeat_every_one_to_three_seconds() {
    let gaps = keepalive_gaps(false, 30).await;
    assert_eq!(gaps.len(), 29);
    for g in gaps {
        assert!(g >= Duration::from_millis(1000) && g < Duration::from_millis(3000), "{g:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn fast_disconnect_keepalives_repeat_every_half_to_one_second() {
    let gaps = keepalive_gaps(true, 30).await;
    for g in gaps {
        assert!(g >= Duration::from_millis(500) && g < Duration::from_millis(1000), "{g:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn silent_peer_is_detected_on_the_runtime_clock() {
    for (fast, timeout_ms) in [(false, KEEP_ALIVE_TIMEOUT_MS), (true, KEEP_ALIVE_TIMEOUT_FAST_MS)] {
        let (u, _) = make_udp(Opts { fast, ..Opts::default() }, 0);
        let start = tokio::time::Instant::now();
        let now = move || 100_000 + start.elapsed().as_millis() as u64;
        u.set_clock(Arc::new(now));
        // 10 s of traffic from the peer, one packet every 500 ms (inside both timeouts), makes the path usable.
        for step in 0..=20u64 {
            u.handle_datagram(&pp(1000 + step * 500, now() - 100, &[]), loopback(5000));
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        // The last packet arrived 500 ms ago.
        assert!(u.is_usable());
        tokio::time::sleep(Duration::from_millis(timeout_ms - 500)).await;
        assert!(u.is_usable(), "silent for exactly the timeout ({timeout_ms} ms) is still alive");
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert!(!u.is_usable(), "silent for more than {timeout_ms} ms");
        // A late packet does not revive the path until the stable period has run again.
        u.handle_datagram(&pp(50_000, now() - 100, &[]), loopback(5000));
        assert!(!u.is_usable());
    }
}
