use super::*;

/// Runs `secs` one-second ticks adding `per_sec` inbound bytes each; probes are answered by `alive`.
fn run(w: &mut Watchdog, now: &mut f64, bytes: &mut u64, secs: u32, per_sec: u64, alive: bool) -> Vec<Verdict> {
    let mut out = Vec::new();
    for _ in 0..secs {
        *now += 1.0;
        *bytes += per_sec;
        if w.tick(*now, *bytes) == Step::Probe {
            out.push(w.probed(*now, alive));
        }
    }
    out
}

#[test]
fn a_busy_tunnel_is_never_probed() {
    let (mut w, mut now, mut bytes) = (Watchdog::new(0.0, 0), 0.0, 0);
    assert!(run(&mut w, &mut now, &mut bytes, 300, 50_000, false).is_empty());
}

#[test]
fn an_idle_but_healthy_tunnel_is_probed_rarely_and_stays_open() {
    let (mut w, mut now, mut bytes) = (Watchdog::new(0.0, 0), 0.0, 0);
    let verdicts = run(&mut w, &mut now, &mut bytes, 300, 0, true);
    assert!(verdicts.iter().all(|v| *v == Verdict::Healthy));
    assert!(verdicts.len() <= 11, "about one probe per 30 s, got {}", verdicts.len());
    assert!(!w.failed_open());
}

#[test]
fn a_silent_relay_fails_open_after_two_misses() {
    let (mut w, mut now, mut bytes) = (Watchdog::new(0.0, 0), 0.0, 0);
    let verdicts = run(&mut w, &mut now, &mut bytes, 40, 0, false);
        assert_eq!(verdicts[0], Verdict::Healthy, "one miss is not enough");
    assert_eq!(verdicts[1], Verdict::FailOpen);
    assert!(w.failed_open());
}

#[test]
fn a_dust_trickle_does_not_hide_a_dead_relay() {
    // 400 B/s of keep-alive echoes: bytes keep counting as progress, but the rate says starving.
    let (mut w, mut now, mut bytes) = (Watchdog::new(0.0, 0), 0.0, 0);
    let verdicts = run(&mut w, &mut now, &mut bytes, 90, 400, false);
    assert!(verdicts.contains(&Verdict::FailOpen), "{verdicts:?}");
}

#[test]
fn a_miss_followed_by_a_success_resets_the_count() {
    let mut w = Watchdog::new(0.0, 0);
    assert_eq!(w.tick(10.0, 0), Step::Probe);
    assert_eq!(w.probed(10.0, false), Verdict::Healthy);
    assert_eq!(w.tick(15.0, 0), Step::Probe);
    assert_eq!(w.probed(15.0, true), Verdict::Healthy);
    assert_eq!(w.tick(45.0, 0), Step::Probe);
    assert_eq!(w.probed(45.0, false), Verdict::Healthy, "the earlier miss no longer counts");
    assert!(!w.failed_open());
}

#[test]
fn while_failed_open_probes_continue_and_a_success_recovers() {
    let mut w = Watchdog::new(0.0, 0);
    assert_eq!(w.tick(10.0, 0), Step::Probe);
    w.probed(10.0, false);
    assert_eq!(w.tick(15.0, 0), Step::Probe);
    assert_eq!(w.probed(15.0, false), Verdict::FailOpen);
    assert_eq!(w.tick(16.0, 0), Step::Nothing, "not again within 5 s");
    assert_eq!(w.tick(20.0, 0), Step::Probe);
    assert_eq!(w.probed(20.0, false), Verdict::FailOpen, "still dead: stay open");
    assert_eq!(w.tick(25.0, 0), Step::Probe);
    assert_eq!(w.probed(25.0, true), Verdict::Recover);
    assert!(!w.failed_open());
}

#[test]
fn a_slow_probe_is_not_started_twice() {
    let mut w = Watchdog::new(0.0, 0);
    assert_eq!(w.tick(10.0, 0), Step::Probe);
    assert_eq!(w.tick(11.0, 0), Step::Nothing);
}
