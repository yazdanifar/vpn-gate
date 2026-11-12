//! Liveness of the relay while a tunnel is up (the decision logic only; the probe and the route changes belong to the
//! session). A relay can accept the session and then carry nothing, or trickle a few hundred bytes per second of
//! keep-alive echoes and stray DNS replies, which a "no bytes at all" check never notices. So the inbound *rate* over a
//! window decides when to ask the tunnel directly (a real TLS handshake through it), and two misses in a row mean the
//! relay is not carrying data: the session then fails open (the capture routes come off, the machine keeps working
//! directly) while the app picks another relay. While failed open, a probe that succeeds puts the capture back.

/// Seconds of inbound traffic that make one rate sample.
pub const WINDOW: f64 = 20.0;
/// Below this many inbound bytes per second a window counts as starving.
pub const STARVING_BPS: f64 = 1500.0;
/// No inbound byte for this long also arms a probe (an idle tunnel is healthy, so the probe decides).
pub const QUIET: f64 = 10.0;
/// Pause between probes after a miss, and while failed open.
pub const RETRY_PROBE_EVERY: f64 = 5.0;
/// Pause between probes after a success while the tunnel stays quiet (an idle tunnel must not be probed every few
/// seconds).
pub const IDLE_PROBE_EVERY: f64 = 30.0;
/// Consecutive misses that fail the session open.
pub const MISSES_TO_FAIL: u32 = 2;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Step {
    Nothing,
    /// Ask the tunnel whether it carries data, then report with [`Watchdog::probed`].
    Probe,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Verdict {
    Healthy,
    /// The relay is not carrying data: pull the capture routes.
    FailOpen,
    /// A probe went through again after a fail-open: put the capture back.
    Recover,
}

#[derive(Debug)]
pub struct Watchdog {
    window_start: f64,
    window_in: u64,
    starving: bool,
    last_in: u64,
    last_progress: f64,
    last_probe: f64,
    probe_gap: f64,
    misses: u32,
    failed_open: bool,
}

impl Watchdog {
    pub fn new(now: f64, bytes_in: u64) -> Self {
        Watchdog {
            window_start: now,
            window_in: bytes_in,
            starving: false,
            last_in: bytes_in,
            last_progress: now,
            last_probe: f64::NEG_INFINITY,
            probe_gap: IDLE_PROBE_EVERY,
            misses: 0,
            failed_open: false,
        }
    }

    pub fn failed_open(&self) -> bool {
        self.failed_open
    }

    /// Called once a second with the monotonic time (seconds) and the inbound byte counter.
    pub fn tick(&mut self, now: f64, bytes_in: u64) -> Step {
        if now - self.window_start >= WINDOW {
            let rate = bytes_in.saturating_sub(self.window_in) as f64 / (now - self.window_start);
            self.starving = rate < STARVING_BPS;
            self.window_in = bytes_in;
            self.window_start = now;
        }
        if bytes_in > self.last_in {
            self.last_in = bytes_in;
            self.last_progress = now;
        }
        let due = now - self.last_probe >= self.probe_gap;
        let suspicious = now - self.last_progress >= QUIET || self.starving;
        if due && (suspicious || self.failed_open) {
            // Claimed now, so a slow probe is not started twice.
            self.last_probe = now;
            return Step::Probe;
        }
        Step::Nothing
    }

    /// The outcome of a probe asked for by [`tick`](Self::tick).
    pub fn probed(&mut self, now: f64, alive: bool) -> Verdict {
        self.last_probe = now;
        if alive {
            self.misses = 0;
            self.last_progress = now;
            self.probe_gap = IDLE_PROBE_EVERY;
            if self.failed_open {
                self.failed_open = false;
                // Judge the next window afresh, not by the starved one that failed the session open.
                self.starving = false;
                return Verdict::Recover;
            }
            return Verdict::Healthy;
        }
        self.probe_gap = RETRY_PROBE_EVERY;
        if self.failed_open {
            return Verdict::FailOpen;
        }
        // A trickle of echoes between probes must not reset this: they are not "carrying data".
        self.misses += 1;
        if self.misses >= MISSES_TO_FAIL {
            self.failed_open = true;
            return Verdict::FailOpen;
        }
        Verdict::Healthy
    }
}

#[cfg(test)]
mod tests;
