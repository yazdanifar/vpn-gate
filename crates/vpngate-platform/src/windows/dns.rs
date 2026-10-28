//! DNS for the Wintun adapter: the tunnel's resolvers go on the adapter (`SetInterfaceDnsSettings`) and the adapter gets
//! the lowest interface metric, so the DNS client ranks it first. The Windows twin of `macos::dns`; the decisions
//! live behind [`DnsApi`] and compile everywhere so their tests run against a recording fake.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard};

use super::ip_helper::IpHelper;
use crate::DnsConfigurator;

/// The interface metric the tunnel gets: lower than any physical adapter's automatic metric.
pub const TUNNEL_INTERFACE_METRIC: u32 = 1;
/// Probe destination for "which adapter carries the physical network's traffic".
const PROBE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

pub trait DnsApi: Send + Sync {
    /// Replaces the interface's name servers (empty clears them).
    fn set_servers(&self, if_index: u32, servers: &[Ipv4Addr]) -> Result<(), String>;
    /// Pins the interface metric (`UseAutomaticMetric = false`).
    fn set_metric(&self, if_index: u32, metric: u32) -> Result<(), String>;
    /// Back to the automatic metric.
    fn use_automatic_metric(&self, if_index: u32) -> Result<(), String>;
    /// The IPv4 name servers configured on the interface.
    fn servers(&self, if_index: u32) -> Vec<Ipv4Addr>;
}

pub struct WinDns {
    ip: Arc<dyn IpHelper>,
    api: Arc<dyn DnsApi>,
    /// The adapter `set` configured; `remove` has no argument.
    active: Mutex<Option<u32>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl WinDns {
    pub fn new(ip: Arc<dyn IpHelper>, api: Arc<dyn DnsApi>) -> Self {
        WinDns { ip, api, active: Mutex::new(None) }
    }
}

impl DnsConfigurator for WinDns {
    fn set(&self, servers: &[String], iface: &str, _address: &str, _router: &str) -> bool {
        let Some(index) = self.ip.if_index(iface) else {
            println!("[dns] no interface {iface}");
            return false;
        };
        let parsed: Vec<Ipv4Addr> = servers.iter().filter_map(|s| s.parse().ok()).collect();
        if parsed.is_empty() {
            return false;
        }
        // Remembered first, so a half-applied change is still taken out again.
        *lock(&self.active) = Some(index);
        if let Err(e) = self.api.set_servers(index, &parsed) {
            println!("[dns] publishing resolver failed: {e}");
            return false;
        }
        if let Err(e) = self.api.set_metric(index, TUNNEL_INTERFACE_METRIC) {
            println!("[dns] setting the interface metric failed: {e}");
        }
        true
    }

    /// The adapter disappears with the tunnel, so for a process that never saw `set` (stale cleanup) there is nothing
    /// to take out.
    fn remove(&self) {
        let Some(index) = lock(&self.active).take() else { return };
        // Both fail once the adapter is gone, which is the normal order of events at teardown.
        let _ = self.api.set_servers(index, &[]);
        let _ = self.api.use_automatic_metric(index);
    }

    /// The name servers of the adapter the physical default route uses, read before `set` changes anything.
    fn current_servers(&self) -> Vec<String> {
        let Some(best) = self.ip.best_route(PROBE) else { return Vec::new() };
        self.api.servers(best.if_index).iter().map(Ipv4Addr::to_string).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows::ip_helper::{BestRoute, Route};
    use std::net::IpAddr;

    #[derive(Default)]
    struct FakeIp;
    impl IpHelper for FakeIp {
        fn if_index(&self, name: &str) -> Option<u32> {
            match name {
                "VPNGate" => Some(40),
                _ => None,
            }
        }
        fn add_address(&self, _: u32, _: IpAddr, _: u8) -> Result<(), String> {
            Ok(())
        }
        fn set_mtu(&self, _: u32, _: bool, _: u32) -> Result<(), String> {
            Ok(())
        }
        fn add_route(&self, _: &Route) -> Result<(), String> {
            Ok(())
        }
        fn delete_route(&self, _: &Route) -> Result<(), String> {
            Ok(())
        }
        fn best_route(&self, _: Ipv4Addr) -> Option<BestRoute> {
            Some(BestRoute { if_index: 7, next_hop: Some(Ipv4Addr::new(192, 168, 1, 1)) })
        }
    }

    #[derive(Default)]
    struct FakeDns {
        calls: Mutex<Vec<String>>,
        fail_servers: bool,
    }
    impl DnsApi for FakeDns {
        fn set_servers(&self, i: u32, s: &[Ipv4Addr]) -> Result<(), String> {
            let list: Vec<String> = s.iter().map(|a| a.to_string()).collect();
            lock(&self.calls).push(format!("servers {i} [{}]", list.join(",")));
            if self.fail_servers && !s.is_empty() {
                return Err("boom".into());
            }
            Ok(())
        }
        fn set_metric(&self, i: u32, m: u32) -> Result<(), String> {
            lock(&self.calls).push(format!("metric {i} {m}"));
            Ok(())
        }
        fn use_automatic_metric(&self, i: u32) -> Result<(), String> {
            lock(&self.calls).push(format!("auto {i}"));
            Ok(())
        }
        fn servers(&self, i: u32) -> Vec<Ipv4Addr> {
            if i == 7 {
                vec![Ipv4Addr::new(192, 168, 1, 1)]
            } else {
                Vec::new()
            }
        }
    }

    fn dns(fail: bool) -> (WinDns, Arc<FakeDns>) {
        let api = Arc::new(FakeDns { fail_servers: fail, ..Default::default() });
        (WinDns::new(Arc::new(FakeIp), api.clone()), api)
    }

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn set_publishes_servers_and_metric_then_remove_reverts() {
        let (d, api) = dns(false);
        assert!(d.set(&strings(&["10.0.0.1", "8.8.8.8"]), "VPNGate", "10.0.0.2", "10.0.0.1"));
        d.remove();
        assert_eq!(*lock(&api.calls), ["servers 40 [10.0.0.1,8.8.8.8]", "metric 40 1", "servers 40 []", "auto 40"]);
        d.remove();
        assert_eq!(lock(&api.calls).len(), 4, "a second remove is a no-op");
    }

    #[test]
    fn unknown_adapter_or_no_ipv4_server_is_a_failure() {
        let (d, api) = dns(false);
        assert!(!d.set(&strings(&["10.0.0.1"]), "other", "", ""));
        assert!(!d.set(&strings(&["::1", "junk"]), "VPNGate", "", ""));
        assert!(lock(&api.calls).is_empty());
    }

    #[test]
    fn failed_publish_still_gets_taken_out() {
        let (d, api) = dns(true);
        assert!(!d.set(&strings(&["10.0.0.1"]), "VPNGate", "", ""));
        d.remove();
        assert_eq!(*lock(&api.calls), ["servers 40 [10.0.0.1]", "servers 40 []", "auto 40"]);
    }

    #[test]
    fn current_servers_come_from_the_physical_default_route() {
        let (d, _) = dns(false);
        assert_eq!(d.current_servers(), ["192.168.1.1"]);
    }
}
