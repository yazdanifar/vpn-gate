//! The IP Helper API as the backend uses it (`CreateUnicastIpAddressEntry`, `SetIpInterfaceEntry`,
//! `CreateIpForwardEntry2`, `DeleteIpForwardEntry2`, `GetBestRoute2`), reduced to structured operations so tests can
//! record them instead of changing the machine.

use std::net::{IpAddr, Ipv4Addr};

/// One entry of the forwarding table. `next_hop: None` is an on-link route (next hop `0.0.0.0` / `::`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub dest: IpAddr,
    pub prefix: u8,
    pub next_hop: Option<IpAddr>,
    pub if_index: u32,
    pub metric: u32,
}

impl Route {
    /// The route as persisted in an undo list: `dest/prefix`, the next hop or `onlink`, and the interface index.
    pub fn to_args(&self) -> Vec<String> {
        let hop = self.next_hop.map_or_else(|| "onlink".to_string(), |h| h.to_string());
        vec![format!("{}/{}", self.dest, self.prefix), hop, self.if_index.to_string()]
    }

    /// The inverse of [`Route::to_args`]. The metric is irrelevant for a delete.
    pub fn from_args(args: &[String]) -> Option<Route> {
        let [cidr, hop, index] = args else { return None };
        let (dest, prefix) = cidr.split_once('/')?;
        let next_hop = if hop == "onlink" { None } else { Some(hop.parse().ok()?) };
        Some(Route {
            dest: dest.parse().ok()?,
            prefix: prefix.parse().ok()?,
            next_hop,
            if_index: index.parse().ok()?,
            metric: 0,
        })
    }
}

/// How the system would reach a destination right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BestRoute {
    pub if_index: u32,
    /// `None` when the destination is on-link.
    pub next_hop: Option<Ipv4Addr>,
}

pub trait IpHelper: Send + Sync {
    /// The interface index of the adapter with this friendly name.
    fn if_index(&self, name: &str) -> Option<u32>;
    fn add_address(&self, if_index: u32, ip: IpAddr, prefix: u8) -> Result<(), String>;
    fn set_mtu(&self, if_index: u32, ipv6: bool, mtu: u32) -> Result<(), String>;
    fn add_route(&self, route: &Route) -> Result<(), String>;
    fn delete_route(&self, route: &Route) -> Result<(), String>;
    /// `GetBestRoute2` for an IPv4 destination.
    fn best_route(&self, dest: Ipv4Addr) -> Option<BestRoute>;
}
