//! Publishes the tunnel to configd as a network service of its own (IPv4 + DNS entities).
//!
//! A DNS entity alone (or one marked with supplemental match domains) only becomes a scoped/supplemental resolver, so
//! lookups kept going to the LAN's resolver. With an IPv4 entity carrying `OverridePrimary`, configd ranks the tunnel
//! as the primary service and its DNS becomes the default resolver: the approach vpnc-script and Tunnelblick use.

#[cfg(target_os = "macos")]
pub use system::SystemDns;

pub const SERVICE_ID: &str = "VPNGateMac";

pub fn ipv4_key() -> String {
    format!("State:/Network/Service/{SERVICE_ID}/IPv4")
}

pub fn dns_key() -> String {
    format!("State:/Network/Service/{SERVICE_ID}/DNS")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntityValue {
    Str(String),
    Int(i32),
    List(Vec<String>),
}

pub type Entity = Vec<(&'static str, EntityValue)>;

/// The two configd entities, DNS first: configd re-evaluates the primary service when the IPv4 entity appears.
pub fn entities(servers: &[String], iface: &str, address: &str, router: &str) -> [(String, Entity); 2] {
    use EntityValue::*;
    [
        (dns_key(), vec![("ServerAddresses", List(servers.to_vec()))]),
        (
            ipv4_key(),
            vec![
                ("InterfaceName", Str(iface.to_string())),
                ("Addresses", List(vec![address.to_string()])),
                ("SubnetMasks", List(vec!["255.255.255.255".to_string()])),
                ("Router", Str(router.to_string())),
                ("OverridePrimary", Int(1)),
            ],
        ),
    ]
}

#[cfg(target_os = "macos")]
mod system {
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use system_configuration::dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder};

    use super::{dns_key, entities, ipv4_key, Entity, EntityValue};
    use crate::DnsConfigurator;

    pub struct SystemDns;

    fn store() -> SCDynamicStore {
        SCDynamicStoreBuilder::new("vpngate-mac").build().expect("SCDynamicStore")
    }

    fn to_cf(entity: &Entity) -> CFDictionary<CFString, CFType> {
        let pairs: Vec<(CFString, CFType)> = entity
            .iter()
            .map(|(k, v)| {
                let value = match v {
                    EntityValue::Str(s) => CFString::new(s).as_CFType(),
                    EntityValue::Int(i) => CFNumber::from(*i).as_CFType(),
                    EntityValue::List(l) => {
                        CFArray::from_CFTypes(&l.iter().map(|s| CFString::new(s)).collect::<Vec<_>>()).as_CFType()
                    }
                };
                (CFString::new(k), value)
            })
            .collect();
        CFDictionary::from_CFType_pairs(&pairs)
    }

    impl DnsConfigurator for SystemDns {
        fn set(&self, servers: &[String], iface: &str, address: &str, router: &str) -> bool {
            let store = store();
            let mut ok = [false; 2];
            for (i, (key, entity)) in entities(servers, iface, address, router).iter().enumerate() {
                ok[i] = store.set(CFString::new(key), to_cf(entity).to_untyped());
            }
            if !(ok[0] && ok[1]) {
                println!("[dns] publishing resolver failed");
            }
            // Partial success counts too, so teardown removes whatever was set.
            ok[0] || ok[1]
        }

        fn remove(&self) {
            let store = store();
            store.remove(CFString::new(&ipv4_key()));
            store.remove(CFString::new(&dns_key()));
        }

        /// The primary service's resolvers right now, read before `set` has published the tunnel's own entities.
        fn current_servers(&self) -> Vec<String> {
            let store = store();
            let get = |key: &str| -> Option<CFDictionary<CFString, CFType>> {
                let value = store.get(CFString::new(key))?;
                let dict = value.downcast::<CFDictionary>()?;
                // SAFETY: configd entities are string-keyed dictionaries; the typed view only changes the element types.
                Some(unsafe { CFDictionary::wrap_under_get_rule(dict.as_concrete_TypeRef()) })
            };
            let string = |dict: &CFDictionary<CFString, CFType>, key: &str| -> Option<CFType> {
                dict.find(CFString::new(key)).map(|v| v.clone())
            };
            let Some(global) = get("State:/Network/Global/IPv4") else { return Vec::new() };
            let Some(service) = string(&global, "PrimaryService").and_then(|v| v.downcast::<CFString>()) else {
                return Vec::new();
            };
            let Some(dns) = get(&format!("State:/Network/Service/{service}/DNS")) else { return Vec::new() };
            string(&dns, "ServerAddresses")
                .and_then(|v| v.downcast::<CFArray>())
                .map(|a| {
                    // SAFETY: `ServerAddresses` is an array of strings; each item is borrowed from the array.
                    a.iter().map(|p| unsafe { CFString::wrap_under_get_rule(*p as CFStringRef) }.to_string()).collect()
                })
                .unwrap_or_default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DNS entity alone is only a supplemental/scoped resolver (the LAN resolver stayed in use); the IPv4 entity with
    /// OverridePrimary makes configd rank the tunnel first.
    #[test]
    fn tunnel_is_published_as_the_primary_service() {
        let servers = vec!["10.233.254.254".to_string(), "8.8.8.8".to_string()];
        let [(dkey, dns), (vkey, v4)] = entities(&servers, "utun7", "10.233.145.182", "10.233.254.254");
        assert_eq!(dkey, dns_key());
        assert_eq!(vkey, ipv4_key());
        let get = |e: &Entity, k: &str| e.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert_eq!(get(&v4, "InterfaceName"), Some(EntityValue::Str("utun7".into())));
        assert_eq!(get(&v4, "OverridePrimary"), Some(EntityValue::Int(1)));
        assert_eq!(get(&v4, "Addresses"), Some(EntityValue::List(vec!["10.233.145.182".into()])));
        assert_eq!(get(&v4, "Router"), Some(EntityValue::Str("10.233.254.254".into())));
        assert_eq!(get(&dns, "ServerAddresses"), Some(EntityValue::List(servers)));
        assert!(get(&dns, "SupplementalMatchDomains").is_none(), "supplemental domains demote the resolver");
        assert!(ipv4_key().starts_with("State:/Network/Service/") && dns_key().ends_with("/DNS"));
    }
}
