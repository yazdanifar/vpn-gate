use super::*;
use crate::secrets::MemorySecrets;
use std::sync::Arc;

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("vg-acc-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn store(d: &Path) -> (AccountStore, Arc<MemorySecrets>) {
    let secrets = Arc::new(MemorySecrets::default());
    (AccountStore::new(d.join("accounts.json"), secrets.clone()), secrets)
}

fn editor(host: &str) -> AccountEditor {
    AccountEditor { host: host.into(), ..AccountEditor::default() }
}

#[test]
fn secrets_stay_out_of_the_file() {
    let d = dir("secrets");
    let (mut s, secrets) = store(&d);
    let mut e = editor("vpn.example.com");
    e.username = "bob".into();
    e.password = "hunter2".into();
    let mut account = e.make_account(None);
    account.proxy.password = Some("proxy-secret".into());
    assert!(s.add(account.clone(), e.secrets()));
    let text = std::fs::read_to_string(s.path()).unwrap();
    assert!(!text.contains("hunter2") && !text.contains("proxy-secret"), "{text}");
    assert_eq!(s.password(&account).as_deref(), Some("hunter2"));
    assert_eq!(s.proxy_password(&account).as_deref(), Some("proxy-secret"));
    let reloaded = AccountStore::new(s.path(), secrets);
    assert_eq!(reloaded.accounts.len(), 1);
    assert_eq!(reloaded.accounts[0].host, "vpn.example.com");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn switching_auth_type_drops_stale_secrets() {
    let d = dir("auth");
    let (mut s, _) = store(&d);
    let mut e = editor("1.2.3.4");
    e.auth_type = AccountAuthType::Certificate;
    e.cert_der = Some(vec![1]);
    e.key_der = Some(vec![2]);
    let a = e.make_account(None);
    s.add(a.clone(), e.secrets());
    assert!(s.has_identity(&a));
    let mut e2 = AccountEditor::from_account(&a, None, true);
    e2.auth_type = AccountAuthType::Password;
    e2.password = "pw".into();
    s.update(e2.make_account(Some(&a)), e2.secrets());
    assert!(!s.has_identity(&a) && s.certificate(&a).is_none());
    assert_eq!(s.password(&a).as_deref(), Some("pw"));
    e2.auth_type = AccountAuthType::Anonymous;
    s.update(e2.make_account(Some(&a)), e2.secrets());
    assert_eq!(s.password(&a), None);
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn update_keeps_stored_password_when_blank() {
    let d = dir("keep");
    let (mut s, _) = store(&d);
    let mut e = editor("1.2.3.4");
    e.password = "pw".into();
    let a = e.make_account(None);
    s.add(a.clone(), e.secrets());
    let blank = AccountEditor::from_account(&a, None, false);
    s.update(blank.make_account(Some(&a)), blank.secrets());
    assert_eq!(s.password(&a).as_deref(), Some("pw"));
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn duplicate_and_delete() {
    let d = dir("dup");
    let (mut s, secrets) = store(&d);
    let mut e = editor("1.2.3.4");
    e.password = "pw".into();
    let a = e.make_account(None);
    s.add(a.clone(), e.secrets());
    assert!(s.duplicate(a.id));
    assert_eq!(s.accounts.len(), 2);
    let copy = s.accounts[1].clone();
    assert_ne!(copy.id, a.id);
    assert_eq!(copy.name, "New Connection (Copy)");
    assert_eq!(s.password(&copy).as_deref(), Some("pw"));
    s.delete(a.id);
    assert_eq!(s.accounts.len(), 1);
    assert_eq!(secrets.get(&key(&a, "pw")), None);
    assert!(s.password(&copy).is_some(), "the copy keeps its own secrets");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn damaged_files_are_set_aside() {
    let d = dir("bad");
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(d.join("accounts.json"), b"not json").unwrap();
    let (s, _) = store(&d);
    assert!(s.accounts.is_empty());
    assert!(s.load_notice.as_deref().unwrap().contains("could not be read"));
    assert!(!d.join("accounts.json").exists(), "moved aside");

    let good = serde_json::to_value(editor("a.example.com").make_account(None)).unwrap();
    std::fs::write(d.join("accounts.json"), serde_json::to_vec(&serde_json::json!([good, {"id": 5}])).unwrap())
        .unwrap();
    let (s, _) = store(&d);
    assert_eq!(s.accounts.len(), 1);
    assert!(s.load_notice.as_deref().unwrap().starts_with("1 saved connection"));
    assert!(d.join("accounts.json").exists(), "copied, not moved");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn editor_validation_and_normalisation() {
    let mut e = editor("");
    assert!(!e.can_save(), "host required");
    e.host = " vpn.example.com ".into();
    assert!(e.can_save());
    e.host = "bad host".into();
    assert!(!e.can_save() && e.host_error().is_some());
    e.host = "1.2.3.4".into();
    e.mtu = "100".into();
    assert!(!e.can_save() && e.advanced_invalid());
    e.mtu = " 1400 ".into();
    e.mac = "zz".into();
    assert!(e.mac_error().is_some());
    e.mac = "00:AC:DE:12:34:56".into();
    e.fingerprint = "AB:CD".into();
    assert!(e.fingerprint_error().is_some());
    e.fingerprint = "AB".repeat(20);
    assert!(e.can_save());
    e.ports = "443, 0, 70000, abc, 992".into();
    e.hub = "  ".into();
    e.max_connection = 99;
    let a = e.make_account(None);
    assert_eq!(a.port_list, [443, 992]);
    assert_eq!(a.hub, "DEFAULT");
    assert_eq!(a.max_connection, 32);
    assert_eq!(a.mtu, Some(1400));
    assert_eq!(a.server_cert_fingerprint.as_deref(), Some("ab".repeat(20).as_str()));
    e.ports = "x".into();
    assert_eq!(e.make_account(None).port_list, [443]);
    e.mtu.clear();
    e.mac.clear();
    let a = e.make_account(None);
    assert!(a.mtu.is_none() && a.virtual_mac_address.is_none() && a.routing.is_none());
}

#[test]
fn certificate_accounts_need_an_identity() {
    let mut e = editor("1.2.3.4");
    e.auth_type = AccountAuthType::Certificate;
    assert!(!e.can_save());
    e.has_stored_identity = true;
    assert!(e.can_save(), "a stored identity is enough when editing");
    e.has_stored_identity = false;
    e.import_identity(b"junk", b"junk");
    assert!(e.import_error.is_some() && !e.can_save());
    e.cert_der = Some(vec![1]);
    e.key_der = Some(vec![2]);
    assert!(e.can_save());
    e.auth_type = AccountAuthType::Password;
    e.password = "x".into();
    let s = e.secrets();
    assert!(s.cert_der.is_none() && s.password.is_some(), "only what the auth type uses is stored");
}

#[test]
fn custom_routing_round_trips_and_blocks_invalid_rules() {
    use vpngate_core::routing_rule::{RoutingAction, RoutingRule, RoutingRuleType};
    let mut e = editor("1.2.3.4");
    e.use_custom_routing = true;
    e.routing.rules.push(RoutingRule::new(RoutingRuleType::Cidr, "10.0.0.0", RoutingAction::Direct));
    assert!(e.routing_invalid() && !e.can_save());
    e.routing.rules[0].value = "10.0.0.0/8".into();
    assert!(e.can_save());
    let a = e.make_account(None);
    assert_eq!(a.routing.as_ref().unwrap().rules.len(), 1);
    let back = AccountEditor::from_account(&a, None, false);
    assert!(back.use_custom_routing && back.routing.rules.len() == 1);
}

#[test]
fn pkcs12_import_fills_the_identity() {
    let file = std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/modern.p12")).unwrap();
    let mut e = editor("1.2.3.4");
    e.auth_type = AccountAuthType::Certificate;
    e.p12_passphrase = "nope".into();
    e.import_pkcs12(&file);
    assert!(e.import_error.is_some() && !e.can_save());
    e.p12_passphrase = "secret".into();
    e.import_pkcs12(&file);
    assert!(e.import_error.is_none() && e.can_save());
}
