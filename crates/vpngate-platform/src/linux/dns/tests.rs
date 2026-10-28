use std::sync::Mutex;

use super::*;
use crate::CommandOutput;

#[derive(Default)]
struct Runner {
    log: Mutex<Vec<String>>,
    /// `resolvectl dns` fails (resolved not running).
    no_resolved: bool,
}

impl CommandRunner for Runner {
    fn run(&self, program: &str, args: &[&str]) -> CommandOutput {
        let line = format!("{program} {}", args.join(" "));
        let fail = self.no_resolved;
        self.log.lock().unwrap().push(line);
        CommandOutput { status: if fail { 1 } else { 0 }, output: String::new() }
    }
}

struct Dirs {
    root: PathBuf,
}

impl Dirs {
    fn new(name: &str) -> Dirs {
        let root = std::env::temp_dir().join(format!("vpngate-dns-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Dirs { root }
    }
    fn p(&self, f: &str) -> PathBuf {
        self.root.join(f)
    }
    fn dns(&self, runner: Arc<Runner>) -> LinuxDns {
        LinuxDns::with_paths(runner, self.p("resolv.conf"), self.p("upstream.conf"), self.p("backup"))
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn servers() -> Vec<String> {
    vec!["10.233.254.254".into(), "8.8.8.8".into()]
}

#[test]
fn resolved_gets_servers_the_catch_all_domain_and_the_default_route() {
    let dirs = Dirs::new("resolved");
    let runner = Arc::new(Runner::default());
    let dns = dirs.dns(runner.clone());
    assert!(dns.set(&servers(), "vpngate0", "10.233.145.182", "10.233.254.254"));
    assert_eq!(
        *runner.log.lock().unwrap(),
        vec![
            "/usr/bin/resolvectl dns vpngate0 10.233.254.254 8.8.8.8",
            "/usr/bin/resolvectl domain vpngate0 ~.",
            "/usr/bin/resolvectl default-route vpngate0 yes",
        ]
    );
    assert!(!dirs.p("resolv.conf").exists(), "resolv.conf untouched while resolved works");
    dns.remove();
    assert_eq!(runner.log.lock().unwrap().last().unwrap(), "/usr/bin/resolvectl revert vpngate0");
}

#[test]
fn without_resolved_resolv_conf_is_backed_up_replaced_and_restored() {
    let dirs = Dirs::new("file");
    fs::write(dirs.p("resolv.conf"), "nameserver 192.168.1.1\nsearch lan\n").unwrap();
    let dns = dirs.dns(Arc::new(Runner { no_resolved: true, ..Default::default() }));
    assert!(dns.set(&servers(), "vpngate0", "", ""));
    let now = fs::read_to_string(dirs.p("resolv.conf")).unwrap();
    assert!(now.contains("nameserver 10.233.254.254\nnameserver 8.8.8.8\n"));
    assert!(!now.contains("192.168.1.1"));
    // A second `set` (reconnect) must not back up our own file over the original.
    assert!(dns.set(&servers(), "vpngate0", "", ""));
    // A different instance, as after a daemon crash, restores it.
    let later = dirs.dns(Arc::new(Runner::default()));
    later.remove();
    assert_eq!(fs::read_to_string(dirs.p("resolv.conf")).unwrap(), "nameserver 192.168.1.1\nsearch lan\n");
    assert!(!dirs.p("backup").exists());
}

#[test]
fn a_symlinked_resolv_conf_comes_back_as_the_symlink() {
    let dirs = Dirs::new("link");
    fs::write(dirs.p("stub"), "nameserver 127.0.0.53\n").unwrap();
    std::os::unix::fs::symlink(dirs.p("stub"), dirs.p("resolv.conf")).unwrap();
    let dns = dirs.dns(Arc::new(Runner { no_resolved: true, ..Default::default() }));
    assert!(dns.set(&servers(), "vpngate0", "", ""));
    assert!(fs::read_link(dirs.p("resolv.conf")).is_err(), "replaced by a regular file");
    assert_eq!(fs::read_to_string(dirs.p("stub")).unwrap(), "nameserver 127.0.0.53\n", "the target is untouched");
    dns.remove();
    assert_eq!(fs::read_link(dirs.p("resolv.conf")).unwrap(), dirs.p("stub"));
}

#[test]
fn current_servers_prefers_resolveds_upstream_list_over_the_stub() {
    let dirs = Dirs::new("current");
    fs::write(dirs.p("resolv.conf"), "nameserver 127.0.0.53\n").unwrap();
    let dns = dirs.dns(Arc::new(Runner::default()));
    assert_eq!(dns.current_servers(), vec!["127.0.0.53"]);
    fs::write(
        dirs.p("upstream.conf"),
        "# comment\nnameserver 192.168.1.1\nnameserver fe80::1%eth0\nnameserver 1.1.1.1\n",
    )
    .unwrap();
    assert_eq!(dns.current_servers(), vec!["192.168.1.1", "1.1.1.1"]);
}

#[test]
fn remove_without_a_backup_does_nothing() {
    let dirs = Dirs::new("none");
    fs::write(dirs.p("resolv.conf"), "nameserver 1.1.1.1\n").unwrap();
    dirs.dns(Arc::new(Runner::default())).remove();
    assert_eq!(fs::read_to_string(dirs.p("resolv.conf")).unwrap(), "nameserver 1.1.1.1\n");
}
