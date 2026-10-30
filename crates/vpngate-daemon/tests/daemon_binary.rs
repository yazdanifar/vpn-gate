//! Starts the real `vpngate-daemon --daemon` binary (the port of `daemon/real-binary-serves-ipc-clients`).
#![cfg(unix)]

use std::process::{Command, Stdio};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

async fn read_until(c: &mut UnixStream, needle: &str) -> String {
    let mut got = String::new();
    let mut buf = [0u8; 4096];
    while !got.contains(needle) {
        match tokio::time::timeout(Duration::from_secs(5), c.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => got.push_str(&String::from_utf8_lossy(&buf[..n])),
            _ => break,
        }
    }
    got
}

#[tokio::test]
async fn real_binary_serves_ipc_clients() {
    let bin = env!("CARGO_BIN_EXE_vpngate-daemon");
    let path = format!("/tmp/vg-bin-{}.sock", std::process::id());
    let me = {
        let (a, _b) = UnixStream::pair().unwrap();
        a.peer_cred().unwrap().uid()
    };
    let mut child = Command::new(bin)
        .args(["--daemon", "--uid", &me.to_string(), "--socket", &path])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        if std::path::Path::new(&path).exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // long enough for a released server to have stopped
    let mut c = UnixStream::connect(&path).await.expect("cannot connect");
    let first = read_until(&mut c, "\n").await;
    assert!(first.contains("disconnected"), "no state snapshot from the daemon: {first}");
    c.write_all(b"{\"cmd\":\"status\"}\n").await.unwrap();
    assert!(read_until(&mut c, "helperVersion").await.contains("helperVersion"), "status request unanswered");
    // a rejected request must be answered too
    c.write_all(b"{\"cmd\":\"connect\",\"host\":\"-bad\"}\n").await.unwrap();
    assert!(read_until(&mut c, "Rejected").await.contains("Rejected"), "invalid request unanswered");

    // SIGTERM shuts it down and removes the socket.
    let status = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(status.success());
    let exit = tokio::task::spawn_blocking(move || child.wait().unwrap()).await.unwrap();
    assert!(exit.success(), "{exit:?}");
    assert!(!std::path::Path::new(&path).exists(), "socket left behind");
}

#[test]
fn version_prints_the_helper_version() {
    let out = Command::new(env!("CARGO_BIN_EXE_vpngate-daemon")).arg("--version").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), vpngate_core::ipc::HELPER_VERSION.to_string());
}

#[test]
fn usage_exits_2() {
    let out = Command::new(env!("CARGO_BIN_EXE_vpngate-daemon")).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn list_mode_prints_the_shipped_list_without_a_daemon() {
    let bin = env!("CARGO_BIN_EXE_vpngate-daemon");
    let bundle = concat!(env!("CARGO_MANIFEST_DIR"), "/../../assets/VPNGate.dat");
    let cache = format!("/tmp/vg-list-cache-{}.dat", std::process::id());
    let out = Command::new(bin).args(["--list", "--bundle", bundle, "--cache", &cache]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("one JSON object");
    assert!(v["servers"].as_array().is_some_and(|s| !s.is_empty()), "{v}");
    assert_eq!(v["source"], "Built-in");

    // nothing stored and no bundle: a readable failure, not an empty list
    let out = Command::new(bin).args(["--list", "--cache", &cache]).output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("No server list"));
}
