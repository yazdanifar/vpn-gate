//! The socket protector reaches every outgoing connection. Its own test binary: the protector is process-wide.
#![cfg(unix)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::net::TcpListener;
use vpngate_net::connect::connect_tcp;
use vpngate_platform::protect::set_protector;

#[tokio::test]
async fn connections_are_protected_before_they_connect_and_refusal_stops_them() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Without a protector: plain connect.
    assert!(connect_tcp("127.0.0.1", port).await.is_ok());

    let calls = Arc::new(AtomicUsize::new(0));
    let allow = Arc::new(AtomicUsize::new(1));
    let (c, a) = (calls.clone(), allow.clone());
    set_protector(Some(Arc::new(move |fd| {
        assert!(fd >= 0);
        c.fetch_add(1, Ordering::SeqCst);
        a.load(Ordering::SeqCst) == 1
    })));

    let stream = connect_tcp("127.0.0.1", port).await.unwrap();
    assert_eq!(stream.peer_addr().unwrap().port(), port);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    allow.store(0, Ordering::SeqCst);
    let err = connect_tcp("127.0.0.1", port).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // A name that cannot resolve is an error, not a hang.
    allow.store(1, Ordering::SeqCst);
    assert!(connect_tcp("nonexistent.invalid", 443).await.is_err());

    set_protector(None);
}
