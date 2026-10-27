use super::*;

#[test]
fn direction_from_wire() {
    assert_eq!(SocketDirection::from_wire(None), SocketDirection::Both);
    assert_eq!(SocketDirection::from_wire(Some(0)), SocketDirection::Both);
    assert_eq!(SocketDirection::from_wire(Some(1)), SocketDirection::ServerToClient);
    assert_eq!(SocketDirection::from_wire(Some(2)), SocketDirection::ClientToServer);
    assert_eq!(SocketDirection::from_wire(Some(7)), SocketDirection::Both);
}

#[test]
fn direction_capabilities() {
    assert!(SocketDirection::Both.can_send() && SocketDirection::Both.can_receive());
    assert!(!SocketDirection::ServerToClient.can_send() && SocketDirection::ServerToClient.can_receive());
    assert!(SocketDirection::ClientToServer.can_send() && !SocketDirection::ClientToServer.can_receive());
}
