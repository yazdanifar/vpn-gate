//! SoftEther protocol error codes from Cedar.h (SoftEtherVPN_Stable), turned into the messages shown in the UI log.

/// One row of the code table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub code: i64,
    pub name: &'static str,
    pub message: &'static str,
}

const fn e(code: i64, name: &'static str, message: &'static str) -> Info {
    Info { code, name, message }
}

static TABLE: &[Info] = &[
    e(0, "ERR_NO_ERROR", "No error"),
    e(1, "ERR_CONNECT_FAILED", "Connection to the server has failed"),
    e(2, "ERR_SERVER_IS_NOT_VPN", "The destination server is not a VPN server"),
    e(3, "ERR_DISCONNECTED", "The connection has been interrupted"),
    e(4, "ERR_PROTOCOL_ERROR", "Protocol error"),
    e(5, "ERR_CLIENT_IS_NOT_VPN", "Connecting client is not a VPN client"),
    e(6, "ERR_USER_CANCEL", "User cancel"),
    e(7, "ERR_AUTHTYPE_NOT_SUPPORTED", "Specified authentication method is not supported"),
    e(8, "ERR_HUB_NOT_FOUND", "The HUB does not exist"),
    e(9, "ERR_AUTH_FAILED", "Authentication failure"),
    e(10, "ERR_HUB_STOPPING", "HUB is stopped"),
    e(11, "ERR_SESSION_REMOVED", "Session has been deleted"),
    e(12, "ERR_ACCESS_DENIED", "Access denied"),
    e(13, "ERR_SESSION_TIMEOUT", "Session timed out"),
    e(14, "ERR_INVALID_PROTOCOL", "Protocol is invalid"),
    e(15, "ERR_TOO_MANY_CONNECTION", "Too many connections"),
    e(16, "ERR_HUB_IS_BUSY", "Too many sessions of the HUB"),
    e(17, "ERR_PROXY_CONNECT_FAILED", "Connection to the proxy server failed"),
    e(18, "ERR_PROXY_ERROR", "Proxy error"),
    e(19, "ERR_PROXY_AUTH_FAILED", "Failed to authenticate on the proxy server"),
    e(20, "ERR_TOO_MANY_USER_SESSION", "Too many sessions of the same user"),
    e(21, "ERR_LICENSE_ERROR", "License error"),
    e(22, "ERR_DEVICE_DRIVER_ERROR", "Device driver error"),
    e(23, "ERR_INTERNAL_ERROR", "Internal error"),
    e(24, "ERR_SECURE_DEVICE_OPEN_FAILED", "The secure device cannot be opened"),
    e(25, "ERR_SECURE_PIN_LOGIN_FAILED", "PIN code is incorrect"),
    e(26, "ERR_SECURE_NO_CERT", "Specified certificate is not stored"),
    e(27, "ERR_SECURE_NO_PRIVATE_KEY", "Specified private key is not stored"),
    e(28, "ERR_SECURE_CANT_WRITE", "Write failure"),
    e(29, "ERR_OBJECT_NOT_FOUND", "Specified object cannot be found"),
    e(30, "ERR_VLAN_ALREADY_EXISTS", "Virtual LAN card with the specified name already exists"),
    e(31, "ERR_VLAN_INSTALL_ERROR", "Specified virtual LAN card cannot be created"),
    e(32, "ERR_VLAN_INVALID_NAME", "Specified name of the virtual LAN card is invalid"),
    e(33, "ERR_NOT_SUPPORTED", "Unsupported"),
    e(34, "ERR_ACCOUNT_ALREADY_EXISTS", "Account already exists"),
    e(35, "ERR_ACCOUNT_ACTIVE", "Account is operating"),
    e(36, "ERR_ACCOUNT_NOT_FOUND", "Specified account doesn't exist"),
    e(37, "ERR_ACCOUNT_INACTIVE", "Account is offline"),
    e(38, "ERR_INVALID_PARAMETER", "Parameter is invalid"),
    e(39, "ERR_SECURE_DEVICE_ERROR", "Error has occurred in the operation of the secure device"),
    e(40, "ERR_NO_SECURE_DEVICE_SPECIFIED", "Secure device is not specified"),
    e(41, "ERR_VLAN_IS_USED", "Virtual LAN card in use by account"),
    e(42, "ERR_VLAN_FOR_ACCOUNT_NOT_FOUND", "Virtual LAN card of the account cannot be found"),
    e(43, "ERR_VLAN_FOR_ACCOUNT_USED", "Virtual LAN card of the account is already in use"),
    e(44, "ERR_VLAN_FOR_ACCOUNT_DISABLED", "Virtual LAN card of the account is disabled"),
    e(45, "ERR_INVALID_VALUE", "Value is invalid"),
    e(46, "ERR_NOT_FARM_CONTROLLER", "Not a farm controller"),
    e(47, "ERR_TRYING_TO_CONNECT", "Attempting to connect"),
    e(48, "ERR_CONNECT_TO_FARM_CONTROLLER", "Failed to connect to the farm controller"),
    e(49, "ERR_COULD_NOT_HOST_HUB_ON_FARM", "A virtual HUB on farm could not be created"),
    e(50, "ERR_FARM_MEMBER_HUB_ADMIN", "HUB cannot be managed on a farm member"),
    e(51, "ERR_NULL_PASSWORD_LOCAL_ONLY", "Accepting only local connections for an empty password"),
    e(52, "ERR_NOT_ENOUGH_RIGHT", "Right is insufficient"),
    e(53, "ERR_LISTENER_NOT_FOUND", "Listener cannot be found"),
    e(54, "ERR_LISTENER_ALREADY_EXISTS", "Listener already exists"),
    e(55, "ERR_NOT_FARM_MEMBER", "Not a farm member"),
    e(56, "ERR_CIPHER_NOT_SUPPORTED", "Encryption algorithm is not supported"),
    e(57, "ERR_HUB_ALREADY_EXISTS", "HUB already exists"),
    e(58, "ERR_TOO_MANY_HUBS", "Too many HUBs"),
    e(59, "ERR_LINK_ALREADY_EXISTS", "Link already exists"),
    e(60, "ERR_LINK_CANT_CREATE_ON_FARM", "The link cannot be created on the server farm"),
    e(61, "ERR_LINK_IS_OFFLINE", "Link is off-line"),
    e(62, "ERR_TOO_MANY_ACCESS_LIST", "Too many access list entries"),
    e(63, "ERR_TOO_MANY_USER", "Too many users"),
    e(64, "ERR_TOO_MANY_GROUP", "Too many groups"),
    e(65, "ERR_GROUP_NOT_FOUND", "Group cannot be found"),
    e(66, "ERR_USER_ALREADY_EXISTS", "User already exists"),
    e(67, "ERR_GROUP_ALREADY_EXISTS", "Group already exists"),
    e(68, "ERR_USER_AUTHTYPE_NOT_PASSWORD", "Authentication method of the user is not password authentication"),
    e(69, "ERR_OLD_PASSWORD_WRONG", "The user does not exist or the old password is wrong"),
    e(73, "ERR_LINK_CANT_DISCONNECT", "Cascade session cannot be disconnected"),
    e(74, "ERR_ACCOUNT_NOT_PRESENT", "Not completed configuring the connection to the VPN server"),
    e(75, "ERR_ALREADY_ONLINE", "It is already online"),
    e(76, "ERR_OFFLINE", "It is offline"),
    e(77, "ERR_NOT_RSA_1024", "The certificate is not RSA 1024-bit"),
    e(78, "ERR_SNAT_CANT_DISCONNECT", "SecureNAT session cannot be disconnected"),
    e(79, "ERR_SNAT_NEED_STANDALONE", "SecureNAT works only in stand-alone HUB"),
    e(80, "ERR_SNAT_NOT_RUNNING", "SecureNAT function is not working"),
    e(81, "ERR_SE_VPN_BLOCK", "Stopped by PacketiX VPN Block"),
    e(82, "ERR_BRIDGE_CANT_DISCONNECT", "Bridge session cannot be disconnected"),
    e(83, "ERR_LOCAL_BRIDGE_STOPPING", "Bridge function is stopped"),
    e(84, "ERR_LOCAL_BRIDGE_UNSUPPORTED", "Bridge feature is not supported"),
    e(85, "ERR_CERT_NOT_TRUSTED", "Certificate of the destination server cannot be trusted"),
    e(86, "ERR_PRODUCT_CODE_INVALID", "Product code is different"),
    e(87, "ERR_VERSION_INVALID", "Version is different"),
    e(88, "ERR_CAPTURE_DEVICE_ADD_ERROR", "Adding capture device failure"),
    e(89, "ERR_VPN_CODE_INVALID", "VPN code is different"),
    e(90, "ERR_CAPTURE_NOT_FOUND", "Capture device cannot be found"),
    e(91, "ERR_LAYER3_CANT_DISCONNECT", "Layer-3 session cannot be disconnected"),
    e(92, "ERR_LAYER3_SW_EXISTS", "L3 switch of the same name already exists"),
    e(93, "ERR_LAYER3_SW_NOT_FOUND", "Layer-3 switch cannot be found"),
    e(94, "ERR_INVALID_NAME", "Name is invalid"),
    e(95, "ERR_LAYER3_IF_ADD_FAILED", "Failed to add interface"),
    e(96, "ERR_LAYER3_IF_DEL_FAILED", "Failed to delete the interface"),
    e(97, "ERR_LAYER3_IF_EXISTS", "Interface that you specified already exists"),
    e(98, "ERR_LAYER3_TABLE_ADD_FAILED", "Failed to add routing table"),
    e(99, "ERR_LAYER3_TABLE_DEL_FAILED", "Failed to delete the routing table"),
    e(100, "ERR_LAYER3_TABLE_EXISTS", "Routing table entry that you specified already exists"),
    e(101, "ERR_BAD_CLOCK", "Time is incorrect"),
    e(102, "ERR_LAYER3_CANT_START_SWITCH", "The Virtual Layer 3 Switch cannot be started"),
    e(103, "ERR_CLIENT_LICENSE_NOT_ENOUGH", "Client connection licenses shortage"),
    e(104, "ERR_BRIDGE_LICENSE_NOT_ENOUGH", "Bridge connection licenses shortage"),
    e(105, "ERR_SERVER_CANT_ACCEPT", "Not accepting on technical issues"),
    e(106, "ERR_SERVER_CERT_EXPIRES", "Destination VPN server has expired"),
    e(107, "ERR_MONITOR_MODE_DENIED", "Monitor port mode was rejected"),
    e(108, "ERR_BRIDGE_MODE_DENIED", "Bridge-mode or Routing-mode was rejected"),
    e(109, "ERR_IP_ADDRESS_DENIED", "Client IP address is denied"),
    e(110, "ERR_TOO_MANT_ITEMS", "Too many items"),
    e(111, "ERR_MEMORY_NOT_ENOUGH", "Out of memory"),
    e(112, "ERR_OBJECT_EXISTS", "Object already exists"),
    e(113, "ERR_FATAL", "A fatal error occurred"),
    e(114, "ERR_SERVER_LICENSE_FAILED", "License violation has occurred on the server side"),
    e(115, "ERR_SERVER_INTERNET_FAILED", "Server side is not connected to the Internet"),
    e(116, "ERR_CLIENT_LICENSE_FAILED", "License violation occurs on the client side"),
    e(117, "ERR_BAD_COMMAND_OR_PARAM", "Command or parameter is invalid"),
    e(118, "ERR_INVALID_LICENSE_KEY", "License key is invalid"),
    e(119, "ERR_NO_VPN_SERVER_LICENSE", "There is no valid license for the VPN Server"),
    e(120, "ERR_NO_VPN_CLUSTER_LICENSE", "There is no cluster license"),
    e(121, "ERR_NOT_ADMINPACK_SERVER", "Not trying to connect to a server with the Administrator Pack license"),
    e(
        122,
        "ERR_NOT_ADMINPACK_SERVER_NET",
        "Not trying to connect to a server with the Administrator Pack license (for .NET)",
    ),
    e(123, "ERR_BETA_EXPIRES", "Destination Beta VPN Server has expired"),
    e(124, "ERR_BRANDED_C_TO_S", "Branding string of connection limit is different (server-side authentication)"),
    e(125, "ERR_BRANDED_C_FROM_S", "Branding string of connection limit is different (client-side authentication)"),
    e(149, "ERR_DHCP_SERVER_NOT_RUNNING", "DHCP server is not running"),
];

/// Looks up a server error code. `None` for code 0 (no error) and for unknown codes.
pub fn info(code: i64) -> Option<Info> {
    if code == 0 {
        return None;
    }
    lookup(code)
}

fn lookup(code: i64) -> Option<Info> {
    TABLE.binary_search_by_key(&code, |i| i.code).ok().map(|i| TABLE[i])
}

/// Human-readable description, e.g. `ERR_AUTH_FAILED (9): Authentication failure`.
/// Unknown codes give `ERR_<code> (<code>): Unknown server error`.
pub fn describe(code: i64) -> String {
    match lookup(code) {
        Some(i) => format!("{} ({code}): {}", i.name, i.message),
        None => format!("ERR_{code} ({code}): Unknown server error"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden;

    #[test]
    fn table_is_sorted_and_unique() {
        assert!(TABLE.windows(2).all(|w| w[0].code < w[1].code));
    }

    #[test]
    fn describe_examples() {
        assert_eq!(describe(9), "ERR_AUTH_FAILED (9): Authentication failure");
        assert_eq!(describe(-1), "ERR_-1 (-1): Unknown server error");
        assert_eq!(info(0), None);
    }

    #[test]
    fn golden() {
        let v = golden::load("softether_error");
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() > 150);
        for c in cases {
            let code = c["code"].as_i64().unwrap();
            assert_eq!(describe(code), c["describe"].as_str().unwrap(), "describe {code}");
            // the vectors record code 0 with its name and a null message, like the Swift `info(for:)` nil case
            let got = info(code);
            assert_eq!(got.map(|i| i.name), c["name"].as_str().filter(|_| code != 0), "name {code}");
            assert_eq!(got.map(|i| i.message), c["message"].as_str(), "message {code}");
        }
    }
}
