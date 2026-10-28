//! [`IpHelper`] over the real IP Helper API (`iphlpapi`).

use std::mem;
use std::net::{IpAddr, Ipv4Addr};

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceLuidToIndex, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GetBestRoute2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeUnicastIpAddressEntry, SetIpInterfaceEntry, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW,
    MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

use super::ip_helper::{BestRoute, IpHelper, Route};

pub struct SystemIpHelper;

fn check(what: &str, code: u32) -> Result<(), String> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(format!("{what}: error {code}"))
    }
}

fn luid_of(if_index: u32) -> Option<NET_LUID_LH> {
    use windows_sys::Win32::NetworkManagement::IpHelper::ConvertInterfaceIndexToLuid;
    // SAFETY: plain out-parameter call.
    let mut luid: NET_LUID_LH = unsafe { mem::zeroed() };
    (unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) } == NO_ERROR).then_some(luid)
}

fn sockaddr(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET is a union of plain integers; all-zero is valid.
    let mut sa: SOCKADDR_INET = unsafe { mem::zeroed() };
    match ip {
        IpAddr::V4(a) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(a.octets());
        }
        IpAddr::V6(a) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = a.octets();
        }
    }
    sa
}

fn forward_row(route: &Route) -> Result<MIB_IPFORWARD_ROW2, String> {
    let luid = luid_of(route.if_index).ok_or_else(|| format!("no interface {}", route.if_index))?;
    // SAFETY: the row is plain data; InitializeIpForwardEntry fills in the defaults.
    let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid;
    row.InterfaceIndex = route.if_index;
    row.DestinationPrefix.Prefix = sockaddr(route.dest);
    row.DestinationPrefix.PrefixLength = route.prefix;
    let unspecified = if route.dest.is_ipv4() {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
    };
    row.NextHop = sockaddr(route.next_hop.unwrap_or(unspecified));
    row.Metric = route.metric;
    row.SitePrefixLength = 0;
    Ok(row)
}

impl IpHelper for SystemIpHelper {
    fn if_index(&self, name: &str) -> Option<u32> {
        let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated; the out-parameters are valid.
        let mut luid: NET_LUID_LH = unsafe { mem::zeroed() };
        if unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut luid) } != NO_ERROR {
            return None;
        }
        let mut index = 0u32;
        (unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) } == NO_ERROR).then_some(index)
    }

    fn add_address(&self, if_index: u32, ip: IpAddr, prefix: u8) -> Result<(), String> {
        let luid = luid_of(if_index).ok_or_else(|| format!("no interface {if_index}"))?;
        // SAFETY: plain data initialised by the API.
        let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { mem::zeroed() };
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.InterfaceLuid = luid;
        row.InterfaceIndex = if_index;
        row.Address = sockaddr(ip);
        row.OnLinkPrefixLength = prefix;
        // SAFETY: `row` is fully initialised.
        match unsafe { CreateUnicastIpAddressEntry(&row) } {
            code if code == ERROR_OBJECT_ALREADY_EXISTS => Ok(()),
            code => check("CreateUnicastIpAddressEntry", code),
        }
    }

    fn set_mtu(&self, if_index: u32, ipv6: bool, mtu: u32) -> Result<(), String> {
        // SAFETY: plain data; Family and InterfaceIndex select the row to read back.
        let mut row: MIB_IPINTERFACE_ROW = unsafe { mem::zeroed() };
        row.Family = if ipv6 { AF_INET6 } else { AF_INET };
        row.InterfaceIndex = if_index;
        check("GetIpInterfaceEntry", unsafe { GetIpInterfaceEntry(&mut row) })?;
        row.NlMtu = mtu;
        // SetIpInterfaceEntry on IPv4 requires the subnet length to be reset, or it fails with ERROR_INVALID_PARAMETER.
        row.SitePrefixLength = 0;
        check("SetIpInterfaceEntry", unsafe { SetIpInterfaceEntry(&mut row) })
    }

    fn add_route(&self, route: &Route) -> Result<(), String> {
        let row = forward_row(route)?;
        // SAFETY: `row` is fully initialised.
        check("CreateIpForwardEntry2", unsafe { CreateIpForwardEntry2(&row) })
    }

    fn delete_route(&self, route: &Route) -> Result<(), String> {
        let row = forward_row(route)?;
        // SAFETY: `row` is fully initialised.
        check("DeleteIpForwardEntry2", unsafe { DeleteIpForwardEntry2(&row) })
    }

    fn best_route(&self, dest: Ipv4Addr) -> Option<BestRoute> {
        let dest = sockaddr(IpAddr::V4(dest));
        // SAFETY: out-parameters are plain data.
        let mut row: MIB_IPFORWARD_ROW2 = unsafe { mem::zeroed() };
        let mut source: SOCKADDR_INET = unsafe { mem::zeroed() };
        let code = unsafe { GetBestRoute2(std::ptr::null(), 0, std::ptr::null(), &dest, 0, &mut row, &mut source) };
        if code != NO_ERROR {
            return None;
        }
        // SAFETY: the family tag says which union member is live.
        let hop = unsafe { row.NextHop.Ipv4 };
        let next_hop = (hop.sin_family == AF_INET && unsafe { hop.sin_addr.S_un.S_addr } != 0)
            .then(|| Ipv4Addr::from(unsafe { hop.sin_addr.S_un.S_addr }.to_ne_bytes()));
        Some(BestRoute { if_index: row.InterfaceIndex, next_hop })
    }
}
