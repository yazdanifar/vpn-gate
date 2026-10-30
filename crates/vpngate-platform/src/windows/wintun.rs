//! The Wintun adapter (L3, raw IP packets with no framing), driven through `wintun.dll`, which is loaded at run time so
//! the service can report a missing DLL instead of failing to start.
//!
//! One reader thread owns `WintunReceivePacket`; `close` signals it through a stop event and waits for it before the
//! session and adapter are released, so no thread ever touches a freed handle.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::Duration;

use libloading::Library;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForMultipleObjects, INFINITE};

use crate::{PacketFn, PlatformError, TunDevice};

const ADAPTER_NAME: &str = "VPNGate";
const TUNNEL_TYPE: &str = "VPN Gate";
/// 4 MiB ring: room for bursts without holding much memory (Wintun accepts 128 KiB to 64 MiB, a power of two).
const RING_CAPACITY: u32 = 0x40_0000;

type CreateAdapter = unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> *mut c_void;
type CloseAdapter = unsafe extern "system" fn(*mut c_void);
type StartSession = unsafe extern "system" fn(*mut c_void, u32) -> *mut c_void;
type EndSession = unsafe extern "system" fn(*mut c_void);
type ReadWaitEvent = unsafe extern "system" fn(*mut c_void) -> HANDLE;
type ReceivePacket = unsafe extern "system" fn(*mut c_void, *mut u32) -> *mut u8;
type ReleaseReceive = unsafe extern "system" fn(*mut c_void, *const u8);
type AllocateSend = unsafe extern "system" fn(*mut c_void, u32) -> *mut u8;
type SendPacket = unsafe extern "system" fn(*mut c_void, *const u8);

/// The entry points, copied out of the library; `_lib` keeps them valid.
struct Api {
    _lib: Library,
    create_adapter: CreateAdapter,
    close_adapter: CloseAdapter,
    start_session: StartSession,
    end_session: EndSession,
    read_wait_event: ReadWaitEvent,
    receive: ReceivePacket,
    release_receive: ReleaseReceive,
    allocate_send: AllocateSend,
    send: SendPacket,
}

impl Api {
    fn load(path: &str) -> Result<Api, PlatformError> {
        // SAFETY: loading wintun.dll runs its DllMain, which only initialises the library.
        let lib = unsafe { Library::new(path) }
            .map_err(|e| PlatformError::new(format!("cannot load {path} (reinstall VPN Gate): {e}")))?;
        macro_rules! sym {
            ($name:literal, $ty:ty) => {
                // SAFETY: the symbol has the documented Wintun signature.
                *unsafe { lib.get::<$ty>(concat!($name, "\0").as_bytes()) }
                    .map_err(|e| PlatformError::new(format!("{path} lacks {}: {e}", $name)))?
            };
        }
        Ok(Api {
            create_adapter: sym!("WintunCreateAdapter", CreateAdapter),
            close_adapter: sym!("WintunCloseAdapter", CloseAdapter),
            start_session: sym!("WintunStartSession", StartSession),
            end_session: sym!("WintunEndSession", EndSession),
            read_wait_event: sym!("WintunGetReadWaitEvent", ReadWaitEvent),
            receive: sym!("WintunReceivePacket", ReceivePacket),
            release_receive: sym!("WintunReleaseReceivePacket", ReleaseReceive),
            allocate_send: sym!("WintunAllocateSendPacket", AllocateSend),
            send: sym!("WintunSendPacket", SendPacket),
            _lib: lib,
        })
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// A raw handle that may cross threads: Wintun sessions are safe to use from several threads.
#[derive(Clone, Copy)]
struct Raw(*mut c_void);
// SAFETY: see above; the owner guarantees the handle outlives every thread using it.
unsafe impl Send for Raw {}
unsafe impl Sync for Raw {}

struct Live {
    adapter: Raw,
    session: Raw,
    stop: Raw,
}

type Callback = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

pub struct WintunDevice {
    api: Arc<Api>,
    /// `None` once closed. Writers hold the read lock, so a write never lands on a released session.
    live: RwLock<Option<Live>>,
    stopped: Mutex<Option<Receiver<()>>>,
    on_packet: Arc<Mutex<Option<Callback>>>,
    forward_ipv6: Arc<AtomicBool>,
}

impl WintunDevice {
    /// Creates the "VPNGate" adapter and starts its session. Needs Administrator rights and `wintun.dll`.
    pub fn create(dll_path: &str) -> Result<Self, PlatformError> {
        let api = Arc::new(Api::load(dll_path)?);
        let (name, kind) = (wide(ADAPTER_NAME), wide(TUNNEL_TYPE));
        // SAFETY: both strings are NUL-terminated; a null GUID lets Wintun pick one.
        let adapter = unsafe { (api.create_adapter)(name.as_ptr(), kind.as_ptr(), std::ptr::null()) };
        if adapter.is_null() {
            return Err(PlatformError::new(format!(
                "WintunCreateAdapter: {} (run as Administrator)",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: `adapter` is valid.
        let session = unsafe { (api.start_session)(adapter, RING_CAPACITY) };
        if session.is_null() {
            let e = std::io::Error::last_os_error();
            // SAFETY: closed once, on this error path.
            unsafe { (api.close_adapter)(adapter) };
            return Err(PlatformError::new(format!("WintunStartSession: {e}")));
        }
        // SAFETY: manual-reset, initially unsignalled, unnamed event.
        let stop = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        Ok(WintunDevice {
            api,
            live: RwLock::new(Some(Live { adapter: Raw(adapter), session: Raw(session), stop: Raw(stop) })),
            stopped: Mutex::new(None),
            on_packet: Arc::default(),
            forward_ipv6: Arc::default(),
        })
    }

    fn write(&self, packet: &[u8]) {
        let live = self.live.read().unwrap_or_else(|e| e.into_inner());
        let Some(live) = live.as_ref() else { return };
        // SAFETY: the session is open while the read lock is held; the buffer is `packet.len()` bytes.
        unsafe {
            let out = (self.api.allocate_send)(live.session.0, packet.len() as u32);
            if out.is_null() {
                return; // ring full: dropping is what a NIC does
            }
            std::ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len());
            (self.api.send)(live.session.0, out);
        }
    }
}

fn read_loop(api: &Api, session: Raw, stop: Raw, on_packet: &Mutex<Option<Callback>>, forward6: &AtomicBool) {
    // SAFETY: `session` stays open until `close` has seen this thread stop.
    let wait = unsafe { (api.read_wait_event)(session.0) };
    loop {
        let mut size = 0u32;
        // SAFETY: valid session and out-parameter.
        let packet = unsafe { (api.receive)(session.0, &mut size) };
        if packet.is_null() {
            if std::io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_MORE_ITEMS as i32) {
                return;
            }
            let handles = [wait, stop.0];
            // SAFETY: both handles are valid events.
            if unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) } != WAIT_OBJECT_0 {
                return; // the stop event, or a failure
            }
            continue;
        }
        // SAFETY: Wintun hands out `size` readable bytes until the packet is released.
        let data = unsafe { std::slice::from_raw_parts(packet, size as usize) }.to_vec();
        // SAFETY: `packet` came from `receive` on this session.
        unsafe { (api.release_receive)(session.0, packet) };
        let version = data.first().map(|b| b >> 4);
        if version == Some(4) || (version == Some(6) && forward6.load(Ordering::SeqCst)) {
            let callback = lock(on_packet).clone();
            if let Some(f) = callback {
                f(data);
            }
        }
    }
}

impl TunDevice for WintunDevice {
    fn name(&self) -> String {
        ADAPTER_NAME.into()
    }

    fn set_on_packet(&self, f: PacketFn) {
        *lock(&self.on_packet) = Some(Arc::from(f));
    }

    fn start_reading(&self) {
        let mut stopped = lock(&self.stopped);
        let live = self.live.read().unwrap_or_else(|e| e.into_inner());
        let Some(live) = live.as_ref() else { return };
        if stopped.is_some() {
            return;
        }
        let (api, session, stop) = (self.api.clone(), live.session, live.stop);
        let (on_packet, forward6) = (self.on_packet.clone(), self.forward_ipv6.clone());
        let (tx, rx) = channel();
        std::thread::Builder::new()
            .name("vpngate-tun-reader".into())
            .spawn(move || {
                read_loop(&api, session, stop, &on_packet, &forward6);
                let _ = tx.send(());
            })
            .expect("spawn tun reader");
        *stopped = Some(rx);
    }

    fn write_ipv4(&self, packet: Vec<u8>) {
        self.write(&packet);
    }

    fn write_ipv6(&self, packet: Vec<u8>) {
        self.write(&packet);
    }

    fn set_forward_ipv6(&self, on: bool) {
        self.forward_ipv6.store(on, Ordering::SeqCst);
    }

    fn close(&self) {
        let mut live = self.live.write().unwrap_or_else(|e| e.into_inner());
        let Some(l) = live.take() else { return };
        // SAFETY: the stop event is ours; signalling wakes the reader.
        unsafe { SetEvent(l.stop.0) };
        if let Some(rx) = lock(&self.stopped).take() {
            let _ = rx.recv_timeout(Duration::from_secs(2));
        }
        // SAFETY: the reader has stopped (or timed out, in which case it exits on its next wake); each handle is
        // released exactly once. Closing the adapter also removes it from the system.
        unsafe {
            (self.api.end_session)(l.session.0);
            (self.api.close_adapter)(l.adapter.0);
            CloseHandle(l.stop.0);
        }
    }
}

impl Drop for WintunDevice {
    fn drop(&mut self) {
        self.close();
    }
}
