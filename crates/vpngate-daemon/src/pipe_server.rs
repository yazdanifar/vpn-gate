//! The Windows IPC listener: a named pipe with an ACL (SYSTEM, Administrators, Interactive) that rejects remote
//! clients and checks the connecting process's SIDs ([`crate::sid_policy`]). Accepted pipes go to the same
//! [`IpcCore`] as the Unix socket.

use std::ffi::c_void;
use std::io;
use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::task::JoinHandle;
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenGroups, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION};

use crate::ipc_server::IpcCore;
use crate::sid_policy::{self, PIPE_SDDL};

/// Owns a security descriptor allocated by `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
struct Descriptor(PSECURITY_DESCRIPTOR);

// SAFETY: the descriptor is immutable after creation and only freed on drop.
unsafe impl Send for Descriptor {}
unsafe impl Sync for Descriptor {}

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Descriptor> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and `sd` receives a LocalAlloc'ed descriptor.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: allocated by the conversion call above.
        unsafe { LocalFree(self.0) };
    }
}

struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: a handle this struct opened.
        unsafe { CloseHandle(self.0) };
    }
}

fn sid_string(sid: *mut c_void) -> Option<String> {
    let mut out: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` points into a buffer that outlives the call; the result is LocalAlloc'ed.
    if unsafe { ConvertSidToStringSidW(sid, &mut out) } == 0 {
        return None;
    }
    // SAFETY: `out` is a NUL-terminated wide string.
    let len = (0..).take_while(|&i| unsafe { *out.add(i) } != 0).count();
    let text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(out, len) });
    unsafe { LocalFree(out.cast()) };
    Some(text)
}

fn token_info(token: &Token, class: i32) -> Option<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: the first call only asks for the size.
    unsafe { GetTokenInformation(token.0, class, std::ptr::null_mut(), 0, &mut len) };
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u64; len as usize / 8 + 1];
    // SAFETY: `buf` holds at least `len` bytes, 8-byte aligned.
    (unsafe { GetTokenInformation(token.0, class, buf.as_mut_ptr().cast(), len, &mut len) } != 0).then_some(buf)
}

/// The user and group SIDs of the process on the other end of the pipe.
fn client_sids(pipe: &NamedPipeServer) -> Option<(String, Vec<String>)> {
    let mut pid = 0u32;
    // SAFETY: the handle is a live pipe handle.
    if unsafe { GetNamedPipeClientProcessId(pipe.as_raw_handle() as HANDLE, &mut pid) } == 0 {
        return None;
    }
    // SAFETY: plain calls; handles are closed by `Token`/below.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return None;
    }
    let process = Token(process);
    let mut raw: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut raw) } == 0 {
        return None;
    }
    let token = Token(raw);
    let user_buf = token_info(&token, TokenUser)?;
    // SAFETY: the buffer holds a TOKEN_USER written by the API.
    let user = sid_string(unsafe { (*user_buf.as_ptr().cast::<TOKEN_USER>()).User.Sid })?;
    let group_buf = token_info(&token, TokenGroups)?;
    let groups = unsafe {
        let g = group_buf.as_ptr().cast::<TOKEN_GROUPS>();
        std::slice::from_raw_parts((*g).Groups.as_ptr(), (*g).GroupCount as usize)
            .iter()
            .filter_map(|a| sid_string(a.Sid))
            .collect()
    };
    Some((user, groups))
}

pub struct PipeServer {
    name: String,
    core: Arc<IpcCore>,
    accept: Mutex<Option<JoinHandle<()>>>,
}

impl PipeServer {
    pub fn new(name: impl Into<String>, core: Arc<IpcCore>) -> PipeServer {
        PipeServer { name: name.into(), core, accept: Mutex::new(None) }
    }

    fn create(name: &str, sd: &Descriptor, first: bool) -> io::Result<NamedPipeServer> {
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let mut options = ServerOptions::new();
        options.first_pipe_instance(first).reject_remote_clients(true);
        // SAFETY: `attributes` and the descriptor it points to are valid for the call.
        unsafe {
            options.create_with_security_attributes_raw(name, (&mut attributes as *mut SECURITY_ATTRIBUTES).cast())
        }
    }

    /// Creates the first pipe instance (failing when another process owns the name) and starts accepting. Must run
    /// inside a Tokio runtime.
    pub fn start(&self) -> io::Result<()> {
        let sd = Arc::new(Descriptor::from_sddl(PIPE_SDDL)?);
        let first = Self::create(&self.name, &sd, true)
            .map_err(|e| io::Error::new(e.kind(), format!("create pipe {}: {e}", self.name)))?;
        let (name, core) = (self.name.clone(), self.core.clone());
        *self.accept.lock().unwrap_or_else(|e| e.into_inner()) = Some(tokio::spawn(accept_loop(name, sd, first, core)));
        Ok(())
    }

    /// Stops listening and drops every client.
    pub fn stop(&self) {
        if let Some(t) = self.accept.lock().unwrap_or_else(|e| e.into_inner()).take() {
            t.abort();
        }
        self.core.close_clients();
    }
}

impl Drop for PipeServer {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn accept_loop(name: String, sd: Arc<Descriptor>, mut server: NamedPipeServer, core: Arc<IpcCore>) {
    loop {
        if server.connect().await.is_err() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        // The next instance must exist before this client is handed off, or a connect would find no pipe.
        let next = loop {
            match PipeServer::create(&name, &sd, false) {
                Ok(p) => break p,
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        };
        let client = std::mem::replace(&mut server, next);
        let allowed = client_sids(&client).is_some_and(|(user, groups)| sid_policy::is_allowed(&user, &groups));
        if allowed {
            core.attach(client);
        } // else dropping the instance disconnects the client without a byte sent
    }
}
