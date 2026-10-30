//! The status-notifier tray icon (UI-SPEC 2). KDE, XFCE and others show it as is; GNOME needs the AppIndicator extension
//! (see apps/linux/README.md). Without a watcher on the bus the tray silently does not appear.

use ksni::menu::{MenuItem, StandardItem};
use ksni::{Tray, TrayMethods};
use tokio::runtime::Handle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Show,
    ShowLog,
    Connect,
    Disconnect,
    Reconnect,
    Quit,
}

/// What the menu displays; the window pushes a new one after every model change.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraySnapshot {
    pub icon: String,
    pub title: String,
    pub server_line: Option<String>,
    pub virtual_ip: Option<String>,
    pub traffic: Option<String>,
    pub disconnected: bool,
    /// "Connect to <host>" when disconnected and there is a server to connect to.
    pub connect_label: Option<String>,
    pub can_reconnect: bool,
}

type Dispatch = Box<dyn Fn(TrayAction) + Send + Sync>;

struct VpnTray {
    snap: TraySnapshot,
    dispatch: Dispatch,
}

impl VpnTray {
    fn item(&self, label: impl Into<String>, action: TrayAction) -> MenuItem<Self> {
        StandardItem {
            label: label.into(),
            activate: Box::new(move |t: &mut Self| (t.dispatch)(action)),
            ..Default::default()
        }
        .into()
    }

    fn info(label: impl Into<String>) -> MenuItem<Self> {
        StandardItem { label: label.into(), enabled: false, ..Default::default() }.into()
    }
}

impl Tray for VpnTray {
    fn id(&self) -> String {
        "net.vpngate.App".into()
    }

    fn title(&self) -> String {
        format!("VPN Gate — {}", self.snap.title)
    }

    fn icon_name(&self) -> String {
        self.snap.icon.clone()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        (self.dispatch)(TrayAction::Show);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let s = &self.snap;
        let mut m = vec![Self::info(s.title.clone())];
        m.extend(s.server_line.iter().map(|l| Self::info(l.clone())));
        m.extend(s.virtual_ip.iter().map(|ip| Self::info(format!("Virtual IP {ip}"))));
        m.extend(s.traffic.iter().map(|t| Self::info(t.clone())));
        m.push(MenuItem::Separator);
        if s.disconnected {
            m.extend(s.connect_label.iter().map(|l| self.item(l.clone(), TrayAction::Connect)));
        } else {
            m.push(self.item("Disconnect", TrayAction::Disconnect));
            if s.can_reconnect {
                m.push(self.item("Reconnect", TrayAction::Reconnect));
            }
        }
        m.push(self.item("Show VPN Gate", TrayAction::Show));
        m.push(self.item("Connection Log", TrayAction::ShowLog));
        m.push(MenuItem::Separator);
        m.push(self.item("Quit", TrayAction::Quit));
        m
    }
}

/// Starts the tray on `rt`; returns the channel that snapshots are pushed into. If the bus has no watcher the task ends
/// and pushes are dropped.
pub fn spawn(
    rt: &Handle,
    dispatch: impl Fn(TrayAction) + Send + Sync + 'static,
) -> tokio::sync::mpsc::UnboundedSender<TraySnapshot> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<TraySnapshot>();
    let dispatch: Dispatch = Box::new(dispatch);
    rt.spawn(async move {
        let Some(first) = rx.recv().await else { return };
        let Ok(handle) = (VpnTray { snap: first, dispatch }).spawn().await else { return };
        while let Some(snap) = rx.recv().await {
            if handle.update(move |t| t.snap = snap).await.is_none() {
                return;
            }
        }
    });
    tx
}
