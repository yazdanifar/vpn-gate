//! What every window needs: the controller and the tokio runtime that runs its async calls.

use std::future::Future;
use std::sync::Arc;

use vpngate_app_model::Controller;

#[derive(Clone)]
pub struct Ctx {
    pub ctl: Controller,
    pub rt: Arc<tokio::runtime::Runtime>,
}

impl Ctx {
    pub fn spawn(&self, f: impl Future<Output = ()> + Send + 'static) {
        self.rt.spawn(f);
    }
}
