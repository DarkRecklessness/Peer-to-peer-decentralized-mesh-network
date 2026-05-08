use std::any::Any;
use std::time::Instant;
use iroh::endpoint::{Controller, ControllerFactory};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct CustomController {
    mtu: u16,
}

impl Controller for CustomController {
    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _is_ecn: bool,
        _lost_bytes: u64,
    ) {}

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
    }

    fn window(&self) -> u64 {
        1_000_000_000
    }

    fn initial_window(&self) -> u64 {
        1_000_000_000
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

#[derive(Debug)]
pub struct CustomControllerFactory;

impl ControllerFactory for CustomControllerFactory {
    fn build(
        self: Arc<Self>, 
        _now: Instant, 
        _current_mtu: u16,
    ) -> Box<dyn Controller> {
        Box::new(CustomController{
        	mtu: 1200,
        })
    }
}
