use crate::vpn_core::{VpnCore, Action, Event};
use crate::iroh::{CoreAction, IrohEvent};
use tokio::sync::mpsc::{self, error::TrySendError};
use bytes::Bytes;
use tracing::{info, warn, error, debug, trace, instrument};

pub struct Coordinator {
	core: VpnCore,
	// channels to iroh
	tx_to_iroh: mpsc::Sender<CoreAction>,
	rx_from_iroh: mpsc::Receiver<IrohEvent>,
	// channels to tun
	tx_to_tun: mpsc::Sender<Bytes>,
	rx_from_tun: mpsc::Receiver<Bytes>,
} 

pub struct ChannelWasClosed;

impl Coordinator {
	pub fn new(core: VpnCore,
			   tx_to_iroh: mpsc::Sender<CoreAction>,
			   rx_from_iroh: mpsc::Receiver<IrohEvent>,
			   tx_to_tun: mpsc::Sender<Bytes>,
			   rx_from_tun: mpsc::Receiver<Bytes>) 
		-> Self 
	{
		Coordinator {
			core,
			tx_to_iroh,
			rx_from_iroh,
			tx_to_tun,
			rx_from_tun,
		}
	}

	#[instrument(skip_all)]
	pub async fn run(mut self) {
		loop {
			tokio::select! {
				result = self.rx_from_iroh.recv() => {
					match result {
						Some(event) => {
							trace!("Receive event from iroh");
							if self.handle_iroh_event(event).await.is_err() {
								return;
							}
						}
						None => {
							warn!("Channel to iroh was closed");
							return;
						}
					}
				}

				result = self.rx_from_tun.recv() => {
					match result {
						Some(packet) => {
							trace!("Receive packet from tun");
							if self.handle_packet_from_tun(packet).await.is_err() {
								return;
							}
						}
						None => {
							warn!("Channel to tun was closed");
							return;
						}
					}
				}
			}
		}
	}

	async fn handle_iroh_event(&mut self, event: IrohEvent) -> Result<(), ChannelWasClosed> {
		let actions = self.core.process(Self::map_iroh_event_to_core_event(event));
		self.handle_actions(actions).await
	}

	async fn handle_packet_from_tun(&mut self, packet: Bytes) -> Result<(), ChannelWasClosed> {
		let actions = self.core.process(Event::PacketFromTun(packet));
		self.handle_actions(actions).await
	}

	#[instrument(skip_all)]
	async fn handle_actions(&self, actions: Vec<Action>) -> Result<(), ChannelWasClosed> {
		for action in actions {
			match action {
				Action::ConnectToPeer(_pub_key) => {} // not implemented
				Action::DisconnectFromPeer(pub_key) => { // weird, unlikely
					if self.tx_to_iroh.send(CoreAction::DisconnectFromPeer(pub_key)).await.is_err() {
						warn!("Channel to iroh was closed");
						return Err(ChannelWasClosed);
					}
				}
				Action::SendPacketTo(packet, to) => {
					if let Err(e) = self.tx_to_iroh.try_send(CoreAction::SendPacketTo(packet, to)) {
						match e {
							TrySendError::Full(_) => debug!("Channel to iroh is full, drop packet"),
							TrySendError::Closed(_) => {
								warn!("Channel to iroh was closed");
								return Err(ChannelWasClosed);
							}
						}
					}
				}
				Action::WriteToTun(packet) => {
					if let Err(e) = self.tx_to_tun.try_send(packet) {
						match e {
							TrySendError::Full(_) => debug!("Channel to tun is full, drop packet"),
							TrySendError::Closed(_) => {
								warn!("Channel to tun was closed");
								return Err(ChannelWasClosed);
							}
						}
					}
				}
				Action::NoAction(log) => {
					debug!(log = %log, "Log from core");
				}
			}
		}

		Ok(())
	}
	
	fn map_iroh_event_to_core_event(event: IrohEvent) -> Event {
		match event {
			IrohEvent::ConnectedToPeer(pub_key) => Event::PeerConnected(pub_key),
			IrohEvent::DisconnectedFromPeer(pub_key) => Event::PeerDisconnected(pub_key),
			IrohEvent::RecvPacketFrom(packet, pub_key) => Event::PacketFromIroh(packet, pub_key),
		}
	}
}
