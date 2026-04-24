use tokio::sync::mpsc::{Sender, Receiver};
use bytes::Bytes;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use tun::Configuration;
use core::time::Duration;

const TUN_NAME: &str = "iroh_vpn_tun";

pub struct Tun {
	mtu: u16,
	config: Configuration,
	tx_to_coord: Sender<Bytes>,
	rx_from_coord: Receiver<Bytes>,
	tx_logs: Sender<TunEvent>,
}  

pub enum TunEvent {
	Info(String),
	InitError(tun::Error),
    FatalError(String),
    DropPacket,
    ReconnectRequired,
}

fn classify_tun_error(err: &Error) -> TunEvent {
    match err.kind() {
        ErrorKind::WouldBlock |
        ErrorKind::Interrupted |
        ErrorKind::WriteZero |
        ErrorKind::InvalidData |
        ErrorKind::UnexpectedEof |
        ErrorKind::TimedOut => TunEvent::DropPacket,

        ErrorKind::NetworkDown |
        ErrorKind::BrokenPipe |
        ErrorKind::StaleNetworkFileHandle |
        ErrorKind::NotConnected |
        ErrorKind::ConnectionReset |
        ErrorKind::ConnectionAborted => TunEvent::ReconnectRequired,

        ErrorKind::PermissionDenied |
        ErrorKind::NotFound |
        ErrorKind::AlreadyExists |
        ErrorKind::InvalidInput |
        ErrorKind::ResourceBusy |
        ErrorKind::AddrInUse |
		ErrorKind::Unsupported => TunEvent::FatalError(format!("Critical error: {}", err)),

        _ => TunEvent::FatalError(format!("Unknown critical error: {}", err)),
    }
}

impl Tun {
	pub fn new(mtu: u16, tun_ip: Ipv4Addr, tun_subnet: Ipv4Addr, 
			   tx_to_coord: Sender<Bytes>, rx_from_coord: Receiver<Bytes>, tx_logs: Sender<TunEvent>) 
		-> Self {

		let mut config = Configuration::default();
		
		config.mtu(mtu)
		      .address(tun_ip)
		      .netmask(tun_subnet)
		      .tun_name(TUN_NAME)
		      .up();

		Tun {
			mtu,
			config,
			tx_to_coord,
			rx_from_coord,
			tx_logs,
		}
	}

	pub async fn run(&mut self) {
		loop {
			let tun_device = match tun::create_as_async(&self.config) {
				Ok(ad) => ad,
				Err(e) => {
					let _ = self.tx_logs.send(TunEvent::InitError(e)).await;
					tokio::time::sleep(Duration::from_secs(2)).await;
					continue;
				}
			};

			let _ = self.tx_logs.send(TunEvent::Info("Tun interface is up".to_string())).await;

			let mut buf = vec![0u8; self.mtu as usize];

			loop {
				tokio::select! {
					result = tun_device.recv(&mut buf[..]) => {
						match result {
							Ok(size) => {
								if let Err(_) = self.tx_to_coord.send(Bytes::copy_from_slice(&buf[..size])).await {
									let _ = self.tx_logs.send(TunEvent::FatalError(
										"The channel for sending packets to coordinator was closed".to_string()
									)).await;
									return;
								}
							}
							Err(e) => {
								let action = classify_tun_error(&e);
								match action {
									TunEvent::ReconnectRequired => {
										let _ = self.tx_logs.send(TunEvent::ReconnectRequired).await;
										break;
									}
									TunEvent::DropPacket => {
										// let _ = self.tx_logs.send(TunEvent::DropPacket).await;
										continue;
									}
									TunEvent::FatalError(msg) => {
										let _ = self.tx_logs.send(TunEvent::FatalError(msg)).await;
										return;
									}
									_ => {}
								}
							}
						}	
					}

					opt = self.rx_from_coord.recv() => {
						match opt {
							Some(packet) => {
								match tun_device.send(&packet[..]).await {
									Ok(_) => continue,
									Err(e) => {
										let action = classify_tun_error(&e);
										match action {
											TunEvent::ReconnectRequired => {
												let _ = self.tx_logs.send(TunEvent::ReconnectRequired).await;
												break;
											}
											TunEvent::DropPacket => {
												// let _ = self.tx_logs.send(TunEvent::DropPacket).await;
												continue;
											}
											TunEvent::FatalError(msg) => {
												let _ = self.tx_logs.send(TunEvent::FatalError(msg)).await;
												return;
											}
											_ => {}
										}
									}
								}
							}
							None => {
								let _ = self.tx_logs.send(TunEvent::FatalError(
									"The channel for receiving packets from the coordinator was closed".to_string()
								)).await;
								return;
							}
						}
					}
				}
			}			
		}
	}
}
