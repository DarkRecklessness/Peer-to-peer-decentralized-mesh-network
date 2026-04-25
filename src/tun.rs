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

#[derive(Debug)]
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

	pub async fn run(mut self) {
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
							// check https://docs.rs/tokio/1.51.1/tokio/io/trait.AsyncReadExt.html#method.read
							Ok(0) => {
								let _ = self.tx_logs.send(TunEvent::ReconnectRequired).await;
								break;
							}
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


// ======================
// TESTS
// ======================

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};

    #[test]
    fn test_classify_tun_error() {
        let err_block = Error::from(ErrorKind::WouldBlock);
        let action = classify_tun_error(&err_block);
        assert!(matches!(action, TunEvent::DropPacket));

        let err_pipe = Error::from(ErrorKind::BrokenPipe);
        let action = classify_tun_error(&err_pipe);
        assert!(matches!(action, TunEvent::ReconnectRequired));

        let err_perm = Error::from(ErrorKind::PermissionDenied);
        let action = classify_tun_error(&err_perm);
        if let TunEvent::FatalError(msg) = action {
            assert!(msg.contains("Critical error:"));
        } else {
            panic!("Expected FatalError");
        }
    }

    #[test]
    fn test_tun_new() {
        let (tx_coord, _) = mpsc::channel(1);
        let (_, rx_coord) = mpsc::channel(1);
        let (tx_logs, _) = mpsc::channel(1);

        let tun = Tun::new(
            1420,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            tx_coord,
            rx_coord,
            tx_logs,
        );

        assert_eq!(tun.mtu, 1420);
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_tun_lifecycle_and_channels() {
        let (tx_coord, _rx_coord) = mpsc::channel(100);
        let (tx_from_coord, rx_from_coord) = mpsc::channel(100);
        let (tx_logs, mut rx_logs) = mpsc::channel(100);

        let tun = Tun::new(
            1500,
            Ipv4Addr::new(10, 200, 200, 1), 
            Ipv4Addr::new(255, 255, 255, 0),
            tx_coord,
            rx_from_coord,
            tx_logs,
        );

        let handle = tokio::spawn(tun.run());

        let mut is_up = false;
        while let Ok(Some(event)) = timeout(Duration::from_secs(3), rx_logs.recv()).await {
            match event {
                TunEvent::Info(msg) if msg == "Tun interface is up" => {
                    is_up = true;
                    break;
                }
                TunEvent::InitError(e) => {
                    panic!("Failed to init TUN interface (did you run with sudo?): {:?}", e);
                }
                _ => {}
            }
        }
        assert!(is_up, "Tun interface failed to start");

        let fake_ipv4_packet = Bytes::from(vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 
            0x40, 0x01, 0x00, 0x00, 0x0A, 0xC8, 0xC8, 0x02, 
            0x0A, 0xC8, 0xC8, 0x01
        ]);
        
        let send_res = tx_from_coord.send(fake_ipv4_packet).await;
        assert!(send_res.is_ok(), "Failed to push packet to TunWorker");

        tokio::time::sleep(Duration::from_millis(100)).await;

        drop(tx_from_coord);

        let mut fatal_found = false;
        while let Ok(Some(event)) = timeout(Duration::from_secs(2), rx_logs.recv()).await {
            if let TunEvent::FatalError(msg) = event {
                assert!(msg.contains("closed"), "Unexpected fatal error msg: {}", msg);
                fatal_found = true;
                break;
            }
        }
        assert!(fatal_found, "Worker did not exit properly after channel closed");

        let _ = timeout(Duration::from_secs(1), handle).await
            .expect("Task did not terminate");
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_tun_read_actual_bytes_from_os() {
        let (tx_coord, mut rx_coord) = mpsc::channel(100);
        let (_tx_from_coord, rx_from_coord) = mpsc::channel(100);
        let (tx_logs, mut rx_logs) = mpsc::channel(100);

        let tun = Tun::new(
            1500,
            Ipv4Addr::new(10, 201, 201, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            tx_coord,
            rx_from_coord,
            tx_logs,
        );

        let handle = tokio::spawn(tun.run());

        let mut is_up = false;
        while let Ok(Some(event)) = timeout(Duration::from_secs(3), rx_logs.recv()).await {
            if let TunEvent::Info(msg) = event {
                if msg == "Tun interface is up" {
                    is_up = true;
                    break;
                }
            }
        }
        assert!(is_up, "Tun interface failed to start");

        tokio::time::sleep(Duration::from_millis(100)).await;

        tokio::spawn(async move {
            let _ = std::process::Command::new("ping")
                .arg("-c").arg("1")
                .arg("-W").arg("1")
                .arg("10.201.201.67")
                .output();
        });

        let mut icmp_packet_found = false;

        while let Ok(Some(packet)) = timeout(Duration::from_secs(2), rx_coord.recv()).await {
            assert!(!packet.is_empty(), "Received empty packet");

            let version = packet[0] >> 4;
            if version != 4 {
                continue;
            }

            let protocol = packet[9];
            if protocol == 1 {
                println!("Caught real ICMP packet from OS! Size: {} bytes", packet.len());
                assert_eq!(packet[16], 10);
                assert_eq!(packet[17], 201);
                assert_eq!(packet[18], 201);
                assert_eq!(packet[19], 67);
                
                icmp_packet_found = true;
                break;
            }
        }

        assert!(icmp_packet_found, "Did not receive the ICMP Echo packet from the OS");

        handle.abort();
    }
}
