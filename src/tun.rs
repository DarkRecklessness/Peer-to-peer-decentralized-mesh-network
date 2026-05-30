use bytes::Bytes;
use core::time::Duration;
use std::io::{Error, ErrorKind};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{
    mpsc::{self, error::TrySendError},
    oneshot,
};
use tracing::{debug, error, info, instrument, trace, warn};
use tun::{AsyncDevice, Configuration};

pub struct Tun {
    config: Configuration,
    tx_to_coord: mpsc::Sender<Bytes>,
    rx_from_coord: mpsc::Receiver<Bytes>,
    tun_name: String,
    tun_ip: Ipv4Addr,
    netmask: Ipv4Addr,
    mtu: u16,
}

#[derive(Debug)]
pub enum TunEvent {
    Info(String),
    InitError(tun::Error),
    FatalError,
    DropPacket,
    ReconnectRequired,
}

fn classify_tun_error(err: &Error) -> TunEvent {
    match err.kind() {
        ErrorKind::WouldBlock
        | ErrorKind::Interrupted
        | ErrorKind::WriteZero
        | ErrorKind::InvalidData
        | ErrorKind::UnexpectedEof
        | ErrorKind::TimedOut => TunEvent::DropPacket,

        ErrorKind::NetworkDown
        | ErrorKind::BrokenPipe
        | ErrorKind::StaleNetworkFileHandle
        | ErrorKind::NotConnected
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => TunEvent::ReconnectRequired,

        ErrorKind::PermissionDenied
        | ErrorKind::NotFound
        | ErrorKind::AlreadyExists
        | ErrorKind::InvalidInput
        | ErrorKind::ResourceBusy
        | ErrorKind::AddrInUse
        | ErrorKind::Unsupported => TunEvent::FatalError,

        _ => TunEvent::FatalError,
    }
}

impl Tun {
    pub fn new(
        tun_name: &str,
        mtu: u16,
        tun_ip: Ipv4Addr,
        netmask: Ipv4Addr,
        tx_to_coord: mpsc::Sender<Bytes>,
        rx_from_coord: mpsc::Receiver<Bytes>,
    ) -> Self {
        let mut config = Configuration::default();

        #[cfg(target_os = "linux")]
        {
            config
                .mtu(mtu)
                .address(tun_ip)
                .netmask(netmask)
                .tun_name(tun_name)
                .up();
        }

        #[cfg(target_os = "windows")]
        {
            config.tun_name("MeshVPN").up();
        }

        Tun {
            config,
            tx_to_coord,
            rx_from_coord,
            tun_name: if cfg!(target_os = "windows") {
                "MeshVPN".to_string()
            } else {
                tun_name.to_string()
            },
            tun_ip,
            netmask,
            mtu,
        }
    }

    #[instrument(skip_all)]
    pub async fn run(mut self) {
        loop {
            info!("Try to create a tun device...");
            let tun_device = match tun::create_as_async(&self.config) {
                Ok(ad) => ad,
                Err(e) => {
                    info!(error = %e, "Tun device create error");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };

            info!("Tun interface is up");

            #[cfg(target_os = "windows")]
            {
                info!("Configuring Windows TUN IP manually via netsh...");
                let ip_str = self.tun_ip.to_string();
                let mask_str = self.netmask.to_string();
                let tun_name_arg = format!("name={}", self.tun_name);

                let ip_output = std::process::Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "address",
                        &tun_name_arg,
                        "static",
                        &ip_str,
                        &mask_str,
                    ])
                    .output();

                if let Ok(out) = ip_output {
                    if !out.status.success() {
                        error!(
                            "netsh IP set failed: {}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                    }
                }

                let mtu_str = format!("mtu={}", self.mtu);
                let mtu_output = std::process::Command::new("netsh")
                    .args([
                        "interface",
                        "ipv4",
                        "set",
                        "subinterface",
                        &self.tun_name,
                        &mtu_str,
                        "store=persistent",
                    ])
                    .output();

                match mtu_output {
                    Ok(out) if !out.status.success() => {
                        error!(
                            "netsh MTU set failed: {}",
                            String::from_utf8_lossy(&out.stderr)
                        );
                    }
                    Err(e) => error!("Failed to execute netsh for MTU: {}", e),
                    _ => info!(
                        "Windows TUN IP and MTU ({}) configured successfully",
                        self.mtu
                    ),
                }
            }

            let (tun_device_reader, tun_device_writer) = tokio::io::split(tun_device);

            let (tx_stop_signal_reader, rx_stop_signal_reader) = oneshot::channel();
            let (tx_stop_signal_writer, rx_stop_signal_writer) = oneshot::channel();
            let (tx_end_data_reader, mut rx_end_data_reader) = oneshot::channel();
            let (tx_end_data_writer, mut rx_end_data_writer) = oneshot::channel();

            tokio::spawn(Self::worker_tun_reader(
                tun_device_reader,
                self.tx_to_coord.clone(),
                rx_stop_signal_reader,
                tx_end_data_reader,
            ));

            tokio::spawn(Self::worker_tun_writer(
                tun_device_writer,
                self.rx_from_coord,
                rx_stop_signal_writer,
                tx_end_data_writer,
            ));

            tokio::select! {
                // don't own rx_end_data_reader for another branch due to borrow checker
                result = &mut rx_end_data_reader => {
                    match result {
                        Ok(event) => {
                            let _ = tx_stop_signal_writer.send(());

                            match rx_end_data_writer.await {
                                Ok((rx_from_coord, _)) => {
                                    self.rx_from_coord = rx_from_coord;

                                    match event {
                                        TunEvent::ReconnectRequired => {
                                            continue;
                                        }
                                        TunEvent::FatalError => {
                                            return;
                                        }
                                        _ => {} // impossible
                                    }
                                }
                                Err(_) => {
                                    error!("Oneshot sync channels unexpected error");
                                    return;
                                }
                            }
                        }
                        Err(_) => {
                            error!("Oneshot sync channels unexpected error");
                            return;
                        }
                    }
                }

                // don't own rx_end_data_writer for another branch due to borrow checker
                result = &mut rx_end_data_writer => {
                    match result {
                        Ok((rx_from_coord, event)) => {
                            self.rx_from_coord = rx_from_coord;
                            let _ = tx_stop_signal_reader.send(());

                            match rx_end_data_reader.await {
                                Ok(_) => {
                                    match event {
                                        TunEvent::ReconnectRequired => {
                                            continue;
                                        }
                                        TunEvent::FatalError => {
                                            return;
                                        }
                                        _ => {} // impossible
                                    }
                                }
                                Err(_) => {
                                    error!("Oneshot sync channels unexpected error");
                                    return;
                                }
                            }
                        }
                        Err(_) => {
                            error!("Oneshot sync channels unexpected error");
                            return;
                        }
                    }
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn worker_tun_reader(
        mut tun_device: ReadHalf<AsyncDevice>,
        tx_to_coord: mpsc::Sender<Bytes>,
        mut rx_stop_signal: oneshot::Receiver<()>,
        tx_end_data: oneshot::Sender<TunEvent>,
    ) {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            tokio::select! {
                // don't own rx_stop_signal for loop safety exec due to borrow checker
                _ = &mut rx_stop_signal => {
                    debug!("Receive stop signal");
                    let _ = tx_end_data.send(TunEvent::Info("nothing".to_string()));
                    return;
                }

                result = tun_device.read(&mut buf[..]) => {
                    match result {
                        // check https://docs.rs/tokio/1.51.1/tokio/io/trait.AsyncReadExt.html#method.read
                        Ok(0) => {
                            warn!("Reconnection required due to received 0 bytes");
                            let _ = tx_end_data.send(TunEvent::ReconnectRequired);
                            return;
                        }
                        Ok(size) => {
                            trace!(size, "Read packet from tun");
                            if let Err(e) = tx_to_coord.try_send(Bytes::copy_from_slice(&buf[..size])) {
                                match e {
                                    TrySendError::Full(_) => debug!("Packet queue to coordinator is full, drop packet"),
                                    TrySendError::Closed(_) => {
                                         error!("The channel for sending packets to coordinator was closed");
                                         let _ = tx_end_data.send(TunEvent::FatalError);
                                         return;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            let action = classify_tun_error(&e);
                            match action {
                                TunEvent::ReconnectRequired => {
                                    warn!("Reconnection required due to tun read error");
                                    let _ = tx_end_data.send(TunEvent::ReconnectRequired);
                                    return;
                                }
                                TunEvent::DropPacket => {
                                    debug!("Drop packet while reading from tun");
                                    continue;
                                }
                                TunEvent::FatalError => {
                                    error!("Unexpected error while reading from tun");
                                    let _ = tx_end_data.send(TunEvent::FatalError);
                                    return;
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }

    #[instrument(skip_all)]
    async fn worker_tun_writer(
        mut tun_device: WriteHalf<AsyncDevice>,
        mut rx_from_coord: mpsc::Receiver<Bytes>,
        mut rx_stop_signal: oneshot::Receiver<()>,
        tx_end_data: oneshot::Sender<(mpsc::Receiver<Bytes>, TunEvent)>,
    ) {
        loop {
            tokio::select! {
                // don't own rx_stop_signal for loop safety exec due to borrow checker
                _ = &mut rx_stop_signal => {
                    debug!("Receive stop signal");
                    let _ = tx_end_data.send((rx_from_coord, TunEvent::Info("nothing".to_string())));
                    return;
                }

                opt = rx_from_coord.recv() => {
                    match opt {
                        Some(packet) => {
                            trace!(size = packet.len(), "Receive packet from coordinator");
                            match tun_device.write(&packet[..]).await {
                                Ok(_) => {
                                    trace!(size = packet.len(), "Write packet to tun");
                                    continue;
                                }
                                Err(e) => {
                                    let action = classify_tun_error(&e);
                                    match action {
                                        TunEvent::ReconnectRequired => {
                                            warn!("Reconnection required due to write to tun error");
                                            let _ = tx_end_data.send((rx_from_coord, TunEvent::ReconnectRequired));
                                            return;
                                        }
                                        TunEvent::DropPacket => {
                                            debug!("Drop packet while writing to tun");
                                            continue;
                                        }
                                        TunEvent::FatalError => {
                                            error!("Unexpected error while writing to tun");
                                            let _ = tx_end_data.send((rx_from_coord, TunEvent::FatalError));
                                            return;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                        None => {
                            error!("The channel for receiving packets from the coordinator was closed");
                            let _ = tx_end_data.send((rx_from_coord, TunEvent::FatalError));
                            return;
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
    use tokio::time::{Duration, timeout};

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
        if !matches!(action, TunEvent::FatalError) {
            panic!("Expected FatalError");
        }
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_tun_lifecycle_and_channels() {
        let (tx_coord, _rx_coord) = mpsc::channel(100);
        let (tx_from_coord, rx_from_coord) = mpsc::channel(100);

        let tun = Tun::new(
            "iroh_vpn_tun",
            1500,
            Ipv4Addr::new(10, 200, 200, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            tx_coord,
            rx_from_coord,
        );

        let handle = tokio::spawn(tun.run());

        tokio::time::sleep(Duration::from_millis(500)).await;

        let fake_ipv4_packet = Bytes::from(vec![
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0A, 0xC8,
            0xC8, 0x02, 0x0A, 0xC8, 0xC8, 0x01,
        ]);

        let send_res = tx_from_coord.send(fake_ipv4_packet).await;
        assert!(send_res.is_ok(), "Failed to push packet to TunWorker");

        tokio::time::sleep(Duration::from_millis(100)).await;

        drop(tx_from_coord);

        let res = timeout(Duration::from_secs(2), handle).await;
        assert!(
            res.is_ok(),
            "Worker did not exit properly after channel closed"
        );
    }

    #[tokio::test]
    #[ignore = "requires root"]
    async fn test_tun_read_actual_bytes_from_os() {
        let (tx_coord, mut rx_coord) = mpsc::channel(100);
        let (_tx_from_coord, rx_from_coord) = mpsc::channel(100);

        let tun = Tun::new(
            "iroh_vpn_tun",
            1500,
            Ipv4Addr::new(10, 201, 201, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            tx_coord,
            rx_from_coord,
        );

        let handle = tokio::spawn(tun.run());

        tokio::time::sleep(Duration::from_millis(500)).await;

        tokio::spawn(async move {
            let _ = std::process::Command::new("ping")
                .arg("-c")
                .arg("1")
                .arg("-W")
                .arg("1")
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
                println!(
                    "Caught real ICMP packet from OS! Size: {} bytes",
                    packet.len()
                );
                assert_eq!(packet[16], 10);
                assert_eq!(packet[17], 201);
                assert_eq!(packet[18], 201);
                assert_eq!(packet[19], 67);

                icmp_packet_found = true;
                break;
            }
        }

        assert!(
            icmp_packet_found,
            "Did not receive the ICMP Echo packet from the OS"
        );

        handle.abort();
    }
}
