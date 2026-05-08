use iroh::{SecretKey, PublicKey};
use iroh::endpoint::{Endpoint, presets, Connection, InvalidSocketAddr, 
					 BindError, SendDatagramError, Builder, QuicTransportConfig};
use bytes::Bytes;
use tokio::sync::mpsc;
use std::collections::{HashSet, HashMap};
use tokio::time::{sleep, Duration};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, debug, trace, instrument};
use std::fmt;
use std::error::Error;
use iroh::address_lookup::{AddressLookupBuilder, pkarr::PkarrPublisher, pkarr::PkarrResolver};
use crate::custom_controller::CustomControllerFactory;

const ALPN: &[u8] = b"iroh_vpn";
const CHANNEL_CAPACITY: usize = 8192;

pub struct Iroh {
	endpoint: Endpoint,
	tx_to_coord: mpsc::Sender<IrohEvent>,
	rx_from_coord: mpsc::Receiver<CoreAction>,
	tx_to_manager: mpsc::Sender<ConnectionEvent>,
	rx_from_tasks: mpsc::Receiver<ConnectionEvent>,
	state_table: HashMap<PublicKey, ConnectionState>,
	peers: HashSet<PublicKey>,
}

enum ConnectionState {
	Connected {
		task: JoinHandle<()>,
		connection: Connection,
		tx_packet_channel: mpsc::Sender<Bytes>,
	},
	Connecting(JoinHandle<()>),
	WaitingIncomingConnection,
	Disconnected,
}

#[derive(Debug, PartialEq)]
pub enum IrohEvent {
	ConnectedToPeer(PublicKey),
	DisconnectedFromPeer(PublicKey),
	RecvPacketFrom(Bytes, PublicKey),
}

#[derive(Debug, PartialEq)]
pub enum CoreAction {
	SendPacketTo(Bytes, PublicKey),
	ConnectToPeer(PublicKey),
	DisconnectFromPeer(PublicKey),
}

#[derive(Debug)]
pub enum InitError {
	BindAddrError(InvalidSocketAddr),
	BuildError(BindError),
}

#[derive(Debug)]
enum ConnectionEvent {
	OutgoingConnection(Connection),
	IncomingConnection(Connection),
	Disconnected(PublicKey),
	InternalError,
}

impl fmt::Display for InitError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			InitError::BindAddrError(e) => write!(f, "Iroh init error: {}", e),
			InitError::BuildError(e) => write!(f, "Iroh init error: {}", e),
		}
	}
}

impl Error for InitError {}

impl Iroh {
	pub async fn new(secret_key: SecretKey, 
			   		 peers: HashSet<PublicKey>, 
			   		 tx_to_coord: mpsc::Sender<IrohEvent>,
			   	  	 rx_from_coord: mpsc::Receiver<CoreAction>,
			   		 listen_port: u16) 
		-> Result<Self, InitError> 
	{
		let mut state_table: HashMap<PublicKey, ConnectionState> = HashMap::with_capacity(peers.len());
		for pub_key in &peers {
			state_table.insert(pub_key.clone(), ConnectionState::Disconnected);
		}

		let quic_transport = QuicTransportConfig::builder()
								.congestion_controller_factory(Arc::new(CustomControllerFactory))
								.initial_mtu(1200)
								.build();

		let mut builder = Endpoint::builder(presets::N0)
		    .secret_key(secret_key.clone())
		    .alpns(vec![ALPN.to_vec()])
		    .transport_config(quic_transport)
		    .bind_addr("0.0.0.0:".to_string() + &listen_port.to_string())
		    .map_err(InitError::BindAddrError)?;
		
		let pkarr_publisher = PkarrPublisher::n0_dns(); 
		let pkarr_resolver = PkarrResolver::n0_dns();
		builder = builder
					.clear_address_lookup()
					.address_lookup(pkarr_publisher)
					.address_lookup(pkarr_resolver);
		
		let endpoint = builder
		    .bind()
		    .await
		    .map_err(InitError::BuildError)?;

		let (tx_to_manager, rx_from_tasks) = mpsc::channel(CHANNEL_CAPACITY);    
		
		Ok(Iroh {
			endpoint,
			tx_to_coord,
			rx_from_coord,
			tx_to_manager,
			rx_from_tasks,
			state_table,
			peers,
		})
	}

	#[instrument(skip_all)]
	pub async fn run(mut self) {
		self.init();		
		// event loop
		loop {
			tokio::select! {
				result = self.rx_from_tasks.recv() => {
					match result {
						Some(event) => {
							if self.handle_conn_event(event).await.is_err() {
								error!("Internal error in iroh manager");
								return;
							}
						}
						None => {
							error!("Channel between iroh manager and tasks was closed");
							return;
						}
					}
				}

				result = self.rx_from_coord.recv() => {
					match result {
						Some(event) => {
							self.handle_core_event(event).await;
						}
						None => {
							error!("Channel between iroh manager and coordinator was closed");
							return;
						}
					}
				}
			}
		}
	}

	#[instrument(skip_all)]
	async fn handle_conn_event(&mut self, event: ConnectionEvent) -> Result<(), ()> {
		match event {
			ConnectionEvent::OutgoingConnection(conn) => {
				match self.state_table.get(&conn.remote_id()) {
					Some(state) => match state { 
						ConnectionState::Connecting(_) => {
							info!(peer = %conn.remote_id(), "Successfully init connection to");
							self.init_ready_connection(conn).await;
						}

						ConnectionState::Connected{task: expired_task, connection: expired_conn, ..} => {
							info!("data race: receive outgoing connecting while current state is Connected");
							expired_task.abort();
							expired_conn.close(1u32.into(), b"connection is expired: data race resolver");

							info!(peer = %conn.remote_id(), "Successfully init connection to");
							self.init_ready_connection(conn).await;	
						}

						ConnectionState::WaitingIncomingConnection => {
							// base invariant of order of public keys
							conn.close(1u32.into(), b"peer violated public keys invariant");
							warn!("weird connection event: 
									receive outgoing connecting while current state is WaitingIncomingConnection");
						}

						// possible when this event come early then Disconnect from core was handled 
						ConnectionState::Disconnected => {
							conn.close(1u32.into(), b"can't connect right now");
							debug!("ignored outgoing connection: current state is Disconnected");
						}	
					}
					
					None => {
						warn!(peer = %conn.remote_id(), "ignored outgoing connection: unknown peer");
						conn.close(1u32.into(), b"can't connect to unknown peer");	
					}
				}
			}
			
			ConnectionEvent::IncomingConnection(conn) => {
				match self.state_table.get(&conn.remote_id()) {
					Some(state) => match state {
						ConnectionState::WaitingIncomingConnection => {
							info!(peer = %conn.remote_id(), "Succesfully accept incoming connection from");
							self.init_ready_connection(conn).await;		
						}

						ConnectionState::Connected{task: expired_task, connection: expired_conn, ..} => {
							info!("New incoming connection replace previous task");
							expired_task.abort();
							expired_conn.close(1u32.into(), b"connection is expired: peer open another connection");

							info!(peer = %conn.remote_id(), "Succesfully accept incoming connection from");
							self.init_ready_connection(conn).await;		
						}

						ConnectionState::Connecting(_) => {
							// base invariant of order of public keys
							conn.close(1u32.into(), b"peer violated public keys invariant");
							warn!("weird connection event: receive incoming connection while current state is Connecting");
						}

						// possible when this event come early then Disconnect from core was handled
						ConnectionState::Disconnected => {
							conn.close(1u32.into(), b"can't connect right now");
							debug!("ignored incoming connection: current state is Disconnected");
						}	
					}
					
					None => {
						warn!(peer = %conn.remote_id(), "ignored incoming connection: unknown peer");
						conn.close(1u32.into(), b"can't connect to unknown peer");
					}
				}
			}
			
			ConnectionEvent::Disconnected(pub_key) => {
				match self.state_table.get(&pub_key) {
					Some (state) => match state {
						ConnectionState::Connected{..} => {
							info!(peer = %pub_key, "Disconnected from");
							let _ = self.tx_to_coord.send(
								IrohEvent::DisconnectedFromPeer(pub_key.clone())
							).await;
							self.init_new_connection(pub_key);
						}

						ConnectionState::Connecting(_) => {
							// possible queue {DisconnectCore, ConnectCore, Disconnected from task}
							debug!("data race: receive ConnectionEvent::Disconnected while current state is Connecting");
						}

						ConnectionState::WaitingIncomingConnection => {
							// same as Connecting
							debug!("data race: receive ConnectionEvent::Disconnected 
								    while current state is WaitingIncomingConnection");
						}

						ConnectionState::Disconnected => {
							// also possible queue {DisconnectCore, Disconnect from task}
							debug!("data race: receive ConnectionEvent::Disconnected while current state is Disconnected")
						}
					}
					
					None => {
						warn!(peer = %pub_key, "ignored Disconnected event: unknown peer");
					}
				}
			}
			ConnectionEvent::InternalError => {
				return Err(());
			}
		}

		Ok(())
	}

	#[instrument(skip_all)]
	async fn handle_core_event(&mut self, event: CoreAction) {
		match event {
			CoreAction::SendPacketTo(packet, to) => {
				if let Some(ConnectionState::Connected{tx_packet_channel, ..}) = self.state_table.get(&to) {
					if let Err(e) = tx_packet_channel.try_send(packet) {
					    debug!(to = %to, "Peer queue is full, dropping packet");
					}
					return;
				}
				// it is possible when the core didn't get the message about disconnect in time
				debug!(size = packet.len(), "Drop packet from tun");
			}
		
			CoreAction::ConnectToPeer(pub_key) => {
				match self.state_table.get(&pub_key) {
					Some(state) => match state {
						ConnectionState::Disconnected => {
							self.init_new_connection(pub_key);
						}

						ConnectionState::Connected{..} => {
							warn!("weird action from core: ConnectToPeer while current state is Connected");
						}

						ConnectionState::Connecting(_) => {
							warn!("weird action from core: ConnectToPeer while current state is Connecting");
						}

						ConnectionState::WaitingIncomingConnection => {
							warn!("weird action from core: ConnectToPeer while current state is WaitingIncomingConnection");
						}
					}
					
					None => {
						warn!(peer = %pub_key, "ignored ConnectToPeer action: unknown peer");
					}
				}
			}
			 
			CoreAction::DisconnectFromPeer(pub_key) => {
				match self.state_table.get(&pub_key) {
					Some(state) => match state {
						ConnectionState::Connected{task: old_task, connection: old_conn, ..} => {
							old_task.abort();
							old_conn.close(1u32.into(), b"disconnect from peer core action");
							let _ = self.tx_to_coord.send(
								IrohEvent::DisconnectedFromPeer(pub_key)
							).await;
						}

						ConnectionState::Connecting(conn_task) => {
							conn_task.abort();
						}

						_ => {}						
					}
					
					None => {
						warn!(peer = %pub_key, "ignored DisconnectFromPeer action: unknown peer");
					}
				}	

				self.state_table.insert(pub_key.clone(), ConnectionState::Disconnected);
			}
		}
	}

	// new state: Connecting or WaitingIncomingConnection
	fn init_new_connection(&mut self, pub_key: PublicKey) {
		if self.endpoint.id() < pub_key {
			self.state_table.insert(pub_key, ConnectionState::WaitingIncomingConnection);
			return;
		}

		let task = tokio::spawn(
			Self::connect_to_peer(self.endpoint.clone(),
								  pub_key.clone(),
								  self.tx_to_manager.clone())
		);

		self.state_table.insert(pub_key, ConnectionState::Connecting(task));
	}

	// new state: Connected
	async fn init_ready_connection(&mut self, conn: Connection) {
		let _ = self.tx_to_coord.send(IrohEvent::ConnectedToPeer(conn.remote_id())).await;
		let (tx_packet_channel, rx_packet_channel) = mpsc::channel(CHANNEL_CAPACITY);
		let task = tokio::spawn(
			Self::on_peer_connected(self.tx_to_coord.clone(),
									rx_packet_channel,
									conn.clone(),
									self.tx_to_manager.clone())
		);
		self.state_table.insert(conn.remote_id(), ConnectionState::Connected{
			task: task,
			connection: conn,
			tx_packet_channel,
		});
	}
	
	fn init(&mut self) {
		for pub_key in &self.peers {
			if *pub_key > self.endpoint.id() {
				self.state_table.insert(pub_key.clone(), ConnectionState::WaitingIncomingConnection);
				continue;
			}

			let task = tokio::spawn(
				Self::connect_to_peer(self.endpoint.clone(), pub_key.clone(), self.tx_to_manager.clone())	
			);
			self.state_table.insert(pub_key.clone(), ConnectionState::Connecting(task));
		}
		
		tokio::spawn(
			Self::accept_connections(self.endpoint.clone(), 
									 std::mem::take(&mut self.peers), 
									 self.tx_to_manager.clone())
		);
	}

	#[instrument(skip_all, fields(peer = %connection.remote_id()))]
	async fn on_peer_connected(tx_packet_channel: mpsc::Sender<IrohEvent>,
							   mut rx_packet_channel: mpsc::Receiver<Bytes>,
							   connection: Connection,
							   tx_to_manager: mpsc::Sender<ConnectionEvent>) 
	{
		info!("Task started");
		loop {
			tokio::select! {
				result = connection.read_datagram() => {
					match result {
						Ok(packet) => {
							trace!(size = packet.len(), "Received packet from peer");
							if let Err(e) = tx_packet_channel.try_send(
								IrohEvent::RecvPacketFrom(packet, connection.remote_id())
							) {
							    debug!("Coordinator queue is full, dropping packet from Iroh peer");
							}
						}
						Err(e) => {
							info!(error = %e, "Connection closed by remote peer or network error");
							let _ = tx_to_manager.send(
								ConnectionEvent::Disconnected(connection.remote_id())
							).await;
							return;
						}
					}
				}

				result = rx_packet_channel.recv() => {
					match result {
						Some(packet) => {
							trace!(size = packet.len(), "Received packet from tun");
							if let Err(e) = connection.send_datagram(packet) {
	                            debug!(error = %e, "Failed to send outgoing packet");
	                            match e {
	                            	SendDatagramError::TooLarge => {},
	                            	_ => {
	                            		let _ = tx_to_manager.send(
	                            			ConnectionEvent::Disconnected(connection.remote_id())
	                            		).await;
										return;
	                            	}
	                            }
	                        }
						}
						None => {
							warn!("Packet channel with manager closed, shutting down session task");
	                        return;
						}
					}
				}
			}
		}
	}

	// 'to' must be in 'peers', 'endpoint.pub_key' must be greater than 'to'
	#[instrument(skip_all, fields(peer = %to))]
	async fn connect_to_peer(endpoint: Endpoint, to: PublicKey, tx_to_manager: mpsc::Sender<ConnectionEvent>) {
		info!("Starting connection attempts");
		loop {
			match endpoint.connect(to, ALPN).await {
				Ok(conn) => {
					let _ = tx_to_manager.send(ConnectionEvent::OutgoingConnection(conn)).await;
					return;
				}
				Err(e) => {
					debug!(error = %e, "Connection failed, retrying in 1s");
					if let Ok(dns_resolver) = endpoint.dns_resolver() {
						dns_resolver.clear_cache().await;
					}
					sleep(Duration::from_secs(1)).await;
				}
			}
		}
	}

	#[instrument(skip_all)]
	async fn accept_connections(endpoint: Endpoint, 
							    peers: HashSet<PublicKey>, 
							    tx_to_manager: mpsc::Sender<ConnectionEvent>) 
	{
		info!("Started listening for incoming connections");
		while let Some(incoming) = endpoint.accept().await {
			match incoming.accept() {
				Ok(ac) => {
					let tx_to_manager_clone = tx_to_manager.clone();
					tokio::spawn(async move {
						match ac.await {
							Ok(conn) => {
								let _ = tx_to_manager_clone.send(ConnectionEvent::IncomingConnection(conn)).await;
							}
							
							Err(e) => debug!(error = %e, "Connecting error"),
						}
					});
				}
				
				Err(e) => debug!(error = %e, "Failed to accept incoming connection"),
			}
		}
	}
}


// =====================
// TESTS
// =====================

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use std::collections::HashSet;
    use tracing_subscriber::{fmt, EnvFilter};

    fn init_logging() {
        let filter = EnvFilter::new("error,mesh_network=debug");
        let _ = fmt().with_env_filter(filter).with_test_writer().try_init();
    }

    #[tokio::test]
    async fn test_n_nodes_resilient_mesh() {
        init_logging();

        let n: usize = std::env::var("MESH_NODES")
            .unwrap_or_else(|_| "25".to_string())
            .parse()
            .expect("Variable MESH_NODES must be a number");
    
        let timeout_secs: u64 = std::env::var("MESH_TIMEOUT")
            .unwrap_or_else(|_| "180".to_string())
            .parse()
            .expect("Variable MESH_TIMEOUT must be a number");

        let mut keys = Vec::new();
        for _ in 0..n {
            keys.push(SecretKey::generate());
        }
        let peers: HashSet<PublicKey> = keys.iter().map(|k| k.public()).collect();

        let (tx_global_events, mut rx_global_events) = mpsc::channel(1000);
        let mut keep_alive_channels = Vec::new();
        let mut iroh_nodes = Vec::new();

        for secret_key in &keys {
            let (tx_to_coord, mut rx_from_iroh) = mpsc::channel(8192);
            let (tx_from_coord, rx_from_coord) = mpsc::channel(8192);
            keep_alive_channels.push(tx_from_coord);

            let node_pub_key = secret_key.public();
            let tx_global_clone = tx_global_events.clone();

            tokio::spawn(async move {
                while let Some(event) = rx_from_iroh.recv().await {
                    let _ = tx_global_clone.send((node_pub_key, event)).await;
                }
            });

            let mut node_peers = peers.clone();
            node_peers.remove(&node_pub_key);

            let iroh_node = Iroh::new(
                secret_key.clone(),
                node_peers, 
                tx_to_coord,
                rx_from_coord,
                0, 
            ).await.expect("Failed to init");

            iroh_nodes.push(iroh_node);
        }

        for node in iroh_nodes {
            tokio::spawn(node.run());
        }

        let expected_connections = n * (n - 1); 
        
        let mut active_connections = HashSet::new();

        let result = timeout(Duration::from_secs(timeout_secs), async {
            while let Some((node_id, event)) = rx_global_events.recv().await {
                match event {
                    IrohEvent::ConnectedToPeer(peer_id) => {
                        active_connections.insert((node_id, peer_id));
                        println!("✅ {} -> {} (Ailve: {}/{})", 
                            node_id, peer_id, active_connections.len(), expected_connections);
                        
                        if active_connections.len() == expected_connections {
                            break;
                        }
                    }
                    IrohEvent::DisconnectedFromPeer(peer_id) => {
                        if active_connections.remove(&(node_id, peer_id)) {
                            println!("❌ {} disconnected from {} (Alive: {}/{})", 
                                node_id, peer_id, active_connections.len(), expected_connections);
                        }
                    }
                    _ => {}
                }
            }
        }).await;

        assert!(
            result.is_ok(),
            "Timeout! Alive connections: {}/{}",
            active_connections.len(),
            expected_connections
        );

        for node_key in &peers {
            let mut expected_neighbors = peers.clone();
            expected_neighbors.remove(node_key);

            let actual_neighbors: HashSet<PublicKey> = active_connections
                .iter()
                .filter_map(|(src, dst)| if src == node_key { Some(*dst) } else { None })
                .collect();

            assert_eq!(
                actual_neighbors.len(),
                n - 1,
                "ERROR: Node {} have only {} instead of expecting {}",
                node_key, actual_neighbors.len(), n - 1
            );

            assert_eq!(
                actual_neighbors,
                expected_neighbors,
                "White list error: Node {} connect to incorrect neighbours!\nExpected: {:?}\nReality: {:?}",
                node_key, expected_neighbors, actual_neighbors
            );
        }
    }
}
