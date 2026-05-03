use iroh::{SecretKey, PublicKey};
use iroh::endpoint::{Endpoint, presets, Connection, InvalidSocketAddr, BindError, SendDatagramError};
use bytes::Bytes;
use tokio::sync::mpsc;
use std::collections::{HashSet, HashMap};
use tokio::time::{sleep, Duration};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, debug, trace, instrument};

const ALPN: &[u8] = b"iroh_vpn";
const CHANNEL_CAPACITY: usize = 8192;

pub struct Iroh {
	endpoint: Endpoint,
	tx_to_coord: mpsc::Sender<IrohEvent>,
	rx_from_coord: mpsc::Receiver<CoreAction>,
	tx_to_manager: mpsc::Sender<ConnectionEvent>,
	rx_from_tasks: mpsc::Receiver<ConnectionEvent>,
	state_table: HashMap<PublicKey, Option<ConnectionState>>,
	peers: HashSet<PublicKey>,
}

struct ConnectionState {
	task: JoinHandle<()>,
	tx_packet: mpsc::Sender<Bytes>,
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

impl Iroh {
	pub async fn new(secret_key: SecretKey, 
			   		 peers: HashSet<PublicKey>, 
			   		 tx_to_coord: mpsc::Sender<IrohEvent>,
			   	  	 rx_from_coord: mpsc::Receiver<CoreAction>,
			   		 listen_port: u16) 
		-> Result<Self, InitError> 
	{
		let mut state_table: HashMap<PublicKey, Option<ConnectionState>> = HashMap::with_capacity(peers.len());
		for pub_key in &peers {
			state_table.insert(pub_key.clone(), None);
		}

		let builder = Endpoint::builder(presets::N0)
		    .secret_key(secret_key)
		    .alpns(vec![ALPN.to_vec()])
		    .bind_addr("0.0.0.0:".to_string() + &listen_port.to_string())
		    .map_err(InitError::BindAddrError)?;
		
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

	async fn handle_conn_event(&mut self, event: ConnectionEvent) -> Result<(), ()> {
		match event {
			ConnectionEvent::OutgoingConnection(conn) => {
				self.init_connection(conn).await;
			}
			ConnectionEvent::IncomingConnection(conn) => {
				if let Some(Some(ConnectionState {task: old_task, ..})) = self.state_table.get(&conn.remote_id()) {
					old_task.abort();
					info!("New incoming connection replace previous task");
				}

				self.init_connection(conn).await;
			}
			ConnectionEvent::Disconnected(pub_key) => {
				let _ = self.tx_to_coord.send(
					IrohEvent::DisconnectedFromPeer(pub_key.clone())
				).await;
				self.state_table.insert(pub_key.clone(), None);

				if self.endpoint.id() < pub_key || !self.state_table.contains_key(&pub_key) {
					return Ok(());
				}
				tokio::spawn(
					Self::connect_to_peer(self.endpoint.clone(),
										  pub_key,
										  self.tx_to_manager.clone())
				);
			}
			ConnectionEvent::InternalError => {
				return Err(());
			}
		}

		Ok(())
	}

	async fn handle_core_event(&mut self, event: CoreAction) {
		match event {
			CoreAction::SendPacketTo(packet, to) => {
				if let Some(Some(ConnectionState {tx_packet, ..})) = self.state_table.get(&to) {
					if let Err(e) = tx_packet.try_send(packet) {
					    debug!(to = %to, "Peer queue is full, dropping packet");
					}
					return;
				}
				// it is possible when the core didn't get the message about disconnect in time
				debug!(size = packet.len(), "Drop packet from tun");
			}
			
			// impossible in current implementation of iroh + core connect managment 
			CoreAction::DisconnectFromPeer(pub_key) => {
				if let Some(Some(ConnectionState {task: old_task, ..})) = self.state_table.get(&pub_key) {
					old_task.abort();
				}

				let _ = self.state_table.remove(&pub_key); // incorrect state from core

				let _ = self.tx_to_coord.send(
					IrohEvent::DisconnectedFromPeer(pub_key)
				).await;
			}
		}
	}

	async fn init_connection(&mut self, conn: Connection) {
		let _ = self.tx_to_coord.send(IrohEvent::ConnectedToPeer(conn.remote_id())).await;
		let (tx_packet, rx_packet_channel) = mpsc::channel(CHANNEL_CAPACITY);
		let task = tokio::spawn(
			Self::on_peer_connected(self.tx_to_coord.clone(),
									rx_packet_channel,
									conn.clone(),
									self.tx_to_manager.clone())
		);
		self.state_table.insert(conn.remote_id(), Some(ConnectionState {
			task,
			tx_packet,
		}));
	}
	
	fn init(&mut self) {
		tokio::spawn(
			Self::accept_connections(self.endpoint.clone(), 
									 std::mem::take(&mut self.peers), 
									 self.tx_to_manager.clone())
		);
		for (pub_key, _) in &self.state_table {
			if *pub_key > self.endpoint.id() {
				continue;
			}

			tokio::spawn(
				Self::connect_to_peer(self.endpoint.clone(), pub_key.clone(), self.tx_to_manager.clone())	
			);
		}
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
					info!("Successfully connected");
					let _ = tx_to_manager.send(ConnectionEvent::OutgoingConnection(conn)).await;
					return;
				}
				Err(e) => {
					debug!(error = %e, "Connection failed, retrying in 1s");
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
					match ac.await {
						Ok(conn) => {
							// check connection
							let pub_key = conn.remote_id();

							if !peers.contains(&pub_key) || pub_key < endpoint.id() {
								debug!(peer = %pub_key, "Rejected connection (not in peers list or order check failed)");
								continue;
							}			

							info!(peer = %pub_key, "Accepted new incoming connection");
							let _ = tx_to_manager.send(ConnectionEvent::IncomingConnection(conn)).await;
							continue;
						}
						Err(e) => debug!(error = %e, "Connecting error"),
					}
				}
				Err(e) => debug!(error = %e, "Failed to accept incoming connection"),
			}
		}
	}
}
