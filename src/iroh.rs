use iroh::{SecretKey, PublicKey};
use iroh::endpoint::{Endpoint, presets, Connection, InvalidSocketAddr, BindError, SendDatagramError};
use bytes::Bytes;
use tokio::sync::mpsc;
use std::collections::{HashSet, HashMap};
use tokio::time::{sleep, Duration};
use tokio::task::JoinHandle;
use tracing::{info, warn, error, debug, trace, instrument};
use std::fmt;
use std::error::Error;

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
						// in queue possible 2 outgoing
						// for example {DisconnectCore, ConnectCore,
						// ... here already produced another outgoing connection from another task ..., 
						// OutgoingConnection}
						
						// so it is comes down to 
						// {OutgoingConn(pub_key_x), OutgoingConn(pub_key_x)}
						// so other peer accept the second one probably
						
						// can he accept the first one??? - no, because the first one change dist peer state to connected,
						// after that he receive the another conn, accept it

						// he definitely accept the second one
						// so here we can do the same - accept the second if we already connected  
						ConnectionState::Connecting(_) => {
							self.init_ready_connection(conn).await;
						}

						ConnectionState::Connected{task: expired_task, connection: expired_conn, ..} => {
							info!("data race: receive outgoing connecting while current state is Connected");
							expired_task.abort();
							expired_conn.close(1u32.into(), b"connection is expired: data race resolver");

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
							// {DisconnectCore, ConnectCore - state = Waiting, IncomingConnection} - it's ok
							// in that queue can be multiple Incoming, so just accept the latest one
							self.init_ready_connection(conn).await;		
						}

						ConnectionState::Connected{task: expired_task, connection: expired_conn, ..} => {
							// already handle Incoming, so in queue 2 incoming, 
							// this should be impossible, without expired connection or data race on another peer

							// also possible ddos
							info!("New incoming connection replace previous task");
							expired_task.abort();
							expired_conn.close(1u32.into(), b"connection is expired: peer open another connection");

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
			
			// invariants done
			ConnectionEvent::Disconnected(pub_key) => {
				match self.state_table.get(&pub_key) {
					Some (state) => match state {
						ConnectionState::Connected{..} => {
							// {DisconnectCore, ConnectCore, already connected (it's not possible,
							// because we handle the ConnctedToPeer after Disconnect from task), Disconnect from task}
							// everything ok, it's correct disconnect for CURRENT connection
							let _ = self.tx_to_coord.send(
								IrohEvent::DisconnectedFromPeer(pub_key.clone())
							).await;
							self.init_new_connection(pub_key);
						}

						ConnectionState::Connecting(_) => {
							// possible queue {DisconnectCore, ConnectCore, Disconnected from task}
							// so nothing to do
							debug!("data race: receive ConnectionEvent::Disconnected while current state is Connecting");
						}

						ConnectionState::WaitingIncomingConnection => {
							// same as Connecting
							debug!("data race: receive ConnectionEvent::Disconnected 
								    while current state is WaitingIncomingConnection");
						}

						ConnectionState::Disconnected => {
							// also possible {DisconnectCore, Disconnect from task}
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

				let _ = self.tx_to_coord.send(
					IrohEvent::DisconnectedFromPeer(pub_key)
				).await;
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

							if !peers.contains(&pub_key) {
								debug!(peer = %pub_key, "Rejected connection (not in peers list)");
								continue;
							}

							if pub_key < endpoint.id() {
								debug!(peer = %pub_key, "Rejected connection (order invariant of public keys are incorrect)");
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
