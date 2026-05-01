use iroh::{SecretKey, PublicKey};
use iroh::endpoint::{Endpoint, presets, Connection, InvalidSocketAddr, BindError, IncomingAddr::Relay};
use bytes::Bytes;
use tokio::sync::mpsc;
use std::collections::{HashSet, HashMap};
use tokio::time::{sleep, Duration};

const ALPN: &[u8] = b"iroh_vpn";
const CHANNEL_CAPACITY: usize = 8192;

pub struct Iroh {
	endpoint: Endpoint,
	tx_to_coord: mpsc::Sender<IrohEvent>,
	rx_from_coord: mpsc::Receiver<CoreEvent>,
	state_table: HashMap<PublicKey, Option<ConnectionState>>,
	peers: HashSet<PublicKey>,
}

struct ConnectionState {
	connection: Connection,
	tx_packet: mpsc::Sender<Bytes>,
}

#[derive(Debug, PartialEq)]
pub enum IrohEvent {
	ConnectedToPeer(PublicKey),
	DisconnectedFromPeer(PublicKey),
	RecvPacketFrom(Bytes, PublicKey),
}

#[derive(Debug, PartialEq)]
pub enum CoreEvent {
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
	InternalError, // bad idea
}

impl Iroh {
	pub async fn new(secret_key: SecretKey, 
			   		 peers: HashSet<PublicKey>, 
			   		 tx_to_coord: mpsc::Sender<IrohEvent>,
			   	  	 rx_from_coord: mpsc::Receiver<CoreEvent>,
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
		
		Ok(Iroh {
			endpoint,
			tx_to_coord,
			rx_from_coord,
			state_table,
			peers,
		})
	}

	pub async fn run(mut self) {
		let mut rx_from_tasks = self.init();		
		// event loop
		loop {
			tokio::select! {
				result = rx_from_tasks.recv() => {
					match result {
						Some(event) => {
							self.handle_conn_event(event).await;
						}
						None => {} // handle this
					}
				}

				result = self.rx_from_coord.recv() => {
					match result {
						Some(event) => {
							self.handle_core_event(event).await;
						}
						None => {} // handle this
					}
				}
			}
		}
	}

	async fn handle_conn_event(&mut self, event: ConnectionEvent) {
		// TODO
	}

	async fn handle_core_event(&mut self, event: CoreEvent) {
		// TODO
	}
	
	fn init(&mut self) -> mpsc::Receiver<ConnectionEvent> {
		let (tx_to_manager, mut rx_from_tasks) = mpsc::channel(CHANNEL_CAPACITY);
		tokio::spawn(
			Self::accept_connections(self.endpoint.clone(), 
									 std::mem::take(&mut self.peers), 
									 tx_to_manager.clone())
		);
		for (pub_key, _) in &self.state_table {
			if *pub_key > self.endpoint.id() {
				continue;
			}

			tokio::spawn(
				Self::connect_to_peer(self.endpoint.clone(), pub_key.clone(), tx_to_manager.clone())	
			);
		}

		rx_from_tasks
	}

	async fn on_peer_connected(tx_packet_channel: mpsc::Sender<IrohEvent>,
							   mut rx_packet_channel: mpsc::Receiver<Bytes>,
							   connection: Connection,
							   tx_to_manager: mpsc::Sender<ConnectionEvent>) 
	{
		// TODO: tracing logs
		loop {
			tokio::select! {
				result = connection.read_datagram() => {
					match result {
						Ok(packet) => {
							let _ = tx_packet_channel.send(
								IrohEvent::RecvPacketFrom(packet, connection.remote_id()
							)).await;
						}
						Err(_err) => { // log this, lost connection
							let _ = tx_to_manager.send(
								ConnectionEvent::Disconnected(connection.remote_id()
							)).await;
							return;
						}
					}
				}

				result = rx_packet_channel.recv() => {
					match result {
						Some(packet) => {
							match connection.send_datagram(packet) {
								Ok(()) => {},
								Err(_) => {} // handle different errors
							}
						}
						None => {} // manager dead, handle this and logging
					}
				}
			}
		}
	}

	// 'to' must be in 'peers', 'endpoint.pub_key' must be greater than 'to'
	async fn connect_to_peer(endpoint: Endpoint, to: PublicKey, tx_to_manager: mpsc::Sender<ConnectionEvent>) {
		loop {
			// TODO: log error / success
			match endpoint.connect(to, ALPN).await {
				Ok(conn) => {
					let _ = tx_to_manager.send(ConnectionEvent::OutgoingConnection(conn)).await;
					return;
				}
				Err(_) => {
					sleep(Duration::from_secs(1)).await;
				}
			}
		}
	}

	async fn accept_connections(endpoint: Endpoint, 
							    peers: HashSet<PublicKey>, 
							    tx_to_manager: mpsc::Sender<ConnectionEvent>) 
	{
		while let Some(incoming) = endpoint.accept().await {
			let pub_key = match incoming.remote_addr() {
				Relay {endpoint_id: pub_key, ..} => pub_key,
				_ => { // weird
					let _ = tx_to_manager.send(ConnectionEvent::InternalError).await;
					return;
				}
			};

			// log failed conn
			if !peers.contains(&pub_key) || pub_key < endpoint.id() {
				continue;
			}

			// TODO: log error / successful connection
			match incoming.accept() {
				Ok(ac) => {
					match ac.await {
						Ok(conn) => { // log
							let _ = tx_to_manager.send(ConnectionEvent::IncomingConnection(conn)).await;
							continue;
						}
						Err(_) => {} // log
					}
				}
				Err(_) => {} // log
			}
		}
	}
}
