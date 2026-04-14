use iroh::PublicKey;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;

struct VpnCore {
	max_packet_size: usize,
	ipv4_addr: Ipv4Addr,
	peer_connections: HashMap<PublicKey, bool>,
	ip_pk: HashMap<Ipv4Addr, PublicKey>,
	packet_queues: HashMap<PublicKey, VecDeque<Vec<u8>>>
}

#[derive(Debug, PartialEq)]
pub enum Action {
	ConnectToPeer(PublicKey),
	DisconnectFromPeer(PublicKey),
	SendPacketTo(Vec<u8>, PublicKey),
	RecvPacketFrom(Vec<u8>, PublicKey),
	NoAction(IgnoreReason)
}

#[derive(Debug, PartialEq)]
pub enum IgnoreReason {
	UnknownPeer,
	AlreadyConnected,
	AlreadyDisconnected,
	SendPacketError(SendPacketError),
	RecvPacketError(RecvPacketError),
	ConnectionNotOpen
}

#[derive(Debug, PartialEq)]
pub enum SendPacketError {
	IncorrectSrcIp,
	UnknownDestIp,
	MtuError,
	IncorrectIpVersion,
	IncorrectTTL
}

#[derive(Debug, PartialEq)]
pub enum RecvPacketError {
	IncorrectSrcIp,
	UnknownDestIp,
	MtuError,
	IncorrectIpVersion,
	IncorrectTTL
}

impl VpnCore {
	pub fn new(ipv4_addr: Ipv4Addr, ip_pk: HashMap<Ipv4Addr, PublicKey>, max_packet_size: usize) -> VpnCore {
		let mut peer_connections: HashMap<PublicKey, bool> = HashMap::new();
		let mut packet_queues: HashMap<PublicKey, VecDeque<Vec<u8>>> = HashMap::new();
		for pair in &ip_pk {
			peer_connections.insert(pair.1.clone(), false);
			packet_queues.insert(pair.1.clone(), VecDeque::<Vec<u8>>::new());
		}
		
		return VpnCore {
			ipv4_addr,
			peer_connections,
			ip_pk,
			packet_queues,
			max_packet_size
		};
	}

	pub fn verify_connection(&self, pub_key: &PublicKey) -> bool {
		return self.is_neighbour(pub_key);
	}

	pub fn peer_connected(&mut self, node: &PublicKey) -> Vec<Action> {
		if !self.verify_connection(node) {
			return vec![Action::DisconnectFromPeer(node.clone())];
		}

		if self.is_connect_open(node) {
			return vec![Action::NoAction(IgnoreReason::AlreadyConnected)];
		}

		let mut actions: Vec<Action> = Vec::new();
		// fix unwrap() everywhere
		*self.peer_connections.get_mut(node).unwrap() = true;
		while let Some(packet) = self.packet_queues.get_mut(node).unwrap().pop_front() {
			actions.push(Action::SendPacketTo(packet, node.clone()));
		}
		return actions;
	}

	pub fn peer_disconnected(&mut self, node: &PublicKey) -> Vec<Action> {
		if !self.verify_connection(node) {
			return vec![Action::NoAction(IgnoreReason::UnknownPeer)];
		}

		if !self.is_connect_open(node) {
			return vec![Action::NoAction(IgnoreReason::AlreadyDisconnected)];
		}

		*self.peer_connections.get_mut(node).unwrap() = false;
		return vec![];
	}

	// packet - ipv4 packet
	pub fn send_packet(&mut self, packet: Vec<u8>) -> Vec<Action> {
		let result = self.verify_send_packet(&packet[..]);
		match result {
			Ok(dest_ip) => {
				let pub_key = self.ip_pk[&dest_ip];
				if self.is_connect_open(&pub_key) {
					return vec![Action::SendPacketTo(packet, pub_key)];
				} else {
					let queue = self.packet_queues.get_mut(&pub_key).unwrap();
					// make global constant instead of 1000
					if queue.len() >= 1000 {
						queue.pop_front();
					}
					queue.push_back(packet);
					return vec![Action::NoAction(IgnoreReason::ConnectionNotOpen)];
				}
			}
			Err(e) => {
				return vec![Action::NoAction(IgnoreReason::SendPacketError(e))];
			}
		}
	}

	fn verify_send_packet(&self, packet: &[u8]) -> Result<Ipv4Addr, SendPacketError> {
		// possible problems
		// 1. wrong src ip
		// 2. dest ip not in list
		// 3. mtu check
		// 4. ip version
		// 5. ttl = 0
		// TODO: total lenght check (slice by OS)
		// TODO: check too small packets!!!

		let ip_version = packet[0] >> 4;
		if ip_version != 4 {
			return Err(SendPacketError::IncorrectIpVersion);
		}

		if packet.len() > self.max_packet_size {
			return Err(SendPacketError::MtuError);
		}

		let ttl = packet[8];
		if ttl == 0 {
			return Err(SendPacketError::IncorrectTTL);
		}

		let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
		if src_ip != self.ipv4_addr {
			return Err(SendPacketError::IncorrectSrcIp);
		}

		let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
		if !self.is_neighbour_ipv4(&dest_ip) {
			return Err(SendPacketError::UnknownDestIp);
		}

		return Ok(dest_ip);
	}

	fn is_neighbour(&self, node: &PublicKey) -> bool {
		return self.peer_connections.contains_key(node);
	}

	fn is_neighbour_ipv4(&self, node: &Ipv4Addr) -> bool {
		return self.ip_pk.contains_key(node);
	}

	fn is_connect_open(&self, node: &PublicKey) -> bool {
		return self.peer_connections[node];
	}

}
