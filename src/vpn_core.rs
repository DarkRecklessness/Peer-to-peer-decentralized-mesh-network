use iroh::PublicKey;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::fmt;
use bytes::Bytes;

const MAX_PACKETS_IN_QUEUE: usize = 1000;

struct VpnCore {
	max_packet_size: usize,
	ipv4_addr: Ipv4Addr,
	peers: HashMap<PublicKey, PeerState>,
	ip_pk: HashMap<Ipv4Addr, PublicKey>,
}

struct PeerState {
	is_connected: bool,
	ipv4_addr: Ipv4Addr,
	packet_queue: VecDeque<Bytes>,
}

#[derive(Debug, PartialEq)]
pub enum Action {
	ConnectToPeer(PublicKey),
	DisconnectFromPeer(PublicKey),
	SendPacketTo(Bytes, PublicKey),
	WriteToTun(Bytes),
	NoAction(LogEvent),
}

#[derive(Debug, PartialEq)]
pub enum LogEvent {
	UnknownPeer,
	AlreadyConnected,
	AlreadyDisconnected,
	SendPacketError(SendPacketError),
	RecvPacketError(RecvPacketError),
	ConnectionNotOpen,
	InternalStateError,
	PacketBuffered,
	PacketQueueOverflow,
}

#[derive(Debug, PartialEq)]
pub enum SendPacketError {
	IncorrectSrcIp,
	UnknownDestIp,
	MtuError,
	IncorrectIpVersion,
	IncorrectTTL,
	TooSmallPacket,
	BrokenPackage,
}

#[derive(Debug, PartialEq)]
pub enum RecvPacketError {
	UnknownSrcIp,
	IncorrectDestIp,
	MtuError,
	IncorrectIpVersion,
	Spoofing,
	TooSmallPacket,
	BrokenPackage,
	// Spam,
}

impl fmt::Display for Action {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Action::ConnectToPeer(pub_key) => write!(f, "Connect to: {}", pub_key),
			Action::DisconnectFromPeer(pub_key) => write!(f, "Disconnect from: {}", pub_key),
			Action::SendPacketTo(packet, pub_key) => write!(f, "Send {} bytes to {}", packet.len(), pub_key),
            Action::WriteToTun(packet) => write!(f, "Write {} bytes to TUN", packet.len()),
            Action::NoAction(reason) => write!(f, "Ignored -> {}", reason),
		}
	}
}

impl fmt::Display for LogEvent {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			LogEvent::UnknownPeer => write!(f, "Unknown peer"),
			LogEvent::AlreadyConnected => write!(f, "Peers are already connected"),
			LogEvent::AlreadyDisconnected => write!(f, "Peers are already disconnected"),
			LogEvent::SendPacketError(e) => write!(f, "Dropped outgoing packet: {}", e),
			LogEvent::RecvPacketError(e) => write!(f, "Dropped incoming packet: {}", e),
			LogEvent::ConnectionNotOpen => write!(f, "Connection is not open"),
			LogEvent::InternalStateError => write!(f, "Internal State Error"),
			LogEvent::PacketBuffered => write!(f, "Packet buffered (connection is not open yet)"),
			LogEvent::PacketQueueOverflow => write!(f, "Queue overflow: oldest packet dropped"),
		}
	}
}

impl fmt::Display for SendPacketError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			SendPacketError::IncorrectSrcIp => write!(f, "source IP does not match the assigned tun IP"),
            SendPacketError::UnknownDestIp => write!(f, "destination IP is not found in the routing table"),
            SendPacketError::MtuError => write!(f, "packet length exceeds the MTU limit"),
            SendPacketError::IncorrectIpVersion => write!(f, "unsupported IP version (only IPv4 is allowed)"),
            SendPacketError::IncorrectTTL => write!(f, "TTL is 0 or invalid"),
            SendPacketError::TooSmallPacket => write!(f, "packet is too small to contain a valid IPv4 header"),
            SendPacketError::BrokenPackage => write!(f, "incorrect length of packet"),
		}
	}
}

impl fmt::Display for RecvPacketError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			RecvPacketError::UnknownSrcIp => write!(f, "source IP is not found in the routing table"),
            RecvPacketError::IncorrectDestIp => write!(f, "destination IP does not match local tun IP"),
            RecvPacketError::MtuError => write!(f, "received packet length exceeds the MTU limit"),
            RecvPacketError::IncorrectIpVersion => write!(f, "unsupported IP version (only IPv4 is allowed)"),
            RecvPacketError::Spoofing => write!(f, "anti-spoofing triggered: Source IP does not match the sender's public key"),
            RecvPacketError::TooSmallPacket => write!(f, "received packet is too small to contain a valid IPv4 header"),
            RecvPacketError::BrokenPackage => write!(f, "incorrect length of packet"),
		}
	}
}

impl VpnCore {
	pub fn new(ipv4_addr: Ipv4Addr, ip_pk: HashMap<Ipv4Addr, PublicKey>, max_packet_size: usize) -> VpnCore {
		let mut peers: HashMap<PublicKey, PeerState> = HashMap::new();
		for (ip, pub_key) in &ip_pk {
			peers.insert(*pub_key, PeerState {
				is_connected: false,
				ipv4_addr: *ip,
				packet_queue: VecDeque::<Bytes>::new(),
			});
		}
		
		VpnCore {
			ipv4_addr,
			ip_pk,
			max_packet_size,
			peers
		}
	}

	pub fn verify_connection(&self, pub_key: &PublicKey) -> bool {
		self.is_neighbour(pub_key)
	}

	pub fn on_peer_connected(&mut self, node: &PublicKey) -> Vec<Action> {
		if !self.verify_connection(node) {
			return vec![Action::DisconnectFromPeer(node.clone())];
		}

		if self.is_connect_open(node) {
			return vec![Action::NoAction(LogEvent::AlreadyConnected)];
		}

		if let Some(peer) = self.peers.get_mut(node) {
			peer.is_connected = true;
			return peer.packet_queue
			           .drain(..)
			           .map(|packet| Action::SendPacketTo(packet, node.clone()))
			           .collect();
		}
		vec![Action::NoAction(LogEvent::InternalStateError)]
	}

	pub fn on_peer_disconnected(&mut self, node: &PublicKey) -> Vec<Action> {
		if !self.verify_connection(node) {
			return vec![Action::NoAction(LogEvent::UnknownPeer)];
		}

		if !self.is_connect_open(node) {
			return vec![Action::NoAction(LogEvent::AlreadyDisconnected)];
		}

		if let Some(peer) = self.peers.get_mut(node) {
			peer.is_connected = false;
			return vec![];
		}
		vec![Action::NoAction(LogEvent::InternalStateError)]
	}

	// packet - ipv4 packet
	pub fn send_packet(&mut self, packet: Bytes) -> Vec<Action> {
		let result = self.verify_send_packet(&packet);
		match result {
			Ok(dest_ip) => {
				if let Some(pub_key) = self.ip_pk.get(&dest_ip) {
					if self.is_connect_open(pub_key) {
						return vec![Action::SendPacketTo(packet, pub_key.clone())];
					} else {
						if let Some(peer) = self.peers.get_mut(pub_key) {
							let queue = &mut peer.packet_queue;
							if queue.len() >= MAX_PACKETS_IN_QUEUE {
								queue.pop_front();
							}
							queue.push_back(packet);
						}
						return vec![Action::NoAction(LogEvent::ConnectionNotOpen)];
					}
				}
				return vec![Action::NoAction(LogEvent::SendPacketError(SendPacketError::UnknownDestIp))];
			}
			Err(e) => {
				return vec![Action::NoAction(LogEvent::SendPacketError(e))];
			}
		}
	}

	pub fn recv_packet(&self, packet: Bytes, from: &PublicKey) -> Vec<Action> {
		let result = self.verify_recv_packet(&packet, from);
		match result {
			Ok(_) => {
				return vec![Action::WriteToTun(packet)];
			}
			Err(e) => {
				return vec![Action::NoAction(LogEvent::RecvPacketError(e))];
			}
		}
	}

	fn verify_send_packet(&self, packet: &Bytes) -> Result<Ipv4Addr, SendPacketError> {
		if packet.len() < 20 {
			return Err(SendPacketError::TooSmallPacket);
		}

		let ip_version = packet[0] >> 4;
		if ip_version != 4 {
			return Err(SendPacketError::IncorrectIpVersion);
		}

		if packet.len() > self.max_packet_size {
			return Err(SendPacketError::MtuError);
		}

		let total_length = ((packet[2] as usize) << 8) | (packet[3] as usize);
		if packet.len() < total_length {
			return Err(SendPacketError::BrokenPackage);
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

		Ok(dest_ip)
	}

	fn verify_recv_packet(&self, packet: &Bytes, from: &PublicKey) -> Result<(), RecvPacketError> {
		if packet.len() < 20 {
			return Err(RecvPacketError::TooSmallPacket);
		}

		let ip_version = packet[0] >> 4;
		if ip_version != 4 {
			return Err(RecvPacketError::IncorrectIpVersion);
		}

		if packet.len() > self.max_packet_size {
			return Err(RecvPacketError::MtuError);
		}

		let total_length = ((packet[2] as usize) << 8) | (packet[3] as usize);
		if packet.len() < total_length {
			return Err(RecvPacketError::BrokenPackage);
		}

		let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
		if !self.is_neighbour_ipv4(&src_ip) {
			return Err(RecvPacketError::UnknownSrcIp);
		}

		let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
		if dest_ip != self.ipv4_addr {
			return Err(RecvPacketError::IncorrectDestIp);
		}

		if self.ip_pk[&src_ip] != *from {
			return Err(RecvPacketError::Spoofing);
		}

		Ok(())
	}

	fn is_neighbour(&self, node: &PublicKey) -> bool {
		self.peers.contains_key(node)
	}

	fn is_neighbour_ipv4(&self, node: &Ipv4Addr) -> bool {
		self.ip_pk.contains_key(node)
	}

	fn is_connect_open(&self, node: &PublicKey) -> bool {
		self.peers[node].is_connected
	}
}
