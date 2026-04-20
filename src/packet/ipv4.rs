use std::net::Ipv4Addr;
use std::fmt;
use std::error::Error;
use bytes::Bytes;

pub struct Ipv4Packet {
	pub packet_length: usize,
	pub total_length: usize,
	pub ttl: u8,
	pub src_ip: Ipv4Addr,
	pub dest_ip: Ipv4Addr,
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
	TooSmallPacket,
	IncorrectIpVersion,
}

impl fmt::Display for ParseError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
            ParseError::IncorrectIpVersion => write!(f, "unsupported IP version (only IPv4 is allowed)"),
            ParseError::TooSmallPacket => write!(f, "packet is too small to contain a valid IPv4 header"),
		}
	}
}

impl Error for ParseError {}

impl Ipv4Packet {
	pub fn new(packet: &Bytes) -> Result<Ipv4Packet, ParseError> {
		if packet.len() < 20 {
			return Err(ParseError::TooSmallPacket);
		}

		let ip_version = packet[0] >> 4;
		if ip_version != 4 {
			return Err(ParseError::IncorrectIpVersion);
		}

		let packet_length = packet.len();
		let total_length = ((packet[2] as usize) << 8) | (packet[3] as usize);
		let ttl = packet[8];
		let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
		let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

		Ok(Ipv4Packet {
			packet_length,
			total_length,
			ttl,
			src_ip,
			dest_ip,
		})
	}
}
