use iroh::{self, SecretKey, PublicKey};
use std::net::{self, Ipv4Addr};
use std::collections::HashMap;
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::io;
use std::str::FromStr;
use std::fmt;
use std::error::Error;

const SUBNET: Ipv4Addr = Ipv4Addr::new(10, 67, 0, 0);
const MASK: Ipv4Addr = Ipv4Addr::new(255, 255, 0, 0);
const DEFAULT_LISTEN_PORT: u16 = 6767;
const DEFAULT_MTU: u16 = 1500;

pub struct Config {
	pub secret_key: SecretKey,
	pub node_ipv4: Ipv4Addr,
	pub listen_port: u16,
	pub mtu: u16,
	pub peers: HashMap<Ipv4Addr, PublicKey>,
}

#[derive(Deserialize)]
struct ConfigToml {
	secret_key_path: String,
   	node_ipv4: String,
   	listen_port: Option<u16>,
   	mtu: Option<u16>,
   	peers: Vec<Peer>,
}

#[derive(Deserialize)]
struct Peer {
	pub_key: String,
	ipv4: String,
}

#[derive(Debug)]
pub enum ConfigError {
	OpenFileError(io::Error),
	FormatParsingError(toml::de::Error),
	SecretKeyError(SecretKeyError),
	Ipv4ParseError(net::AddrParseError),
	PublicKeyParseError(iroh::KeyParsingError),
	Ipv4NotInSubnet,
}

#[derive(Debug)]
pub enum SecretKeyError {
	GetKeyError(io::Error),
	IncorrectKey,
}

impl fmt::Display for ConfigError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			ConfigError::OpenFileError(e) => write!(f, "Open file error: {}", e),
			ConfigError::FormatParsingError(e) => write!(f, "Incorrect config format: {}", e),
			ConfigError::SecretKeyError(e) => write!(f, "Secret key error: {}", e),
			ConfigError::Ipv4ParseError(e) => write!(f, "Ipv4 parse error: {}", e),
			ConfigError::PublicKeyParseError(e) => write!(f, "Public key parse error: {}", e),
			ConfigError::Ipv4NotInSubnet => write!(f, "Node Ipv4 not in correct subnet"),
		}
	}
}

impl fmt::Display for SecretKeyError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self {
			SecretKeyError::GetKeyError(e) => write!(f, "can't get the key: {}", e),
			SecretKeyError::IncorrectKey => write!(f, "given key isn't correct"),
		}
	}
}

impl Error for ConfigError {}
impl Error for SecretKeyError {}

impl Config {
	pub fn from_file(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
		let data = match fs::read(path) {
			Ok(data) => data,
			Err(e) => {
				return Err(ConfigError::OpenFileError(e));
			}
		};
		let config_toml: ConfigToml = match toml::from_slice(&data[..]) {
			Ok(cfg) => cfg,
			Err(e) => {
				return Err(ConfigError::FormatParsingError(e));
			}
		};

		let secret_key = match Self::get_secret_key(&config_toml.secret_key_path) {
			Ok(sk) => sk,
			Err(e) => {
				return Err(ConfigError::SecretKeyError(e));
			}
		};

		let peers = Self::get_peers(&config_toml)?;

		let node_ipv4 = match Ipv4Addr::from_str(&config_toml.node_ipv4) {
			Ok(ip) => ip,
			Err(e) => {
				return Err(ConfigError::Ipv4ParseError(e));
			}
		};
		if (node_ipv4 & MASK) != SUBNET {
			return Err(ConfigError::Ipv4NotInSubnet);
		}

		let listen_port = match config_toml.listen_port {
			Some(port) => port,
			None => DEFAULT_LISTEN_PORT
		};

		let mtu = match config_toml.mtu {
			Some(mtu) => mtu,
			None => DEFAULT_MTU
		};

		Ok(Config {
			secret_key,
			node_ipv4,
			listen_port,
			mtu,
			peers,	
		})
	}

	fn get_peers(cfg: &ConfigToml) -> Result<HashMap<Ipv4Addr, PublicKey>, ConfigError> {
		let mut peers = HashMap::new();
		for peer in &cfg.peers {
			let ipv4 = match Ipv4Addr::from_str(&peer.ipv4) {
				Ok(ip) => ip,
				Err(e) => {
					return Err(ConfigError::Ipv4ParseError(e));
				}
			};
			let pub_key = match PublicKey::from_str(&peer.pub_key) {
				Ok(pk) => pk,
				Err(e) => {
					return Err(ConfigError::PublicKeyParseError(e));
				}
			};
			peers.insert(ipv4, pub_key);
		}
		Ok(peers)
	}

	fn get_secret_key(path: impl AsRef<Path>) -> Result<SecretKey, SecretKeyError> {
        let data = match fs::read(&path) {
 			Ok(data) => data,
 			Err(e) if e.kind() == io::ErrorKind::NotFound => {
 				match Self::gen_secret_key(path) {
 					Ok(sec_key) => {
 						return Ok(sec_key);
 					}
 					Err(e) => {
 						return Err(SecretKeyError::GetKeyError(e));
 					}
 				}
 			},
 			Err(e) => {
 				return Err(SecretKeyError::GetKeyError(e));
 			}
        };

		if data.len() != 32 {
			return Err(SecretKeyError::IncorrectKey);
		}

        Ok(SecretKey::from_bytes(data.as_array::<32>().unwrap()))
	}

	fn gen_secret_key(path: impl AsRef<Path>) -> Result<SecretKey, io::Error> {
		let secret_key = SecretKey::generate();
		fs::write(path, secret_key.to_bytes())?;
		Ok(secret_key)
	}
}
