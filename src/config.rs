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
const NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 0, 0);
const DEFAULT_LISTEN_PORT: u16 = 6767;
const DEFAULT_MTU: u16 = 1500;
const DEFAULT_TUN_NAME: &str = "iroh_vpn";

pub struct Config {
	pub secret_key: SecretKey,
	pub node_ipv4: Ipv4Addr,
	pub netmask: Ipv4Addr,
	pub tun_name: String,
	pub listen_port: u16,
	pub mtu: u16,
	pub log_level: String,
	pub log_path: Option<String>,
	pub peers: HashMap<Ipv4Addr, PublicKey>,
}

#[derive(Deserialize)]
struct ConfigToml {
	secret_key_path: String,
   	node_ipv4: String,
   	tun_name: Option<String>,
   	listen_port: Option<u16>,
   	mtu: Option<u16>,
   	log_level: Option<String>,
   	log_path: Option<String>,
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
	IncorrectLogLevel,
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
			ConfigError::IncorrectLogLevel => write!(f, "Incorrect log level"),
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
		if (node_ipv4 & NETMASK) != SUBNET {
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

		let log_level = match config_toml.log_level {
			Some(lvl) => {
				match &lvl[..] {
					"trace" |
					"debug" |
					"info"  |
					"warn"  |
					"error" |
					"off"   
					=> lvl,
					_ => return Err(ConfigError::IncorrectLogLevel),
				}
			}
			None => "info".to_string(),
		};

		let tun_name = match config_toml.tun_name {
			Some(name) => name,
			None => DEFAULT_TUN_NAME.to_string(),
		};

		Ok(Config {
			secret_key,
			node_ipv4,
			netmask: NETMASK,
			tun_name,
			listen_port,
			mtu,
			log_level,
			log_path: config_toml.log_path,
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
			let pub_key = match PublicKey::from_z32(&peer.pub_key[..]) {
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


// ===============
// TESTS
// ===============


#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use std::fs;
    use std::io::Write;

    fn create_config_file(dir: &tempfile::TempDir, content: &str) -> String {
        let file_path = dir.path().join("config.toml");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file_path.to_string_lossy().to_string()
    }

    #[test]
    fn test_valid_full_config() {
        let dir = tempdir().unwrap();
        let secret_key_path = dir.path().join("tmp_secret.key");
        
        let peer_pub_key = SecretKey::generate().public().to_z32();

        let toml_content = format!(r#"
            secret_key_path = "{}"
            node_ipv4 = "10.67.1.5"
            listen_port = 8080
            mtu = 1400
            log_level = "debug"
            log_path = "/var/log/vpn.log"

            [[peers]]
            pub_key = "{}"
            ipv4 = "10.67.2.10"
        "#, secret_key_path.display(), peer_pub_key);

        let config_path = create_config_file(&dir, &toml_content);
        let config = Config::from_file(&config_path).expect("Failed to parse valid config");

        assert!(secret_key_path.exists());
        
        let saved_key_bytes = fs::read(&secret_key_path).unwrap();
        assert_eq!(saved_key_bytes.len(), 32);
        
        assert_eq!(config.node_ipv4, Ipv4Addr::new(10, 67, 1, 5));
        assert_eq!(config.listen_port, 8080);
        assert_eq!(config.mtu, 1400);
        assert_eq!(config.log_level, "debug");
        assert_eq!(config.log_path, Some("/var/log/vpn.log".to_string()));
        
        let peer_ip = Ipv4Addr::new(10, 67, 2, 10);
        assert!(config.peers.contains_key(&peer_ip));
        assert_eq!(config.peers.get(&peer_ip).unwrap().to_z32(), peer_pub_key);
    }

    #[test]
    fn test_valid_minimal_config_and_existing_raw_secret_key() {
        let dir = tempdir().unwrap();
        let secret_key_path = dir.path().join("tmp_secret.key");
        
        let existing_sk = SecretKey::generate();
        fs::write(&secret_key_path, existing_sk.to_bytes()).unwrap();

        let toml_content = format!(r#"
            secret_key_path = "{}"
            node_ipv4 = "10.67.255.254"
            peers = []
        "#, secret_key_path.display());

        let config_path = create_config_file(&dir, &toml_content);
        let config = Config::from_file(&config_path).unwrap();

        assert_eq!(config.listen_port, DEFAULT_LISTEN_PORT);
        assert_eq!(config.mtu, DEFAULT_MTU);
        assert_eq!(config.log_level, "info");
        assert_eq!(config.log_path, None);
        
        assert_eq!(config.secret_key.to_bytes(), existing_sk.to_bytes());
    }

    #[test]
    fn test_invalid_secret_key_length() {
        let dir = tempdir().unwrap();
        let secret_key_path = dir.path().join("broken.key");
        
        fs::write(&secret_key_path, b"1234567890").unwrap();

        let toml_content = format!(r#"
            secret_key_path = "{}"
            node_ipv4 = "10.67.1.1"
            peers = []
        "#, secret_key_path.display());

        let config_path = create_config_file(&dir, &toml_content);
        let result = Config::from_file(&config_path);
        
        assert!(matches!(
            result,
            Err(ConfigError::SecretKeyError(SecretKeyError::IncorrectKey))
        ));
    }

    #[test]
    fn test_invalid_peer_pub_key_z32() {
        let dir = tempdir().unwrap();
        
        let toml_content = r#"
            secret_key_path = "/tmp/dummy.key"
            node_ipv4 = "10.67.1.1"
            [[peers]]
            pub_key = "this_is_obviously_not_a_valid_z32_iroh_key"
            ipv4 = "10.67.2.10"
        "#;
        let config_path = create_config_file(&dir, toml_content);
        assert!(matches!(Config::from_file(&config_path), Err(ConfigError::PublicKeyParseError(_))));
    }

    #[test]
    fn test_ipv4_not_in_subnet() {
        let dir = tempdir().unwrap();
        let toml_content = r#"
            secret_key_path = "/tmp/dummy.key"
            node_ipv4 = "192.168.1.1"
            peers = []
        "#;
        let config_path = create_config_file(&dir, toml_content);
        
        let result = Config::from_file(&config_path);
        assert!(matches!(result, Err(ConfigError::Ipv4NotInSubnet)));
    }
}
