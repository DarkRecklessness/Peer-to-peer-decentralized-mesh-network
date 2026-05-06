use mesh_network::{config::Config, vpn_core::VpnCore, coord::Coordinator, iroh::Iroh, tun::Tun};
use iroh::{SecretKey, PublicKey};
use tracing::{info, warn, error, debug, trace, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, fmt};
use std::collections::HashSet;
use tokio::sync::mpsc;

//const CONFIG_PATH: &str = "config.toml";
const INTERMOD_CHANNEL_CAPACITY: usize = 8192;

#[tokio::main]
async fn main() {
	let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    println!("Using config file: {}", config_path);

    let cfg = match Config::from_file(config_path) {
    	Ok(cfg) => cfg,
    	Err(e) => {
    		eprintln!("Error while reading config: {}", e);
    		return;
    	}
    };
	println!("Config read sucessfully");

	// Configure logger
	let log_dir: Option<&str> = cfg.log_path.as_deref();
    let _log_guard = init_logger(log_dir, &cfg.log_level[..]);
	info!("Logger start successfully");

	// Print public key
	info!(public_key = cfg.secret_key.public().to_string(), "Your public key");

	// Calculate application mtu
	let final_mtu = cfg.mtu - 20  // ipv4 header
							- 8   // udp header
							- 50  // quic overhead
							- 22; // safe extra

	// Configure dependencies
	let mut peers: HashSet<PublicKey> = HashSet::new();
	for (_, pub_key) in &cfg.peers {
		peers.insert(pub_key.clone());
	}
	
	let core = VpnCore::new(cfg.node_ipv4.clone(),
							cfg.peers,
							final_mtu.into());
	info!("Core was created");

	let (tx_from_coord_to_iroh, rx_from_coord_to_iroh) = 
		mpsc::channel(INTERMOD_CHANNEL_CAPACITY);
	let (tx_from_iroh_to_coord, rx_from_iroh_to_coord) =
		mpsc::channel(INTERMOD_CHANNEL_CAPACITY);
	let (tx_from_coord_to_tun, rx_from_coord_to_tun) = 
		mpsc::channel(INTERMOD_CHANNEL_CAPACITY);
	let (tx_from_tun_to_coord, rx_from_tun_to_coord) =
		mpsc::channel(INTERMOD_CHANNEL_CAPACITY);
	info!("Channels was created");
	
	let coord = Coordinator::new(core,
								 tx_from_coord_to_iroh,
								 rx_from_iroh_to_coord,
								 tx_from_coord_to_tun,
								 rx_from_tun_to_coord);
	info!("Coordinator was created");

	let iroh = match Iroh::new(cfg.secret_key,
						 peers,
						 tx_from_iroh_to_coord,
						 rx_from_coord_to_iroh,
						 cfg.listen_port).await 
	{
	 	Ok(obj) => obj,
	 	Err(e) => {
	 		error!(error = %e);
	 		return;
	 	}	
	};
	info!("Iroh was creaed");

	let tun = Tun::new(&cfg.tun_name[..],
					   final_mtu,
					   cfg.node_ipv4,
					   cfg.netmask,
					   tx_from_tun_to_coord,
					   rx_from_coord_to_tun);
	info!("Tun was created");

	let coord_handle = tokio::spawn(coord.run());
	let iroh_handle = tokio::spawn(iroh.run());
	let tun_handle = tokio::spawn(tun.run());

	tokio::select! {
	    res = coord_handle => warn!("Coordinator task ended: {:?}", res),
	    res = iroh_handle => warn!("Iroh task ended: {:?}", res),
	    res = tun_handle => warn!("Tun task ended: {:?}", res),
	}
}

pub fn init_logger(log_dir: Option<&str>, app_level: &str)
 	-> Option<tracing_appender::non_blocking::WorkerGuard> 
{
	let filter_settings = format!("error,mesh_network={}", app_level);

	let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(filter_settings));

    let console_layer = fmt::layer()
        .with_ansi(true)
        .with_target(true);

    let (file_layer, guard) = if let Some(path) = log_dir {
        let file_appender = tracing_appender::rolling::daily(path, "iroh-node.log");
        let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);
        
        let layer = fmt::layer()
            .with_writer(non_blocking_appender)
            .with_ansi(false);
            
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    tracing_subscriber::registry()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer) 
        .init();

    guard
}
