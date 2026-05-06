use std::env;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use iroh::SecretKey;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Using: cargo run --bin gen_configs <count_of_nodes>");
        std::process::exit(1);
    }

    let n: usize = args[1].parse().expect("N must be a number");
    let tmp_dir = Path::new("tmp");
    
    if !tmp_dir.exists() {
        fs::create_dir_all(tmp_dir)?;
    }

    println!("Gen keys and configs for {} nodes...", n);

    let mut nodes = Vec::new();
    for i in 1..=n {
        let secret_key = SecretKey::generate();
        let pub_key = secret_key.public();
        let ip = format!("10.67.1.{}", i);
        let secret_path = format!("tmp/secret{}.key", i);
        let tun_name = format!("tun{}", i);
        fs::write(&secret_path, secret_key.to_bytes())?; 
        nodes.push((i, pub_key.to_string(), ip, secret_path, tun_name));
    }

    for (i, _pub_key, ip, secret_path, tun_name) in &nodes {
        let config_path = tmp_dir.join(format!("node_{}.toml", i));
        let mut file = File::create(&config_path)?;

        writeln!(file, "# Path to the secret key")?;
        writeln!(file, "secret_key_path = \"{}\"", secret_path)?;
        writeln!(file, "")?;
        
        writeln!(file, "# Node IPv4 address")?;
        writeln!(file, "node_ipv4 = \"{}\"", ip)?;
        writeln!(file, "")?;
        
        writeln!(file, "# Port for incoming connections (0 means random available port)")?;
        writeln!(file, "listen_port = 0")?;
        writeln!(file, "")?;

		writeln!(file, "tun_name = \"{}\"", tun_name)?;
		writeln!(file, "")?;

		writeln!(file, "log_level = \"debug\"")?;
		writeln!(file, "")?;
        
        writeln!(file, "# ==========================================")?;
        writeln!(file, "# Adjacent nodes (Whitelist)")?;
        writeln!(file, "# ==========================================")?;

        for (j, peer_pub_key, peer_ip, _, _) in &nodes {
            if i == j {
                continue;
            }
            writeln!(file, "[[peers]]")?;
            writeln!(file, "pub_key = \"{}\"", peer_pub_key)?;
            writeln!(file, "ipv4 = \"{}\"", peer_ip)?;
            writeln!(file, "")?;
        }

        println!("Create config: {}", config_path.display());
    }

    println!("Everything is ready!");
    Ok(())
}
