# RustP2PNetwork

![Rust](https://img.shields.io/badge/rust-1.93%2B-orange.svg)
![Platform](https://img.shields.io/badge/platform-linux-blue.svg)
![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-green.svg)
![Status](https://img.shields.io/badge/status-experimental-yellow.svg)

> Decentralized user-space L3 mesh VPN built with Rust and Iroh. Secure, high-throughput P2P networking with decentralized DHT-based discovery.

**RustP2PNetwork** is a lightweight, high-performance virtual private network router. It intercepts IP packets via a virtual `TUN` interface and encapsulates them into QUIC datagrams. By operating entirely in user-space and leveraging modern P2P protocols, it establishes a Full Mesh network with UDP hole punching and iroh-relays.

## Key Features

* **High-Performance Transport (No Meltdown):** Leverages the **QUIC** protocol utilizing QUIC datagrams for unreliable packet delivery. By intentionally disabling QUIC's internal Congestion Control, the project entirely avoids the "TCP-in-TCP meltdown" issue, allowing the encapsulated payload to manage its own reliability.
* **Decentralized Discovery & Relay Signaling:** Employs Mainline **DHT** (via `pkarr`) for genuinely decentralized peer discovery. To achieve successful simultaneous holepunching, the system utilizes Iroh relay servers as STUN and signaling servers, as well as for the initial routing of traffic while the direct P2P connection is being negotiated.
* **Lock-Free Actor Architecture:** Built on the **Sans-IO** pattern and **Tokio** actors. The core routing logic is strictly isolated from I/O, ensuring high throughput and no data races.
* **Automatic NAT Traversal:** Built-in **UDP Hole Punching** for direct P2P connectivity, with a seamless **Relay Fallback** for restricted symmetric NAT environments.
* **Proven Network Stability:** The system has been tested in highly complex and degraded network conditions, demonstrating high stability and reliable tunneling under stress.

## Architecture & Topology

**RustP2PNetwork** implements a Full Mesh topology where every node attempts to establish a direct encrypted link with every other peer in the whitelist.

* Decentralized Control Plane: Peer direct addresses are resolved by Public Keys via a Distributed Hash Table (DHT) using the Pkarr protocol. There is no central management server or database that stores network state.
* Infrastructure-Assisted Data Plane: While the goal is direct P2P communication, the system acknowledges the technical necessity of STUN and Relay servers. These servers (provided by the Iroh infrastructure) act as:
    + STUN: For public IP discovery.
    + Coordination Channel: Relays act as a secure "meeting point" for peers to exchange direct addresses and synchronize simultaneous outbound connection attempts (UDP hole punching).
    + Fallback: To provide connectivity for nodes behind restrictive Symmetric NATs.

### Internal Components

* **VPN Core (vpn_core.rs)**: A purely synchronous state machine. It handles the mapping of internal IPv4 addresses to Public Keys, manages packet buffering during connection handshakes, and decides whether a packet should be forwarded, dropped, or queued.  

* **Async Coordinator (coord.rs)**: The "brain" of the application based on the Actor Model. It orchestrates communication between the TUN interface, the Iroh module, and the VPN Core using high-speed tokio::sync::mpsc channels.  

* **TUN Interface (tun.rs)**: Encapsulates Linux kernel system calls to create and manage the virtual L3 network device. It provides asynchronous read/write streams to intercept outgoing IP packets from the host OS and inject incoming decrypted packets back into the system's network stack.  

* **Iroh Module**: Manages the QUIC state machine, encryption (TLS 1.3), and the complex process of NAT traversal.

## Configuration

**RustP2PNetwork** uses a static, TOML-based configuration file. This architectural choice guarantees deterministic routing and enforces a strict zero-trust environment: the system operates purely on a cryptographic whitelist, rejecting any connection attempts or packets from unknown public keys.

### Node Configuration (config.toml)
Below is the standard structure of a node's configuration file:

``` toml
# Path to the secret key (required).
# If the file does not exist, a new secret key will be generated and saved here.
# The public key will be printed to the standard output at startup.
secret_key_path = "/path/to/your/secret.key"

# Node IPv4 address. 
# IMPORTANT: The address must be within the 10.67.0.0/16 subnet.
node_ipv4 = "10.67.1.5"

# Tun interface name (optional, default is "iroh_vpn")
# tun_name = "my_custom_name"

# Port for incoming connections (optional).
# Uncomment to override the default behavior.
# listen_port = 6767

# Maximum Transmission Unit (optional, default is 1500).
# Specifies the maximum packet size that will not be fragmented 
# on the way to adjacent nodes.
# mtu = 1500

# Log level (optional, possible variants: trace, debug, info, warn, error, off, default is info)
# log_level = "info"

# Log path (optional, this is an additional logging in file to stdout)
# log_path = "/path/to/your/log/file"

# ==========================================
# Adjacent nodes (Whitelist)
# ==========================================
# You can add multiple [[peers]] blocks to define your whitelist.
[[peers]]
pub_key = "xkh8cq69d6qxt5zz9gx9x97djohf3c1mgqbiq3ku5cc679nix91o"
ipv4 = "10.67.2.10"

# [[peers]]
# pub_key = "xkh8cq65d6qxt5zz9gx9x97djohf3c1mgqbiq3ku5cc679nix91o"
# ipv4 = "10.67.1.11"
```

### Key Parameters Explained
`secret_key_path`: The path to the node's private cryptographic key. For seamless onboarding, if the file is missing, the application will automatically generate a new secure key pair upon its first execution.

`node_ipv4`: The virtual IP address inside the VPN tunnel. The system strictly isolates traffic to the 10.67.0.0/16 subnet to prevent routing conflicts with local host networks.

`[[peers]]` (The Whitelist):  The [[peers]] section is the core of the network's security model. It statically maps an authorized Iroh Public Key to its designated virtual IPv4 address.
+ Unique Addressing: IPv4 addresses must be uniquely assigned to each node by the network administrator. Failure to maintain unique addressing can lead to unpredictable routing behavior and packet collisions within the mesh.
+ Strict Security: This configuration serves as the primary mechanism for security enforcement. The system performs validation for every interaction: if a node not present in the whitelist attempts to establish a connection or send a packet, it will be immediately rejected and dropped.

### Automated Network Provisioning
Manually configuring a Full Mesh network for a large number of nodes is error-prone, as it requires managing $N(N-1)$ peer relationships. To simplify deployment, this project includes a Configuration Generator script.

To run the script write in your terminal:
```bash
cargo run --bin gen_configs N
```
Where N is the total number of nodes you wish to include in the mesh network.

Once the script finishes its work you will receive N configs and N Secret Keys for your network.

## Getting Started

### Prerequisites
* Operating System: Linux.
* Permissions: Root privileges are required to create and manage the TUN interface.

### Installation

**Option 1: Download a Pre-built Binary**
1. Go to the [Releases](https://github.com/DarkRecklessness/Peer-to-peer-decentralized-mesh-network/releases) page.
2. Download the latest archive for your architecture (e.g., mesh-network-x86_64.tar.gz).
3. Extract the binary and give it execution permissions:
```bash
chmod +x mesh_network
```

**Option 2: Build from Source**
1. Clone the repository:
```bash
git clone https://github.com/DarkRecklessness/Peer-to-peer-decentralized-mesh-network
cd Peer-to-peer-decentralized-mesh-network
```
2. Build the project in release mode:
```bash
cargo build --release
```
3. The binary will be available at ./target/release/mesh_network

### Usage
1. **Prepare your configuration**: Use the configuration generator or create a config.toml manually. Make sure each node has a unique node_ipv4 address.
2. **Run the application**: Launch the VPN node by pointing to your configuration file
```bash
sudo ./mesh_network path/to/your/config.toml
```
3. **Verify connectivity**: After some time you will see in logs the message about successful connection between nodes, so write in your terminal
```bash
ping 10.67.x.x
```

## Performance & Testing
The system has been tested for high-throughput performance, stability under unstable network conditions, and scalability in a decentralized mesh environment.

> **Detailed instructions for reproducing these tests can be found in the [Tests README](https://github.com/DarkRecklessness/Peer-to-peer-decentralized-mesh-network/blob/main/tests/README.md).**

### 1. Localhost Throughput

Testing was conducted on an **AMD Ryzen 7 7840HS** processor between two local nodes to measure raw encapsulation and transport overhead.

* **UDP Throughput:** ~2.5 Gbps (Pure QUIC datagram performance).
* **TCP Throughput:** ~1.7 Gbps (Using BBR congestion control over the tunnel).

The results demonstrate that the **Sans-IO** architecture and **Rust** implementation provide high-speed packet processing.

### 2. Network Resilience & Emulation

To simulate real-world internet conditions, network emulation tools were used to introduce latency, jitter, and packet loss.

All tests described in [Tests README](https://github.com/DarkRecklessness/Peer-to-peer-decentralized-mesh-network/blob/main/tests/README.md) were passed highly stable.

### 3. Scalability & Mesh Stability (Full Mesh)

Scalability tests were successfully performed by connecting N nodes in a Full Mesh topology using real public infrastructure:

* **Discovery:** Nodes used the public **Pkarr DHT** for global peer resolution.
* **Connectivity:** Initial handshakes and NAT traversal were coordinated through public **Iroh Relays**.

**Test Outcome:** The tests confirmed that the connection logic correctly resolves **connection race conditions**. Even when multiple nodes attempt to initiate a handshake simultaneously, the system consistently establishes a single, stable P2P tunnel per peer pair, maintaining a reliable Full Mesh state.
