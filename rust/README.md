# CISC468 p2p2p Rust Implementation

This project is a command-line application for sharing files directly with other peers on the local network using a custom TCP-based protocol with encryption and peer discovery via mDNS.

## How to Use

1.  **Start the application:** `cargo run` (consider setting `RUST_LOG=info` to see whats going on)
2.  **Password:**
    - On the first run, you will be prompted to create a password to encrypt your application data (ex: private key, contact list, files).
    - On subsequent runs, enter the existing password to decrypt and load your data.
3.  **Connect:**
    - Find local peers with `search`, this will show you the following types of cleints
      - Online but unconnected Peers: Nickname is n/a, connections is 0. Type `Connect IP:PORT <nickname>` to perform the introduction handshake
      - Online and connected Contacts: Nickname is \<nickname\>, connections is 1. Type `listfile <nickname>` to see what files are available
      - Offline Contacts: Nickname is \<nickname\>, connections is 0. Type `listfile <nickname>` to see what files are available
    - Tip: An offline contact and an unconnected peer might be the same device. Open a connection to the peer to see their public key.

### Commands

- `help`: Show the list of available commands.
- `search`: List discovered peers and known contacts, showing their status (nickname, connection status, security status, socket address).
- `connect <address> <nickname>`: Manually connect to a peer at a specific address (e.g., 192.168.1.10:5200) and assign them a nickname. This initiates the key exchange process.
- `rename <old_nickname> <new_nickname>`: Change the nickname of a known contact.
- `listfiles <nickname>`: Request and display the list of files available from a peer.
- `upload <nickname> <file_name>`: Send a request to upload a local file (previously imported) to the specified peer. The peer will need to approve the upload.
- `download <nickname> <file_name>`: Request to download a specific file from a peer. You implicitly approve the download by initiating it, but the peer needs to approve sending it.
- `approve <nickname> <upload|download> <file_name>`: Approve a pending upload or download request from a peer.
- `reject <nickname> <upload|download> <file_name>`: Reject a pending upload or download request from a peer.
- `ls`: List local files that have been imported into the application.
- `import <file_path>`: Import a file from your computer into the application's managed file list, making it available for uploading.
- `export <file_name> <file_path>`: Export a managed file (usually after downloading) to a specific location on your computer.
- `exit`: Save the current state (encrypted), shut down connections, and exit the application.

## Multi-Threading

The application utilizes multiple threads for concurrent operations:

1.  **mDNS Thread:** A dedicated thread runs the mDNS service for discovering peers on the network and advertising the user's presence.
2.  **TCP Listener Thread:** A main TCP server thread listens for incoming connections from other peers.
3.  **Client Handler Threads:**
    - Each time a new peer connects (either incoming or outgoing), a new thread is spawned to handle all communication (reading, writing, processing messages) with that specific peer.
    - This allows the application to manage multiple peer connections simultaneously without blocking the main interface or other connections.
4.  **Main Thread:** Handles user input via the command-line interface (Rustyline) and dispatches commands.

## Contact System

- **Discovery:** Peers are primarily discovered automatically using mDNS on the local network. The mDNS service listens for other instances advertising the `_ppp._tcp.local.` service and resolves their IP addresses and port. Discovered peers are added to a list, initially without nicknames. Peers on the same machine are ignored.
- **Manual Connection:** Users can manually connect to peers using the `connect` command if mDNS discovery fails or is not desired.
- **Identification & Nicknames:**
  - Peers are internally tracked by their `SocketAddr` (IP address and port).
  - Users assign persistent nicknames to peers using the `connect` or `rename` commands. These nicknames map to the peer's `SocketAddr` for easy command usage.
- **State Management:** Information about each peer (nickname, connection status, RSA public key, established AES session key, list of their shared files) is stored in memory (`CLIENT_DATA` and `NICKNAME_TO_SOCKET` maps).

## Contact Restoration

- **Persistence:** When the application exits, information about known contacts (their nickname, RSA public key, and last known file list) is saved to an encrypted file (`clientdata.bin`). Their actual IP address is not saved.
- **Fake IPs:** To represent these offline contacts before they reconnect, the application assigns placeholder IP addresses from a reserved block (192.0.2.0/24) sequentially. These are the "fake IP addresses". They allow the contact to be listed (ex: via `search`) even when offline.
- **Restoration/Migration:**
  - When a peer connects (either initiating or receiving a connection), they send an `Introduction` message containing their RSA public key.
  - The application checks if this incoming RSA public key matches the saved key of any known contact with a "fake IP".
  - If a match is found, the application knows this is the same peer reconnecting. It then migrates the persistent data (nickname, file list history) from the old "fake IP" entry to the `SocketAddr` for the current connection. The old entry with the fake IP is removed.
