#![warn(unused_extern_crates)]

mod logic;
mod mdns;
mod state;
mod tcp;

use mdns::Mdns;
use rustyline::error::ReadlineError;
use rustyline::history::DefaultHistory;
use rustyline::Editor;
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use tcp::TcpServer;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting...");
    thread::spawn(move || {
        // RSA key generation is super slow
        // Will replace once keys are
        state::init_app_data();
    });

    // TODO Import data on 2nd startup

    // mDNS
    let _mdns_handle = thread::spawn(move || {
        let mdns = Mdns::new().unwrap();
        mdns.run();
    });

    // TCP
    let _tcp_handle = thread::spawn(move || {
        let tcp = TcpServer::new().unwrap();
        tcp.run();
    });

    // Rustyline setup
    let mut rl: Editor<(), DefaultHistory> =
        Editor::new().expect("Unable to create rustyline editor");

    loop {
        let readline = rl.readline(">> ")?;
        rl.add_history_entry(readline.as_str())?;

        let parts: Vec<&str> = readline.split_whitespace().collect();

        match parts.get(0).map(|s| s.to_lowercase()).as_deref() {
            Some("help") => {
                println!("Available commands:");
                println!("  help - Show this help message");
            }
            Some("connect") => {
                if parts.len() >= 2 {
                    let socket_addr: Result<SocketAddr, _> = parts[1].parse();
                    match socket_addr {
                        Ok(addr) => {
                            state::init_client_data(addr);
                            tcp::connect(addr);
                        }
                        Err(e) => {
                            eprintln!("Invalid address: {:?}: {}", parts, e);
                            continue;
                        }
                    }
                } else {
                    println!("Usage: connect 127.0.0.1:8080");
                }
            }
            Some("contacts") => {
                println!("{}", state::list_clients());
            }
            Some("exit") => {
                break;
            }
            None => {} // Empty line, do nothing.
            _ => {
                println!("Unknown command. Type 'help' for a list of commands.");
            }
        }
    }

    // TODO: Save App Data on shutdown
    rl.save_history("history.txt").unwrap();
    Ok(())
}
