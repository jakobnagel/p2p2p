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

fn main() {
    state::init_app_data();

    // mDNS
    let mdns = Mdns::new().unwrap();
    let _mdns_handle = thread::spawn(move || {
        mdns.run();
    });

    // TCP
    let tcp = TcpServer::new().unwrap();
    let _tcp_handle = thread::spawn(move || {
        tcp.run();
    });

    // TODO: Initialize RSA keys and file directory

    // Rustyline setup
    // Use DefaultHistory for the History type
    let mut rl: Editor<(), DefaultHistory> =
        Editor::new().expect("Unable to create rustyline editor");
    if rl.load_history("history.txt").is_err() {
        println!("No previous history.");
    }

    loop {
        let readline = rl.readline(">> ");
        match readline {
            Ok(line) => {
                rl.add_history_entry(line.as_str());
                let input_string = line.trim().to_ascii_lowercase();

                match input_string.as_str() {
                    "help" => {
                        println!("Available commands:");
                        println!("  help - Show this help message");
                        println!("  send <address> - Attempt to connect to the given address");
                        println!("  contacts - List known clients");
                        println!("  exit - Exit the application");
                    }
                    "send" => {
                        // get input inside the send block
                        println!("Enter address: ");
                        let addr_line = rl.readline("send>> ");
                        match addr_line {
                            Ok(addr_str) => {
                                let socket_addr = match SocketAddr::from_str(addr_str.trim()) {
                                    Ok(addr) => addr,
                                    Err(e) => {
                                        eprintln!("Invalid address: {}: {}", addr_str.trim(), e);
                                        continue;
                                    }
                                };
                                state::init_client_data(socket_addr);
                                tcp::connect(socket_addr);
                            }
                            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                                break;
                            }
                            Err(err) => {
                                eprintln!("Error reading address: {:?}", err);
                                continue;
                            }
                        }
                    }
                    "receive" => {
                        println!("Not yet implemented");
                    }
                    "contacts" => {
                        println!("{}", state::list_clients());
                    }
                    "exit" => {
                        break;
                    }
                    _ => {
                        println!("Unknown command. Type 'help' for a list of commands.");
                    }
                }
            }
            Err(ReadlineError::Interrupted) => {
                println!("CTRL-C");
                break;
            }
            Err(ReadlineError::Eof) => {
                println!("CTRL-D");
                break;
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
            }
        }
    }
    rl.save_history("history.txt").unwrap();
}
