mod logic;
mod mdns;
mod state;
mod tcp;

use mdns::Mdns;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread;
use tcp::Tcp;

fn main() {
    // mDNS
    let (ip_sender, ip_receiver) = mpsc::channel();
    let mdns = Mdns::new(ip_sender).unwrap();
    let mdns_handle = thread::spawn(move || {
        mdns.run();
    });

    // TCP
    let tcp = Tcp::new().unwrap();
    let server_state = tcp.get_state();
    let tcp_handle = thread::spawn(move || {
        tcp.run();
    });

    // TODO: Initialize RSA keys and file directory

    loop {
        let mut input_string = String::new();
        io::stdin()
            .read_line(&mut input_string)
            .expect("error reading line");

        input_string = input_string.trim().to_string();
        input_string = input_string.to_ascii_lowercase();
        match input_string.as_str() {
            "help" => {
                println!("what");
            }
            "send" => {}
            "receive" => {}
            "contacts" => {}
            "exit" => {
                break;
            }
            _ => {
                println!("the possible commands are ...");
            }
        }
    }
}
