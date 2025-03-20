mod mdns;

use mdns::init_mdns;
use std::{io, sync::mpsc};

fn main() {
    let (ip_sender, ip_receiver) = mpsc::channel();

    let mdns: mdns_sd::ServiceDaemon = init_mdns(ip_sender).unwrap();
    // TODO: Initialize File Receiving thread
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
    mdns.shutdown().unwrap();
}
