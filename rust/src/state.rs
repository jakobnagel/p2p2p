use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use rsa::RsaPublicKey;

pub struct ServerState {
    pub clients: HashMap<SocketAddr, Arc<Mutex<ClientData>>>,
}

#[derive(Debug)]
pub struct ClientData {
    pub connections: u16,
    pub message_count: u16,
    pub rsa_public: Option<RsaPublicKey>,
}
