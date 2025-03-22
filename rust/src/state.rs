use rsa::RsaPublicKey;
use sha256::digest;
use std::path::Path;
use std::str::FromStr;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

// Per client data
pub struct ServerState {
    pub clients: HashMap<SocketAddr, Arc<Mutex<ClientData>>>,
}

#[derive(Debug)]
pub struct ClientData {
    pub connections: u16,
    pub message_count: u16,
    pub rsa_public: Option<RsaPublicKey>,
}

// Persistent System & Device Data
#[derive(Debug)]
pub struct File {
    pub file_name: String,
    pub file_hash: String,
    pub file_data: Vec<u8>,
}

pub struct FileSystem {
    pub files: HashMap<String, File>,
}

impl FileSystem {
    pub fn new() -> Self {
        // TODO: Load in existing data here
        FileSystem {
            files: HashMap::new(),
        }
    }

    pub fn import_file(mut self, path: &Path) -> std::io::Result<String> {
        let file_name = path.file_name().unwrap().to_str().unwrap().to_string();

        let file_data = std::fs::read(path)?;

        let file_hash = digest(&file_data);

        self.files.insert(
            file_hash.clone(),
            File {
                file_name,
                file_hash: file_hash.clone(),
                file_data,
            },
        );

        Ok(file_hash)
    }

    pub fn export_file(mut self, file_hash: &str, path: &Path) -> std::io::Result<String> {
        let file = self.files.get(file_hash).unwrap();

        std::fs::write(path, &file.file_data)?;

        self.files.remove(file_hash).unwrap();

        Ok(String::from_str(path.to_str().unwrap()).unwrap())
    }
}
