use hex;
use lazy_static::lazy_static;
use rsa::pkcs1v15::VerifyingKey;
use rsa::sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::RwLock;

lazy_static! {
    // static ref MY_DATA: RwLock<HashMap<String, i32>> = RwLock::new(HashMap::new());
    static ref FILE_SYSTEM: RwLock<FileSystem> = RwLock::new(FileSystem {
        files: HashMap::new()
    });
    static ref CLIENT_DATA: RwLock<HashMap<SocketAddr, RwLock<ClientData>>> = RwLock::new(HashMap::new());
}

pub struct AppData {}

struct FileSystem {
    pub files: HashMap<String, File>,
}

pub struct File {
    pub file_name: String,
    pub file_hash: String,
    pub file_data: Vec<u8>,
}

pub struct ClientData {
    pub connections: u16,
    pub message_count: u16,
    pub rsa_public: Option<VerifyingKey<Sha256>>,
}

pub fn import_file(path: &Path) -> io::Result<String> {
    let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
    let file_data = fs::read(path)?;
    // let file_hash = sha256::digest(&file_data);

    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    let file_hash = hex::encode(hasher.finalize());

    {
        let mut file_system = FILE_SYSTEM.write().unwrap();
        file_system.files.insert(
            file_hash.clone(),
            File {
                file_name,
                file_hash: file_hash.clone(),
                file_data,
            },
        );
    }

    Ok(file_hash)
}

pub fn export_file(file_hash: &str, path: &Path) -> io::Result<String> {
    {
        let file_system = FILE_SYSTEM.read().unwrap();
        let file = file_system.files.get(file_hash).unwrap();
        fs::write(path, &file.file_data)?;
    }
    {
        let mut file_system = FILE_SYSTEM.write().unwrap();
        file_system.files.remove(file_hash).unwrap();
    }
    Ok(path.to_str().unwrap().to_string())
}

pub fn init_client_data(socket_addr: SocketAddr) {
    let client_data = ClientData {
        connections: 1,
        message_count: 0,
        rsa_public: None,
    };
    {
        let mut client_data_map = CLIENT_DATA.write().unwrap();
        client_data_map.insert(socket_addr, RwLock::new(client_data));
    }
}

pub fn remove_client_data(socket_addr: SocketAddr) {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();
        client_data.connections = 0;
    }
}

pub fn get_client_rsa_key(socket_addr: SocketAddr) -> Option<VerifyingKey<Sha256>> {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();
        client_data.rsa_public.clone()
    }
}

pub fn set_client_rsa_key(socket_addr: SocketAddr, rsa_public: VerifyingKey<Sha256>) {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();
        client_data.rsa_public = Some(rsa_public.clone());
    }
}
