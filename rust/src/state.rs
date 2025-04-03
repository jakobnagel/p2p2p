use aes_gcm::{aead, aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit};
use hex;
use lazy_static::lazy_static;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::rand_core::{OsRng, RngCore};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignerMut, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::{Mutex, RwLock};
use std::thread::JoinHandle;
use std::{fmt, fs};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::pb;

lazy_static! {
    static ref APP_DATA: RwLock<AppData> = RwLock::new(AppData { private_key: None });
    static ref FILE_SYSTEM: RwLock<FileSystem> = RwLock::new(FileSystem {
        files: HashMap::new()
    });
    static ref CLIENT_DATA: RwLock<HashMap<SocketAddr, RwLock<ClientData>>> =
        RwLock::new(HashMap::new());
    static ref NICKNAME_TO_SOCKET: RwLock<HashMap<String, SocketAddr>> =
        RwLock::new(HashMap::new());
    static ref OUTGOING_MESSAGES: RwLock<Vec<(SocketAddr, pb::WrappedMessage)>> =
        RwLock::new(Vec::new());
    static ref APPROVED_TRANSFERS: RwLock<HashSet<TransferApproval>> = RwLock::new(HashSet::new());
    static ref UNAPPROVED_TRANSFERS: RwLock<HashSet<TransferApproval>> =
        RwLock::new(HashSet::new());
    pub static ref TCP_HANDLES: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
    pub static ref SHUTDOWN: AtomicBool = AtomicBool::new(false);
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AppData {
    private_key: Option<RsaPrivateKey>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct FileSystem {
    pub files: HashMap<String, File>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct File {
    pub file_name: String,
    pub file_hash: String,
    pub file_data: Option<Vec<u8>>,
}

#[derive(Eq, Hash, PartialEq)]
pub struct TransferApproval {
    socket_addr: SocketAddr,
    file_direction: FileDirection,
    file_name: String,
    file_hash: String,
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub enum FileDirection {
    UPLOAD = 1,
    DOWNLOAD = 2,
}

impl fmt::Display for FileDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileDirection::UPLOAD => write!(f, "UPLOAD"),
            FileDirection::DOWNLOAD => write!(f, "DOWNLOAD"),
        }
    }
}

pub struct ClientData {
    nickname: Option<String>,
    connections: u16,
    rsa_public: Option<RsaPublicKey>,
    aes_ephemeral: Option<EphemeralSecret>,
    aes_public: Option<PublicKey>,
    aes_shared: Option<SharedSecret>,
    file_map: Option<HashMap<String, File>>,
}

pub struct AesEncrypted {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Clone)]
pub struct EncryptionModes {
    pub use_rsa: bool,
    pub use_aes: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PersistentClientInfo {
    nickname: String,
    rsa_public_der: Option<RsaPublicKey>,
    file_map: Option<HashMap<String, File>>,
}

pub fn init_app_data() {
    {
        let app_data = APP_DATA.read().unwrap();
        if app_data.private_key.is_some() {
            log::info!("RSA key already exists, skipping new generation.");
            return;
        }
    }
    {
        let mut app_data = APP_DATA.write().unwrap();
        let private_key =
            rsa::RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate a key");
        log::info!("RSA key generated successfully.");
        // let signing_key = SigningKey::<Sha256>::new(private_key);
        app_data.private_key = Some(private_key);
    }
}

pub fn save_app_data_to_disk(password: &str) -> io::Result<()> {
    {
        let app_data = APP_DATA.read().unwrap();
        let data = serde_json::to_vec(&*app_data).unwrap();

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let aes_encrypted = encrypt_password_data(&data, password, &salt).unwrap();
        let mut file = fs::File::create("./appdata.bin")?;
        file.write_all(&salt)?;
        file.write_all(&aes_encrypted.nonce)?;
        file.write_all(&aes_encrypted.ciphertext)?;
        log::info!("Saved appdata.bin");
    }
    {
        let file_system = FILE_SYSTEM.read().unwrap();
        let data = serde_json::to_vec(&*file_system).unwrap();

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let aes_encrypted = encrypt_password_data(&data, password, &salt).unwrap();
        let mut file = fs::File::create("./filesystem.bin")?;
        file.write_all(&salt)?;
        file.write_all(&aes_encrypted.nonce)?;
        file.write_all(&aes_encrypted.ciphertext)?;
        log::info!("Saved filesystem.bin");
    }
    {
        // Save client file data with RSA public key, FileList, Nickname to a file
        let mut persistent_clients: Vec<PersistentClientInfo> = Vec::new();

        let client_data_map = CLIENT_DATA.read().unwrap();
        let nickname_to_socket_map = NICKNAME_TO_SOCKET.read().unwrap();

        for (nickname, socket_addr) in nickname_to_socket_map.iter() {
            if let Some(client_data_lock) = client_data_map.get(socket_addr) {
                let client_data = client_data_lock.read().unwrap();

                let info = PersistentClientInfo {
                    nickname: nickname.clone(),
                    rsa_public_der: client_data.rsa_public.clone(),
                    file_map: client_data.file_map.clone(),
                };

                persistent_clients.push(info);
            } else {
                log::warn!(
                    "Client data not found for nickname {} which maps to socket {:?}",
                    nickname,
                    socket_addr
                );
            }
        }
        let data = serde_json::to_vec(&persistent_clients).map_err(|e| {
            log::error!("Failed to serialize client data vector: {}", e);
            io::Error::new(io::ErrorKind::Other, format!("Serialization failed: {}", e))
        })?;

        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let aes_encrypted = encrypt_password_data(&data, password, &salt).map_err(|e| {
            log::error!("Failed to encrypt client data vector: {}", e);
            io::Error::new(io::ErrorKind::Other, format!("Encryption failed: {}", e))
        })?;

        let mut file = fs::File::create("./clientdata.bin")?;
        file.write_all(&salt)?;
        file.write_all(&aes_encrypted.nonce)?;
        file.write_all(&aes_encrypted.ciphertext)?;
        log::info!("Saved clientdata.bin (as Vec<PersistentClientInfo>)");
    }
    Ok(())
}

pub fn load_app_data_from_disk(password: &str) -> io::Result<()> {
    {
        let mut file = fs::File::open("./appdata.bin")?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut ciphertext = Vec::new();

        file.read_exact(&mut salt)?;
        file.read_exact(&mut nonce)?;
        file.read_to_end(&mut ciphertext)?;
        log::info!("Loaded appdata.bin");

        let decrypted_data = decrypt_password_data(&ciphertext, &nonce, password, &salt);
        if decrypted_data.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password",
            ));
        }
        log::info!("Decrypted appdata.bin successfully");

        let loaded_app_data = serde_json::from_slice(&decrypted_data.unwrap())?;
        log::info!("loaded_app_data: {:?}", loaded_app_data);

        let mut app_data = APP_DATA.write().unwrap();
        *app_data = loaded_app_data;
    }
    {
        let mut file = fs::File::open("./filesystem.bin")?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut ciphertext = Vec::new();

        file.read_exact(&mut salt)?;
        file.read_exact(&mut nonce)?;
        file.read_to_end(&mut ciphertext)?;
        log::info!("Loaded filesystem.bin");

        let decrypted_data = decrypt_password_data(&ciphertext, &nonce, password, &salt);
        if decrypted_data.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password",
            ));
        }
        log::info!("Decrypted filesystem.bin successfully");

        let loaded_file_system = serde_json::from_slice(&decrypted_data.unwrap())?;
        log::info!("loaded_file_system: {:?}", loaded_file_system);

        let mut file_system = FILE_SYSTEM.write().unwrap();
        *file_system = loaded_file_system;
    }
    {
        // Load client data file with RSA public key, nickname, and IP range
        // Use this IP range (test block) 192.0.2.0/24
        let mut file = fs::File::open("./clientdata.bin")?;
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        let mut ciphertext = Vec::new();

        file.read_exact(&mut salt)?;
        file.read_exact(&mut nonce)?;
        file.read_to_end(&mut ciphertext)?;
        log::info!("Loaded clientdata.bin");

        let decrypted_data = decrypt_password_data(&ciphertext, &nonce, password, &salt);
        if decrypted_data.is_err() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid password",
            ));
        }
        log::info!("Decrypted clientdata.bin successfully");

        let loaded_client_data: Vec<PersistentClientInfo> =
            serde_json::from_slice(&decrypted_data.unwrap())?;
        log::info!("loaded_client_data: {:?}", loaded_client_data);

        for (i, client_info) in loaded_client_data.into_iter().enumerate() {
            let ip_bytes = u32::from(Ipv4Addr::new(192, 0, 2, 0));
            let generated_ip = Ipv4Addr::from(ip_bytes.checked_add(i as u32).unwrap());
            let socket_addr = SocketAddr::new(IpAddr::V4(generated_ip), 5200);

            init_client_data(socket_addr);
            set_client_nickname(socket_addr, client_info.nickname.clone()).unwrap();

            if let Some(rsa_public) = client_info.rsa_public_der {
                set_client_rsa_key(socket_addr, rsa_public);
            }

            if let Some(file_map) = client_info.file_map {
                set_client_file_list(socket_addr, file_map);
            }
        }
        log::info!("Loaded client data successfully");
    }

    Ok(())
}

pub fn does_app_data_exist() -> bool {
    Path::new("./appdata.bin").exists()
}

fn get_key_from_password(password: &str, salt: &[u8]) -> Key<Aes256Gcm> {
    let mut key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100000, &mut key);
    key.into()
}

fn encrypt_password_data(
    plaintext: &[u8],
    password: &str,
    salt: &[u8],
) -> aead::Result<AesEncrypted> {
    let key = get_key_from_password(password, salt);
    let cipher = aes_gcm::Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    Ok(AesEncrypted {
        ciphertext: cipher.encrypt(&nonce, plaintext).unwrap(),
        nonce: nonce.to_vec(),
    })
}

fn decrypt_password_data(
    ciphertext: &[u8],
    nonce: &[u8],
    password: &str,
    salt: &[u8],
) -> aead::Result<Vec<u8>> {
    let key = get_key_from_password(password, salt);
    let cipher = Aes256Gcm::new(&key);
    let nonce = aes_gcm::Nonce::from_slice(nonce);

    cipher.decrypt(nonce, ciphertext)
}

pub fn sign_message(msg: &[u8]) -> Signature {
    let app_data = APP_DATA.read().unwrap();

    let private_key = app_data.private_key.as_ref().unwrap();
    let mut signing_key = SigningKey::<Sha256>::new(private_key.clone());

    let signature = signing_key.sign(msg);
    signature
}

pub fn get_rsa_key() -> RsaPublicKey {
    let app_data = APP_DATA.read().unwrap();
    app_data.private_key.as_ref().unwrap().to_public_key()
}

pub fn hash_file(file_data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&file_data);
    hex::encode(hasher.finalize())
}

pub fn import_file(path: &Path) -> io::Result<File> {
    let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
    let file_data = fs::read(path)?;
    let file_hash = hash_file(&file_data);

    let file = File {
        file_name: file_name,
        file_hash: file_hash.clone(),
        file_data: Some(file_data),
    };
    {
        let mut file_system = FILE_SYSTEM.write().unwrap();
        file_system.files.insert(file_hash.clone(), file.clone());
    }

    Ok(file)
}

pub fn export_file(file_hash: &str, path: &Path) -> io::Result<String> {
    {
        let file_system = FILE_SYSTEM.read().unwrap();
        let file = file_system.files.get(file_hash).unwrap();
        fs::write(path, file.file_data.as_ref().unwrap())?;
    }
    {
        let mut file_system = FILE_SYSTEM.write().unwrap();
        file_system.files.remove(file_hash).unwrap();
    }
    Ok(path.to_str().unwrap().to_string())
}

pub fn get_file_list() -> Vec<File> {
    let file_system = FILE_SYSTEM.read().unwrap();
    file_system.files.values().cloned().collect()
}

pub fn print_file_list() {
    let file_system = FILE_SYSTEM.read().unwrap();
    for file in file_system.files.values() {
        println!("{} {}", file.file_name, file.file_hash);
    }
}

pub fn get_file_by_hash(file_hash: &str) -> File {
    let file_system = FILE_SYSTEM.read().unwrap();
    file_system.files.get(file_hash).unwrap().clone()
}

pub fn get_file_by_name(file_name: &str) -> File {
    let file_system = FILE_SYSTEM.read().unwrap();
    for file in file_system.files.values() {
        if file.file_name == file_name {
            return file.clone();
        }
    }
    panic!("File not found")
}

pub fn file_hash_to_name(file_hash: &str) -> String {
    let file_system = FILE_SYSTEM.read().unwrap();
    file_system.files.get(file_hash).unwrap().file_name.clone()
}

pub fn file_name_to_hash(file_name: &str) -> Option<String> {
    let file_system = FILE_SYSTEM.read().unwrap();
    for file in file_system.files.values() {
        if file.file_name == file_name {
            return Some(file.file_hash.clone());
        }
    }

    log::warn!("File not found");
    return None;
}

pub fn remote_file_name_to_hash(socket_addr: SocketAddr, file_name: &str) -> Option<String> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();
    if client_data.file_map.is_none() {
        return None;
    }

    let file_map = client_data.file_map.as_ref().unwrap();
    for file in file_map.values() {
        if file.file_name == file_name {
            return Some(file.file_hash.clone());
        }
    }

    log::warn!("File not found");
    return None;
}

pub fn set_file(file: File) {
    let mut file_system = FILE_SYSTEM.write().unwrap();
    file_system.files.insert(file.file_hash.clone(), file);
}

pub fn increment_client_connections(socket_addr: SocketAddr) -> u16 {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();

    client_data.connections += 1;
    client_data.connections
}

pub fn decrement_client_connections(socket_addr: SocketAddr) -> u16 {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();

    client_data.connections -= 1;
    client_data.connections
}

pub fn set_client_nickname(socket_addr: SocketAddr, nickname: String) -> Result<(), ()> {
    init_client_data(socket_addr);

    {
        let nickname_to_socket_map = NICKNAME_TO_SOCKET.read().unwrap();
        if nickname_to_socket_map.contains_key(&nickname) {
            return Err(());
        }
    }
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();
        client_data.nickname = Some(nickname.clone());
    }
    {
        let mut nickname_to_socket_map = NICKNAME_TO_SOCKET.write().unwrap();
        nickname_to_socket_map.insert(nickname.clone(), socket_addr);
    }
    Ok(())
}

pub fn set_client_nickname_randomly(socket_addr: SocketAddr) {
    let mut rng = OsRng;
    let mut nickname = String::with_capacity(8);
    for _ in 0..6 {
        let random_val = rng.next_u32();
        let offset = random_val % 26;
        let c = (b'a' + offset as u8) as char;
        nickname.push(c);
    }
    set_client_nickname(socket_addr, nickname).unwrap();
}

pub fn change_client_nickname(old_nickname: String, new_nickname: String) -> Result<(), ()> {
    // Ensure old name is valid and save socket
    let socket_addr = match get_socket_from_nickname(&old_nickname) {
        Some(socket_addr) => socket_addr,
        None => return Err(()),
    };

    // Check new nickname is free
    if get_socket_from_nickname(&new_nickname).is_some() {
        return Err(());
    }
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();
        client_data.nickname = Some(new_nickname.clone());
    }
    {
        let mut nickname_to_socket_map = NICKNAME_TO_SOCKET.write().unwrap();
        nickname_to_socket_map.remove(&old_nickname);
        nickname_to_socket_map.insert(new_nickname.clone(), socket_addr);
    }
    Ok(())
}

pub fn get_nickname_from_socket(socket_addr: SocketAddr) -> Option<String> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    client_data.nickname.clone()
}

pub fn get_socket_from_nickname(nickname: &str) -> Option<SocketAddr> {
    let nickname_to_socket_map = NICKNAME_TO_SOCKET.read().unwrap();
    log::info!(
        "Mapped {} to {:?}",
        nickname,
        nickname_to_socket_map.get(nickname)
    );
    nickname_to_socket_map.get(nickname).cloned()
}

pub fn try_migrate_client_socket(
    rsa_public_key: &RsaPublicKey,
    new_socket_addr: SocketAddr,
) -> Result<(), ()> {
    let mut client_data_map = CLIENT_DATA.write().unwrap();
    let mut nickname_to_socket_map = NICKNAME_TO_SOCKET.write().unwrap();

    let mut old_socket_addr_option: Option<SocketAddr> = None;
    let mut nickname_option: Option<String> = None;

    log::info!("Searching for old client with RSA key");

    for (socket_addr, client_data_lock) in client_data_map.iter() {
        let client_data = client_data_lock.read().unwrap();
        if client_data.rsa_public.as_ref() == Some(rsa_public_key) {
            if client_data.connections > 0 {
                log::info!(
                    "Duplicate RSA keys? Tried to migrate but the RSA key already has a connection"
                );
            }
        }
        old_socket_addr_option = Some(*socket_addr);
        nickname_option = client_data.nickname.clone();
        break;
    }

    if old_socket_addr_option.is_none() || nickname_option.is_none() {
        log::info!("Didn't find existing RSA key");
        return Err(());
    }
    let old_socket_addr = old_socket_addr_option.unwrap();
    let nickname = nickname_option.unwrap();

    let client_data = client_data_map.remove(&old_socket_addr).unwrap();
    nickname_to_socket_map.remove(&nickname);

    log::info!(
        "Migrating client '{}' from fake address {} to new address {}",
        nickname,
        old_socket_addr,
        new_socket_addr
    );

    if let Some(existing_lock) = client_data_map.insert(new_socket_addr, client_data) {
        match existing_lock.read() {
            Ok(existing_data) => {
                log::info!(
                    "Replaced existing client data at {} (Nickname: {:?}) during migration of '{}'.",
                    new_socket_addr,
                    existing_data.nickname,
                    nickname
                );
                if let Some(replaced_nickname) = existing_data.nickname.as_ref() {
                    nickname_to_socket_map.remove(replaced_nickname);
                }
            }
            Err(_) => {
                log::warn!(
                    "Replaced existing client data at {} (could not read data) during migration of '{}'.",
                    new_socket_addr,
                    nickname
                );
            }
        }
    }

    nickname_to_socket_map.insert(nickname.clone(), new_socket_addr);

    log::info!(
        "Successfully migrated client '{}' to {}",
        nickname,
        new_socket_addr
    );

    Ok(())
}

pub fn set_client_file_list(socket_addr: SocketAddr, file_map: HashMap<String, File>) {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();

    client_data.file_map = Some(file_map);
}

pub fn get_client_file_list(socket_addr: SocketAddr) -> Option<HashMap<String, File>> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    client_data.file_map.clone()
}

pub fn print_client_file_list(socket_addr: SocketAddr) {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    println!("Files Available: ");
    if client_data.file_map.is_none() {
        println!("No file list received from {}", socket_addr);
        return;
    }

    let file_map = client_data.file_map.as_ref().unwrap();
    if file_map.len() == 0 {
        println!("N/A");
    } else {
        for (file_name, file) in file_map {
            println!("{} {}", file_name, file.file_hash);
        }
    }
}

pub fn init_client_data(socket_addr: SocketAddr) {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        if client_data_map.contains_key(&socket_addr) {
            return;
        }
    }

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let public_key = PublicKey::from(&ephemeral_secret);
    let client_data = ClientData {
        nickname: None,
        connections: 0,
        rsa_public: None,
        aes_ephemeral: Some(ephemeral_secret),
        aes_public: Some(public_key),
        aes_shared: None,
        file_map: None,
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
        client_data.aes_shared = None;
    }
}

pub fn print_clients() {
    let client_data_map = CLIENT_DATA.read().unwrap();
    println!("nickname, connections, rsa used, aes used, socket");
    for (socket_addr, client_data) in client_data_map.iter() {
        let client_data = client_data.read().unwrap();
        println!(
            "{} {} {} {:?} {:?}",
            client_data.nickname.clone().unwrap(),
            client_data.connections,
            client_data.rsa_public.is_some(),
            client_data.aes_shared.is_some(),
            socket_addr,
        );
    }
}

pub fn is_client_connected(socket_addr: SocketAddr) -> bool {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    client_data.connections >= 1
}

pub fn get_client_list() -> Vec<SocketAddr> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    client_data_map.keys().cloned().collect()
}

pub fn find_clients_with_hash(file_hash: &str) -> Vec<SocketAddr> {
    let mut clients_with_hash = Vec::new();
    let client_data_map = CLIENT_DATA.read().unwrap();
    for (socket_addr, client_data) in client_data_map.iter() {
        let client_data = client_data.read().unwrap();
        if client_data.connections == 0 {
            continue;
        }
        if let Some(file_map) = &client_data.file_map {
            if file_map.values().any(|file| file.file_hash == file_hash) {
                clients_with_hash.push(*socket_addr);
            }
        }
    }
    clients_with_hash
}

pub fn get_client_encryption_modes(socket_addr: SocketAddr) -> EncryptionModes {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    EncryptionModes {
        use_rsa: client_data.rsa_public.is_some(),
        use_aes: client_data.aes_shared.is_some(),
    }
}

pub fn get_client_rsa_key(socket_addr: SocketAddr) -> Option<RsaPublicKey> {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();
        client_data.rsa_public.clone()
    }
}

pub fn set_client_rsa_key(socket_addr: SocketAddr, rsa_public: RsaPublicKey) {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();
        client_data.rsa_public = Some(rsa_public);
    }
}

pub fn verify_client_signature(
    socket_addr: SocketAddr,
    msg: &Vec<u8>,
    signature: &Signature,
) -> rsa::signature::Result<()> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    let public_key = client_data.rsa_public.clone().unwrap();
    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);

    verifying_key.verify(msg, signature)
}

pub fn get_client_dh_public(socket_addr: SocketAddr) -> PublicKey {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

        client_data.aes_public.unwrap()
    }
}

pub fn set_client_dh_shared(socket_addr: SocketAddr, bob_public: PublicKey) {
    {
        let client_data_map = CLIENT_DATA.read().unwrap();
        let mut client_data = client_data_map.get(&socket_addr).unwrap().write().unwrap();

        let ephemeral_secret = Option::take(&mut client_data.aes_ephemeral).unwrap();
        let shared_secret = ephemeral_secret.diffie_hellman(&bob_public);
        client_data.aes_shared = Some(shared_secret);
    }
}

pub fn encrypt_aes_message(socket_addr: SocketAddr, plaintext: &[u8]) -> AesEncrypted {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    let shared_secret = client_data.aes_shared.as_ref().unwrap();
    let key: &Key<Aes256Gcm> = shared_secret.as_bytes().into();

    let cipher = aes_gcm::Aes256Gcm::new(&key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    AesEncrypted {
        ciphertext,
        nonce: nonce.to_vec(),
    }
}

pub fn decrypt_aes_message(socket_addr: SocketAddr, nonce: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    let shared_secret = client_data.aes_shared.as_ref().unwrap();
    let key: &Key<Aes256Gcm> = shared_secret.as_bytes().into();

    let cipher = aes_gcm::Aes256Gcm::new(&key);

    let nonce = aes_gcm::Nonce::from_slice(nonce);
    let decrypted_bytes = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    decrypted_bytes
}

pub fn get_outgoing_message(socket_addr: SocketAddr) -> Option<pb::WrappedMessage> {
    let outgoing_messages = OUTGOING_MESSAGES.read().unwrap();
    for (i, (recipient, _)) in outgoing_messages.iter().enumerate() {
        if *recipient == socket_addr {
            drop(outgoing_messages);
            let mut outgoing_messages = OUTGOING_MESSAGES.write().unwrap();
            let (_, wrapped_message) = outgoing_messages.remove(i);
            return Some(wrapped_message);
        }
    }
    None
}

pub fn add_outgoing_message(socket_addr: SocketAddr, wrapped_message: pb::WrappedMessage) {
    let mut outgoing_messages = OUTGOING_MESSAGES.write().unwrap();
    outgoing_messages.push((socket_addr, wrapped_message));
}

pub fn approve_transfer(
    socket_addr: SocketAddr,
    file_direction: FileDirection,
    file_name: String,
    file_hash: String,
) {
    let approval = TransferApproval {
        socket_addr,
        file_direction,
        file_name,
        file_hash,
    };
    {
        let mut unapproved_transfers = UNAPPROVED_TRANSFERS.write().unwrap();
        unapproved_transfers.remove(&approval);
    }
    {
        let mut approved_transfers = APPROVED_TRANSFERS.write().unwrap();
        approved_transfers.insert(approval);
    }
}

pub fn reject_transfer(
    socket_addr: SocketAddr,
    file_direction: FileDirection,
    file_name: String,
    file_hash: String,
) {
    let approval = TransferApproval {
        socket_addr,
        file_direction,
        file_name,
        file_hash,
    };
    {
        let mut unapproved_transfers = UNAPPROVED_TRANSFERS.write().unwrap();
        unapproved_transfers.remove(&approval);
    }
    {
        let mut approved_transfers = APPROVED_TRANSFERS.write().unwrap();
        approved_transfers.remove(&approval);
    }
}

pub fn request_transfer_approval(
    socket_addr: SocketAddr,
    file_direction: FileDirection,
    file_name: String,
    file_hash: String,
) -> bool {
    let approval = TransferApproval {
        file_direction,
        socket_addr,
        file_name,
        file_hash,
    };
    {
        // If already approved, allow operation
        let consent_messages = APPROVED_TRANSFERS.read().unwrap();
        if consent_messages.contains(&approval) {
            return true;
        }
    }
    {
        // If unapproved, disallow operation
        let unapproved_consent_messages = UNAPPROVED_TRANSFERS.read().unwrap();
        if unapproved_consent_messages.contains(&approval) {
            return false;
        }
    }
    {
        // If first time requesting, add to unapproved_messages
        let mut unapproved_consent_messages = UNAPPROVED_TRANSFERS.write().unwrap();
        unapproved_consent_messages.insert(approval);
    }
    return false;
}

pub fn get_transfer_approval(
    socket_addr: SocketAddr,
    file_direction: FileDirection,
    file_name: String,
    file_hash: String,
) -> bool {
    let approval = TransferApproval {
        file_direction,
        socket_addr,
        file_name,
        file_hash,
    };
    {
        // If already approved, allow operation
        let consent_messages = APPROVED_TRANSFERS.read().unwrap();
        if consent_messages.contains(&approval) {
            return true;
        }
    }
    return false;
}

pub fn get_pending_hash_from_name(file_name: &str) -> Option<String> {
    let unapproved_transfers = UNAPPROVED_TRANSFERS.read().unwrap();
    for transfer in unapproved_transfers.iter() {
        if transfer.file_name == file_name {
            return Some(transfer.file_hash.clone());
        }
    }
    None
}
