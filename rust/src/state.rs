use aes_gcm::{aead, aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit};
use hex;
use lazy_static::lazy_static;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::rand_core::{OsRng, RngCore};
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignerMut, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::RwLock;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

use crate::pb;

type Result<T> = std::result::Result<T, Box<dyn Error + Sync + Send>>;

lazy_static! {
    // static ref MY_DATA: RwLock<HashMap<String, i32>> = RwLock::new(HashMap::new());
    static ref APP_DATA: RwLock<AppData> = RwLock::new(AppData { private_key: None});
    static ref FILE_SYSTEM: RwLock<FileSystem> = RwLock::new(FileSystem {
        files: HashMap::new()
    });
    static ref CLIENT_DATA: RwLock<HashMap<SocketAddr, RwLock<ClientData>>> = RwLock::new(HashMap::new());
    static ref OUTGOING_MESSAGES: RwLock<Vec<(SocketAddr, pb::WrappedMessage)>> = RwLock::new(Vec::new());
    static ref APPROVED_TRANSFERS: RwLock<HashSet<TransferApproval>> = RwLock::new(HashSet::new());
    static ref UNAPPROVED_TRANSFERS: RwLock<HashSet<TransferApproval>> = RwLock::new(HashSet::new());
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
    file_hash: String,
}

#[derive(Eq, Hash, PartialEq)]
pub enum FileDirection {
    UPLOAD = 1,
    DOWNLOAD = 2,
}

pub struct ClientData {
    // hostname: hostname
    connections: u16,
    rsa_public: Option<VerifyingKey<Sha256>>,
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

pub fn import_file(path: &Path) -> io::Result<String> {
    let file_name = path.file_name().unwrap().to_str().unwrap().to_string();
    let file_data = fs::read(path)?;

    let file_hash = hash_file(&file_data);

    {
        let mut file_system = FILE_SYSTEM.write().unwrap();
        file_system.files.insert(
            file_hash.clone(),
            File {
                file_name: file_name,
                file_hash: file_hash.clone(),
                file_data: Some(file_data),
            },
        );
    }

    Ok(file_hash)
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

    if client_data.file_map.is_none() {
        println!("No file list received from {}", socket_addr);
        return;
    }

    let file_map = client_data.file_map.as_ref().unwrap();
    for (file_name, file) in file_map {
        println!("{} {}", file_name, file.file_hash);
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
    println!("socket, connections, rsa, aes");
    for (socket_addr, client_data) in client_data_map.iter() {
        let client_data = client_data.read().unwrap();
        println!(
            "{} {} {:?} {:?}",
            socket_addr,
            client_data.connections,
            client_data.rsa_public.is_some(),
            client_data.aes_shared.is_some(),
        );
    }
}

pub fn get_client_list() -> Vec<SocketAddr> {
    let client_data_map = CLIENT_DATA.read().unwrap();
    client_data_map.keys().cloned().collect()
}

pub fn get_client_encryption_modes(socket_addr: SocketAddr) -> EncryptionModes {
    let client_data_map = CLIENT_DATA.read().unwrap();
    let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

    EncryptionModes {
        use_rsa: client_data.rsa_public.is_some(),
        use_aes: client_data.aes_shared.is_some(),
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

    let verifying_key = client_data.rsa_public.as_ref().unwrap();

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

pub fn approve_transfer(socket_addr: SocketAddr, file_direction: FileDirection, file_hash: String) {
    let approval = TransferApproval {
        socket_addr,
        file_direction,
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

pub fn reject_transfer(socket_addr: SocketAddr, file_direction: FileDirection, file_hash: String) {
    let approval = TransferApproval {
        socket_addr,
        file_direction,
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
    file_hash: String,
) -> bool {
    let approval = TransferApproval {
        file_direction,
        socket_addr,
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
    file_hash: String,
) -> bool {
    let approval = TransferApproval {
        file_direction,
        socket_addr,
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
