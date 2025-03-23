use aes_gcm::aead::Aead;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit};
use hex;
use lazy_static::lazy_static;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::rand_core::OsRng;
use rsa::sha2::{Digest, Sha256};
use rsa::signature::{SignerMut, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::RwLock;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

lazy_static! {
    // static ref MY_DATA: RwLock<HashMap<String, i32>> = RwLock::new(HashMap::new());
    static ref APP_DATA: RwLock<AppData> = RwLock::new(AppData { private_key: None});
    static ref FILE_SYSTEM: RwLock<FileSystem> = RwLock::new(FileSystem {
        files: HashMap::new()
    });
    static ref CLIENT_DATA: RwLock<HashMap<SocketAddr, RwLock<ClientData>>> = RwLock::new(HashMap::new());
}

pub struct AppData {
    private_key: Option<RsaPrivateKey>,
}

struct FileSystem {
    pub files: HashMap<String, File>,
}

#[derive(Clone)]
pub struct File {
    pub file_name: String,
    pub file_hash: String,
    pub file_data: Option<Vec<u8>>,
}

pub struct EncryptionModes {
    pub use_rsa: bool,
    pub use_aes: bool,
}

pub struct ClientData {
    connections: u16,
    message_count: u16,
    rsa_public: Option<VerifyingKey<Sha256>>,
    aes_ephemeral: Option<EphemeralSecret>,
    aes_shared: Option<SharedSecret>,
    file_map: Option<HashMap<String, File>>,
}

pub struct AesEncrypted {
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn init_app_data() {
    let mut app_data = APP_DATA.write().unwrap();
    let bits = 2048;
    let private_key = rsa::RsaPrivateKey::new(&mut OsRng, bits).expect("failed to generate a key");
    // let signing_key = SigningKey::<Sha256>::new(private_key);
    app_data.private_key = Some(private_key);
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

pub fn set_file(file: File) {
    let mut file_system = FILE_SYSTEM.write().unwrap();
    file_system.files.insert(file.file_hash.clone(), file);
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

pub fn init_client_data(socket_addr: SocketAddr) {
    let client_data = ClientData {
        connections: 1,
        message_count: 0,
        rsa_public: None,
        aes_ephemeral: Some(EphemeralSecret::random_from_rng(OsRng)),
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
        client_data.connections = 0;
    }
}

pub fn get_client_encryption(socket_addr: SocketAddr) -> EncryptionModes {
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

        let ephemeral_secret = client_data.aes_ephemeral.as_ref().unwrap();
        PublicKey::from(ephemeral_secret)
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
