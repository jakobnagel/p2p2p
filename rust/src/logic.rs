use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pb;
use crate::state::{self, FileDirection};
use colored::*;
use num_traits::cast::ToPrimitive;
use prost::Message;
use rsa::pkcs1v15::Signature;
use rsa::signature::SignatureEncoding;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

use x25519_dalek::PublicKey;

pub fn handle_message(
    socket_addr: SocketAddr,
    wrapped_message: pb::WrappedMessage,
) -> Option<pb::WrappedMessage> {
    match wrapped_message.payload {
        Some(pb::wrapped_message::Payload::Introduction(introduction)) => {
            log::info!("[{}]: received introduction", socket_addr);
            // Introduction message
            // States RSA public key
            // Both steps of Diffehellman

            let rsa_public_key = introduction.rsa_public_key.unwrap();
            let e = BigUint::from(rsa_public_key.e);
            let n = BigUint::from_bytes_be(rsa_public_key.n.as_slice());
            let public_key = RsaPublicKey::new(n, e).unwrap();

            log::info!(
                "[{}]: extracted incoming RSA key {:?}",
                socket_addr,
                public_key,
            );

            match state::try_migrate_client_socket(&public_key, socket_addr) {
                Ok(()) => log::info!("Migrated existing client"),
                Err(()) => log::info!("Didn't migrate"),
            }

            // let verifying_key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha256>::new(public_key);
            state::set_client_rsa_key(socket_addr, public_key);

            if state::get_client_encryption_modes(socket_addr).use_aes {
                log::info!(
                    "[{}]: not sending hello back since AES already established",
                    socket_addr,
                );
                return None;
            }

            let dh_array: [u8; 32] = introduction
                .diffe_hellman
                .unwrap()
                .dh_public_key
                .try_into()
                .expect("error fitting into 32 bytes");
            let bob_dh_public_key = PublicKey::from(dh_array);

            log::info!(
                "[{}]: extracted incoming dh shared key {:?}",
                socket_addr,
                bob_dh_public_key
            );

            state::set_client_dh_shared(socket_addr, bob_dh_public_key);
            log::info!("[{}]: established AES shared key", socket_addr);

            let rsa_public_key = state::get_rsa_key();
            log::info!("[{}]: calculated public RSA key", socket_addr);

            let alice_dh_public_key = state::get_client_dh_public(socket_addr);
            log::info!("[{}]: calculated public DH key", socket_addr);

            log::info!("[{}]: returning RSA & DH public key", socket_addr);
            return Some(pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::Introduction(
                    pb::Introduction {
                        rsa_public_key: {
                            Some(pb::RsaPublicKey {
                                e: rsa_public_key.e().to_u32().unwrap(),
                                n: rsa_public_key.n().to_bytes_be(),
                            })
                        },
                        diffe_hellman: Some(pb::DiffeHellman {
                            dh_public_key: alice_dh_public_key.to_bytes().to_vec(),
                        }),
                    },
                )),
            });
        }
        Some(pb::wrapped_message::Payload::FileListRequest(_)) => {
            log::info!("[{}]: received file list request", socket_addr);

            let file_list = state::get_file_list();

            let mut file_metadata_list: Vec<pb::FileMetadata> = Vec::new();
            for file in file_list {
                file_metadata_list.push(pb::FileMetadata {
                    name: file.file_name,
                    hash: file.file_hash.as_bytes().to_vec(),
                });
            }
            log::info!(
                "[{}]: fetched list of files {:?}",
                socket_addr,
                file_metadata_list
            );

            log::info!("[{}]: returning file list", socket_addr);
            return Some(pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::FileList(pb::FileList {
                    files: file_metadata_list,
                })),
            });
        }
        Some(pb::wrapped_message::Payload::FileList(file_list)) => {
            log::info!("[{}]: received file list", socket_addr);

            let mut file_map: std::collections::HashMap<String, state::File> =
                std::collections::HashMap::new();
            for file_metadata in file_list.files {
                file_map.insert(
                    file_metadata.name.clone(),
                    state::File {
                        file_name: file_metadata.name,
                        file_hash: String::from_utf8(file_metadata.hash).unwrap(),
                        file_data: None,
                    },
                );
            }
            log::info!("[{}]: extracted file list {:?}", socket_addr, file_map);

            state::set_client_file_list(socket_addr, file_map);

            log::info!("[{}]: no response necessary", socket_addr);
            return None;
        }
        Some(pb::wrapped_message::Payload::FileDownloadRequest(file_download_request)) => {
            log::info!("[{}]: received file download request", socket_addr);

            let file_name = file_download_request.file_name;
            let file_hash = match state::file_name_to_hash(&file_name) {
                Some(file_hash) => file_hash,
                None => {
                    return Some(pb::WrappedMessage {
                        payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                            message: "File not found".to_string(),
                        })),
                    });
                }
            };
            let nickname = state::get_nickname_from_socket(socket_addr).unwrap();

            log::info!(
                "[{}]: extracted file name and associated hash {} {}",
                socket_addr,
                file_name,
                file_hash
            );

            if !state::request_transfer_approval(
                socket_addr,
                FileDirection::DOWNLOAD,
                file_name.clone(),
                file_hash.clone(),
            ) {
                log::info!(
                    "[{}]: file approval not found for download {} {}",
                    socket_addr,
                    file_name,
                    file_hash,
                );
                println!(
                    "[{}]: Incoming request to download {}, type {}",
                    socket_addr,
                    file_name,
                    format!("approve {} download {}", nickname, file_name)
                        .yellow()
                        .bold()
                );

                let start_time = Instant::now();
                let timeout = Duration::from_secs(30);
                let check_interval = Duration::from_secs(5);

                let mut approved = false;
                while start_time.elapsed() < timeout {
                    if state::get_transfer_approval(
                        socket_addr,
                        FileDirection::DOWNLOAD,
                        file_name.clone(),
                        file_hash.clone(),
                    ) {
                        approved = true;
                        break;
                    }
                    log::info!(
                        "[{}]: file approval not found for download {} {}",
                        socket_addr,
                        file_name,
                        file_hash
                    );
                    std::thread::sleep(check_interval);
                }

                if !approved {
                    log::info!(
                        "[{}]: file approval not received for download {} {}",
                        socket_addr,
                        file_name,
                        file_hash
                    );
                    let error_message = format!(
                        "Download approval not received for file '{}' (hash: {}) from {} within {} seconds",
                        file_name, file_hash, socket_addr, timeout.as_secs()
                    );

                    log::info!(
                        "[{}]: returning rejection error {} {}",
                        socket_addr,
                        file_name,
                        file_hash
                    );
                    return Some(pb::WrappedMessage {
                        payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                            message: error_message,
                        })),
                    });
                }
            }

            log::info!(
                "[{}]: found download approval {} {}",
                socket_addr,
                file_name,
                file_hash
            );

            println!(
                "[{}]: transfering file data {} {}",
                socket_addr, file_name, file_hash
            );
            let file = state::get_file_by_name(&file_name);
            return Some(pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::FileDownload(
                    pb::FileDownload {
                        file_name: file.file_name,
                        file_data: file.file_data.unwrap(),
                    },
                )),
            });
        }
        Some(pb::wrapped_message::Payload::FileDownload(file_download)) => {
            let file_name = file_download.file_name;
            let file_hash = state::hash_file(file_download.file_data.as_slice());

            println!(
                "[{}]: received download {} {}",
                socket_addr, file_name, file_hash
            );

            if !state::get_transfer_approval(
                socket_addr,
                FileDirection::DOWNLOAD,
                file_name.clone(),
                file_hash.clone(),
            ) {
                log::info!(
                    "[{}]: download wasn't requested or doesn't match hash {} {}",
                    socket_addr,
                    file_name,
                    file_hash
                );
                return Some(pb::WrappedMessage {
                    payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                        message: "Download wasn't requested or doesn't match hash".to_string(),
                    })),
                });
            }

            state::set_file(state::File {
                file_name,
                file_hash: state::hash_file(file_download.file_data.as_slice()),
                file_data: Some(file_download.file_data),
            });

            log::info!("[{}]: no response necessary", socket_addr);

            return None;
        }
        Some(pb::wrapped_message::Payload::FileUploadRequest(file_upload_request)) => {
            log::info!("[{}]: received file upload request", socket_addr);

            let file_name = file_upload_request.file_name.clone();
            let file_data = file_upload_request.file_data.clone();
            let file_hash = state::hash_file(&file_data);
            let nickname = state::get_nickname_from_socket(socket_addr).unwrap();

            log::info!(
                "[{}]: extracted file name and associated hash {} {}",
                socket_addr,
                file_name,
                file_hash
            );

            if !state::request_transfer_approval(
                socket_addr,
                FileDirection::UPLOAD,
                file_name.clone(),
                file_hash.clone(),
            ) {
                log::info!(
                    "[{}]: file approval not found for upload {} {}",
                    socket_addr,
                    file_name,
                    file_hash
                );
                println!(
                    "[{}]: Incoming request to upload {}, type {}",
                    socket_addr,
                    file_name,
                    format!("approve {} upload {}", nickname, file_name)
                        .yellow()
                        .bold()
                );

                let start_time = Instant::now();
                let timeout = Duration::from_secs(30);
                let check_interval = Duration::from_secs(5);

                let mut approved = false;
                while start_time.elapsed() < timeout {
                    if state::get_transfer_approval(
                        socket_addr,
                        FileDirection::UPLOAD,
                        file_name.clone(),
                        file_hash.clone(),
                    ) {
                        approved = true;
                        break;
                    }
                    std::thread::sleep(check_interval);
                }

                if !approved {
                    log::info!(
                        "[{}]: file approval not received for download {} {}",
                        socket_addr,
                        file_name,
                        file_hash
                    );
                    let error_message = format!(
                        "Upload approval not received for file '{}' (hash: {}) from {} within {} seconds",
                        file_name, file_hash, socket_addr, timeout.as_secs()
                    );

                    log::info!(
                        "[{}]: returning rejection error {} {}",
                        socket_addr,
                        file_name,
                        file_hash
                    );
                    return Some(pb::WrappedMessage {
                        payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                            message: error_message,
                        })),
                    });
                }
            }

            log::info!(
                "[{}]: found upload approval {} {}",
                socket_addr,
                file_name,
                file_hash
            );

            state::set_file(state::File {
                file_name: file_upload_request.file_name,
                file_hash: state::hash_file(file_upload_request.file_data.as_slice()),
                file_data: Some(file_upload_request.file_data),
            });

            log::info!("[{}]: no response necessary", socket_addr);
            return None;
        }
        Some(pb::wrapped_message::Payload::Error(error)) => {
            log::error!("[{}]: {}", socket_addr, error.message);
            log::info!("[{}]: no response necessary", socket_addr);
            return None;
        }
        _ => {
            return Some(pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                    message: "Unknown message type".to_string(),
                })),
            });
        }
    }
}

pub fn unsign_decrypt_message(
    socket_addr: SocketAddr,
    use_client_encryption: &state::EncryptionModes,
    signed_message: &pb::SignedMessage,
) -> Result<pb::WrappedMessage, Box<dyn std::error::Error>> {
    log::info!(
        "[{}]: decrypting: rsa: {}, aes: {}",
        socket_addr,
        use_client_encryption.use_rsa,
        use_client_encryption.use_aes
    );

    // Check what encryption modes are used
    if use_client_encryption.use_rsa {
        log::info!(
            "[{}]: RSA public key is known, verifying signature",
            socket_addr
        );

        // If Bob's RSA signature is known, verify the signature
        let msg = &signed_message.signed_payload;
        let signature: Signature = Signature::try_from(signed_message.rsa_signature.as_slice())?;
        match state::verify_client_signature(socket_addr, msg, &signature) {
            Ok(_) => {}
            Err(e) => {
                log::error!("[{}]: Signature is invalid: {}", socket_addr, e);
                return Err(e.into());
            }
        }
        log::info!("[{}]: Signature is valid", socket_addr);
    }

    let wrapped_message: pb::WrappedMessage;
    match pb::signed_message::EncryptedMessage::try_from(signed_message.encrypted_message).unwrap()
    {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage => {
            log::info!("[{}]: Message is encrypted", socket_addr);

            // If AES has been established, decrypt the message
            if !use_client_encryption.use_aes {
                return Err("Received encrypted message but no session key negotiated".into());
            }

            // Decrypt with AES session
            let encrypted_message =
                pb::EncryptedMessage::decode(signed_message.signed_payload.as_slice())?;
            log::info!(
                "[{}]: Decoded protobuf payload into encrypted_payload",
                socket_addr
            );

            let decrypted_payload = match state::decrypt_aes_message(
                socket_addr,
                &encrypted_message.aes_nonce,
                &encrypted_message.encrypted_payload,
            ) {
                Ok(decrypted_payload) => decrypted_payload,
                Err(e) => {
                    log::error!("[{}]: Error decrypting payload: {}", socket_addr, e);
                    return Err(format!("AES Decryption Error: {}", e).into());
                }
            };

            wrapped_message = pb::WrappedMessage::decode(decrypted_payload.as_slice()).unwrap();
            log::info!(
                "[{}]: Decoded decrypted_payload into wrapped_message",
                socket_addr
            );
        }
        pb::signed_message::EncryptedMessage::WrappedMessage => {
            // If unencrypted, decode the message
            wrapped_message = pb::WrappedMessage::decode(signed_message.signed_payload.as_slice())
                .expect("error decoding signed_payload");
            log::info!("[{}]: Decoded payload into wrapped_message", socket_addr);
        }
    }
    Ok(wrapped_message)
}

pub fn sign_encrypt_message(
    socket_addr: SocketAddr,
    use_client_encryption: &state::EncryptionModes,
    wrapped_message: &pb::WrappedMessage,
) -> Result<pb::SignedMessage, Box<dyn std::error::Error>> {
    let payload_bytes;
    if use_client_encryption.use_aes {
        log::info!(
            "[{}]: AES has been established, encrypting message",
            socket_addr
        );

        // If AES has been established, encrypt the message
        let encrypted_message =
            state::encrypt_aes_message(socket_addr, &wrapped_message.encode_to_vec());
        log::info!("[{}]: Encrypted wrapped_message", socket_addr);

        let return_encrypted_message = pb::EncryptedMessage {
            aes_nonce: encrypted_message.nonce,
            encrypted_payload: encrypted_message.ciphertext,
        };
        log::info!("[{}]: Wrapped payload as encrypted_message", socket_addr);

        payload_bytes = return_encrypted_message.encode_to_vec();
    } else {
        payload_bytes = wrapped_message.encode_to_vec();
    }

    // Set the encrypted_message_enum to mark if AES was used
    let encrypted_message_enum = if use_client_encryption.use_aes {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage
    } else {
        pb::signed_message::EncryptedMessage::WrappedMessage
    };
    log::info!("[{}]: Set enum {:?}", socket_addr, encrypted_message_enum);

    // Sign the message
    let signature = state::sign_message(&payload_bytes);
    log::info!("[{}]: Signed message", socket_addr);

    let signed_message = pb::SignedMessage {
        encrypted_message: encrypted_message_enum as i32,
        signed_payload: payload_bytes,
        rsa_signature: signature.to_bytes().to_vec(),
    };
    log::info!("[{}]: Wrapped message and signature", socket_addr);

    Ok(signed_message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{self, EncryptionModes};
    use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, Key, KeyInit};
    use rsa::rand_core::OsRng;
    use rsa::signature::SignerMut;
    use rsa::{pkcs1v15::SigningKey, RsaPrivateKey};
    use std::net::{IpAddr, Ipv4Addr};
    use x25519_dalek::{EphemeralSecret, PublicKey};

    fn setup_state_for_test(socket_addr: SocketAddr) -> RsaPrivateKey {
        // Own RSA key
        state::init_app_data();

        // Peer RSA key
        let private_key = RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate a key");
        let public_key = private_key.to_public_key();

        let alice_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let alice_public = PublicKey::from(&alice_secret);

        {
            let mut client_map_lock = state::CLIENT_DATA.write().unwrap();
            let client_data = state::ClientData {
                nickname: Some("testclient".to_string()),
                connections: 1,
                rsa_public: Some(public_key),
                aes_ephemeral: Some(alice_secret),
                aes_public: Some(alice_public),
                aes_shared: None,
                file_map: None,
            };
            client_map_lock.insert(socket_addr, std::sync::RwLock::new(client_data));
        }
        private_key
    }

    #[test]
    fn good_signed_unencrypted_message() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let private_key = setup_state_for_test(socket_addr);
        let use_client_encryption = EncryptionModes {
            use_rsa: true,
            use_aes: false,
        };
        let wrapped_message = pb::WrappedMessage {
            payload: Some(pb::wrapped_message::Payload::FileListRequest(
                pb::FileListRequest {},
            )),
        };

        let msg = wrapped_message.encode_to_vec();

        let mut signing_key = SigningKey::<rsa::sha2::Sha256>::new(private_key.clone());
        let signature = signing_key.sign(&msg);

        let signed_message = pb::SignedMessage {
            encrypted_message: pb::signed_message::EncryptedMessage::WrappedMessage as i32,
            signed_payload: msg,
            rsa_signature: signature.to_vec(),
        };

        let result = unsign_decrypt_message(socket_addr, &use_client_encryption, &signed_message);

        assert!(result.is_ok());
        let unwrapped_message = result.unwrap();
        assert_eq!(unwrapped_message.payload, wrapped_message.payload);
    }

    #[test]
    fn good_signed_encrypted_message() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let private_key = setup_state_for_test(socket_addr);

        let bob_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        state::set_client_dh_shared(socket_addr, bob_public);
        let wrapped_message = pb::WrappedMessage {
            payload: Some(pb::wrapped_message::Payload::FileListRequest(
                pb::FileListRequest {},
            )),
        };

        let client_data_map = state::CLIENT_DATA.read().unwrap();
        let client_data = client_data_map.get(&socket_addr).unwrap().read().unwrap();

        let shared_secret = client_data.aes_shared.as_ref().unwrap();
        let key: &Key<Aes256Gcm> = shared_secret.as_bytes().into();
        let cipher = aes_gcm::Aes256Gcm::new(&key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, wrapped_message.encode_to_vec().as_slice())
            .unwrap();

        let signed_payload = pb::EncryptedMessage {
            aes_nonce: nonce.to_vec(),
            encrypted_payload: ciphertext,
        }
        .encode_to_vec();

        let mut signing_key = SigningKey::<rsa::sha2::Sha256>::new(private_key.clone());
        let signature = signing_key.sign(&signed_payload);

        let signed_message = pb::SignedMessage {
            encrypted_message: pb::signed_message::EncryptedMessage::EncryptedWrappedMessage as i32,
            signed_payload: signed_payload,
            rsa_signature: signature.to_vec(),
        };

        let result = unsign_decrypt_message(
            socket_addr,
            &EncryptionModes {
                use_rsa: true,
                use_aes: true,
            },
            &signed_message,
        );

        assert!(result.is_ok());
        let unwrapped_message = result.unwrap();
        assert_eq!(unwrapped_message.payload, wrapped_message.payload);
    }

    #[test]
    fn bad_signed_unencrypted_message() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let _private_key = setup_state_for_test(socket_addr);
        let use_client_encryption = EncryptionModes {
            use_rsa: true,
            use_aes: false,
        };
        let wrapped_message = pb::WrappedMessage {
            payload: Some(pb::wrapped_message::Payload::FileListRequest(
                pb::FileListRequest {},
            )),
        };

        let msg = wrapped_message.encode_to_vec();

        let mut bad_signing_key = SigningKey::<rsa::sha2::Sha256>::new(
            RsaPrivateKey::new(&mut OsRng, 2048).expect("failed to generate a key"),
        );
        let bad_signature = bad_signing_key.sign(&msg);

        let signed_message = pb::SignedMessage {
            encrypted_message: pb::signed_message::EncryptedMessage::WrappedMessage as i32,
            signed_payload: msg,
            rsa_signature: bad_signature.to_vec(),
        };

        let result = unsign_decrypt_message(socket_addr, &use_client_encryption, &signed_message);

        assert!(result.is_err());
    }

    #[test]
    fn good_signed_bad_encrypted_message() {
        let socket_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8081);
        let private_key = setup_state_for_test(socket_addr);

        let bob_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let bob_public = PublicKey::from(&bob_secret);
        state::set_client_dh_shared(socket_addr, bob_public);
        let wrapped_message = pb::WrappedMessage {
            payload: Some(pb::wrapped_message::Payload::FileListRequest(
                pb::FileListRequest {},
            )),
        };

        let bad_shared_secret_bytes: [u8; 32] = [0u8; 32];
        let bad_key = Key::<Aes256Gcm>::from_slice(&bad_shared_secret_bytes);
        let bad_key_cipher = Aes256Gcm::new(&bad_key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = bad_key_cipher
            .encrypt(&nonce, wrapped_message.encode_to_vec().as_slice())
            .unwrap();

        let signed_payload = pb::EncryptedMessage {
            aes_nonce: nonce.to_vec(),
            encrypted_payload: ciphertext,
        }
        .encode_to_vec();

        let mut signing_key = SigningKey::<rsa::sha2::Sha256>::new(private_key.clone());
        let signature = signing_key.sign(&signed_payload);

        let signed_message = pb::SignedMessage {
            encrypted_message: pb::signed_message::EncryptedMessage::EncryptedWrappedMessage as i32,
            signed_payload: signed_payload,
            rsa_signature: signature.to_vec(),
        };

        let result = unsign_decrypt_message(
            socket_addr,
            &EncryptionModes {
                use_rsa: true,
                use_aes: true,
            },
            &signed_message,
        );

        assert!(result.is_err());
    }
}
