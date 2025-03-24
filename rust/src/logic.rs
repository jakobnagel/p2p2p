use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::pb;
use crate::state::{self, FileDirection};
use num_traits::cast::ToPrimitive;
use prost::Message;
use rsa::pkcs1v15::Signature;
use rsa::sha2::Sha256;
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
            // Introduction message
            // States RSA public key
            // Both steps of Diffehellman

            let rsa_public_key = introduction.rsa_public_key.unwrap();
            let e = BigUint::from(rsa_public_key.e);
            let n = BigUint::from_bytes_be(rsa_public_key.n.as_slice());
            let public_key = RsaPublicKey::new(n, e).unwrap();
            let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
            state::set_client_rsa_key(socket_addr, verifying_key);

            let alice_dh_public_key = state::get_client_dh_public(socket_addr);

            let dh_array: [u8; 32] = introduction
                .diffe_hellman
                .unwrap()
                .dh_public_key
                .try_into()
                .expect("error fitting into 32 bytes");

            let bob_dh_public_key = PublicKey::from(dh_array);

            state::set_client_dh_shared(socket_addr, bob_dh_public_key);

            let rsa_public_key = state::get_rsa_key();

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
            // Respond to file list request

            let file_list = state::get_file_list();

            let mut file_metadata_list: Vec<pb::FileMetadata> = Vec::new();
            for file in file_list {
                file_metadata_list.push(pb::FileMetadata {
                    name: file.file_name,
                    hash: file.file_hash.as_bytes().to_vec(),
                });
            }
            return Some(pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::FileList(pb::FileList {
                    files: file_metadata_list,
                })),
            });
        }
        Some(pb::wrapped_message::Payload::FileList(file_list)) => {
            // Received file list
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
            state::set_client_file_list(socket_addr, file_map);
            return None;
        }
        Some(pb::wrapped_message::Payload::FileDownloadRequest(file_download_request)) => {
            // Respond to file download request

            let file_name = file_download_request.file_name;
            let file_hash = state::file_name_to_hash(&file_name);

            if !state::request_transfer_approval(
                socket_addr,
                FileDirection::DOWNLOAD,
                file_hash.clone(),
            ) {
                let start_time = Instant::now();
                let timeout = Duration::from_secs(30);
                let check_interval = Duration::from_secs(5);

                let mut approved = false;
                while start_time.elapsed() < timeout {
                    if state::get_transfer_approval(
                        socket_addr,
                        FileDirection::DOWNLOAD,
                        file_hash.clone(),
                    ) {
                        approved = true;
                        break;
                    }
                    std::thread::sleep(check_interval);
                }

                if !approved {
                    let error_message = format!(
                        "Download approval not received for file '{}' (hash: {}) from {} within {} seconds",
                        file_name, file_hash, socket_addr, timeout.as_secs()
                    );

                    return Some(pb::WrappedMessage {
                        payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                            message: error_message,
                        })),
                    });
                }
            }

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
            // Received file download
            state::set_file(state::File {
                file_name: file_download.file_name,
                file_hash: state::hash_file(file_download.file_data.as_slice()),
                file_data: Some(file_download.file_data),
            });

            return None;
        }
        Some(pb::wrapped_message::Payload::FileUploadRequest(file_upload_request)) => {
            // Received request to upload file

            let file_name = file_upload_request.file_name.clone();
            let file_data = file_upload_request.file_data.clone();
            let file_hash = state::hash_file(&file_data);

            if !state::request_transfer_approval(
                socket_addr,
                FileDirection::UPLOAD,
                file_hash.clone(),
            ) {
                let start_time = Instant::now();
                let timeout = Duration::from_secs(30);
                let check_interval = Duration::from_secs(5);

                let mut approved = false;
                while start_time.elapsed() < timeout {
                    if state::get_transfer_approval(
                        socket_addr,
                        FileDirection::UPLOAD,
                        file_hash.clone(),
                    ) {
                        approved = true;
                        break;
                    }
                    std::thread::sleep(check_interval);
                }

                if !approved {
                    let error_message = format!(
                        "Upload approval not received for file '{}' (hash: {}) from {} within {} seconds",
                        file_name, file_hash, socket_addr, timeout.as_secs()
                    );

                    return Some(pb::WrappedMessage {
                        payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                            message: error_message,
                        })),
                    });
                }
            }

            state::set_file(state::File {
                file_name: file_upload_request.file_name,
                file_hash: state::hash_file(file_upload_request.file_data.as_slice()),
                file_data: Some(file_upload_request.file_data),
            });

            return None;
        }
        Some(pb::wrapped_message::Payload::Error(error)) => {
            eprint!("{}", error.message);
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
    use_client_encryption: state::EncryptionModes,
    signed_message: &pb::SignedMessage,
) -> Result<pb::WrappedMessage, Box<dyn std::error::Error>> {
    // Check what encryption modes are used
    if use_client_encryption.use_rsa {
        // If Bob's RSA signature is known, verify the signature
        let msg = &signed_message.signed_payload;
        let signature: Signature = Signature::try_from(signed_message.rsa_signature.as_slice())?;
        state::verify_client_signature(socket_addr, msg, &signature)?;
    }

    let wrapped_message: pb::WrappedMessage;
    match signed_message.encrypted_message() {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage => {
            // If AES has been established, decrypt the message

            if !use_client_encryption.use_aes {
                return Err("Received encrypted message but no session key negotiated".into());
            }

            // Decrypt with AES session
            let encrypted_message =
                pb::EncryptedMessage::decode(signed_message.signed_payload.as_slice())?;

            let decrypted_payload = state::decrypt_aes_message(
                socket_addr,
                &encrypted_message.aes_nonce,
                &encrypted_message.encrypted_payload,
            );

            wrapped_message = pb::WrappedMessage::decode(decrypted_payload.as_slice())?;
        }
        pb::signed_message::EncryptedMessage::WrappedMessage => {
            // If unencrypted, decode the message
            wrapped_message = pb::WrappedMessage::decode(signed_message.signed_payload.as_slice())?;
        }
    }
    Ok(wrapped_message)
}

pub fn sign_encrypt_message(
    socket_addr: SocketAddr,
    use_client_encryption: state::EncryptionModes,
    wrapped_message: &pb::WrappedMessage,
) -> Result<pb::SignedMessage, Box<dyn std::error::Error>> {
    let payload_bytes;
    if use_client_encryption.use_aes {
        // If AES has been established, encrypt the message
        let encrypted_message =
            state::encrypt_aes_message(socket_addr, &wrapped_message.encode_to_vec());
        let return_encrypted_message = pb::EncryptedMessage {
            aes_nonce: encrypted_message.nonce,
            encrypted_payload: encrypted_message.ciphertext,
        };
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

    // Sign the message
    let signature = state::sign_message(&payload_bytes);
    let signed_message = pb::SignedMessage {
        encrypted_message: encrypted_message_enum as i32,
        signed_payload: payload_bytes,
        rsa_signature: signature.to_bytes().to_vec(),
    };
    Ok(signed_message)
}
