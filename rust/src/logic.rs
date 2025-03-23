use std::net::SocketAddr;

use crate::state;
use num_traits::cast::ToPrimitive;
use prost::Message;
use rsa::pkcs1v15::Signature;
use rsa::sha2::Sha256;
use rsa::signature::SignatureEncoding;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};

pub mod p2p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

use p2p2p as pb;
use x25519_dalek::PublicKey;

pub fn handle_message(
    socket_addr: SocketAddr,
    data: &[u8],
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    // Decode message into first protobuf type
    let signed_message: pb::SignedMessage = pb::SignedMessage::decode(data)?;

    // Verify signature if one exists
    let use_client_encryption = state::get_client_encryption(socket_addr);
    if use_client_encryption.use_rsa {
        let msg = &signed_message.signed_payload;
        let signature: Signature = Signature::try_from(signed_message.rsa_signature.as_slice())?;
        state::verify_client_signature(socket_addr, msg, &signature)?;
    }

    // Decrypt messages if AES has been established
    let wrapped_message: pb::WrappedMessage;
    match signed_message.encrypted_message() {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage => {
            assert!(use_client_encryption.use_aes);

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
            wrapped_message = pb::WrappedMessage::decode(signed_message.signed_payload.as_slice())?;
        }
    }

    // Complete operations and generate return message
    let return_wrapped_message: pb::WrappedMessage;
    match wrapped_message.payload {
        Some(pb::wrapped_message::Payload::Introduction(introduction)) => {
            // Introduction message
            // States RSA public key
            // Both steps of Diffehellman

            let rsa_public_key = introduction.rsa_public_key.unwrap();
            let e = BigUint::from(rsa_public_key.e);
            let n = BigUint::from_bytes_be(rsa_public_key.n.as_slice());
            let public_key = RsaPublicKey::new(n, e)?;
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

            return_wrapped_message = pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::Introduction(
                    p2p2p::Introduction {
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
            };
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
            return_wrapped_message = pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::FileList(pb::FileList {
                    files: file_metadata_list,
                })),
            };
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
            return Ok(None);
        }
        Some(pb::wrapped_message::Payload::FileDownloadRequest(file_download_request)) => {
            // Respond to file download request
            // TODO: Add consent

            let file = state::get_file_by_name(&file_download_request.file_name);
            return_wrapped_message = pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::FileDownload(
                    pb::FileDownload {
                        file_name: file.file_name,
                        file_data: file.file_data.unwrap(),
                    },
                )),
            };
        }
        Some(pb::wrapped_message::Payload::FileDownload(file_download)) => {
            // Received file download
            state::set_file(state::File {
                file_name: file_download.file_name,
                file_hash: state::hash_file(file_download.file_data.as_slice()),
                file_data: Some(file_download.file_data),
            });

            return Ok(None);
        }
        Some(pb::wrapped_message::Payload::FileUploadRequest(file_upload_request)) => {
            // Received request to upload file
            // TODO: Add consent

            state::set_file(state::File {
                file_name: file_upload_request.file_name,
                file_hash: state::hash_file(file_upload_request.file_data.as_slice()),
                file_data: Some(file_upload_request.file_data),
            });

            return Ok(None);
        }
        Some(pb::wrapped_message::Payload::Error(error)) => {
            eprint!("{}", error.message);
            return Ok(None);
        }
        _ => {
            return_wrapped_message = pb::WrappedMessage {
                payload: Some(pb::wrapped_message::Payload::Error(pb::Error {
                    message: "Unknown message type".to_string(),
                })),
            };
        }
    }

    let use_client_encryption = state::get_client_encryption(socket_addr);

    let return_unsigned_message;
    if use_client_encryption.use_aes {
        let encrypted_message =
            state::encrypt_aes_message(socket_addr, &return_wrapped_message.encode_to_vec());
        let return_encrypted_message = pb::EncryptedMessage {
            aes_nonce: encrypted_message.nonce,
            encrypted_payload: encrypted_message.ciphertext,
        };
        return_unsigned_message = return_encrypted_message.encode_to_vec();
    } else {
        return_unsigned_message = return_wrapped_message.encode_to_vec();
    }

    let encrypted_message_enum = if use_client_encryption.use_aes {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage
    } else {
        pb::signed_message::EncryptedMessage::WrappedMessage
    };

    let signature = state::sign_message(&return_unsigned_message);
    let return_signed_message = pb::SignedMessage {
        encrypted_message: encrypted_message_enum as i32,
        rsa_signature: signature.to_bytes().to_vec(),
        signed_payload: return_unsigned_message,
    };

    let return_message = return_signed_message.encode_to_vec();

    Ok(Some(return_message))
}
