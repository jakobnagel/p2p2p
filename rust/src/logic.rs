use std::net::SocketAddr;

use crate::state::{self, decrypt_aes_message};
use num_traits::cast::ToPrimitive;
use prost::Message;
use rsa::pkcs1v15::Signature;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

pub mod p2p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

use p2p2p as pb;
use x25519_dalek::PublicKey;

pub fn handle_message(
    socket_addr: SocketAddr,
    data: &[u8],
) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    let return_wrapped_message: pb::WrappedMessage;

    let signed_message: pb::SignedMessage = pb::SignedMessage::decode(data)?;

    let use_client_encryption = state::get_client_encryption(socket_addr);

    // Verify signature if one exists
    if use_client_encryption.use_rsa {
        let msg = &signed_message.signed_payload;
        let signature: Signature = Signature::try_from(signed_message.rsa_signature.as_slice())?;
        state::verify_client_signature(socket_addr, msg, &signature);
    }

    let wrapped_message: pb::WrappedMessage;
    match signed_message.encrypted_message() {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage => {
            assert!(use_client_encryption.use_aes);

            // Decrypt with AES session
            let encrypted_message =
                pb::EncryptedMessage::decode(signed_message.signed_payload.as_slice())?;

            let decrypted_payload = decrypt_aes_message(
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

    match wrapped_message.payload {
        Some(pb::wrapped_message::Payload::Introduction(introduction)) => {
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

            // Return alice_dh_public_key
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
            todo!();
        }
        Some(pb::wrapped_message::Payload::FileList(_)) => {
            todo!();
        }
        Some(pb::wrapped_message::Payload::FileDownloadRequest(_)) => {
            todo!();
        }
        Some(pb::wrapped_message::Payload::FileDownload(_)) => {
            todo!();
        }
        Some(pb::wrapped_message::Payload::FileUploadRequest(_)) => {
            todo!();
        }
        Some(pb::wrapped_message::Payload::Error(_)) => {
            todo!();
        }
        None => {
            todo!();
        }
    }

    let use_client_encryption = state::get_client_encryption(socket_addr);

    if use_client_encryption.use_aes {
        // TODO:
    }

    let encrypted_message_enum = if use_client_encryption.use_aes {
        pb::signed_message::EncryptedMessage::EncryptedWrappedMessage
    } else {
        pb::signed_message::EncryptedMessage::WrappedMessage
    };

    let return_unsigned_message = return_wrapped_message.encode_to_vec();
    let signature = state::sign_message(&return_unsigned_message);
    let return_signed_message = pb::SignedMessage {
        encrypted_message: encrypted_message_enum as i32,
        rsa_signature: signature.to_bytes().to_vec(),
        signed_payload: return_unsigned_message,
    };

    let return_message = return_signed_message.encode_to_vec();

    Ok(Some(return_message))
}
