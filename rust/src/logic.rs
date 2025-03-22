use std::net::SocketAddr;

use crate::state::{self, set_client_rsa_key};
use prost::Message;
use rsa::pkcs1v15::Signature;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::sha2::Sha256;
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};

pub mod p2p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

use p2p2p::{signed_message, wrapped_message, EncryptedMessage, SignedMessage, WrappedMessage};

pub fn handle_message(
    socket_addr: SocketAddr,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let signed_message: SignedMessage = SignedMessage::decode(data)?;

    // Verify signature if one exists
    let verifying_key: Option<VerifyingKey<Sha256>> = state::get_client_rsa_key(socket_addr);
    if verifying_key.is_some() {
        let msg = &signed_message.signed_payload;
        let signature: Signature = Signature::try_from(signed_message.rsa_signature.as_slice())?;
        verifying_key
            .unwrap()
            .verify(msg, &signature)
            .expect("Failed signature check");
    }

    match signed_message.encrypted_message() {
        signed_message::EncryptedMessage::EncryptedWrappedMessage => {
            // Decrypt with AES session
            let encrypted_message =
                EncryptedMessage::decode(signed_message.signed_payload.as_slice())?;
            todo!();
        }
        signed_message::EncryptedMessage::WrappedMessage => {
            let wrapped_message = WrappedMessage::decode(signed_message.signed_payload.as_slice())?;
            match wrapped_message.payload {
                Some(wrapped_message::Payload::Introduction(introduction)) => {
                    let rsa_public_key = introduction.rsa_public_key.unwrap();
                    let e = BigUint::from(rsa_public_key.e);
                    let n = BigUint::from_bytes_be(rsa_public_key.n.as_slice());
                    let public_key = RsaPublicKey::new(n, e)?;
                    let verifying_key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(public_key);
                    set_client_rsa_key(socket_addr, verifying_key);
                }
                Some(wrapped_message::Payload::FileListRequest(_)) => {
                    todo!();
                }
                Some(wrapped_message::Payload::FileList(_)) => {
                    todo!();
                }
                Some(wrapped_message::Payload::FileDownloadRequest(_)) => {
                    todo!();
                }
                Some(wrapped_message::Payload::FileDownload(_)) => {
                    todo!();
                }
                Some(wrapped_message::Payload::FileUploadRequest(_)) => {
                    todo!();
                }
                Some(wrapped_message::Payload::Error(_)) => {
                    todo!();
                }
                None => {
                    todo!();
                }
            }
        }
    }
    Ok(())
}
