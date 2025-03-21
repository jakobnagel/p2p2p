use crate::state::{ClientData, ServerState};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;

use p2p2p::wrapped_message::Payload;
use prost::bytes::Bytes;
use prost::Message;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::signature::{Keypair, RandomizedSigner, SignatureEncoding, Verifier};
use rsa::RsaPrivateKey;
use sha2::{Digest, Sha256};

// use crate::message::*;

pub mod p2p2p {
    include!(concat!(env!("OUT_DIR"), "/p2p2p.rs"));
}

use p2p2p::{
    signed_message, wrapped_message, EncryptedMessage, Introduction, SignedMessage, WrappedMessage,
};

pub fn handle_message(
    data: &[u8],
    client_data: &Arc<Mutex<ClientData>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Decode messages
    let signed_message: SignedMessage = SignedMessage::decode(data)?;

    let mut client_data_lock = client_data.lock().unwrap();
    if client_data_lock.rsa_public.is_some() {
        todo!();
        // Verify the public key signing
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
                    todo!();
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
