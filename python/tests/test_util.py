import pytest
import os

from util.encryption import encrypt, decrypt
from util.hash import hash_data
from util.rsa import get_RSA_private_key, ensure_local_RSA_key, get_RSA_public_key, get_RSA_signature, verify_RSA_signature
import os
from cryptography.hazmat.primitives import serialization

# --- Encryption Tests ---
def test_encrypt_decrypt():
    key = os.urandom(32)  # AES-256 key
    data = b"Test data to encrypt"
    rsa_key = get_RSA_private_key()  #Need a valid RSA key for this to work

    ciphertext_and_tag, nonce = encrypt(data, rsa_key, key)
    decrypted_data = decrypt(ciphertext_and_tag, key, nonce)
    assert decrypted_data == data

# --- RSA Tests ---
def test_rsa_key_generation():
    ensure_local_RSA_key()
    assert os.path.exists("keys/rsaprivkey.pem")
    assert os.path.exists("keys/rsapubkey.pub")

def test_rsa_key_loading():
    private_key = get_RSA_private_key()
    public_key = get_RSA_public_key()
    assert private_key is not None
    assert public_key is not None

def test_rsa_signing_verification():
    private_key = get_RSA_private_key()
    public_key = get_RSA_public_key()
    message = b"Data to sign"
    signature = get_RSA_signature(private_key, message)
    try:
        verify_RSA_signature(public_key, signature, message)
        assert True  # Verification successful
    except Exception:
        assert False # Verification failed

# --- Hash Tests ---
def test_hash_data():
    data = b"Data to hash"
    hashed_data = hash_data(data)
    assert hashed_data is not None
    assert len(hashed_data) > 0
