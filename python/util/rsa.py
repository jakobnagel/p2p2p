from cryptography.hazmat.primitives import serialization as crypto_serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding, utils
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from util.hash import hash_data
import os.path

private_path = "keys/rsaprivkey.pem"
public_path = "keys/rsapubkey.pub"

def ensure_local_RSA_key():
    if not os.path.isfile(private_path):
        print("No local RSA key found, creating new")
        key = rsa.generate_private_key(
                backend=crypto_default_backend(),
                public_exponent=65537,
                key_size=2048
        )
        private_key = key.private_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PrivateFormat.PKCS8,
                crypto_serialization.NoEncryption()
        )
        public_key = key.public_key().public_bytes(
                crypto_serialization.Encoding.PEM,
                crypto_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        f = open(private_path, 'x')
        f.close()
        f = open(public_path, 'x')
        f.close()
        with open(private_path, 'wb') as pem_out:
            pem_out.write(private_key)
        with open(public_path, 'wb') as pem_out:
            pem_out.write(public_key)
    else:
        print("Found local RSA key")

def get_RSA_private_key():
    ensure_local_RSA_key()

    with open(private_path, 'rb') as pem_in:
        pemlines = pem_in.read()
    private_key = load_pem_private_key(pemlines, None, crypto_default_backend())
    return private_key

def get_RSA_public_key():
    ensure_local_RSA_key()

    with open(public_path, 'rb') as pubkey:
        pemlines = pubkey.read()
    public_key = load_pem_public_key(pemlines)
    return public_key

def get_RSA_signature(key, msg):
    chosen_hash = hashes.SHA256()
    digest = hash_data(msg)
    signature = key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            utils.Prehashed(chosen_hash)
            )
    return signature

# Throws exception if invalid
    print(serialized_msg)
def verify_RSA_signature(pubkey, sig, msg):
    chosen_hash = hashes.SHA256()
    digest = hash_data(msg)
    pubkey.verify(
            sig,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
                ),
            utils.Prehashed(chosen_hash)
            )

