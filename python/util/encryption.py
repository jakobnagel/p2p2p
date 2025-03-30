from Cryptodome.Cipher import AES

def encrypt(data, rsa_key, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM)
    nonce = cipher.nonce

    ciphertext, tag = cipher.encrypt_and_digest(data)
    ciphertext_and_tag = ciphertext + tag
    return ciphertext_and_tag, nonce

def decrypt(ctxt, aes_key, nonce):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = ctxt[:-16], ctxt[-16:]
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

