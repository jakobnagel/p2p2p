from cryptography.hazmat.primitives import hashes
def hash_data(data):
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(data)
    digest = hasher.finalize()
    return digest
