import hashlib


def compute_hash(data):
    # SAFE: SHA-256 is a strong hash algorithm
    return hashlib.sha256(data).hexdigest()
