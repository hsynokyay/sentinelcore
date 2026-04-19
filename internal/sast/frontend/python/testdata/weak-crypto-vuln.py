import hashlib


def compute_hash(data):
    # VULNERABLE: MD5 is cryptographically broken
    return hashlib.md5(data).hexdigest()
