import jwt

JWT_SECRET = "supersecretpassword12345"  # SC-PY-JWT-003

def verify_token_unsafe(token):
    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})  # SC-PY-JWT-001

def verify_token_alg_none(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["none"])  # SC-PY-JWT-002
