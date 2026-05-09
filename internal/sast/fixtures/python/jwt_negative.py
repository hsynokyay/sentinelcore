import jwt
import os

JWT_SECRET = os.environ["JWT_SECRET"]

def verify_token(token):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
