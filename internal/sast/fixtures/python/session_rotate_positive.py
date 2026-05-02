from flask import Flask, request
from flask_login import login_user

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    login_user(user)  # SC-PY-SESSION-002
    return "ok"

def authenticate(u, p):
    return None
