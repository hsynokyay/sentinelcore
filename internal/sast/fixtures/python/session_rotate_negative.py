from flask import Flask, request, session
from flask_login import login_user

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    user = authenticate(request.form["username"], request.form["password"])
    session.clear()
    login_user(user)
    return "ok"

def authenticate(u, p):
    return None
