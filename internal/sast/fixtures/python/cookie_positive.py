from flask import Flask, Response

app = Flask(__name__)

@app.route("/login")
def login():
    resp = Response("ok")
    resp.set_cookie("session", "abc123", httponly=True, samesite="Lax")
    return resp
