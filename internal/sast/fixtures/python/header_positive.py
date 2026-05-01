# internal/sast/fixtures/python/header_positive.py
from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/track")
def track():
    resp = Response("ok")
    resp.headers.set("X-Tracking", request.args.get("id", ""))
    return resp
