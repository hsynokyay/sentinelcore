# internal/sast/fixtures/python/header_negative.py
from flask import Flask, request, Response
import re

app = Flask(__name__)

@app.route("/track")
def track():
    raw = request.args.get("id", "")
    safe = re.sub(r"[\r\n]", "", raw)[:64]
    resp = Response("ok")
    resp.headers.set("X-Tracking", safe)
    return resp
