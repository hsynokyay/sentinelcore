# internal/sast/fixtures/python/log_negative.py
import logging
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)

@app.route("/login")
def login():
    user = (request.args.get("user", "") or "").replace("\n", "").replace("\r", "")[:64]
    log.info("Login attempt: %s", user)
    return "ok"
