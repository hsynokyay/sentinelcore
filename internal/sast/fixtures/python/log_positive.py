# internal/sast/fixtures/python/log_positive.py
import logging
from flask import Flask, request

app = Flask(__name__)
log = logging.getLogger(__name__)

@app.route("/login")
def login():
    user = request.args.get("user", "")
    log.info("Login attempt: " + user)
    return "ok"
