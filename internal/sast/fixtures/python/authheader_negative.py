from flask import Flask, Response
import os

app = Flask(__name__)

@app.route("/static-auth")
def static_auth():
    resp = Response("ok")
    resp.headers.set("Authorization", "Bearer " + os.environ["SERVICE_TOKEN"])
    return resp
