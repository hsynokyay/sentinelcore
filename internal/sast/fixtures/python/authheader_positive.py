from flask import Flask, request, Response

app = Flask(__name__)

@app.route("/echo")
def echo():
    resp = Response("ok")
    resp.headers.set("Authorization", request.args.get("token", ""))
    return resp
