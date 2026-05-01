# internal/sast/fixtures/python/ssti_negative.py
from flask import Flask, request, render_template

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    return render_template("hello.html", name=name)
