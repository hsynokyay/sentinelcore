# internal/sast/fixtures/python/ssti_positive.py
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    template = "Hello " + name + "!"
    return render_template_string(template)
