# internal/sast/fixtures/python/xss_negative.py
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    return render_template_string("<p>{{ msg }}</p>", msg=msg)
