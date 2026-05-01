# internal/sast/fixtures/python/xss_positive.py
from flask import Flask, request, render_template_string, Markup

app = Flask(__name__)

@app.route("/echo")
def echo():
    msg = Markup(request.args.get("msg", ""))
    return render_template_string("<p>{{ msg }}</p>", msg=msg)
