# internal/sast/fixtures/python/xxe_negative.py
from flask import Flask, request
from defusedxml import ElementTree as ET

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse_xml():
    tree = ET.fromstring(request.data)
    return tree.tag
