# internal/sast/fixtures/python/xxe_positive.py
from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route("/parse", methods=["POST"])
def parse_xml():
    tree = etree.fromstring(request.data)
    return tree.tag
