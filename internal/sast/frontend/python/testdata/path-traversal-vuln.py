import os
from flask import request


def read_upload():
    filename = request.args.get("file")
    # VULNERABLE: user input concatenated into file path
    with open("/uploads/" + filename) as f:
        return f.read()
