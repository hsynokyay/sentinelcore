import requests
from flask import request


def fetch_url():
    url = request.args.get("url")
    # VULNERABLE: user-controlled URL passed directly to requests.get
    response = requests.get(url)
    return response.text
