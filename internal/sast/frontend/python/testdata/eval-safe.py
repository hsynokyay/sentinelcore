import json
from flask import request


def parse_data():
    raw = request.form.get("data")
    # SAFE: json.loads instead of eval for data parsing
    parsed = json.loads(raw)
    return parsed
