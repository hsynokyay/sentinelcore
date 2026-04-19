import json
from flask import request


def process_data():
    data = request.form.get("data")
    # SAFE: JSON cannot execute arbitrary code during deserialization
    obj = json.loads(data)
    return str(obj)
