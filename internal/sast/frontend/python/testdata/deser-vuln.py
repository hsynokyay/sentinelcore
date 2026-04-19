import pickle
from flask import request


def process_data():
    data = request.form.get("data")
    # VULNERABLE: deserializing untrusted user input with pickle
    obj = pickle.loads(data)
    return str(obj)
