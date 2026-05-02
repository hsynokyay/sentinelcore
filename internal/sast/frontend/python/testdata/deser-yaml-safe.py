import yaml
from flask import request


def process_yaml():
    data = request.form.get("config")
    # SAFE: yaml.safe_load does not execute arbitrary Python objects
    obj = yaml.safe_load(data)
    return str(obj)
