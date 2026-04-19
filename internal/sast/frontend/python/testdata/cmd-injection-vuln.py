import os
from flask import request


def execute_command():
    user_input = request.args.get("cmd")
    # VULNERABLE: user input flows directly into os.system
    os.system(user_input)
