from flask import request


def calculate():
    expr = request.form.get("expr")
    # VULNERABLE: user input passed directly to eval()
    result = eval(expr)
    return str(result)
