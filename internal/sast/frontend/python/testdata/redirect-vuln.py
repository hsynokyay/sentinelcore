from flask import request, redirect


def handle_redirect():
    url = request.args.get("url")
    # VULNERABLE: user-controlled redirect target
    return redirect(url)
