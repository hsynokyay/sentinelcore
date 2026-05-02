from flask import redirect


def handle_redirect():
    # SAFE: hardcoded redirect target
    return redirect("/dashboard")
