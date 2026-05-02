def verify_csrf(req, sess):
    return req["csrf_token"] == sess["csrf_token"]
