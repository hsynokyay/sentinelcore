import hmac

def verify_csrf(req, sess):
    return hmac.compare_digest(req["csrf_token"], sess["csrf_token"])
