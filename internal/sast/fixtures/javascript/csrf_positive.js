function verifyCsrf(req) {
  return req.body.csrfToken === req.session.csrfToken;
}
