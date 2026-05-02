const crypto = require("crypto");

function verifyCsrf(req) {
  const a = Buffer.from(req.body.csrfToken || "", "utf-8");
  const b = Buffer.from(req.session.csrfToken || "", "utf-8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
