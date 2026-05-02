const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

function verifySafe(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
}
