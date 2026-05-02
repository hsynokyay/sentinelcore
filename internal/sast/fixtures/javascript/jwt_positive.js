const jwt = require("jsonwebtoken");
const JWT_SECRET = "supersecretpassword12345"; // SC-JS-JWT-003

function decodeUnsafe(token) {
  return jwt.decode(token); // SC-JS-JWT-001
}

function verifyAllowsNone(token) {
  return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] }); // SC-JS-JWT-002
}
