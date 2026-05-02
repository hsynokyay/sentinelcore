const crypto = require("crypto");

function hashData(data) {
  // SAFE: SHA-256 is a strong hash algorithm
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

module.exports = { hashData };
