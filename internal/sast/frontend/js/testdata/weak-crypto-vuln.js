const crypto = require("crypto");

function hashData(data) {
  // VULNERABLE: MD5 is cryptographically broken
  const hash = crypto.createHash("md5");
  hash.update(data);
  return hash.digest("hex");
}

module.exports = { hashData };
