const crypto = require("crypto");

function newSessionId() {
  return "sess-" + crypto.randomBytes(16).toString("hex");
}
