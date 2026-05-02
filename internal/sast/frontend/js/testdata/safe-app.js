const APP_NAME = "SentinelCore";
const VERSION = "1.0.0";

function healthCheck(req, res) {
  res.json({ status: "ok", app: APP_NAME, version: VERSION });
}

module.exports = { healthCheck };
