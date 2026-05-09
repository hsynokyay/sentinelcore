// internal/sast/fixtures/javascript/log_negative.js
const express = require("express");
const app = express();

app.get("/login", (req, res) => {
  const safe = String(req.query.user || "").replace(/[\r\n]/g, "").slice(0, 64);
  console.log("Login attempt: %s", safe);
  res.send("ok");
});
