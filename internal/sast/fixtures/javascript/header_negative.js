// internal/sast/fixtures/javascript/header_negative.js
const express = require("express");
const app = express();

app.get("/track", (req, res) => {
  const safe = String(req.query.id || "").replace(/[\r\n]/g, "").slice(0, 64);
  res.setHeader("X-Tracking", safe);
  res.send("ok");
});
