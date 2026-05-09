// internal/sast/fixtures/javascript/header_positive.js
const express = require("express");
const app = express();

app.get("/track", (req, res) => {
  res.setHeader("X-Tracking", req.query.id || "");
  res.send("ok");
});
