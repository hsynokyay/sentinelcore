// internal/sast/fixtures/javascript/log_positive.js
const express = require("express");
const app = express();

app.get("/login", (req, res) => {
  console.log("Login attempt: " + req.query.user);
  res.send("ok");
});
