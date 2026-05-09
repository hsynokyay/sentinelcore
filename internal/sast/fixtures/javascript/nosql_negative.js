// internal/sast/fixtures/javascript/nosql_negative.js
const express = require("express");
const User = require("./models/user");
const app = express();

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");
  const user = await User.findOne({ username, password });
  res.json({ success: !!user });
});
