// internal/sast/fixtures/javascript/nosql_positive.js
const express = require("express");
const User = require("./models/user");
const app = express();

app.post("/login", async (req, res) => {
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  res.json({ success: !!user });
});
