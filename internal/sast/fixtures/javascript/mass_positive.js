// internal/sast/fixtures/javascript/mass_positive.js
const express = require("express");
const User = require("./models/user");
const app = express();
app.use(express.json());

app.post("/users", async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});
