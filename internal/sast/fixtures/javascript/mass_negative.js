// internal/sast/fixtures/javascript/mass_negative.js
const express = require("express");
const User = require("./models/user");
const app = express();
app.use(express.json());

app.post("/users", async (req, res) => {
  const { name, email } = req.body;
  const user = await User.create({ name: String(name), email: String(email) });
  res.json(user);
});
