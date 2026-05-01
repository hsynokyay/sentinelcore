// internal/sast/fixtures/javascript/proto_negative.js
const express = require("express");
const app = express();
app.use(express.json());

const ALLOWED = ["theme", "language", "timezone"];
const config = { theme: "light" };

app.post("/config", (req, res) => {
  for (const key of ALLOWED) {
    if (req.body[key] !== undefined) config[key] = String(req.body[key]);
  }
  res.json(config);
});
