// internal/sast/fixtures/javascript/deser_negative.js
const express = require("express");
const app = express();
app.use(express.json());

app.post("/state", (req, res) => {
  res.json(req.body);
});
