// internal/sast/fixtures/javascript/deser_positive.js
const express = require("express");
const serialize = require("node-serialize");
const app = express();
app.use(express.text());

app.post("/state", (req, res) => {
  const obj = serialize.unserialize(req.body);
  res.json(obj);
});
