// internal/sast/fixtures/javascript/proto_positive.js
const _ = require("lodash");
const express = require("express");
const app = express();
app.use(express.json());

const config = { admin: false };

app.post("/config", (req, res) => {
  _.merge(config, req.body);
  res.json(config);
});
