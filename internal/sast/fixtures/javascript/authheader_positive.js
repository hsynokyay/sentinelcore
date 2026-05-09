const express = require("express");
const app = express();

app.get("/echo", (req, res) => {
  res.setHeader("Authorization", req.query.token || "");
  res.send("ok");
});
