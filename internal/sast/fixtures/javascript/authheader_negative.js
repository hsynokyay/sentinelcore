const express = require("express");
const app = express();
const SERVICE_TOKEN = process.env.SERVICE_TOKEN;

app.get("/static-auth", (req, res) => {
  res.setHeader("Authorization", "Bearer " + SERVICE_TOKEN);
  res.send("ok");
});
