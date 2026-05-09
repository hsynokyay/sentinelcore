const express = require("express");
const app = express();

function handleLogin(req, res) {
  res.cookie("session", "abc123", { httpOnly: true, sameSite: "lax" });
  res.send("ok");
}

app.post("/login", handleLogin);
