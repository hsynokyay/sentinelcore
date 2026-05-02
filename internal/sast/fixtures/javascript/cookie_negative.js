const express = require("express");
const app = express();

function handleLogin(req, res) {
  res.cookie("session", "abc123", { secure: true, httpOnly: true, sameSite: "lax" });
  res.send("ok");
}

app.post("/login", handleLogin);
