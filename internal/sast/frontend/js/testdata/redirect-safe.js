const express = require("express");

function handleRedirect(req, res) {
  // SAFE: hardcoded redirect target
  res.redirect("/dashboard");
}

module.exports = { handleRedirect };
