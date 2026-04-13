const express = require("express");

function handleRedirect(req, res) {
  const url = req.query.url;
  // VULNERABLE: user-controlled redirect target
  res.redirect(url);
}

module.exports = { handleRedirect };
