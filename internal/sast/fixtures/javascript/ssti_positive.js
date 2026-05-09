// internal/sast/fixtures/javascript/ssti_positive.js
const express = require("express");
const handlebars = require("handlebars");

const app = express();

app.get("/greet", (req, res) => {
  const userTpl = "Hello {{name}}, " + req.query.suffix;
  const compiled = handlebars.compile(userTpl);
  res.send(compiled({ name: req.query.name }));
});
