// internal/sast/fixtures/javascript/ssti_negative.js
const express = require("express");
const handlebars = require("handlebars");
const fs = require("fs");

const app = express();
const tpl = handlebars.compile(fs.readFileSync("./templates/hello.hbs", "utf-8"));

app.get("/greet", (req, res) => {
  res.send(tpl({ name: req.query.name }));
});
