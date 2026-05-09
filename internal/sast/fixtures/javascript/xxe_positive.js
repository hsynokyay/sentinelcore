// internal/sast/fixtures/javascript/xxe_positive.js
const libxmljs = require("libxmljs");
const express = require("express");
const app = express();
app.use(express.text({ type: "application/xml" }));

app.post("/parse", (req, res) => {
  const doc = libxmljs.parseXmlString(req.body, { noent: true });
  res.json({ root: doc.root().name() });
});
