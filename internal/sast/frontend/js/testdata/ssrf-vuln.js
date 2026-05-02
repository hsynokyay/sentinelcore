const axios = require("axios");

function proxy(req, res) {
  const url = req.query.url;
  axios.get(url);
}

module.exports = { proxy };
