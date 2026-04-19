const axios = require("axios");

function fetchData(req, res) {
  axios.get("https://api.internal.example.com/data");
}

module.exports = { fetchData };
