function search(req, res) {
  const q = req.query.q;
  res.send("<h1>Results for: " + q + "</h1>");
}

module.exports = { search };
