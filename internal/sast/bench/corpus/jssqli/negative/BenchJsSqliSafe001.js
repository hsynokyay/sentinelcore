const mysql = require("mysql2");

function getUser(req, res) {
  const id = req.query.id;
  mysql.query("SELECT * FROM users WHERE id = ?", [id]);
}

module.exports = { getUser };
