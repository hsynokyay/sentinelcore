const mysql = require("mysql2");

function getUser(req, res) {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  mysql.query(sql);
}

module.exports = { getUser };
