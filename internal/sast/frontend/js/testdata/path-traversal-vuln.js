const fs = require("fs");

function download(req, res) {
  const filename = req.query.file;
  fs.readFile("/uploads/" + filename, (err, data) => {
    res.send(data);
  });
}

module.exports = { download };
