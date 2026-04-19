const { execFile } = require("child_process");

function handleRequest(req, res) {
  const filename = req.query.file;
  // Safe: execFile with explicit argument array
  execFile("cat", ["/opt/reports/" + filename], (err, stdout) => {
    res.send(stdout);
  });
}

module.exports = { handleRequest };
