const { exec } = require("child_process");

function handleRequest(req, res) {
  const cmd = req.query.cmd;
  exec("ls " + cmd, (err, stdout) => {
    res.send(stdout);
  });
}

module.exports = { handleRequest };
