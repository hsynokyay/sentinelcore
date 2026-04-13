function calculate(req, res) {
  const expr = req.body.expression;
  const result = eval(expr);
  res.send({ result });
}

module.exports = { calculate };
