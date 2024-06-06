
const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
  let userName = req.param('userName');

  // GOOD: Use parameterized XPath expression to avoid injection
  let goodXPathExpr = xpath.parse("//users/user[login/text()=$username]/home_dir/text()");
  let root = ...; // Need to initialize root accordingly
  let select = xpath.useNamespaces({"x": "http://example.com"}); 
  let result = select(goodXPathExpr, root, {username: userName});
  
  res.send(result);
});
