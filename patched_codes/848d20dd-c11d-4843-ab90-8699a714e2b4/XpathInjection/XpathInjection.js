const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
  let userName = req.param("userName");

  // GOOD: Sanitize user-provided data before use in an XPath expression
  userName = sanitizeInput(userName);
  let safeXPathExpr = xpath.parse("//users/user[login/text()='" + userName + "']/home_dir/text()");
  safeXPathExpr.select({
    node: root
  });
});

function sanitizeInput(input) {
  // Basic sanitization to remove potential malicious characters
  return input.replace(/['"]/g, '');
}
