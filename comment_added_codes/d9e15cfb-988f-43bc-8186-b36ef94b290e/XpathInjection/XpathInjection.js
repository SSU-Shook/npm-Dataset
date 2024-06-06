const express = require('express');
const xpath = require('xpath');
const app = express();

app.get('/some/route', function(req, res) {
  let userName = req.param("userName");

  // BAD: Use user-provided data directly in an XPath expression
  let badXPathExpr = xpath.parse("//users/user[login/text()='" + userName + "']/home_dir/text()"); /*Vulnerability name: XPath injection	Vulnerability description: Building an XPath expression from user-controlled sources is vulnerable to insertion of malicious code by the user.	Vulnerability message: XPath expression depends on a [["user-provided value"|"relative:///XpathInjection.js:6:18:6:38"]].*/
  badXPathExpr.select({
    node: root
  });
});
