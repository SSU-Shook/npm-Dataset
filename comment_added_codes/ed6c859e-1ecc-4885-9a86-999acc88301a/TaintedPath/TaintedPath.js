const fs = require('fs'),
      http = require('http'),
      url = require('url');

const ROOT = "/var/www/";

var server = http.createServer(function(req, res) {
  let filePath = url.parse(req.url, true).query.path;

  // BAD: This function uses unsanitized input that can read any file on the file system.
  res.write(fs.readFileSync(ROOT + filePath, 'utf8')); /*Vulnerability name: Uncontrolled data used in path expression	Vulnerability description: Accessing paths influenced by users can allow an attacker to access unexpected resources.	Vulnerability message: This path depends on a [["user-provided value"|"relative:///TaintedPath.js:8:28:8:34"]].*/
});