const fs = require('fs'),
      http = require('http'),
      path = require('path'),
      url = require('url');

const ROOT = "/var/www/";

var server = http.createServer(function(req, res) {
  let filePath = url.parse(req.url, true).query.path;
  
  // Normalize and join the path
  let sanitizedPath = path.normalize(filePath).replace(/^(\.\.[\/\])+/, '');
  let fullPath = path.join(ROOT, sanitizedPath);
  
  // Ensure the path is within the ROOT directory
  if (fullPath.startsWith(ROOT)) {
    try {
      res.write(fs.readFileSync(fullPath, 'utf8'));
    } catch (err) {
      res.writeHead(404, {'Content-Type': 'text/plain'});
      res.end('File not found
');
    }
  } else {
    res.writeHead(403, {'Content-Type': 'text/plain'});
    res.end('Access denied
');
  }
});
