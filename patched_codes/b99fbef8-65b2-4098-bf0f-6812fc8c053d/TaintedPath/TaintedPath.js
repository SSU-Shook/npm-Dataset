const fs = require('fs'),
      http = require('http'),
      url = require('url'),
      path = require('path');

const ROOT = "/var/www/";

var server = http.createServer(function(req, res) {
  let filePath = url.parse(req.url, true).query.path;

  // Patch: Sanitize the user input to prevent path traversal attacks.
  let sanitizedPath = path.normalize(filePath).replace(/^(\.\.(\/|\|$))+/, '');

  // Validate the final path to ensure it's within the ROOT directory.
  let finalPath = path.join(ROOT, sanitizedPath);

  if (finalPath.startsWith(path.join(ROOT))) {
    // Safe to read the file
    try {
      res.write(fs.readFileSync(finalPath, 'utf8'));
    } catch (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.write('File not found');
    }
  } else {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.write('Access denied');
  }
  res.end();
});
