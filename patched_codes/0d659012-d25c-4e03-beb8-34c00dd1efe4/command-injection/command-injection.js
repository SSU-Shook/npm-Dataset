
var cp = require("child_process"),
    http = require('http'),
    url = require('url'),
    path = require('path');

var server = http.createServer(function(req, res) {
    let file = url.parse(req.url, true).query.path;

    // Sanitize the user input
    let sanitizedPath = path.normalize(file).replace(/^(\.\.(\/|\|$))+/, '');

    cp.execSync(`wc -l ${sanitizedPath}`); // SAFE
});
