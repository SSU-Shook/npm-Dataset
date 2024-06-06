
var cp = require("child_process"),
    http = require('http'),
    url = require('url'),
    path = require('path'),
    fs = require('fs');

var server = http.createServer(function(req, res) {
    let file = url.parse(req.url, true).query.path;

    // Validate and sanitize the input
    if (file && typeof file === 'string' && file.match(/^[a-zA-Z0-9._-]+$/)) {
        let filePath = path.join(__dirname, file);
        
        // Check if the file exists and is a file
        if (fs.existsSync(filePath) && fs.lstatSync(filePath).isFile()) {
            let lineCount = fs.readFileSync(filePath, 'utf8').split('\n').length;
            res.writeHead(200, {'Content-Type': 'text/plain'});
            res.end(`Line count: ${lineCount}`);
        } else {
            res.writeHead(404, {'Content-Type': 'text/plain'});
            res.end('File not found');
        }
    } else {
        res.writeHead(400, {'Content-Type': 'text/plain'});
        res.end('Invalid file name');
    }
});

server.listen(8080);
