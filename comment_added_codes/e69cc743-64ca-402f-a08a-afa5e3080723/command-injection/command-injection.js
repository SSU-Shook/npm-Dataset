var cp = require("child_process"),
    http = require('http'),
    url = require('url');

var server = http.createServer(function(req, res) {
    let file = url.parse(req.url, true).query.path;

    cp.execSync(`wc -l ${file}`); // BAD /*Vulnerability name: Uncontrolled command line	Vulnerability description: Using externally controlled strings in a command line may allow a malicious user to change the meaning of the command.	Vulnerability message: This command line depends on a [["user-provided value"|"relative:///command-injection.js:6:26:6:32"]].*/
});
