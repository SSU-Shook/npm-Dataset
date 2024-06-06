var app = require('express')();

app.get('/user/:id', function(req, res) {
  if (!isValidUserId(req.params.id))
    // BAD: a request parameter is incorporated without validation into the response
    res.send("Unknown user: " + req.params.id); /*Vulnerability name: Reflected cross-site scripting	Vulnerability description: Writing user input directly to an HTTP response allows for a cross-site scripting vulnerability.	Vulnerability message: Cross-site scripting vulnerability due to a [["user-provided value"|"relative:///ReflectedXss.js:6:33:6:45"]].*/
  else
    // TODO: do something exciting
    ;
});
