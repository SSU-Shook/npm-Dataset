var app = require('express')();
var escapeHtml = require('escape-html');

app.get('/user/:id', function(req, res) {
  if (!isValidUserId(req.params.id))
    // Good: Escaping the request parameter before incorporating it into the response
    res.send("Unknown user: " + escapeHtml(req.params.id));
  else
    // TODO: do something exciting
    ;
});
