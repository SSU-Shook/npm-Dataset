var app = require('express')();
var expressSanitizer = require('express-sanitizer');
var app = express();

app.use(expressSanitizer());

app.get('/user/:id', function(req, res) {
  var sanitizedId = req.sanitize(req.params.id);
  if (!isValidUserId(sanitizedId))
    // Updated: Sanitize user input before incorporating into the response
    res.send("Unknown user: " + sanitizedId);
  else
    // TODO: do something exciting
    ;
});
