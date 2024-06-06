
var express = require('express');

var app = express();
var myObj = {}

app.get('/user/:id', function(req, res) {
    var prop = req.query.userControlled; // BAD
    // Vulnerability name: Remote property injection
    // Vulnerability description: Allowing writes to arbitrary properties of an object may lead to denial-of-service attacks.
    // Vulnerability message: A property name to write to depends on a [["user-provided value"|"relative:///RemotePropertyInjection.js:7:13:7:36"]].
    
    // Patch: Validate 'prop' against a whitelist of allowed properties
    var allowedProps = ['allowedProp1', 'allowedProp2']; // Define allowed properties
    if(allowedProps.includes(prop)) {
        myObj[prop] = function() {};
    } else {
        res.status(400).send('Invalid property name.');
        return;
    }
    console.log("Request object " + myObj);
    res.send('Property set successfully');
});
