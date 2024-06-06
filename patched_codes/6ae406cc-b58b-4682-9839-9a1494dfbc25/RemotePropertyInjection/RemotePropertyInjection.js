var express = require('express');

var app = express();
var myObj = {}

app.get('/user/:id', function(req, res) {
    var prop = req.query.userControlled; // BAD
    if (typeof prop === 'string' && /^[a-zA-Z0-9_]+$/.test(prop)) { // Ensure property is a safe string
        myObj[prop] = function() {}; /* Vulnerability name: Remote property injection Vulnerability description: Allowing writes to arbitrary properties of an object may lead to denial-of-service attacks. Vulnerability message: A property name to write to depends on a [["user-provided value"|"relative:///RemotePropertyInjection.js:7:13:7:36"]].*/
    } else {
        res.status(400).send('Invalid property name.');
        return;
    }
    console.log("Request object " + JSON.stringify(myObj)); // Added JSON.stringify for better logging
    res.send('Property set successfully.');
});
