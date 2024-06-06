var express = require('express');

var app = express();
var myObj = {}

app.get('/user/:id', function(req, res) {
    var prop = req.query.userControlled; // BAD
	myObj[prop] = function() {}; /*Vulnerability name: Remote property injection	Vulnerability description: Allowing writes to arbitrary properties of an object may lead to denial-of-service attacks.	Vulnerability message: A property name to write to depends on a [["user-provided value"|"relative:///RemotePropertyInjection.js:7:13:7:36"]].*/
	// Patch: Validate userControlled input
	if (typeof prop === 'string' && prop.match(/^[a-zA-Z0-9_]+$/)) {
	    myObj[prop] = function() {};
	} else {
	    console.log("Invalid property name");
	}
	console.log("Request object " + myObj);
});
