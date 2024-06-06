
var express = require('express');

var app = express();
var myObj = {}

app.get('/user/:id', function(req, res) {
    var prop = req.query.userControlled;
    if (typeof prop === 'string' && prop.match(/^[a-zA-Z0-9_]+$/)) {
        myObj[prop] = function() {};
    } else {
        res.status(400).send('Invalid property name');
        return;
    }
    console.log("Request object " + myObj);
});
