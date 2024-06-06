var express = require('express'),
    fs = require('fs');

express().get('/list-directory', function(req, res) {
    fs.readdir('/public', function (error, fileNames) {
        var list = '<ul>';
        fileNames.forEach(fileName => {
            // BAD: `fileName` can contain HTML elements
            list += '<li>' + fileName + '</li>';
        });
        list += '</ul>'
        res.send(list); /*Vulnerability name: Stored cross-site scripting	Vulnerability description: Using uncontrolled stored values in HTML allows for a stored cross-site scripting vulnerability.	Vulnerability message: Stored cross-site scripting vulnerability due to [["stored value"|"relative:///StoredXss.js:5:44:5:52"]].*/
    });
});
