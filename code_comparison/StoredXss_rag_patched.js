
var express = require('express');
var fs = require('fs');
var escapeHtml = require('escape-html');

express().get('/list-directory', function(req, res) {
    fs.readdir('/public', function (error, fileNames) {
        var list = '<ul>';
        fileNames.forEach(fileName => {
            // GOOD: escapeHTML to prevent XSS
            list += '<li>' + escapeHtml(fileName) + '</li>';
        });
        list += '</ul>';
        res.send(list);
    });
});
