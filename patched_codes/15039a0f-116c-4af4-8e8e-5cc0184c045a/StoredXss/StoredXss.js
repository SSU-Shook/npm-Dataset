var express = require('express'),
    fs = require('fs');

// Function to escape HTML special characters
function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, '&amp;')
         .replace(/</g, '&lt;')
         .replace(/>/g, '&gt;')
         .replace(/"/g, '&quot;')
         .replace(/'/g, '&#039;');
}

express().get('/list-directory', function(req, res) {
    fs.readdir('/public', function (error, fileNames) {
        var list = '<ul>';
        fileNames.forEach(fileName => {
            // Escape HTML special characters
            list += '<li>' + escapeHtml(fileName) + '</li>';
        });
        list += '</ul>'
        res.send(list);
    });
});
