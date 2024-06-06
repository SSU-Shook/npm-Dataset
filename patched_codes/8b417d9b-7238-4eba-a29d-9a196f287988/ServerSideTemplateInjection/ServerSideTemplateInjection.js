const express = require('express');
var pug = require('pug');
const app = express();

app.post('/', (req, res) => {
    var input = req.query.username;
    var sanitizedInput = input.replace(/[&<>"'`=\/]/g, (s) => {
        return {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;',
            '/': '&#x2F;',
            '`': '&#x60;',
            '=': '&#x3D;'
        }[s];
    });
    var template = `
doctype
html
head
    title= 'Hello world'
body
    form(action='/' method='post')
        input#name.form-control(type='text)
        button.btn.btn-primary(type='submit') Submit
    p Hello ` + sanitizedInput;
    var fn = pug.compile(template);
    var html = fn();
    res.send(html);
});
