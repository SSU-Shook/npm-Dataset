const express = require('express')
var pug = require('pug');
const app = express()

app.post('/', (req, res) => {
    var input = req.query.username;
    var safeInput = pug.escape(input); // Escape the user input to mitigate code injection
    var template = `
doctype
html
head
    title= 'Hello world'
body
    form(action='/' method='post')
        input#name.form-control(type='text)
        button.btn.btn-primary(type='submit') Submit
    p Hello `+ safeInput;
    var fn = pug.compile(template); 
    var html = fn();
    res.send(html);
})
