const express = require('express')
var pug = require('pug');
const app = express()

app.post('/', (req, res) => {
    var input = req.query.username;
    var template = `
doctype
html
head
    title= 'Hello world'
body
    form(action='/' method='post')
        input#name.form-control(type='text)
        button.btn.btn-primary(type='submit') Submit
    p Hello `+ input
    var fn = pug.compile(template); /*Vulnerability name: Code injection	Vulnerability description: Interpreting unsanitized user input as code allows a malicious user arbitrary code execution.	Vulnerability message: Template, which may contain code, depends on a [["user-provided value"|"relative:///ServerSideTemplateInjection.js:6:17:6:34"]].*/
    var html = fn();
    res.send(html);
})
