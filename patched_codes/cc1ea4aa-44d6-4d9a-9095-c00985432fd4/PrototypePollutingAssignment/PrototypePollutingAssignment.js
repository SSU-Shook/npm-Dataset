let express = require('express');
let app = express()

app.put('/todos/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    const forbiddenNames = ['__proto__', 'constructor', 'prototype'];
    if (!forbiddenNames.includes(req.query.name)) {
        items[req.query.name] = req.query.text; /* Patched: Added check to prevent prototype pollution */
    }
    res.end(200);
});
