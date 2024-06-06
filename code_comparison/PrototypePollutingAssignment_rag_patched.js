
let express = require('express');
let app = express();

app.put('/todos/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }

    const dangerousProperties = ['__proto__', 'constructor', 'prototype'];
    if (!dangerousProperties.includes(req.query.name)) {
        items[req.query.name] = req.query.text; /* Patched: prevent dangerous properties from being assigned */
    } else {
        res.status(400).send('Invalid property name.');
        return;
    }

    res.end(200);
});
