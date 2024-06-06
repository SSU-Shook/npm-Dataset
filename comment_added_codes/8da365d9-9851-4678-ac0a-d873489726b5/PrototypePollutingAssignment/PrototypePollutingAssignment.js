let express = require('express');
let app = express()

app.put('/todos/:id', (req, res) => {
    let id = req.params.id;
    let items = req.session.todos[id];
    if (!items) {
        items = req.session.todos[id] = {};
    }
    items[req.query.name] = req.query.text; /*Vulnerability name: Prototype-polluting assignment	Vulnerability description: Modifying an object obtained via a user-controlled property name may lead to accidental mutation of the built-in Object prototype, and possibly escalate to remote code execution or cross-site scripting.	Vulnerability message: This assignment may alter Object.prototype if a malicious '__proto__' string is injected from [["user controlled input"|"relative:///PrototypePollutingAssignment.js:5:14:5:26"]].*/
    res.end(200);
});
