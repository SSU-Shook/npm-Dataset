import express from 'express';
import Ajv from 'ajv';

let ajv = new Ajv({ allErrors: true });
ajv.addSchema(require('./input-schema'), 'input');

// Function to limit object depth traversal
function isValidDepth(obj, depth) {
    if (depth === 0) return false;
    if (typeof obj !== 'object' || obj === null) return true;
    for (let key in obj) {
        if (!isValidDepth(obj[key], depth - 1)) return false;
    }
    return true;
}

var app = express();
app.get('/user/:id', function(req, res) {
    const MAX_DEPTH = 5;

    if (!isValidDepth(req.body, MAX_DEPTH)) {
        res.status(400).send('Request body is too deeply nested.');
        return;
    }

    if (!ajv.validate('input', req.body)) {
        res.end(ajv.errorsText());
        return;
    }
    // ...
});
