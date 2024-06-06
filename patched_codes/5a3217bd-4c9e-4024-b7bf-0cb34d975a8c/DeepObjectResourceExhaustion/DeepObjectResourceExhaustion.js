
import express from 'express';
import Ajv from 'ajv';
import addFormats from "ajv-formats";

const ajv = new Ajv({ allErrors: false, maxErrors: 1 }); // Set to process fewer errors to avoid DoS
addFormats(ajv);
ajv.addSchema(require('./input-schema'), 'input');

var app = express();
app.use(express.json()); // Ensure request body is parsed into JSON format

app.get('/user/:id', function (req, res) {
    if (!ajv.validate('input', req.body)) {
        res.status(400).json({ error: ajv.errorsText() }); // Return JSON error with status code 400
        return;
    }
    // ...
});
