import express from 'express';
import Ajv from 'ajv';

let app = express();
let ajv = new Ajv();

ajv.addSchema({type: 'object', additionalProperties: {type: 'number'}}, 'pollData');

app.post('/polldata', (req, res) => {
    if (!ajv.validate('pollData', req.body)) {
        res.send(escape_html(ajv.errorsText()));
    }
});

// Function to escape HTML characters
function escape_html(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
