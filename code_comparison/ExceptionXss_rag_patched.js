
import express from 'express';
import Ajv from 'ajv';

let app = express();
let ajv = new Ajv();

ajv.addSchema({type: 'object', additionalProperties: {type: 'number'}}, 'pollData');

app.post('/polldata', (req, res) => {
    if (!ajv.validate('pollData', req.body)) {
        res.send(escape_html(ajv.errorsText())); 
        /*Vulnerability name: Exception text reinterpreted as HTML
        Vulnerability description: Reinterpreting text from an exception as HTML can lead to a cross-site scripting vulnerability.
        Vulnerability message: [["JSON schema validation error"|"relative:///ExceptionXss-fixed.js:11:18:11:33"]] is reinterpreted as HTML without escaping meta-characters.*/
    }
});

// Function to escape HTML characters
function escape_html(text) {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
