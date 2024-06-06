import express from 'express';
import Ajv from 'ajv';
import expressValidator from 'express-validator'; // Added express-validator for deeper validation

let ajv = new Ajv({ allErrors: true, maxDepth: 5 }); // Limit the depth of object processing
ajv.addSchema(require('./input-schema'), 'input');

var app = express();

// Middleware for body parsing and validation
app.use(express.json());
app.use(expressValidator({
    customSanitizers: {
        // Limiting depth of objects before validation to prevent deep object traversal
        checkDepth: (value) => {
            const check = (obj, depth) => {
                if (depth > 5) return; // limit to 5 levels deep
                for (let key in obj) {
                    if (typeof obj[key] === 'object') {
                        check(obj[key], depth + 1);
                    }
                }
            };
            check(value, 0);
            return value;
        }
    }
}));

app.get('/user/:id', function (req, res) {
    if (!ajv.validate('input', req.body)) { 
        res.end(ajv.errorsText());
        return;
    }
    // ...
});