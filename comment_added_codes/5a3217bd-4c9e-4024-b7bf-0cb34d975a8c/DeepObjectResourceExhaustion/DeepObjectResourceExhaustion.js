import express from 'express';
import Ajv from 'ajv';

let ajv = new Ajv({ allErrors: true });
ajv.addSchema(require('./input-schema'), 'input');

var app = express();
app.get('/user/:id', function(req, res) {
	if (!ajv.validate('input', req.body)) { /*Vulnerability name: Resources exhaustion from deep object traversal	Vulnerability description: Processing user-controlled object hierarchies inefficiently can lead to denial of service.	Vulnerability message: Denial of service caused by processing [["user input"|"relative:///DeepObjectResourceExhaustion.js:9:29:9:36"]] with [["allErrors: true"|"relative:///DeepObjectResourceExhaustion.js:4:21:4:35"]].*/
		res.end(ajv.errorsText());
		return;
	}
	// ...
});
