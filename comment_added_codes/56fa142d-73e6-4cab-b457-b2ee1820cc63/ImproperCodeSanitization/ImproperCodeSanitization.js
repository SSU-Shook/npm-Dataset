function createObjectWrite() {
    const assignment = `obj[${JSON.stringify(key)}]=42`;
    return `(function(){${assignment}})` // NOT OK /*Vulnerability name: Improper code sanitization	Vulnerability description: Escaping code as HTML does not provide protection against code injection.	Vulnerability message: Code construction depends on an [["improperly sanitized value"|"relative:///ImproperCodeSanitization.js:2:31:2:49"]].*/
}