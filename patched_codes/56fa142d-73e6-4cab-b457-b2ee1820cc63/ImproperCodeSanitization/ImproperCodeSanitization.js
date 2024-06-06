function createObjectWrite() {
    const sanitizedKey = String(key).replace(/[^\w\s]/gi, ''); // Sanitize key by removing non-alphanumeric characters
    const assignment = `obj[${JSON.stringify(sanitizedKey)}]=42`;
    return `(function(){${assignment}})`
}
