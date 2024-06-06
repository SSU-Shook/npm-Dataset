
function createObjectWrite(key) {
    if (typeof key !== 'string' || !key.match(/^[a-zA-Z0-9_]+$/)) {
        throw new Error("Invalid key provided.");
    }
    const assignment = `obj[${JSON.stringify(key)}]=42`;
    return `(function(){${assignment}})`;
}
