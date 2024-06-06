
function createObjectWrite() {
    const sanitize = (str) => str.replace(/[^\w\s]/gi, '');
    const safeKey = sanitize(key);
    const assignment = `obj[${JSON.stringify(safeKey)}]=42`;
    return `(function(){${assignment}})`
}
