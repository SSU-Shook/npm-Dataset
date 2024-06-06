
function createObjectWrite() {
    const assignment = `obj[${JSON.stringify(key)}]=42`;
    return (obj) => { obj[JSON.parse(key)] = 42; }; // Safely creating the function instead of using dynamic code execution
}
