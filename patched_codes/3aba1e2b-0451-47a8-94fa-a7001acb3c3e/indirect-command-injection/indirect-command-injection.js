
var cp = require("child_process");
var path = require("path");

const args = process.argv.slice(2);
const script = path.join(__dirname, 'bin', 'main.js');

// Sanitize the command execution 
cp.spawnSync("node", [script, ...args], { stdio: 'inherit' });
