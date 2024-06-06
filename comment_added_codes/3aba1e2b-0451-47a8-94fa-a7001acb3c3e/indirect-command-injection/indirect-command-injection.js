var cp = require("child_process");

const args = process.argv.slice(2);
const script = path.join(__dirname, 'bin', 'main.js');
cp.execSync(`node ${script} ${args.join(' ')}`); // BAD /*Vulnerability name: Indirect uncontrolled command line	Vulnerability description: Forwarding command-line arguments to a child process executed within a shell may indirectly introduce command-line injection vulnerabilities.	Vulnerability message: This command depends on an unsanitized [["command-line argument"|"relative:///indirect-command-injection.js:3:14:3:25"]].*/
