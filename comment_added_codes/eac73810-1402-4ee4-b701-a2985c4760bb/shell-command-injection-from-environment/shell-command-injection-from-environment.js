var cp = require("child_process"),
  path = require("path");
function cleanupTemp() {
  let cmd = "rm -rf " + path.join(__dirname, "temp");
  cp.execSync(cmd); // BAD /*Vulnerability name: Shell command built from environment values	Vulnerability description: Building a shell command string with values from the enclosing environment may cause subtle bugs or vulnerabilities.	Vulnerability message: This shell command depends on an uncontrolled [["absolute path"|"relative:///shell-command-injection-from-environment.js:4:35:4:43"]].*/
}
