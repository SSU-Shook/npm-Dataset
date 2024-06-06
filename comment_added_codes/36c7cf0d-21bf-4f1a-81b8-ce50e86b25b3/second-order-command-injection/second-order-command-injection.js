const express = require("express");
const app = express();

const cp = require("child_process");

app.get("/ls-remote", (req, res) => {
  const remote = req.query.remote;
  cp.execFile("git", ["ls-remote", remote]); // NOT OK /*Vulnerability name: Second order command injection	Vulnerability description: Using user-controlled data as arguments to some commands, such as git clone, can allow arbitrary commands to be executed.	Vulnerability message: Command line argument that depends on [["a user-provided value"|"relative:///second-order-command-injection.js:7:18:7:33"]] can execute an arbitrary command if --upload-pack is used with git.*/
});
