
const express = require("express");
const app = express();

const cp = require("child_process");

app.get("/ls-remote", (req, res) => {
  const remote = req.query.remote;
  if (!(remote.startsWith("git@") || remote.startsWith("https://"))) {
    throw new Error("Invalid remote: " + remote);
  }

  // Patch: Perform strict validation on the 'remote' input
  const validRemotePattern = /^(git@|https:\/\/).*/;
  if (!validRemotePattern.test(remote)) {
    throw new Error("Invalid remote format: " + remote);
  }

  // Proceed with the validated input
  cp.execFile("git", ["ls-remote", remote], (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(`Error: ${stderr}`);
    } else {
      res.send(stdout);
    }
  });
});
