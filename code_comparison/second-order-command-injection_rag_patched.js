const express = require("express");
const app = express();

const cp = require("child_process");

const validRemotes = ["git@github.com:user/repo.git", "https://github.com/user/repo.git"]; // Example whitelist

app.get("/ls-remote", (req, res) => {
  const remote = req.query.remote;
  
  if (!validRemotes.includes(remote)) {
    throw new Error("Invalid remote: " + remote);
  }
  
  cp.execFile("git", ["ls-remote", remote], (error, stdout, stderr) => {
    if (error) {
      res.status(500).send(stderr);
      return;
    }
    res.send(stdout);
  }); // OK
});
