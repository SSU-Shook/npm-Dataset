
const express = require("express");
const app = express();

const cp = require("child_process");
const { URL } = require("url");

app.get("/ls-remote", (req, res) => {
  const remote = req.query.remote;
  
  // Validate the remote input to ensure it is a valid URL
  try {
    const url = new URL(remote);
    if (url.protocol === "http:" || url.protocol === "https:" || url.protocol === "git:") {
      // Only if the remote passes validation, execute the command
      cp.execFile("git", ["ls-remote", remote], (error, stdout, stderr) => {
        if (error) {
          res.status(500).send(stderr);
        } else {
          res.send(stdout);
        }
      });
    } else {
      res.status(400).send("Invalid protocol");
    }
  } catch (e) {
    res.status(400).send("Invalid URL");
  }
});

module.exports = app;
