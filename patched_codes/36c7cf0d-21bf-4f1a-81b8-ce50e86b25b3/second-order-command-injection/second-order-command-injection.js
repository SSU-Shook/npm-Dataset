const express = require("express");
const app = express();

const cp = require("child_process");

// Function to validate the Git remote URL
const isValidGitUrl = (url) => {
    const gitUrlPattern = /^(https|git|ssh|http(s)?)|github.com[:/]([^/:]+)\/(.+?)(\.git)?$/;
    return gitUrlPattern.test(url);
};

app.get("/ls-remote", (req, res) => {
    const remote = req.query.remote;
    
    if (!isValidGitUrl(remote)) {
        return res.status(400).send("Invalid Git remote URL");
    }

    cp.execFile("git", ["ls-remote", remote], (error, stdout, stderr) => {
        if (error) {
            return res.status(500).send(stderr);
        }
        res.send(stdout);
    });
});

app.listen(3000, () => {
    console.log("Server running on port 3000");
});
