
var cp = require("child_process"),
  path = require("path"),
  fs = require("fs");

function cleanupTemp() {
  let tempPath = path.join(__dirname, "temp");
  if (fs.existsSync(tempPath)) {
    fs.rmSync(tempPath, { recursive: true, force: true });
  }
}
