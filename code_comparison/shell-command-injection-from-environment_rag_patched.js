
var cp = require("child_process"),
  path = require("path");

function cleanupTemp() {
  let tempDir = path.join(__dirname, "temp");
  // Use spawnSync to avoid shell command injection vulnerability
  cp.spawnSync("rm", ["-rf", tempDir]);  // SAFE
}
