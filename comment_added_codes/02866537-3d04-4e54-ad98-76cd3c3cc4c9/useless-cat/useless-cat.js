var child_process = require('child_process');

module.exports = function (name) {
    return child_process.execSync("cat " + name).toString(); /*Vulnerability name: Unnecessary use of `cat` process	Vulnerability description: Using the `cat` process to read a file is unnecessarily complex, inefficient, unportable, and can lead to subtle bugs, or even security vulnerabilities.	Vulnerability message: Unnecessary use of `cat` process. Can be replaced with: fs.readFileSync(name)*/
};
