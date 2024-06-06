const fs = require('fs');
const unzip = require('unzip');

fs.createReadStream('archive.zip')
  .pipe(unzip.Parse())
  .on('entry', entry => {
    const fileName = entry.path; /*Vulnerability name: Arbitrary file access during archive extraction ("Zip Slip")	Vulnerability description: Extracting files from a malicious ZIP file, or similar type of archive, without validating that the destination file path is within the destination directory can allow an attacker to unexpectedly gain access to resources.	Vulnerability message: Unsanitized archive entry, which may contain '..', is used in a [["file system operation"|"relative:///ZipSlip.js:9:37:9:44"]].*/
    // BAD: This could write any file on the filesystem.
    entry.pipe(fs.createWriteStream(fileName));
  });
