
const fs = require('fs');
const unzip = require('unzip');
const path = require('path');

const extractPath = path.join(__dirname, 'extracted');

fs.createReadStream('archive.zip')
  .pipe(unzip.Parse())
  .on('entry', entry => {
    const fileName = entry.path;
    const sanitizedPath = path.normalize(fileName).replace(/^(\.\.(\/|\\|$))+/, ''); // Remove any '../' from the path
    const outputPath = path.join(extractPath, sanitizedPath);

    if (!outputPath.startsWith(extractPath)) {
      console.error(`Skipping file with invalid path: ${fileName}`);
      entry.autodrain();
      return;
    }

    // GOOD: Safely write the file to the intended directory
    entry.pipe(fs.createWriteStream(outputPath));
  });
