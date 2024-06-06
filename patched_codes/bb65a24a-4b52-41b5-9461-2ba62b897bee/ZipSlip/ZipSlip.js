
const fs = require('fs');
const unzip = require('unzip');
const path = require('path');

const extractDir = 'extracted_files'; // Intended extraction directory

fs.createReadStream('archive.zip')
  .pipe(unzip.Parse())
  .on('entry', entry => {
    // Resolve the path to avoid directory traversal
    let fileName = entry.path;
    const filePath = path.join(extractDir, fileName);
    
    // Ensure the file path is within the intended extract directory
    if (!filePath.startsWith(path.join(__dirname, extractDir))) {
        console.warn(`Skipping file ${fileName} due to invalid path`);
        entry.autodrain();
        return;
    }

    // Create necessary directories if not exist
    fs.mkdirSync(path.dirname(filePath), { recursive: true });

    console.log(`Extracting file to ${filePath}`);
    entry.pipe(fs.createWriteStream(filePath));
  });
