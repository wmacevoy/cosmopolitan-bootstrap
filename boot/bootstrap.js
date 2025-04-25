#!/usr/bin/env qjs --std

import * as std from 'std';
import * as os  from 'os';
import * as sha256 from './sha256.js';

/**
 * Ensure parent directories exist for a given file path, like `mkdir -p dir/...`.
 * @param {string} filePath   – e.g. "path/to/file.txt"
 * @param {number} [mode=0o755] – permission bits for new directories
 */
function mkpath(filePath, mode = 0o755) {
  // 1) Find the last slash
  const idx = filePath.lastIndexOf('/');                                 
  if (idx <= 0) return;            // no directory component or root only  [oai_citation:7‡W3Schools.com](https://www.w3schools.com/jsref/jsref_lastindexof.asp?utm_source=chatgpt.com)

  // 2) Directory portion before the file
  const dirPath = filePath.slice(0, idx);                               
  // 3) Split into segments
  const parts = dirPath.split('/');                                     

  // 4) Build up each subpath and mkdir
  let subpath = '';
  for (const part of parts) {                                           
    subpath += (subpath ? '/' : '') + part;
    try {
      os.mkdir(subpath, mode);                                          
    } catch (e) {
      // Ignore "directory exists" errors; rethrow others
      if (!/EEXIST/.test(e.message)) throw e;                           
    }
  }
}

async function download(url, filename, checksums = null) {
  // 1) Fetch binary data
  const dataBuf = std.urlGet(url, { binary: true });
  if (!(dataBuf instanceof ArrayBuffer)) {
    std.err.print(`Failed to fetch binary from ${url}\n`);
    os.exit(1);
  }

  // 2) computer sha256 digest
  const digest = sha256.arrayBufferToHex(sha256.sha256(dataBuf));

  // 3) Verify checksum if provided
  if (checksums && !checksums.includes(digest)) {
    std.err.printf(
      "Checksum mismatch for %s:\n  expected one of [%s]\n  got %s\n",
      filename,
      checksums.join(', '),
      digest
    );
    os.exit(1);
  }

  // 4) Write file in binary mode, truncating existing file
  mkpath(filename);
  const fd = os.open(
    filename,
    os.O_CREAT | os.O_RDWR | os.O_TRUNC,
    0x755
  );
  if (fd < 0) {
    std.err.printf("Cannot open '%s' for writing\n", filename);
    os.exit(1);
  }
  const written = os.write(fd, dataBuf, 0, dataBuf.byteLength);
  os.close(fd);
  if (written !== dataBuf.byteLength) {
    std.err.printf(
      "Failed to write '%s' (wrote %d of %d bytes)\n",
      filename,
      written,
      dataBuf.byteLength
    );
    os.exit(1);
  }

  std.out.printf("Downloaded '%s' (%d bytes)\n", filename, written);
}

async function main() {
  // Read config.json (assumes UTF-8 text)
  let configText;
  try {
    configText = std.loadFile('boot/config.json', 'utf-8');
  } catch (e) {
    std.err.print("Error: cannot read 'boot/config.json'\n");
    os.exit(1);
  }


  let config;
  try {
    config = std.parseExtJSON(configText);
  } catch (e) {
    std.err.print("Error: invalid JSON in 'boot/config.json'\n");
    os.exit(1);
  }

  if (!Array.isArray(config.downloads)) {
    std.err.print("Error: 'downloads' must be an array in config\n");
    os.exit(1);
  }

  // Iterate and download each entry
  for (const entry of config.downloads) {
    const { url, filename, checksums } = entry;
    if (!url || !filename) {
      std.err.print("Invalid entry in config: missing url or filename\n");
      os.exit(1);
    }
    await download(url, filename, checksums);
  }
}

// Run it
main();