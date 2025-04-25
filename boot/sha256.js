#!/usr/bin/env qjs
// sha256-arraybuffer.js — pure-JS SHA-256 for ArrayBuffer → ArrayBuffer

/**
 * Compute SHA-256 hash of an ArrayBuffer, returning a new 32-byte ArrayBuffer.
 * @param {ArrayBuffer} buf  – input data
 * @returns {ArrayBuffer}    – 32-byte hash digest
 */
function sha256(buf) {
    const bytes = new Uint8Array(buf);
  
    // --- 1) Pre-processing (padding) ---
    const bitLen = bytes.length * 8;
    // append 0x80, then pad with zeros until length ≡ 56 mod 64
    const withOne = new Uint8Array(bytes.length + 1);
    withOne.set(bytes);
    withOne[bytes.length] = 0x80;
    let padLen = withOne.length;
    while (padLen % 64 !== 56) padLen++;
    const padded = new Uint8Array(padLen + 8);
    padded.set(withOne);
    // append 64-bit big-endian length
    const dv = new DataView(padded.buffer);
    dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padded.length - 4, bitLen >>> 0, false);
  
    // --- 2) Initialize hash values H₀…H₇ ---
    let H = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
  
    // --- 3) SHA-256 constants K[0..63] ---
    const K = new Uint32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
  
    // Helper: right-rotate
    const ROTR = (w, n) => (w >>> n) | (w << (32 - n));
  
    // Process each 512-bit chunk
    const w = new Uint32Array(64);
    for (let i = 0; i < padded.length; i += 64) {
      // 3.1) Prepare message schedule W[0..63]
      for (let t = 0; t < 16; t++) {
        w[t] = dv.getUint32(i + t*4, false);
      }
      for (let t = 16; t < 64; t++) {
        const s0 = ROTR(w[t-15], 7)  ^ ROTR(w[t-15], 18) ^ (w[t-15] >>> 3);
        const s1 = ROTR(w[t-2], 17)  ^ ROTR(w[t-2], 19)  ^ (w[t-2] >>> 10);
        w[t] = (w[t-16] + s0 + w[t-7] + s1) >>> 0;
      }
  
      // 3.2) Initialize working vars a..h with current H
      let [a,b,c,d,e,f,g,h] = H;
  
      // 3.3) Compression rounds
      for (let t = 0; t < 64; t++) {
        const S1   = ROTR(e,6) ^ ROTR(e,11) ^ ROTR(e,25);
        const ch   = (e & f) ^ (~e & g);
        const temp1= (h + S1 + ch + K[t] + w[t]) >>> 0;
        const S0   = ROTR(a,2) ^ ROTR(a,13) ^ ROTR(a,22);
        const maj  = (a & b) ^ (a & c) ^ (b & c);
        const temp2= (S0 + maj) >>> 0;
  
        h = g;
        g = f;
        f = e;
        e = (d + temp1) >>> 0;
        d = c;
        c = b;
        b = a;
        a = (temp1 + temp2) >>> 0;
      }
  
      // 3.4) Compute intermediate hash value
      H[0] = (H[0] + a) >>> 0;
      H[1] = (H[1] + b) >>> 0;
      H[2] = (H[2] + c) >>> 0;
      H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0;
      H[5] = (H[5] + f) >>> 0;
      H[6] = (H[6] + g) >>> 0;
      H[7] = (H[7] + h) >>> 0;
    }
  
    // --- 4) Produce the final hash as ArrayBuffer ---
    const out = new ArrayBuffer(32);
    const outDv = new DataView(out);
    for (let i = 0; i < 8; i++) {
      outDv.setUint32(i * 4, H[i], false);
    }
    return out;
  }

/**
 * Convert an ArrayBuffer to a hex-encoded string.
 * @param {ArrayBuffer} buffer
 * @returns {string} Hex string (lowercase), two chars per byte
 */
function arrayBufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))                  // view bytes  [oai_citation:0‡Stack Overflow](https://stackoverflow.com/questions/40031688/how-can-i-convert-an-arraybuffer-to-a-hexadecimal-string-hex?utm_source=chatgpt.com)
      .map(b => b.toString(16).padStart(2, '0'))                // byte → hex, pad to 2 chars  [oai_citation:1‡Stack Overflow](https://stackoverflow.com/questions/40031688/how-can-i-convert-an-arraybuffer-to-a-hexadecimal-string-hex?utm_source=chatgpt.com)
      .join('');                                                // join into one continuous string
}

export { sha256, arrayBufferToHex }