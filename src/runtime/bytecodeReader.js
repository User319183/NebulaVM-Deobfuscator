/**
 * ============================================================================
 * BYTECODE READER - NebulaVM Bytecode Decoding Utilities
 * ============================================================================
 *
 * BYTECODE ENCODING SCHEME:
 * -------------------------
 * The NebulaVM uses a multi-layer encoding scheme to obfuscate bytecode:
 *
 *   1. Raw bytecode bytes
 *      ↓
 *   2. XOR each byte with 0x80 (flips the high bit)
 *      ↓
 *   3. Base64 encode the result
 *      ↓
 *   4. Embedded as string literal in obfuscated JS
 *
 * To decode, we reverse this process:
 *   Base64 string → decode → XOR 0x80 → raw bytecode bytes
 *
 * COMPRESSION:
 * ------------
 * The first byte of the raw bytecode is a compression flag:
 *   - 0x00: Bytecode is uncompressed, read directly
 *   - 0x01: Remaining bytes are zlib-compressed (pako inflate)
 *
 * OPERAND EXTRACTION:
 * -------------------
 * Operands are read from the bytecode stream in little-endian format:
 *   - BYTE:   1 byte, read directly
 *   - DWORD:  4 bytes, little-endian (b0 | b1<<8 | b2<<16 | b3<<24)
 *   - DOUBLE: 8 bytes, IEEE 754 double-precision float
 *
 * STRING TABLE FORMAT:
 * --------------------
 * Strings are stored as a separate byte array with this structure:
 *   [length:4][char0:2][char1:2]...[charN:2]  (repeated for each string)
 *
 * Each string entry:
 *   - First 4 bytes: string length as little-endian DWORD
 *   - Following bytes: UTF-16 code units (2 bytes each), XOR'd with 0x80
 *
 * To decode each character:
 *   charCode = (lowByte | (highByte << 8)) ^ 0x80
 */

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decodes a Base64 encoded string to raw bytes (as string)
 *
 * Base64 encoding uses 6 bits per character, so we:
 *   1. Look up each char's 6-bit value in the alphabet
 *   2. Concatenate all 6-bit chunks into a binary string
 *   3. Split into 8-bit chunks and convert to characters
 *
 * @param {string} encodedString - Base64 encoded string
 * @returns {string} Decoded string (binary data as string)
 */
function decodeBase64(encodedString) {
  let decodedString = "";
  let binaryBuffer = "";

  for (let i = 0; i < encodedString.length; i++) {
    const currentChar = encodedString[i];
    const base64Index = BASE64_CHARS.indexOf(currentChar);
    if (base64Index === -1) continue;
    binaryBuffer += base64Index.toString(2).padStart(6, '0');
  }

  for (let i = 0; i < binaryBuffer.length; i += 8) {
    const byteChunk = binaryBuffer.substring(i, i + 8);
    if (byteChunk.length < 8) break;
    decodedString += String.fromCharCode(parseInt(byteChunk, 2));
  }

  return decodedString;
}

/**
 * XOR decodes a string by flipping bit 7 of each byte
 *
 * The obfuscator XORs each byte with 0x80 (10000000 binary) which:
 *   - Flips the high bit of each byte
 *   - Is its own inverse (XOR twice = original)
 *   - Makes the bytecode appear as random high-ASCII characters
 *
 * @param {string} str - XOR-encoded string
 * @returns {string} Decoded string
 */
function xorDecode(str) {
  return str.split('').map(c => String.fromCharCode(c.charCodeAt(0) ^ 0x80)).join('');
}

/**
 * Decodes the string table from raw bytes
 *
 * String table structure (repeated entries):
 *   ┌──────────────────┬────────────────────────────────┐
 *   │ Length (4 bytes) │ Characters (length * 2 bytes)  │
 *   │ little-endian    │ UTF-16LE, each XOR'd with 0x80 │
 *   └──────────────────┴────────────────────────────────┘
 *
 * @param {number[]|Uint8Array} stringsBytes - Raw string table bytes
 * @returns {string[]} Array of decoded strings
 */
export function decodeStringsBytes(stringsBytes) {
  const strings = [];
  let i = 0;

  while (i < stringsBytes.length) {
    if (i + 4 > stringsBytes.length) break;

    const length = (stringsBytes[i] & 0xFF) |
      ((stringsBytes[i + 1] & 0xFF) << 8) |
      ((stringsBytes[i + 2] & 0xFF) << 16) |
      ((stringsBytes[i + 3] & 0xFF) << 24);
    i += 4;

    if (length < 0 || length > 100000 || i + length * 2 > stringsBytes.length) break;

    let str = "";
    for (let j = 0; j < length; j++) {
      const code = (stringsBytes[i] & 0xFF) | ((stringsBytes[i + 1] & 0xFF) << 8);
      i += 2;
      str += String.fromCharCode(code ^ 0x80);
    }
    strings.push(str);
  }

  return strings;
}

/**
 * Decodes bytecode from Base64 → XOR 0x80 → raw bytes
 *
 * @param {string} base64String - Base64 encoded bytecode
 * @returns {Uint8Array} Raw bytecode bytes
 */
export function decodeBytecode(base64String) {
  const decodedBytecode = xorDecode(decodeBase64(base64String));
  const bytecode = new Uint8Array(decodedBytecode.length);
  for (let i = 0; i < decodedBytecode.length; i++) {
    bytecode[i] = decodedBytecode.charCodeAt(i);
  }
  return bytecode;
}
