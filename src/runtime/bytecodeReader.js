import pako from 'pako';

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

/**
 * BytecodeReader - Sequential bytecode stream reader
 * 
 * Provides methods to read various data types from the bytecode stream,
 * maintaining a position pointer that advances with each read.
 * 
 * INSTRUCTION FORMAT:
 * -------------------
 * Each VM instruction consists of:
 *   [opcode:1 byte][operands: variable]
 * 
 * Operand sizes depend on the instruction:
 *   - STACK_PUSH_STRING:  [opcode][string_index:4]
 *   - STACK_PUSH_DWORD:   [opcode][value:4]
 *   - STACK_PUSH_DOUBLE:  [opcode][value:8]
 *   - STACK_PUSH_BOOLEAN: [opcode][flag:1]
 *   - JUMP_*:             [opcode][address:4]
 *   - LOAD_VARIABLE:      [opcode][scope:4][slot:4]
 *   etc.
 */
class BytecodeReader {
  /**
   * @param {Uint8Array} bytecode - Raw bytecode bytes
   */
  constructor(bytecode) {
    this.bytecode = bytecode;
    this.pointer = 0;
  }

  /**
   * Returns current position in the bytecode stream
   * @returns {number}
   */
  get position() {
    return this.pointer;
  }

  /**
   * Returns remaining bytes in the stream
   * @returns {number}
   */
  get remaining() {
    return this.bytecode.length - this.pointer;
  }

  /**
   * Checks if there are more bytes to read
   * @returns {boolean}
   */
  hasMore() {
    return this.pointer < this.bytecode.length;
  }

  /**
   * Reads a single byte (instruction opcode or 1-byte operand)
   * 
   * Used for:
   *   - Opcode fetch
   *   - Boolean values (0 = false, 1 = true)
   *   - Compression flag
   * 
   * @returns {number} Single byte value (0-255)
   */
  readInstruction() {
    return this.bytecode[this.pointer++];
  }

  /**
   * Alias for readInstruction() - reads single byte
   * @returns {number}
   */
  readByte() {
    return this.bytecode[this.pointer++];
  }

  /**
   * Reads an unsigned 32-bit integer (DWORD) in little-endian format
   * 
   * Little-endian byte order:
   *   byte[0] = bits 0-7   (LSB)
   *   byte[1] = bits 8-15
   *   byte[2] = bits 16-23
   *   byte[3] = bits 24-31 (MSB)
   * 
   * Used for:
   *   - String table indices
   *   - Jump addresses
   *   - Array/object lengths
   *   - Scope/slot identifiers
   * 
   * @returns {number} Unsigned 32-bit value (0 to 4294967295)
   */
  readDword() {
    const val = this.bytecode[this.pointer] |
      (this.bytecode[this.pointer + 1] << 8) |
      (this.bytecode[this.pointer + 2] << 16) |
      (this.bytecode[this.pointer + 3] << 24);
    this.pointer += 4;
    return val >>> 0;
  }

  /**
   * Reads a signed 32-bit integer in little-endian format
   * 
   * Same byte layout as readDword(), but interprets the result
   * as a signed two's complement value.
   * 
   * Used for:
   *   - STACK_PUSH_DWORD values (can be negative)
   *   - Relative jump offsets
   * 
   * @returns {number} Signed 32-bit value (-2147483648 to 2147483647)
   */
  readSignedDword() {
    const val = this.bytecode[this.pointer] |
      (this.bytecode[this.pointer + 1] << 8) |
      (this.bytecode[this.pointer + 2] << 16) |
      (this.bytecode[this.pointer + 3] << 24);
    this.pointer += 4;
    return val;
  }

  /**
   * Reads an IEEE 754 double-precision floating point (8 bytes)
   * 
   * Format: 64-bit IEEE 754 binary64
   *   - 1 bit sign
   *   - 11 bits exponent
   *   - 52 bits mantissa
   * 
   * We copy 8 bytes into a Uint8Array, then reinterpret as Float64
   * via a shared ArrayBuffer.
   * 
   * Used for:
   *   - STACK_PUSH_DOUBLE values
   *   - Floating point constants
   * 
   * @returns {number} Double-precision float
   */
  readDouble() {
    const u8 = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
      u8[i] = this.readInstruction();
    }
    const f64 = new Float64Array(u8.buffer);
    return f64[0];
  }

  /**
   * Reads N bytes as a Uint8Array slice
   * 
   * @param {number} length - Number of bytes to read
   * @returns {Uint8Array} Byte slice
   */
  readBytes(length) {
    const bytes = this.bytecode.slice(this.pointer, this.pointer + length);
    this.pointer += length;
    return bytes;
  }

  /**
   * Checks and handles bytecode compression
   * 
   * Compression format:
   *   byte[0] = compression flag
   *     0x00 = uncompressed, bytes follow directly
   *     0x01 = remaining bytes are zlib compressed
   * 
   * If compressed, uses pako (zlib) to inflate the data and
   * replaces the internal bytecode buffer with decompressed data.
   * 
   * @throws {Error} If decompression fails
   */
  handleCompression() {
    const isCompressed = this.readInstruction();
    if (isCompressed) {
      const compressedData = this.bytecode.slice(this.pointer);
      try {
        const decompressed = pako.inflate(compressedData);
        this.bytecode = decompressed;
        this.pointer = 0;
      } catch (err) {
        throw new Error(`Failed to decompress bytecode: ${err.message}`);
      }
    }
  }

  /**
   * Resets the read pointer to the beginning
   */
  reset() {
    this.pointer = 0;
  }

  /**
   * Seeks to a specific position in the bytecode
   * @param {number} position - Position to seek to
   */
  seek(position) {
    this.pointer = position;
  }

  /**
   * Peeks at the next byte without advancing the pointer
   * @returns {number} Next byte value
   */
  peek() {
    return this.bytecode[this.pointer];
  }
}
