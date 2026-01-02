/**
 * NebulaVM Bytecode Disassembler
 * ================================
 * 
 * This module implements a disassembler for the NebulaVM's custom bytecode format.
 * It decodes the raw byte stream into structured instruction objects suitable for
 * analysis and decompilation.
 * 
 * VM Instruction Format:
 * - Each instruction begins with a 1-byte opcode
 * - Operands follow in little-endian format (variable length per instruction)
 * - Opcode values are shuffled per-obfuscation (opcodeMap provides translation)
 * 
 * Disassembly Process:
 * 1. Handle optional zlib compression (first byte indicates compression)
 * 2. Read opcode byte and dispatch to appropriate operand decoder
 * 3. Fetch operands based on instruction semantics (immediate values, addresses, etc.)
 * 4. Build instruction objects with decoded operands
 */

import { OperationCode, OpcodeNames } from './opcodes.js';
import pako from 'pako';

export class Disassembler {
  constructor(bytecode, strings, opcodeMap, returnOpcode = null) {
    this.bytecode = bytecode;
    this.strings = strings;
    this.opcodeMap = opcodeMap;
    this.returnOpcode = returnOpcode;
    this.reverseOpcodeMap = this.buildReverseOpcodeMap();
    this.pointer = 0;
    this.instructions = [];
  }

  /**
   * Build reverse opcode map for translating shuffled opcodes back to canonical values.
   * NebulaVM uses opcode shuffling as an obfuscation technique - each obfuscated
   * file has a unique mapping from shuffled opcode bytes to standard operation codes.
   */
  buildReverseOpcodeMap() {
    const reverseMap = {};
    for (const [shuffledOpcode, opcodeName] of Object.entries(this.opcodeMap)) {
      if (opcodeName in OperationCode) {
        reverseMap[parseInt(shuffledOpcode, 10)] = OperationCode[opcodeName];
      } else {
        reverseMap[parseInt(shuffledOpcode, 10)] = parseInt(shuffledOpcode, 10);
      }
    }
    return reverseMap;
  }

  /**
   * Read single byte from bytecode and advance instruction pointer (IP).
   * Used for opcode fetch and single-byte operand extraction.
   */
  readInstruction() {
    return this.bytecode[this.pointer++];
  }

  /**
   * Read unsigned 32-bit DWORD operand in little-endian format.
   * Advances IP by 4 bytes. Used for addresses, indices, and lengths.
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
   * Read signed 32-bit DWORD operand in little-endian format.
   * Advances IP by 4 bytes. Used for integer immediate values.
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
   * Read 64-bit IEEE 754 double-precision floating point operand.
   * Advances IP by 8 bytes. Used for numeric literal values.
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
   * Opcode dispatch: Translate shuffled opcode byte to canonical instruction name.
   * Handles special case for RETURN opcode which may be dynamically determined.
   */
  getOpcodeName(opcode) {
    if (this.returnOpcode !== null && opcode === this.returnOpcode) {
      return 'RETURN';
    }
    if (opcode in this.opcodeMap) {
      return this.opcodeMap[opcode];
    }
    if (opcode in OpcodeNames) {
      return OpcodeNames[opcode];
    }
    return `UNKNOWN_${opcode}`;
  }

  /**
   * Main disassembly loop: Decode bytecode stream into instruction objects.
   * 
   * Algorithm:
   * 1. Check compression flag and decompress if needed
   * 2. Iterate through bytecode until end of stream
   * 3. For each instruction:
   *    a. Record current address (IP before fetch)
   *    b. Fetch opcode byte and dispatch to get instruction name
   *    c. Decode operands based on instruction semantics
   *    d. Build instruction object with address, opcode, name, and args
   */
  disassemble() {
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

    while (this.pointer < this.bytecode.length) {
      const addr = this.pointer;
      const opcode = this.readInstruction();
      const opName = this.getOpcodeName(opcode);
      
      const instr = { addr, opcode, opName, args: [] };

      try {
        switch (opName) {
          case 'STACK_PUSH_STRING': {
            const idx = this.readDword();
            instr.args.push({ type: 'string_index', value: idx });
            instr.stringValue = this.strings[idx] || `[string_${idx}]`;
            break;
          }
          
          case 'STACK_PUSH_DWORD': {
            const val = this.readSignedDword();
            instr.args.push({ type: 'dword', value: val });
            break;
          }
          
          case 'STACK_PUSH_DOUBLE': {
            const val = this.readDouble();
            instr.args.push({ type: 'double', value: val });
            break;
          }
          
          case 'STACK_PUSH_BOOLEAN': {
            const val = this.readInstruction() === 1;
            instr.args.push({ type: 'boolean', value: val });
            break;
          }
          
          case 'STACK_PUSH_NULL':
          case 'STACK_PUSH_UNDEFINED':
          case 'STACK_PUSH_DUPLICATE':
          case 'STACK_POP':
          case 'LOAD_THIS':
          case 'LOAD_GLOBAL':
          case 'LOAD_ARGUMENTS':
          case 'DEBUGGER':
            break;

          case 'ARITHMETIC_ADD':
          case 'ARITHMETIC_SUB':
          case 'ARITHMETIC_MUL':
          case 'ARITHMETIC_DIV':
          case 'ARITHMETIC_MOD':
          case 'COMPARISON_EQUAL':
          case 'COMPARISON_STRICT_EQUAL':
          case 'COMPARISON_NOT_EQUAL':
          case 'COMPARISON_STRICT_NOT_EQUAL':
          case 'COMPARISON_LESS':
          case 'COMPARISON_LESS_OR_EQUAL':
          case 'COMPARISON_GREATER':
          case 'COMPARISON_GREATER_OR_EQUAL':
          case 'BINARY_BIT_SHIFT_LEFT':
          case 'BINARY_BIT_SHIFT_RIGHT':
          case 'BINARY_UNSIGNED_BIT_SHIFT_RIGHT':
          case 'BINARY_BIT_XOR':
          case 'BINARY_BIT_AND':
          case 'BINARY_BIT_OR':
          case 'BINARY_IN':
          case 'BINARY_INSTANCEOF':
          case 'GET_PROPERTY':
            break;

          case 'UNARY_PLUS':
          case 'UNARY_MINUS':
          case 'UNARY_NOT':
          case 'UNARY_BIT_NOT':
          case 'UNARY_TYPEOF':
          case 'UNARY_VOID':
          case 'UNARY_THROW':
            break;

          case 'UPDATE_PLUS':
          case 'UPDATE_MINUS': {
            const isPrefix = this.readInstruction() === 1;
            const scopeId = this.readDword();
            const destination = this.readDword();
            instr.args.push({ type: 'prefix', value: isPrefix });
            instr.args.push({ type: 'scope', value: scopeId });
            instr.args.push({ type: 'dest', value: destination });
            break;
          }

          case 'PROP_UPDATE_PLUS':
          case 'PROP_UPDATE_MINUS': {
            const isPrefix = this.readInstruction() === 1;
            const scopeId = this.readDword();
            const destination = this.readDword();
            instr.args.push({ type: 'prefix', value: isPrefix });
            instr.args.push({ type: 'scope', value: scopeId });
            instr.args.push({ type: 'dest', value: destination });
            break;
          }

          case 'COMPLEX_PROP_UPDATE_PLUS':
          case 'COMPLEX_PROP_UPDATE_MINUS': {
            const isPrefix = this.readInstruction() === 1;
            instr.args.push({ type: 'prefix', value: isPrefix });
            break;
          }

          case 'LOAD_VARIABLE': {
            const scopeId = this.readDword();
            const destination = this.readDword();
            instr.args.push({ type: 'scope', value: scopeId });
            instr.args.push({ type: 'dest', value: destination });
            break;
          }

          case 'STORE_VARIABLE': {
            const scopeId = this.readDword();
            const destination = this.readDword();
            instr.args.push({ type: 'scope', value: scopeId });
            instr.args.push({ type: 'dest', value: destination });
            break;
          }

          case 'ASSIGN_VARIABLE': {
            const isOperation = this.readInstruction();
            const scopeId = this.readDword();
            const destination = this.readDword();
            instr.args.push({ type: 'is_op', value: isOperation });
            instr.args.push({ type: 'scope', value: scopeId });
            instr.args.push({ type: 'dest', value: destination });
            if (isOperation) {
              const assignOpcode = this.readInstruction();
              instr.args.push({ type: 'assign_op', value: this.getOpcodeName(assignOpcode) });
            }
            break;
          }

          case 'LOAD_GLOBAL_PROP':
            break;

          case 'LOAD_ARGUMENT': {
            const idx = this.readDword();
            instr.args.push({ type: 'index', value: idx });
            break;
          }

          case 'CALL_FUNCTION':
          case 'CALL_METHOD':
          case 'CONSTRUCT': {
            const argsCount = this.readDword();
            instr.args.push({ type: 'argc', value: argsCount });
            break;
          }

          case 'SET_PROPERTY':
            break;

          case 'BUILD_ARRAY':
          case 'BUILD_OBJECT': {
            const length = this.readDword();
            instr.args.push({ type: 'length', value: length });
            break;
          }

          case 'BUILD_FUNCTION': {
            const fnBodyLength = this.readDword();
            const fnBody = [];
            for (let i = 0; i < fnBodyLength; i++) {
              fnBody.push(this.readInstruction());
            }
            instr.args.push({ type: 'fn_body_length', value: fnBodyLength });
            instr.fnBody = fnBody;
            break;
          }

          case 'JUMP':
          case 'JUMP_IF_TRUE':
          case 'JUMP_IF_FALSE': {
            const addr = this.readDword();
            instr.args.push({ type: 'address', value: addr });
            break;
          }

          case 'RETURN': {
            const hasValue = this.readInstruction();
            instr.args.push({ type: 'has_value', value: hasValue === 1 });
            break;
          }

          default:
            break;
        }
      } catch (e) {
        instr.error = e.message;
      }

      this.instructions.push(instr);
    }

    return this.instructions;
  }
}
