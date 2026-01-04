/**
 * Statement Emitter
 *
 * Lifts stack-based IR back to high-level JavaScript statements.
 * This module generates JavaScript source code from symbolic execution results.
 *
 * Key concepts:
 * - Lifting: Converting low-level IR (intermediate representation) to high-level code
 * - Statement emission: Producing syntactically correct JavaScript statements
 */

import { Disassembler } from '../lib/disassembler.js';

export class StatementEmitter {
  constructor(codeGenerator) {
    this.generator = codeGenerator;
  }

  /**
   * Emit a line of code with proper indentation
   */
  emit(line) {
    const indentStr = '  '.repeat(this.generator.indent);
    this.generator.output.push(indentStr + line);
  }

  /**
   * Emit variable declaration - lifts STORE_VARIABLE to JavaScript var statement
   */
  emitVariableDeclaration(varName, value) {
    this.emit(`var ${varName} = ${value};`);
  }

  /**
   * Emit assignment statement
   */
  emitAssignment(target, value) {
    this.emit(`${target} = ${value};`);
  }

  /**
   * Emit property assignment - lifts SET_PROPERTY to JavaScript assignment
   */
  emitPropertyAssignment(obj, key, value) {
    let propName = key;
    if (key.startsWith('"') || key.startsWith("'")) {
      propName = key.slice(1, -1);
    }

    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName) && key !== propName) {
      this.emit(`${obj}.${propName} = ${value};`);
    } else {
      this.emit(`${obj}[${key}] = ${value};`);
    }
  }

  /**
   * Emit expression statement - for function calls and side effects
   */
  emitExpression(expr) {
    this.emit(`${expr};`);
  }

  /**
   * Emit if statement start - part of control flow lifting
   */
  emitIfStart(condition) {
    this.emit(`if (${condition}) {`);
    this.generator.indent++;
  }

  /**
   * Emit else clause
   */
  emitElse() {
    this.generator.indent--;
    this.emit('} else {');
    this.generator.indent++;
  }

  /**
   * Emit if/else end
   */
  emitIfEnd() {
    this.generator.indent--;
    this.emit('}');
  }

  /**
   * Emit while loop start - lifts detected loop patterns to while statements
   */
  emitWhileStart(condition) {
    this.emit(`while (${condition}) {`);
    this.generator.indent++;
  }

  /**
   * Emit while loop end
   */
  emitWhileEnd() {
    this.generator.indent--;
    this.emit('}');
  }

  /**
   * Emit return statement - lifts RETURN opcode to JavaScript return
   */
  emitReturn(value, hasValue) {
    if (hasValue) {
      return `return ${value};`;
    }
    return 'return;';
  }

  /**
   * Emit throw statement
   */
  emitThrow(err) {
    this.emit(`throw ${err};`);
  }

  /**
   * Emit debugger statement
   */
  emitDebugger() {
    this.emit('debugger;');
  }

  /**
   * Emit label for unstructured control flow
   */
  emitLabel(label) {
    this.emit(`${label}:`);
  }

  /**
   * Emit conditional jump (fallback for unstructured control flow)
   */
  emitConditionalJump(condition, label, isTrue) {
    if (isTrue) {
      this.emit(`if (${condition}) { /* goto ${label} */ }`);
    } else {
      this.emit(`if (!(${condition})) { /* goto ${label} */ }`);
    }
  }

  /**
   * Emit comment for error or unknown opcode
   */
  emitError(message) {
    this.emit(`/* ${message} */`);
  }

  /**
   * Build function body by recursively decompiling nested bytecode
   * This handles the lifting of BUILD_FUNCTION opcodes
   */
  buildFunctionBody(instr, strings, opcodeMap, currentIndent, varCounter) {
    if (instr.fnBody) {
      const subDisasm = new Disassembler(
        new Uint8Array([0, ...instr.fnBody]),
        strings,
        opcodeMap
      );
      const subInstructions = subDisasm.disassemble();

      const CodeGenerator = this.generator.constructor;
      const subGen = new CodeGenerator(subInstructions, strings, opcodeMap);
      subGen.varCounter = varCounter;
      subGen.indent = currentIndent + 1;
      const fnBody = subGen.generate();

      const fnLines = fnBody.split('\n').map(l => '  ' + l).join('\n');
      return {
        code: `function() {\n${fnLines}\n${'  '.repeat(currentIndent)}}`,
        newVarCounter: subGen.varCounter
      };
    }
    return { code: 'function() {}', newVarCounter: varCounter };
  }

  /**
   * Check if a call result should be emitted as a statement
   * Filters out trivial values that don't need explicit emission
   */
  shouldEmitCallResult(result) {
    if (!result) return false;
    if (result.match(/^(undefined|null|true|false|-?\d+(\.\d+)?)$/)) return false;
    return true;
  }

  /**
   * Get the set of operations that consume stack values
   * Used to determine when to emit pending call results
   */
  getConsumeOps() {
    return new Set([
      'ARITHMETIC_ADD', 'ARITHMETIC_SUB', 'ARITHMETIC_MUL', 'ARITHMETIC_DIV', 'ARITHMETIC_MOD',
      'COMPARISON_EQUAL', 'COMPARISON_STRICT_EQUAL', 'COMPARISON_NOT_EQUAL',
      'COMPARISON_STRICT_NOT_EQUAL', 'COMPARISON_LESS', 'COMPARISON_LESS_OR_EQUAL',
      'COMPARISON_GREATER', 'COMPARISON_GREATER_OR_EQUAL',
      'BINARY_BIT_AND', 'BINARY_BIT_OR', 'BINARY_BIT_XOR',
      'GET_PROPERTY', 'SET_PROPERTY', 'CALL_METHOD',
      'STORE_VARIABLE', 'ASSIGN_VARIABLE'
    ]);
  }

  /**
   * Get the set of call operations that produce results
   */
  getCallOps() {
    return new Set(['CALL_FUNCTION', 'CALL_METHOD', 'CONSTRUCT']);
  }
}
