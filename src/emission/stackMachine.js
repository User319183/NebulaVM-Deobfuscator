/**
 * Stack Machine Emulator
 *
 * Emulates the VM's operand stack during symbolic execution.
 * This module handles stack operations and expression building
 * for the decompilation process.
 *
 * Key concepts:
 * - Symbolic execution: Tracking symbolic values through stack operations
 * - Operand stack: The VM's evaluation stack that holds intermediate values
 */

export class StackMachine {
  constructor(strings, getVarNameFn) {
    this.strings = strings;
    this.getVarName = getVarNameFn;
  }

  /**
   * Stack Operations - Core stack manipulation during symbolic execution
   */
  peek(stack) {
    return stack.length > 0 ? stack[stack.length - 1] : undefined;
  }

  clone(stack) {
    return [...stack];
  }

  /**
   * Operand Formatting - Converts raw values to JavaScript string representations
   */
  formatString(instr) {
    return JSON.stringify(instr.stringValue || this.strings[instr.args[0]?.value] || '');
  }

  formatNumber(instr) {
    return String(instr.args[0]?.value ?? 0);
  }

  formatBoolean(instr) {
    return instr.args[0]?.value ? 'true' : 'false';
  }

  /**
   * Expression Building - Constructs JavaScript expressions from stack operands
   * These operations lift low-level VM operations to high-level expressions
   *
   * Normal handlers do: push(pop() OP pop()) = first_pop OP second_pop
   * Swapped handlers do: n = pop(); push(pop() OP n) = second_pop OP first_pop
   *
   * We pop in same order (first=top, second=next), but emit differently:
   * - Normal: second OP first (because normal handler uses first_pop OP second_pop)
   * - Swapped: first OP second (because swapped handler uses second_pop OP first_pop,
   *   but we want the same semantic output as normal)
   *
   * Actually, the semantic meaning is preserved when we emit the same expression
   * that matches what the handler computes. So:
   * - Normal: handler computes first_pop OP second_pop, emit (first OP second)
   * - Swapped: handler computes second_pop OP first_pop, emit (second OP first)
   */
  buildBinaryExpression(stack, operator, swapped = false, leftDefault = '0', rightDefault = '0') {
    const first = stack.pop() || leftDefault;   // first pop = top of stack
    const second = stack.pop() || rightDefault; // second pop = next on stack

    if (swapped) {
      stack.push(`(${second} ${operator} ${first})`);
    } else {
      stack.push(`(${first} ${operator} ${second})`);
    }
  }

  buildUnaryExpression(stack, operator, defaultVal = '0') {
    const arg = stack.pop() || defaultVal;
    stack.push(`(${operator}${arg})`);
  }

  buildPropertyAccess(stack) {
    const key = stack.pop() || 'prop';
    const obj = stack.pop() || 'obj';

    let propName = key;
    if (key.startsWith('"') || key.startsWith("'")) {
      propName = key.slice(1, -1);
    }

    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName) && key !== propName) {
      stack.push(`${obj}.${propName}`);
    } else {
      stack.push(`${obj}[${key}]`);
    }
  }

  buildMethodCall(stack, argc) {
    const key = stack.pop() || 'method';
    const obj = stack.pop() || 'obj';
    const args = [];
    for (let j = 0; j < argc; j++) {
      args.push(stack.pop() || 'undefined');
    }

    let methodName = key;
    if (key.startsWith('"') || key.startsWith("'")) {
      methodName = key.slice(1, -1);
    }

    if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(methodName)) {
      stack.push(`${obj}.${methodName}(${args.join(', ')})`);
    } else {
      stack.push(`${obj}[${key}](${args.join(', ')})`);
    }
  }

  buildFunctionCall(stack, argc) {
    const fn = stack.pop() || 'fn';
    const args = [];
    for (let j = 0; j < argc; j++) {
      args.push(stack.pop() || 'undefined');
    }
    stack.push(`${fn}(${args.join(', ')})`);
  }

  buildConstruct(stack, argc) {
    const cls = stack.pop() || 'Object';
    const args = [];
    for (let j = 0; j < argc; j++) {
      args.push(stack.pop() || 'undefined');
    }
    stack.push(`new ${cls}(${args.join(', ')})`);
  }

  buildArray(stack, length) {
    const elements = [];
    for (let j = 0; j < length; j++) {
      elements.push(stack.pop() || 'undefined');
    }
    stack.push(`[${elements.join(', ')}]`);
  }

  buildObject(stack, length) {
    const props = [];
    for (let j = 0; j < length; j++) {
      const value = stack.pop() || 'undefined';
      const key = stack.pop() || '"key"';

      let keyStr = key;
      if (key.startsWith('"') || key.startsWith("'")) {
        keyStr = key.slice(1, -1);
      }

      if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(keyStr)) {
        props.push(`${keyStr}: ${value}`);
      } else {
        props.push(`[${key}]: ${value}`);
      }
    }
    stack.push(`{ ${props.join(', ')} }`);
  }

  buildGlobalPropAccess(stack) {
    const name = stack.pop() || 'undefined';
    if (name.startsWith('"') || name.startsWith("'")) {
      const propName = name.slice(1, -1);
      if (/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(propName)) {
        stack.push(propName);
      } else {
        stack.push(`globalThis[${name}]`);
      }
    } else {
      stack.push(`globalThis[${name}]`);
    }
  }

  buildUpdateExpression(stack, instr, isPlus) {
    const isPrefix = instr.args[0]?.value;
    const scopeId = instr.args[1]?.value;
    const dest = instr.args[2]?.value;
    const varName = this.getVarName(scopeId, dest);
    const op = isPlus ? '++' : '--';
    stack.push(isPrefix ? `(${op}${varName})` : `(${varName}${op})`);
  }

  buildPropUpdateExpression(stack, instr, isPlus) {
    const prop = stack.pop() || 'prop';
    const isPrefix = instr.args[0]?.value;
    const scopeId = instr.args[1]?.value;
    const dest = instr.args[2]?.value;
    const varName = this.getVarName(scopeId, dest);
    const op = isPlus ? '++' : '--';
    stack.push(isPrefix ? `(${op}${varName}[${prop}])` : `(${varName}[${prop}]${op})`);
  }

  buildComplexPropUpdateExpression(stack, instr, isPlus) {
    const prop = stack.pop() || 'prop';
    const obj = stack.pop() || 'obj';
    const isPrefix = instr.args[0]?.value;
    const op = isPlus ? '++' : '--';
    stack.push(isPrefix ? `(${op}${obj}[${prop}])` : `(${obj}[${prop}]${op})`);
  }

  buildAssignmentExpression(stack, instr, getVarName) {
    const value = stack.pop() || 'undefined';
    const isOperation = instr.args[0]?.value;
    const scopeId = instr.args[1]?.value;
    const dest = instr.args[2]?.value;
    const varName = getVarName(scopeId, dest);

    if (isOperation && instr.args[3]) {
      const assignOp = instr.args[3].value;
      const opMap = {
        'ADD_ASSIGN_VARIABLE': '+=',
        'SUB_ASSIGN_VARIABLE': '-=',
        'MUL_ASSIGN_VARIABLE': '*=',
        'DIV_ASSIGN_VARIABLE': '/=',
        'MOD_ASSIGN_VARIABLE': '%=',
        'BIT_SHIFT_LEFT_ASSIGN_VARIABLE': '<<=',
        'BIT_SHIFT_RIGHT_ASSIGN_VAIRABLE': '>>=',
        'UNSIGNED_BIT_SHIFT_RIGHT_ASSIGN_VARIABLE': '>>>=',
        'BIT_XOR_ASSIGN_VARIABLE': '^=',
        'BIT_AND_ASSIGN_VARIABLE': '&=',
        'BIT_OR_ASSIGN_VARIABLE': '|=',
      };
      const op = opMap[assignOp] || '=';
      stack.push(`(${varName} ${op} ${value})`);
    } else {
      stack.push(`(${varName} = ${value})`);
    }
  }

  /**
   * Check if an expression represents a trivial value (constant/literal)
   * Used to filter out unnecessary emissions during lifting
   */
  isTrivialValue(expr) {
    if (!expr) return true;
    if (['undefined', 'null', 'true', 'false'].includes(expr)) return true;
    if (/^-?\d+(\.\d+)?$/.test(expr)) return true;
    return false;
  }
}
