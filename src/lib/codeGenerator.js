/**
 * Code Generator Facade
 *
 * Orchestrates the decompilation process by coordinating the stack machine,
 * statement emitter, and control flow reconstructor modules.
 *
 * The decompilation pipeline:
 * 1. Control flow reconstruction - Recovers high-level structures from bytecode
 * 2. Symbolic execution - Simulates the VM stack to track values
 * 3. Statement emission - Lifts IR to JavaScript source code
 */

import { StackMachine } from '../emission/stackMachine.js';
import { StatementEmitter } from '../emission/statementEmitter.js';
import { ControlFlowReconstructor } from '../emission/controlFlowReconstructor.js';

export class CodeGenerator {
  constructor(instructions, strings, opcodeMap, returnOpcode = null, swappedOpcodes = new Set()) {
    this.instructions = instructions;
    this.strings = strings;
    this.opcodeMap = opcodeMap;
    this.returnOpcode = returnOpcode;
    this.swappedOpcodes = swappedOpcodes;
    this.varCounter = 0;
    this.output = [];
    this.indent = 0;
    this.addressToLabel = new Map();
    this.usedLabels = new Set();
    this.pendingReturn = null;

    this.stackMachine = new StackMachine(strings, this.getVarName.bind(this));
    this.emitter = new StatementEmitter(this);
    this.cfReconstructor = new ControlFlowReconstructor(instructions);
    this.tryRegions = this.analyzeTryRegions();
  }

  analyzeTryRegions() {
    const regions = [];
    const tryStack = [];

    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];
      if (instr.opName === 'TRY_PUSH') {
        const catchAddr = instr.args[0]?.value;
        tryStack.push({
          tryStartIdx: i,
          catchAddr,
          catchAddrIdx: null,
          tryEndIdx: null,
          catchEndIdx: null
        });
      } else if (instr.opName === 'TRY_POP' && tryStack.length > 0) {
        const region = tryStack.pop(); // Pop the completed region
        region.tryEndIdx = i;
        // Find the JUMP that skips catch block (usually right after TRY_POP)
        const nextInstr = this.instructions[i + 1];
        if (nextInstr?.opName === 'JUMP') {
          region.afterTryCatchAddr = nextInstr.args[0]?.value;
        }
        regions.push(region); // Move to completed regions immediately
      }
    }

    // Find instruction indices for catch addresses
    for (const region of regions) {
      if (region.catchAddr != null) {
        for (let i = 0; i < this.instructions.length; i++) {
          if (this.instructions[i].addr === region.catchAddr) {
            region.catchAddrIdx = i;
            break;
          }
        }
        // Find catch block end (JUMP to afterTryCatch)
        if (region.catchAddrIdx != null && region.afterTryCatchAddr != null) {
          for (let i = region.catchAddrIdx; i < this.instructions.length; i++) {
            const instr = this.instructions[i];
            if (instr.opName === 'JUMP' && instr.args[0]?.value === region.afterTryCatchAddr) {
              region.catchEndIdx = i;
              break;
            }
          }
        }
      }
    }
    return regions;
  }

  getVarName(scopeId, varId) {
    if (scopeId === undefined || scopeId === null || scopeId > 1000) {
      scopeId = 0;
    }
    if (varId === undefined || varId === null || varId > 10000) {
      return `var_unknown_${this.varCounter++}`;
    }

    const key = `${scopeId}_${varId}`;
    if (!this.scopeVarNames) {
      this.scopeVarNames = new Map();
    }

    if (!this.scopeVarNames.has(key)) {
      this.scopeVarNames.set(key, `var_${this.varCounter++}`);
    }
    return this.scopeVarNames.get(key);
  }

  cleanStringValue(value) {
    if (typeof value !== 'string') return '';
    // Remove surrounding quotes if present
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      return value.slice(1, -1);
    }
    return value;
  }

  generateLabel(addr) {
    if (!this.addressToLabel.has(addr)) {
      this.addressToLabel.set(addr, `label_${addr}`);
    }
    return this.addressToLabel.get(addr);
  }

  addLine(line) {
    this.emitter.emit(line);
  }

  analyzeControlFlow() {
    return this.cfReconstructor.analyze();
  }

  generate() {
    const { loops } = this.analyzeControlFlow();

    const cfg = this.cfReconstructor.buildCFGRegions();
    const { loopsByInitJump, loopsByCondJump, loopsByCondStart } = this.cfReconstructor.buildLoopMaps(loops);
    const regionsByCondIdx = this.cfReconstructor.buildRegionMap(cfg, loops);
    const ternaries = this.cfReconstructor.detectTernaryExpressions(regionsByCondIdx);
    const logicals = this.cfReconstructor.detectLogicalOperators();

    this.usedLabels = this.cfReconstructor.findUsedLabels(loops, regionsByCondIdx, logicals);

    // Build maps for try-catch regions
    const catchBlockStarts = new Map();
    const catchBlockEnds = new Set();
    const skipJumpsAfterTry = new Set();
    for (const region of this.tryRegions) {
      if (region.catchAddrIdx != null) {
        catchBlockStarts.set(region.catchAddrIdx, region);
      }
      if (region.catchEndIdx != null) {
        catchBlockEnds.add(region.catchEndIdx);
      }
      // The JUMP after TRY_POP should be skipped
      if (region.tryEndIdx != null) {
        const jumpIdx = region.tryEndIdx + 1;
        if (this.instructions[jumpIdx]?.opName === 'JUMP') {
          skipJumpsAfterTry.add(jumpIdx);
        }
      }
    }

    const stack = [];
    let i = 0;

    const callOps = this.emitter.getCallOps();
    const consumeOps = this.emitter.getConsumeOps();

    while (i < this.instructions.length) {
      const instr = this.instructions[i];
      const nextInstr = this.instructions[i + 1];

      // Check if we're at catch block start
      if (catchBlockStarts.has(i)) {
        const region = catchBlockStarts.get(i);
        // End the try block properly and start catch
        this.indent--;
        this.emitter.emit('} catch (err) {');
        this.indent++;
        // The first instruction of catch block is STORE_VARIABLE for the error
        // Push 'err' onto the stack so STORE_VARIABLE uses it
        stack.push('err');
      }

      // Check if we should skip this JUMP (it's the try-to-catch skip)
      if (skipJumpsAfterTry.has(i)) {
        i++;
        continue;
      }

      // Check if we're at catch block end
      if (catchBlockEnds.has(i)) {
        // This is the final JUMP of catch block, emit closing brace
        this.indent--;
        this.emitter.emit('}');
        i++;
        continue;
      }

      if (loopsByInitJump.has(i)) {
        const loop = loopsByInitJump.get(i);

        const condStack = [];
        for (let c = loop.condStartIdx; c <= loop.condEndIdx; c++) {
          const condInstr = this.instructions[c];
          if (condInstr.opName !== 'JUMP_IF_TRUE' && condInstr.opName !== 'JUMP_IF_FALSE') {
            this.processInstruction(condInstr, condStack);
          }
        }
        const condition = condStack.pop() || 'true';

        this.emitter.emitWhileStart(condition);

        const loopStack = this.stackMachine.clone(stack);
        for (let b = loop.bodyStartIdx; b < loop.condStartIdx; b++) {
          const bodyInstr = this.instructions[b];
          const bodyNextInstr = this.instructions[b + 1];

          try {
            this.processInstruction(bodyInstr, loopStack);
          } catch (e) {
            this.emitter.emitError(`Error: ${e.message}`);
          }

          if (callOps.has(bodyInstr.opName) && loopStack.length > 0) {
            if (!bodyNextInstr || !consumeOps.has(bodyNextInstr.opName) || b + 1 >= loop.condStartIdx) {
              const callResult = loopStack.pop();
              if (this.emitter.shouldEmitCallResult(callResult)) {
                this.emitter.emitExpression(callResult);
              }
            }
          }
        }

        for (let s = 0; s < loopStack.length; s++) {
          const expr = loopStack[s];
          if (expr && !this.stackMachine.isTrivialValue(expr)) {
            this.emitter.emitExpression(expr);
          }
        }

        this.emitter.emitWhileEnd();

        i = loop.condJumpIdx + 1;
        continue;
      }

      if (loopsByCondJump.has(i)) {
        i++;
        continue;
      }

      // Handle V2 pattern loops (condition-first)
      if (loopsByCondStart.has(i)) {
        const loop = loopsByCondStart.get(i);

        // Evaluate condition
        const condStack = [];
        for (let c = loop.condStartIdx; c <= loop.condEndIdx; c++) {
          const condInstr = this.instructions[c];
          if (condInstr.opName !== 'JUMP_IF_TRUE' && condInstr.opName !== 'JUMP_IF_FALSE') {
            this.processInstruction(condInstr, condStack);
          }
        }
        let condition = condStack.pop() || 'true';
        // V2 uses JUMP_IF_FALSE to exit, so we need to keep condition as-is (it's already correct)
        if (!loop.isTrue) {
          // JUMP_IF_FALSE: loop while condition is true (condition exits when false)
          // condition is already correct
        } else {
          // JUMP_IF_TRUE: loop while condition is false (negate)
          condition = `!(${condition})`;
        }

        this.emitter.emitWhileStart(condition);

        const loopStack = this.stackMachine.clone(stack);
        for (let b = loop.bodyStartIdx; b <= loop.bodyEndIdx; b++) {
          const bodyInstr = this.instructions[b];
          const bodyNextInstr = this.instructions[b + 1];

          try {
            this.processInstruction(bodyInstr, loopStack);
          } catch (e) {
            this.emitter.emitError(`Error: ${e.message}`);
          }

          if (callOps.has(bodyInstr.opName) && loopStack.length > 0) {
            if (!bodyNextInstr || !consumeOps.has(bodyNextInstr.opName) || b + 1 > loop.bodyEndIdx) {
              const callResult = loopStack.pop();
              if (this.emitter.shouldEmitCallResult(callResult)) {
                this.emitter.emitExpression(callResult);
              }
            }
          }
        }

        for (let s = 0; s < loopStack.length; s++) {
          const expr = loopStack[s];
          if (expr && !this.stackMachine.isTrivialValue(expr)) {
            this.emitter.emitExpression(expr);
          }
        }

        this.emitter.emitWhileEnd();

        // Skip to exit point (after the loop)
        i = loop.exitIdx;
        continue;
      }

      // Handle short-circuit logical operators (&&, ||)
      if (logicals.has(i)) {
        const logical = logicals.get(i);
        // Stack has [left, left] due to DUPLICATE - pop one copy for the check
        stack.pop();
        const left = stack.pop() || 'true';

        // Clone current stack for right operand evaluation (preserves any prior context)
        const rightStack = this.stackMachine.clone(stack);
        for (let j = logical.rightStartIdx; j <= logical.rightEndIdx; j++) {
          this.processInstruction(this.instructions[j], rightStack, callOps, consumeOps, true);
        }
        const right = rightStack.pop() || 'undefined';

        // Build logical expression
        stack.push(`(${left} ${logical.operator} ${right})`);

        // Skip to target instruction
        i = logical.targetIdx;
        continue;
      }

      if (ternaries.has(i)) {
        const ternary = ternaries.get(i);
        const condition = stack.pop() || 'true';

        const trueStack = this.stackMachine.clone(stack);
        this.processBlockSequence(ternary.trueBlocks, trueStack, callOps, consumeOps, true, regionsByCondIdx, ternaries, logicals);
        const consequent = trueStack.pop() || 'undefined';

        const falseStack = this.stackMachine.clone(stack);
        this.processBlockSequence(ternary.falseBlocks, falseStack, callOps, consumeOps, true, regionsByCondIdx, ternaries, logicals);
        const alternate = falseStack.pop() || 'undefined';

        stack.push(`(${condition} ? ${consequent} : ${alternate})`);

        if (ternary.mergeBlock) {
          i = ternary.mergeBlock.startIdx;
        } else {
          i = ternary.endIdx;
        }
        continue;
      }

      if (regionsByCondIdx.has(i)) {
        const region = regionsByCondIdx.get(i);
        const condition = stack.pop() || 'true';

        const hasTrueBody = region.trueBlocks && region.trueBlocks.length > 0;
        const hasFalseBody = region.falseBlocks && region.falseBlocks.length > 0;

        if (hasTrueBody || hasFalseBody) {
          this.emitter.emitIfStart(condition);

          if (hasTrueBody) {
            const trueStack = this.stackMachine.clone(stack);
            this.processBlockSequence(region.trueBlocks, trueStack, callOps, consumeOps, false, regionsByCondIdx, ternaries, logicals);
            this.emitRemainingStack(trueStack, stack.length);
          }

          this.indent--;

          if (hasFalseBody) {
            this.emitter.emit('} else {');
            this.indent++;

            const falseStack = this.stackMachine.clone(stack);
            this.processBlockSequence(region.falseBlocks, falseStack, callOps, consumeOps, false, regionsByCondIdx, ternaries, logicals);
            this.emitRemainingStack(falseStack, stack.length);

            this.indent--;
          }

          this.emitter.emit('}');

          if (region.mergeBlock) {
            i = region.mergeBlock.startIdx;
          } else {
            i = region.endIdx;
          }
          continue;
        }
      }

      if (this.usedLabels.has(instr.addr)) {
        this.emitter.emitLabel(this.generateLabel(instr.addr));
      }

      try {
        this.processInstruction(instr, stack);
      } catch (e) {
        this.emitter.emitError(`Error processing ${instr.opName}: ${e.message}`);
      }

      if (callOps.has(instr.opName) && stack.length > 0) {
        // Emit call result if it won't be consumed by the next instruction
        // consumeOps are operations that use values from the stack
        if (!nextInstr || !consumeOps.has(nextInstr.opName)) {
          const callResult = stack.pop();
          if (this.emitter.shouldEmitCallResult(callResult)) {
            this.emitter.emitExpression(callResult);
          }
        }
      }

      i++;
    }

    while (stack.length > 0) {
      const expr = stack.pop();
      if (expr && !expr.startsWith('undefined') && !expr.startsWith('null')) {
        this.emitter.emitExpression(expr);
      }
    }

    if (this.pendingReturn !== null) {
      this.emitter.emit(this.pendingReturn);
    }

    return this.output.join('\n');
  }

  processBlockSequence(blocks, blockStack, callOps, consumeOps, isTernary = false, regionsByCondIdx = null, ternaries = null, logicals = null) {
    // Build set of instruction indices in this block sequence
    const blockInstrIndices = new Set();
    for (const block of blocks) {
      for (let i = block.startIdx; i <= block.endIdx; i++) {
        blockInstrIndices.add(i);
      }
    }

    // Process blocks in order
    let skipUntil = -1;
    for (const block of blocks) {
      for (let b = block.startIdx; b <= block.endIdx; b++) {
        if (b < skipUntil) continue;

        const blockInstr = this.instructions[b];
        if (!blockInstr) continue;
        if (blockInstr.opName === 'JUMP' && b === block.endIdx) continue;

        // Check for ternaries FIRST (more specific pattern than if-else)
        if (ternaries && ternaries.has(b)) {
          const ternary = ternaries.get(b);
          const condition = blockStack.pop() || 'true';

          const trueStack = this.stackMachine.clone(blockStack);
          this.processBlockSequence(ternary.trueBlocks, trueStack, callOps, consumeOps, true, regionsByCondIdx, ternaries, logicals);
          const consequent = trueStack.pop() || 'undefined';

          const falseStack = this.stackMachine.clone(blockStack);
          this.processBlockSequence(ternary.falseBlocks, falseStack, callOps, consumeOps, true, regionsByCondIdx, ternaries, logicals);
          const alternate = falseStack.pop() || 'undefined';

          blockStack.push(`(${condition} ? ${consequent} : ${alternate})`);

          if (ternary.mergeBlock) {
            skipUntil = ternary.mergeBlock.startIdx;
          } else {
            skipUntil = ternary.endIdx;
          }
          continue;
        }

        // Check for logical operators
        if (logicals && logicals.has(b)) {
          const logical = logicals.get(b);
          blockStack.pop();
          const left = blockStack.pop() || 'true';

          const rightStack = this.stackMachine.clone(blockStack);
          for (let j = logical.rightStartIdx; j <= logical.rightEndIdx; j++) {
            this.processInstruction(this.instructions[j], rightStack, callOps, consumeOps, true);
          }
          const right = rightStack.pop() || 'undefined';

          blockStack.push(`(${left} ${logical.operator} ${right})`);
          skipUntil = logical.targetIdx;
          continue;
        }

        // Check for nested if-else regions (after ternaries and logicals)
        if (regionsByCondIdx && regionsByCondIdx.has(b)) {
          const region = regionsByCondIdx.get(b);
          // Skip if this is actually a ternary (already handled above)
          if (ternaries && ternaries.has(b)) {
            continue;
          }

          const condition = blockStack.pop() || 'true';
          const hasTrueBody = region.trueBlocks && region.trueBlocks.length > 0;
          const hasFalseBody = region.falseBlocks && region.falseBlocks.length > 0;

          if (hasTrueBody || hasFalseBody) {
            this.emitter.emitIfStart(condition);

            if (hasTrueBody) {
              const trueStack = this.stackMachine.clone(blockStack);
              this.processBlockSequence(region.trueBlocks, trueStack, callOps, consumeOps, false, regionsByCondIdx, ternaries, logicals);
              this.emitRemainingStack(trueStack, blockStack.length);
            }

            this.indent--;

            if (hasFalseBody) {
              this.emitter.emit('} else {');
              this.indent++;

              const falseStack = this.stackMachine.clone(blockStack);
              this.processBlockSequence(region.falseBlocks, falseStack, callOps, consumeOps, false, regionsByCondIdx, ternaries, logicals);
              this.emitRemainingStack(falseStack, blockStack.length);

              this.indent--;
            }

            this.emitter.emit('}');

            if (region.mergeBlock) {
              skipUntil = region.mergeBlock.startIdx;
            } else {
              skipUntil = region.endIdx;
            }
            continue;
          }
        }

        try {
          this.processInstruction(blockInstr, blockStack);
        } catch (e) {
          this.emitter.emitError(`Error: ${e.message}`);
        }

        if (!isTernary && callOps.has(blockInstr.opName) && blockStack.length > 0) {
          const nextBlockInstr = this.instructions[b + 1];
          if (!nextBlockInstr || !consumeOps.has(nextBlockInstr.opName)) {
            const result = blockStack.pop();
            if (this.emitter.shouldEmitCallResult(result)) {
              this.emitter.emitExpression(result);
            }
          }
        }
      }
    }
  }

  emitRemainingStack(branchStack, parentStackLength) {
    while (branchStack.length > parentStackLength) {
      const expr = branchStack.pop();
      if (expr && !expr.match(/^(undefined|null|true|false|-?\d+(\.\d+)?|".*")$/)) {
        this.emitter.emitExpression(expr);
      }
    }
  }

  processInstruction(instr, stack) {
    const sm = this.stackMachine;
    const swapped = this.swappedOpcodes.has(instr.opcode);

    switch (instr.opName) {
      case 'STACK_PUSH_STRING':
        stack.push(sm.formatString(instr));
        break;

      case 'STACK_PUSH_DWORD':
      case 'STACK_PUSH_DOUBLE':
        stack.push(sm.formatNumber(instr));
        break;

      case 'STACK_PUSH_BOOLEAN':
        stack.push(sm.formatBoolean(instr));
        break;

      case 'STACK_PUSH_NULL':
        stack.push('null');
        break;

      case 'STACK_PUSH_UNDEFINED':
        stack.push('undefined');
        break;

      case 'STACK_PUSH_DUPLICATE':
        if (stack.length > 0) {
          stack.push(sm.peek(stack));
        }
        break;

      case 'STACK_POP':
        if (stack.length > 0) {
          const expr = stack.pop();
          if (!sm.isTrivialValue(expr)) {
            this.emitter.emitExpression(expr);
          }
        }
        break;

      case 'ARITHMETIC_ADD':
        sm.buildBinaryExpression(stack, '+', swapped);
        break;

      case 'ARITHMETIC_SUB':
        sm.buildBinaryExpression(stack, '-', swapped);
        break;

      case 'ARITHMETIC_MUL':
        sm.buildBinaryExpression(stack, '*', swapped);
        break;

      case 'ARITHMETIC_DIV':
        sm.buildBinaryExpression(stack, '/', swapped);
        break;

      case 'ARITHMETIC_MOD':
        sm.buildBinaryExpression(stack, '%', swapped);
        break;

      case 'COMPARISON_EQUAL':
        sm.buildBinaryExpression(stack, '==', swapped);
        break;

      case 'COMPARISON_STRICT_EQUAL':
        sm.buildBinaryExpression(stack, '===', swapped);
        break;

      case 'COMPARISON_NOT_EQUAL':
        sm.buildBinaryExpression(stack, '!=', swapped);
        break;

      case 'COMPARISON_STRICT_NOT_EQUAL':
        sm.buildBinaryExpression(stack, '!==', swapped);
        break;

      case 'COMPARISON_LESS':
        sm.buildBinaryExpression(stack, '<', swapped);
        break;

      case 'COMPARISON_LESS_OR_EQUAL':
        sm.buildBinaryExpression(stack, '<=', swapped);
        break;

      case 'COMPARISON_GREATER':
        sm.buildBinaryExpression(stack, '>', swapped);
        break;

      case 'COMPARISON_GREATER_OR_EQUAL':
        sm.buildBinaryExpression(stack, '>=', swapped);
        break;

      case 'BINARY_BIT_SHIFT_LEFT':
        sm.buildBinaryExpression(stack, '<<', swapped);
        break;

      case 'BINARY_BIT_SHIFT_RIGHT':
        sm.buildBinaryExpression(stack, '>>', swapped);
        break;

      case 'BINARY_UNSIGNED_BIT_SHIFT_RIGHT':
        sm.buildBinaryExpression(stack, '>>>', swapped);
        break;

      case 'BINARY_BIT_XOR':
        sm.buildBinaryExpression(stack, '^', swapped);
        break;

      case 'BINARY_BIT_AND':
        sm.buildBinaryExpression(stack, '&', swapped);
        break;

      case 'BINARY_BIT_OR':
        sm.buildBinaryExpression(stack, '|', swapped);
        break;

      case 'BINARY_IN':
        sm.buildBinaryExpression(stack, 'in', swapped, '""', '{}');
        break;

      case 'BINARY_INSTANCEOF':
        sm.buildBinaryExpression(stack, 'instanceof', swapped, 'null', 'Object');
        break;

      case 'UNARY_PLUS':
        sm.buildUnaryExpression(stack, '+');
        break;

      case 'UNARY_MINUS':
        sm.buildUnaryExpression(stack, '-');
        break;

      case 'UNARY_NOT':
        sm.buildUnaryExpression(stack, '!', 'false');
        break;

      case 'UNARY_BIT_NOT':
        sm.buildUnaryExpression(stack, '~');
        break;

      case 'UNARY_TYPEOF': {
        const arg = stack.pop() || 'undefined';
        stack.push(`(typeof ${arg})`);
        break;
      }

      case 'UNARY_VOID': {
        const arg = stack.pop() || 'undefined';
        stack.push(`(void ${arg})`);
        break;
      }

      case 'UNARY_THROW': {
        const err = stack.pop() || 'new Error()';
        this.emitter.emitThrow(err);
        break;
      }

      case 'UPDATE_PLUS':
        sm.buildUpdateExpression(stack, instr, true);
        break;

      case 'UPDATE_MINUS':
        sm.buildUpdateExpression(stack, instr, false);
        break;

      case 'PROP_UPDATE_PLUS':
      case 'PROP_UPDATE_MINUS':
        sm.buildPropUpdateExpression(stack, instr, instr.opName === 'PROP_UPDATE_PLUS');
        break;

      case 'COMPLEX_PROP_UPDATE_PLUS':
      case 'COMPLEX_PROP_UPDATE_MINUS':
        sm.buildComplexPropUpdateExpression(stack, instr, instr.opName === 'COMPLEX_PROP_UPDATE_PLUS');
        break;

      case 'LOAD_VARIABLE': {
        const scopeId = instr.args[0]?.value;
        const dest = instr.args[1]?.value;
        stack.push(this.getVarName(scopeId, dest));
        break;
      }

      case 'STORE_VARIABLE': {
        const value = stack.pop() || 'undefined';
        const scopeId = instr.args[0]?.value;
        const dest = instr.args[1]?.value;
        const varName = this.getVarName(scopeId, dest);
        this.emitter.emitVariableDeclaration(varName, value);
        break;
      }

      case 'ASSIGN_VARIABLE':
        sm.buildAssignmentExpression(stack, instr, this.getVarName.bind(this));
        break;

      case 'LOAD_GLOBAL':
        stack.push('globalThis');
        break;

      case 'LOAD_GLOBAL_PROP':
        sm.buildGlobalPropAccess(stack);
        break;

      case 'LOAD_THIS':
        stack.push('this');
        break;

      case 'LOAD_ARGUMENT': {
        const idx = instr.args[0]?.value ?? 0;
        stack.push(`arguments[${idx}]`);
        break;
      }

      case 'LOAD_ARGUMENTS':
        stack.push('arguments');
        break;

      case 'CALL_FUNCTION': {
        const argc = instr.args[0]?.value ?? 0;
        sm.buildFunctionCall(stack, argc);
        break;
      }

      case 'CALL_METHOD': {
        const argc = instr.args[0]?.value ?? 0;
        sm.buildMethodCall(stack, argc);
        break;
      }

      case 'CONSTRUCT': {
        const argc = instr.args[0]?.value ?? 0;
        sm.buildConstruct(stack, argc);
        break;
      }

      case 'GET_PROPERTY':
        sm.buildPropertyAccess(stack);
        break;

      case 'SET_PROPERTY': {
        const value = stack.pop() || 'undefined';
        const key = stack.pop() || 'prop';
        const obj = stack.pop() || 'obj';
        this.emitter.emitPropertyAssignment(obj, key, value);
        stack.push(obj);
        break;
      }

      case 'BUILD_ARRAY': {
        const length = instr.args[0]?.value ?? 0;
        sm.buildArray(stack, length);
        break;
      }

      case 'BUILD_OBJECT': {
        const length = instr.args[0]?.value ?? 0;
        sm.buildObject(stack, length);
        break;
      }

      case 'BUILD_FUNCTION': {
        const result = this.emitter.buildFunctionBody(
          instr, this.strings, this.opcodeMap, this.indent, this.varCounter
        );
        stack.push(result.code);
        this.varCounter = result.newVarCounter;
        break;
      }

      case 'JUMP': {
        const addr = instr.args[0]?.value;
        this.generateLabel(addr);
        break;
      }

      case 'JUMP_IF_TRUE': {
        const addr = instr.args[0]?.value;
        const cond = stack.pop() || 'true';
        const label = this.generateLabel(addr);
        this.emitter.emitConditionalJump(cond, label, true);
        break;
      }

      case 'JUMP_IF_FALSE': {
        const addr = instr.args[0]?.value;
        const cond = stack.pop() || 'false';
        const label = this.generateLabel(addr);
        this.emitter.emitConditionalJump(cond, label, false);
        break;
      }

      case 'RETURN': {
        const hasValue = instr.args[0]?.value;
        const value = hasValue ? (stack.pop() || 'undefined') : undefined;
        this.pendingReturn = this.emitter.emitReturn(value, hasValue);
        break;
      }

      case 'DEBUGGER':
        this.emitter.emitDebugger();
        break;

      case 'BUILD_REGEXP': {
        // V2: pattern and flags come from stack
        // V1: pattern and flags come from instruction properties
        let pattern, flags;
        if (instr.args[0]?.type === 'has_flags') {
          // V2 format: pop from stack
          const hasFlags = instr.args[0].value;
          flags = hasFlags ? this.cleanStringValue(stack.pop()) : '';
          pattern = this.cleanStringValue(stack.pop());
        } else {
          // V1 format: from instruction properties
          pattern = instr.patternValue || '';
          flags = instr.flagsValue || '';
        }
        // Escape forward slashes in pattern
        pattern = pattern.replace(/\//g, '\\/');
        stack.push(`/${pattern}/${flags}`);
        break;
      }

      case 'TRY_PUSH': {
        const catchAddr = instr.args[0]?.value;
        const finallyAddr = instr.args[1]?.value;
        this.emitter.emitTryStart();
        break;
      }

      case 'TRY_POP':
        break;

      case 'TRY_CATCH': {
        const scopeId = instr.args[0]?.value;
        const varSlot = instr.args[1]?.value;
        const errVarName = this.getVarName(scopeId, varSlot);
        this.emitter.emitCatchStart(errVarName);
        break;
      }

      case 'TRY_FINALLY':
        this.emitter.emitFinallyStart();
        break;

      case 'SEQUENCE_POP':
        break;

      default:
        if (instr.opName.startsWith('UNKNOWN_') || instr.opName.startsWith('OP_')) {
          this.emitter.emitError(`Unknown opcode: ${instr.opName}`);
        }
        break;
    }
  }
}
