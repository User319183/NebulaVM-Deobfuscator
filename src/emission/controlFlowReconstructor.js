/**
 * Control Flow Reconstructor
 *
 * Recovers structured control flow from flat bytecode sequences.
 * This module analyzes instruction patterns to detect and reconstruct
 * high-level control flow structures (loops, conditionals).
 *
 * Key concepts:
 * - Basic block: A straight-line sequence of code with no branches except at the end
 * - Merge point: Where divergent control flow paths reconverge
 * - Loop detection: Identifying back edges and loop headers
 * - Conditional detection: Identifying if-else patterns from conditional jumps
 */

import { ControlFlowGraph } from '../lib/cfg.js';

export class ControlFlowReconstructor {
  constructor(instructions) {
    this.instructions = instructions;
    this.addrToIdx = new Map();

    for (let i = 0; i < instructions.length; i++) {
      this.addrToIdx.set(instructions[i].addr, i);
    }
  }

  /**
   * Analyze control flow to detect loops
   * Returns structured information about control flow patterns
   */
  analyze() {
    const loops = this.detectLoops();
    return { loops };
  }

  /**
   * Detect while loops by identifying backward jump patterns
   * 
   * V1 Pattern (post-test):
   * 1. Initial JUMP to condition (skips loop body on first iteration)
   * 2. Loop body (basic block sequence)
   * 3. Condition evaluation followed by conditional back-jump
   *
   * V2 Pattern (pre-test):
   * 1. Condition evaluation
   * 2. JUMP_IF_FALSE to exit (or JUMP_IF_TRUE to body)
   * 3. Loop body
   * 4. Unconditional JUMP back to condition
   */
  detectLoops() {
    const loops = [];
    const usedInstructions = new Set();

    // V1 Pattern: JUMP → body → condition → JUMP_IF_* (back)
    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];

      if (instr.opName === 'JUMP') {
        const targetAddr = instr.args[0]?.value;
        const targetIdx = this.addrToIdx.get(targetAddr);

        if (targetIdx !== undefined && targetIdx > i) {
          for (let j = targetIdx; j < this.instructions.length; j++) {
            const checkInstr = this.instructions[j];
            if (checkInstr.opName === 'JUMP_IF_TRUE' || checkInstr.opName === 'JUMP_IF_FALSE') {
              const backTarget = checkInstr.args[0]?.value;
              const backIdx = this.addrToIdx.get(backTarget);
              if (backIdx !== undefined && backIdx <= i + 1) {
                loops.push({
                  type: 'while',
                  pattern: 'v1',
                  initJumpIdx: i,
                  bodyStartIdx: i + 1,
                  condStartIdx: targetIdx,
                  condEndIdx: j,
                  condJumpIdx: j,
                  isTrue: checkInstr.opName === 'JUMP_IF_TRUE'
                });
                usedInstructions.add(i);
                usedInstructions.add(j);
                break;
              }
            }
            if (checkInstr.opName === 'JUMP') break;
          }
        }
      }
    }

    // V2 Pattern: condition → JUMP_IF_FALSE (exit) → body → JUMP (back to condition)
    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];
      if (usedInstructions.has(i)) continue;

      if (instr.opName === 'JUMP_IF_FALSE' || instr.opName === 'JUMP_IF_TRUE') {
        const exitAddr = instr.args[0]?.value;
        const exitIdx = this.addrToIdx.get(exitAddr);

        if (exitIdx !== undefined && exitIdx > i) {
          // Look for a JUMP back to condition within the body
          for (let j = i + 1; j < exitIdx; j++) {
            const bodyInstr = this.instructions[j];
            if (bodyInstr.opName === 'JUMP') {
              const backAddr = bodyInstr.args[0]?.value;
              const backIdx = this.addrToIdx.get(backAddr);

              // Must be the last instruction before exit and jump back before condition start
              if (backIdx !== undefined && backIdx <= i && j === exitIdx - 1) {
                // Find the condition start by looking backward from the conditional jump
                let condStartIdx = backIdx;
                // Validate this is a loop structure
                loops.push({
                  type: 'while',
                  pattern: 'v2',
                  condStartIdx: condStartIdx,
                  condEndIdx: i,
                  condJumpIdx: i,
                  bodyStartIdx: i + 1,
                  bodyEndIdx: j - 1,
                  backJumpIdx: j,
                  exitIdx: exitIdx,
                  isTrue: instr.opName === 'JUMP_IF_TRUE'
                });
                usedInstructions.add(i);
                usedInstructions.add(j);
                break;
              }
            }
          }
        }
      }
    }

    return loops;
  }

  /**
   * Build CFG and detect structured regions using dominator analysis
   * This provides more accurate control flow reconstruction by analyzing
   * the full control flow graph
   */
  buildCFGRegions() {
    const cfg = new ControlFlowGraph(this.instructions);
    cfg.build();
    cfg.computeDominators();
    cfg.detectStructuredRegions();
    return cfg;
  }

  /**
   * Build a map of structured regions indexed by condition instruction index
   * This allows quick lookup when processing instructions
   * @param {ControlFlowGraph} cfg - The control flow graph
   * @param {Array} loops - Optional array of detected loops to exclude from regions
   */
  buildRegionMap(cfg, loops = []) {
    const regionsByCondIdx = new Map();

    // Build set of loop-related instruction indices to exclude
    const loopCondJumps = new Set();
    for (const loop of loops) {
      if (loop.condJumpIdx !== undefined) {
        loopCondJumps.add(loop.condJumpIdx);
      }
    }

    for (const region of cfg.regions) {
      if (region.type === 'if-else' && region.conditionBlock) {
        const condBlock = region.conditionBlock;
        const condJumpIdx = condBlock.endIdx;

        if (loopCondJumps.has(condJumpIdx)) continue;

        regionsByCondIdx.set(condJumpIdx, region);
      }
    }

    return regionsByCondIdx;
  }

  /**
   * Detect ternary expression pattern (ConditionalExpression)
   *
   * Ternary pattern from NebulaVM ConditionalExpressionCompiler:
   * - [test expression]
   * - JUMP_IF_FALSE -> else_label
   * - [consequent expression - pushes 1 value]
   * - JUMP -> end_label
   * - else_label: [alternate expression - pushes 1 value]
   * - end_label:
   *
   * Key difference from if-else statement: both branches are pure expressions
   * that push exactly one value onto the stack.
   */
  detectTernaryExpressions(regionsByCondIdx) {
    const ternaries = new Map();

    for (const [condIdx, region] of regionsByCondIdx) {
      if (!region.falseBlocks || region.falseBlocks.length === 0) continue;

      const isTernary = this.isTernaryPattern(region);
      if (isTernary) {
        ternaries.set(condIdx, {
          ...region,
          isTernary: true,
          trueExprRange: isTernary.trueRange,
          falseExprRange: isTernary.falseRange
        });
      }
    }

    return ternaries;
  }

  /**
   * Check if a conditional region matches the ternary expression pattern
   * Returns range info if it's a ternary, null otherwise
   */
  isTernaryPattern(region) {
    if (!region.trueBlocks || !region.falseBlocks) return null;
    if (region.trueBlocks.length !== 1 || region.falseBlocks.length !== 1) return null;

    const trueBlock = region.trueBlocks[0];
    const falseBlock = region.falseBlocks[0];

    const trueInstrs = trueBlock.instructions.filter(i => i.opName !== 'JUMP');
    const falseInstrs = falseBlock.instructions.filter(i => i.opName !== 'JUMP');

    const isPureExpr = (instrs) => {
      if (instrs.length === 0) return false;

      const statementOps = new Set([
        'STORE_VARIABLE', 'SET_PROPERTY', 'UNARY_THROW', 'RETURN', 'DEBUGGER'
      ]);

      for (const instr of instrs) {
        if (statementOps.has(instr.opName)) return false;
      }

      return true;
    };

    if (isPureExpr(trueInstrs) && isPureExpr(falseInstrs)) {
      return {
        trueRange: { start: trueBlock.startIdx, end: trueBlock.endIdx },
        falseRange: { start: falseBlock.startIdx, end: falseBlock.endIdx }
      };
    }

    return null;
  }

  /**
   * Detect short-circuit logical operator patterns (&&, ||)
   *
   * Pattern from NebulaVM:
   * - [left operand expression]
   * - STACK_PUSH_DUPLICATE
   * - JUMP_IF_FALSE -> target (for &&) or JUMP_IF_TRUE -> target (for ||)
   * - STACK_POP
   * - [right operand expression]
   * - target: [continues with result on stack]
   *
   * Key characteristics:
   * - Uses DUPLICATE to preserve left operand before conditional jump
   * - No explicit "else" branch - just continues to target if short-circuited
   * - STACK_POP discards duplicate when continuing to right operand
   */
  detectLogicalOperators() {
    const logicals = new Map();

    // Statement-level ops that should not appear in a pure expression
    const statementOps = new Set([
      'STORE_VARIABLE', 'SET_PROPERTY', 'UNARY_THROW', 'RETURN', 'DEBUGGER',
      'JUMP', 'JUMP_IF_TRUE', 'JUMP_IF_FALSE', 'TRY_PUSH', 'TRY_POP'
    ]);

    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];

      if (instr.opName !== 'JUMP_IF_FALSE' && instr.opName !== 'JUMP_IF_TRUE') continue;

      const prevInstr = i > 0 ? this.instructions[i - 1] : null;
      if (!prevInstr || prevInstr.opName !== 'STACK_PUSH_DUPLICATE') continue;

      const nextInstr = i + 1 < this.instructions.length ? this.instructions[i + 1] : null;
      if (!nextInstr || nextInstr.opName !== 'STACK_POP') continue;

      const targetAddr = instr.args[0]?.value;
      const targetIdx = this.addrToIdx.get(targetAddr);

      if (targetIdx === undefined || targetIdx <= i + 1) continue;

      // Validate right operand is a pure expression sequence (no jumps/statements)
      let isPureExpression = true;
      for (let j = i + 2; j < targetIdx; j++) {
        const rightInstr = this.instructions[j];
        if (statementOps.has(rightInstr.opName)) {
          isPureExpression = false;
          break;
        }
      }

      if (!isPureExpression) continue;

      const operator = instr.opName === 'JUMP_IF_FALSE' ? '&&' : '||';

      logicals.set(i, {
        operator,
        duplicateIdx: i - 1,
        jumpIdx: i,
        popIdx: i + 1,
        rightStartIdx: i + 2,
        rightEndIdx: targetIdx - 1,
        targetIdx
      });
    }

    return logicals;
  }

  /**
   * Build maps for quick loop lookup by instruction index
   */
  buildLoopMaps(loops) {
    const loopsByInitJump = new Map();
    const loopsByCondJump = new Map();
    const loopsByCondStart = new Map();

    for (const loop of loops) {
      if (loop.pattern === 'v1' && loop.initJumpIdx !== undefined) {
        loopsByInitJump.set(loop.initJumpIdx, loop);
      }
      if (loop.pattern === 'v2' && loop.condStartIdx !== undefined) {
        loopsByCondStart.set(loop.condStartIdx, loop);
      }
      loopsByCondJump.set(loop.condJumpIdx, loop);
    }

    return { loopsByInitJump, loopsByCondJump, loopsByCondStart };
  }

  /**
   * Determine which jump targets need labels (unstructured jumps)
   * Structured control flow (loops, if-else, logicals) doesn't need labels
   */
  findUsedLabels(loops, regionsByCondIdx, logicals = null) {
    const usedLabels = new Set();
    const logicalJumps = logicals || new Map();

    // Build set of loop-related jump targets
    const loopJumpTargets = new Set();
    for (const loop of loops) {
      if (loop.condJumpIdx !== undefined) {
        const target = this.instructions[loop.condJumpIdx]?.args[0]?.value;
        if (target !== undefined) loopJumpTargets.add(target);
      }
      if (loop.initJumpIdx !== undefined) {
        const target = this.instructions[loop.initJumpIdx]?.args[0]?.value;
        if (target !== undefined) loopJumpTargets.add(target);
      }
      if (loop.backJumpIdx !== undefined) {
        const target = this.instructions[loop.backJumpIdx]?.args[0]?.value;
        if (target !== undefined) loopJumpTargets.add(target);
      }
      // Add the exit target for V2 loops
      if (loop.exitIdx !== undefined) {
        const exitAddr = this.instructions[loop.exitIdx]?.addr;
        if (exitAddr !== undefined) loopJumpTargets.add(exitAddr);
      }
    }

    for (const instr of this.instructions) {
      if (['JUMP', 'JUMP_IF_TRUE', 'JUMP_IF_FALSE'].includes(instr.opName)) {
        const targetAddr = instr.args[0]?.value;
        const instrIdx = this.instructions.indexOf(instr);

        if (targetAddr !== undefined &&
            !loopJumpTargets.has(targetAddr) &&
            !regionsByCondIdx.has(instrIdx) &&
            !logicalJumps.has(instrIdx)) {
          usedLabels.add(targetAddr);
        }
      }
    }

    return usedLabels;
  }
}
