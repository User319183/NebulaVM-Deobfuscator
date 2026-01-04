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
   * A while loop pattern consists of:
   * 1. Initial JUMP to condition (skips loop body on first iteration)
   * 2. Loop body (basic block sequence)
   * 3. Condition evaluation followed by conditional back-jump
   */
  detectLoops() {
    const loops = [];

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
                  initJumpIdx: i,
                  bodyStartIdx: i + 1,
                  condStartIdx: targetIdx,
                  condEndIdx: j,
                  condJumpIdx: j,
                  isTrue: checkInstr.opName === 'JUMP_IF_TRUE'
                });
                break;
              }
            }
            if (checkInstr.opName === 'JUMP') break;
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
   */
  buildRegionMap(cfg) {
    const regionsByCondIdx = new Map();

    for (const region of cfg.regions) {
      if (region.type === 'if-else' && region.conditionBlock) {
        const condBlock = region.conditionBlock;
        const condJumpIdx = condBlock.endIdx;
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
   * Build maps for quick loop lookup by instruction index
   */
  buildLoopMaps(loops) {
    const loopsByInitJump = new Map();
    const loopsByCondJump = new Map();

    for (const loop of loops) {
      loopsByInitJump.set(loop.initJumpIdx, loop);
      loopsByCondJump.set(loop.condJumpIdx, loop);
    }

    return { loopsByInitJump, loopsByCondJump };
  }

  /**
   * Determine which jump targets need labels (unstructured jumps)
   * Structured control flow (loops, if-else) doesn't need labels
   */
  findUsedLabels(loops, regionsByCondIdx) {
    const usedLabels = new Set();

    for (const instr of this.instructions) {
      if (['JUMP', 'JUMP_IF_TRUE', 'JUMP_IF_FALSE'].includes(instr.opName)) {
        const targetAddr = instr.args[0]?.value;
        const instrIdx = this.instructions.indexOf(instr);

        if (targetAddr !== undefined &&
            !loops.some(l =>
              this.instructions[l.condJumpIdx]?.args[0]?.value === targetAddr ||
              this.instructions[l.initJumpIdx]?.args[0]?.value === targetAddr
            ) &&
            !regionsByCondIdx.has(instrIdx)) {
          usedLabels.add(targetAddr);
        }
      }
    }

    return usedLabels;
  }
}
