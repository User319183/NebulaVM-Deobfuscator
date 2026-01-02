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
   * Analyze control flow to detect loops and conditionals
   * Returns structured information about control flow patterns
   */
  analyze() {
    const loops = this.detectLoops();
    const conditionals = this.detectConditionals(loops);
    
    return { loops, conditionals, addrToIdx: this.addrToIdx };
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
   * Detect conditional (if-else) patterns
   * Excludes jump instructions that are part of loops
   * 
   * If-else pattern:
   * - JUMP_IF_X to else_label
   * - [if body basic blocks]
   * - JUMP to end_label (if has else)
   * - else_label: [else body basic blocks]
   * - end_label: (merge point)
   */
  detectConditionals(loops) {
    const conditionals = [];
    
    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];
      
      if ((instr.opName === 'JUMP_IF_TRUE' || instr.opName === 'JUMP_IF_FALSE') && 
          !loops.some(l => l.condJumpIdx === i)) {
        const targetAddr = instr.args[0]?.value;
        const targetIdx = this.addrToIdx.get(targetAddr);
        
        if (targetIdx !== undefined && targetIdx > i) {
          let hasElse = false;
          let elseStartIdx = targetIdx;
          let endIdx = targetIdx;
          
          for (let j = i + 1; j < targetIdx; j++) {
            const bodyInstr = this.instructions[j];
            if (bodyInstr.opName === 'JUMP' && j === targetIdx - 1) {
              const endAddr = bodyInstr.args[0]?.value;
              const endTargetIdx = this.addrToIdx.get(endAddr);
              if (endTargetIdx !== undefined && endTargetIdx > targetIdx) {
                hasElse = true;
                endIdx = endTargetIdx;
                break;
              }
            }
          }
          
          conditionals.push({
            condIdx: i,
            ifBodyStart: i + 1,
            ifBodyEnd: hasElse ? targetIdx - 1 : targetIdx,
            elseStart: hasElse ? targetIdx : null,
            elseEnd: hasElse ? endIdx : null,
            endIdx: hasElse ? endIdx : targetIdx,
            hasElse: hasElse,
            isIfFalse: instr.opName === 'JUMP_IF_FALSE'
          });
        }
      }
    }
    
    return conditionals;
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
