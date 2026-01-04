/**
 * Control Flow Graph (CFG) Construction Module
 * =============================================
 *
 * This module implements CFG construction from disassembled NebulaVM bytecode.
 * The CFG is essential for semantic recovery during deobfuscation, enabling
 * reconstruction of high-level control structures (if/else, loops) from
 * low-level jump instructions.
 *
 * CFG Construction Process:
 * 1. Leader Instruction Identification - First instruction of each basic block
 * 2. Basic Block Partitioning - Grouping sequential instructions between control transfers
 * 3. Edge Construction - Connecting blocks based on control flow (jumps, fallthrough)
 * 4. Dominator Analysis - Computing dominance relationships for structure detection
 * 5. Region Detection - Identifying structured control flow patterns
 */

/**
 * BasicBlock represents a maximal straight-line sequence of instructions.
 * TLDR: basic block has exactly one entry point (the leader instruction)
 * and one exit point (the terminating control transfer or fallthrough).
 */
export class BasicBlock {
  constructor(id, startIdx) {
    this.id = id;
    this.startIdx = startIdx;
    this.endIdx = startIdx;
    this.instructions = [];
    this.successors = [];
    this.predecessors = [];
    this.isConditional = false;
    this.trueSuccessor = null;
    this.falseSuccessor = null;
  }

  addInstruction(instr, idx) {
    this.instructions.push(instr);
    this.endIdx = idx;
  }
}

/**
 * ControlFlowGraph implements CFG construction and analysis for VM bytecode.
 *
 * The CFG is built by identifying leader instructions (basic block entry points)
 * and partitioning the instruction stream into basic blocks. Control transfer
 * edges are then added based on jump targets and fallthrough paths.
 */
export class ControlFlowGraph {
  constructor(instructions) {
    this.instructions = instructions;
    this.blocks = new Map();
    this.entryBlock = null;
    this.exitBlocks = [];
    this.addrToIdx = new Map();
    this.idxToBlock = new Map();

    for (let i = 0; i < instructions.length; i++) {
      this.addrToIdx.set(instructions[i].addr, i);
    }
  }

  /**
   * Build the CFG from the instruction stream.
   *
   * Phase 1: Leader Identification
   * Leaders are instructions that begin basic blocks:
   * - First instruction (program entry point)
   * - Jump/branch targets (control transfer destinations)
   * - Instructions following jumps/returns (fallthrough after control transfer)
   *
   * Phase 2: Basic Block Partitioning
   * Group consecutive instructions between leaders into basic blocks.
   *
   * Phase 3: Edge Construction
   * Connect blocks based on control flow semantics of terminating instructions.
   */
  build() {
    if (this.instructions.length === 0) return;

    const leaders = new Set([0]);
    const jumpTargets = new Set();

    for (let i = 0; i < this.instructions.length; i++) {
      const instr = this.instructions[i];

      if (instr.opName === 'JUMP' || instr.opName === 'JUMP_IF_TRUE' || instr.opName === 'JUMP_IF_FALSE') {
        const targetAddr = instr.args[0]?.value;
        const targetIdx = this.addrToIdx.get(targetAddr);
        if (targetIdx !== undefined) {
          leaders.add(targetIdx);
          jumpTargets.add(targetIdx);
        }
        if (i + 1 < this.instructions.length) {
          leaders.add(i + 1);
        }
      }

      if (instr.opName === 'RETURN') {
        if (i + 1 < this.instructions.length) {
          leaders.add(i + 1);
        }
      }
    }

    const sortedLeaders = [...leaders].sort((a, b) => a - b);

    for (let i = 0; i < sortedLeaders.length; i++) {
      const startIdx = sortedLeaders[i];
      const endIdx = i + 1 < sortedLeaders.length ? sortedLeaders[i + 1] - 1 : this.instructions.length - 1;

      const block = new BasicBlock(i, startIdx);
      for (let j = startIdx; j <= endIdx; j++) {
        block.addInstruction(this.instructions[j], j);
      }

      this.blocks.set(i, block);
      for (let j = startIdx; j <= endIdx; j++) {
        this.idxToBlock.set(j, block);
      }
    }

    this.entryBlock = this.blocks.get(0);

    for (const [, block] of this.blocks) {
      const lastInstr = block.instructions[block.instructions.length - 1];
      const lastIdx = block.endIdx;

      if (lastInstr.opName === 'JUMP') {
        const targetAddr = lastInstr.args[0]?.value;
        const targetIdx = this.addrToIdx.get(targetAddr);
        if (targetIdx !== undefined) {
          const targetBlock = this.idxToBlock.get(targetIdx);
          if (targetBlock) {
            block.successors.push(targetBlock);
            targetBlock.predecessors.push(block);
          }
        }
      } else if (lastInstr.opName === 'JUMP_IF_TRUE' || lastInstr.opName === 'JUMP_IF_FALSE') {
        block.isConditional = true;

        const targetAddr = lastInstr.args[0]?.value;
        const targetIdx = this.addrToIdx.get(targetAddr);
        const fallthroughIdx = lastIdx + 1;

        if (targetIdx !== undefined) {
          const targetBlock = this.idxToBlock.get(targetIdx);
          if (targetBlock) {
            if (lastInstr.opName === 'JUMP_IF_TRUE') {
              block.trueSuccessor = targetBlock;
            } else {
              block.falseSuccessor = targetBlock;
            }
            block.successors.push(targetBlock);
            targetBlock.predecessors.push(block);
          }
        }

        if (fallthroughIdx < this.instructions.length) {
          const fallthroughBlock = this.idxToBlock.get(fallthroughIdx);
          if (fallthroughBlock) {
            if (lastInstr.opName === 'JUMP_IF_TRUE') {
              block.falseSuccessor = fallthroughBlock;
            } else {
              block.trueSuccessor = fallthroughBlock;
            }
            block.successors.push(fallthroughBlock);
            fallthroughBlock.predecessors.push(block);
          }
        }
      } else if (lastInstr.opName === 'RETURN') {
        this.exitBlocks.push(block);
      } else {
        const nextIdx = lastIdx + 1;
        if (nextIdx < this.instructions.length) {
          const nextBlock = this.idxToBlock.get(nextIdx);
          if (nextBlock) {
            block.successors.push(nextBlock);
            nextBlock.predecessors.push(block);
          }
        } else {
          this.exitBlocks.push(block);
        }
      }
    }

    return this;
  }

  /**
   * Compute dominator and post-dominator sets using iterative dataflow analysis.
   *
   * Dominator Analysis:
   * Block A dominates block B if every path from entry to B goes through A.
   * Uses forward dataflow: Dom(n) = {n} ∪ (∩ Dom(pred) for all predecessors)
   *
   * Post-Dominator Analysis:
   * Block A post-dominates block B if every path from B to exit goes through A.
   * Uses backward dataflow: PostDom(n) = {n} ∪ (∩ PostDom(succ) for all successors)
   *
   * The immediate dominator (idom) is the closest dominator - used to build
   * the dominator tree for structured control flow recovery.
   * The immediate post-dominator (ipdom) identifies merge points where
   * control flow paths converge after conditionals.
   */
  computeDominators() {
    const blockList = [...this.blocks.values()];
    const dominators = new Map();
    const postDominators = new Map();

    for (const block of blockList) {
      dominators.set(block.id, new Set(blockList.map(b => b.id)));
      postDominators.set(block.id, new Set(blockList.map(b => b.id)));
    }

    if (this.entryBlock) {
      dominators.set(this.entryBlock.id, new Set([this.entryBlock.id]));
    }

    let changed = true;
    while (changed) {
      changed = false;
      for (const block of blockList) {
        if (block === this.entryBlock) continue;

        const newDom = new Set(blockList.map(b => b.id));
        for (const pred of block.predecessors) {
          const predDom = dominators.get(pred.id);
          for (const id of [...newDom]) {
            if (!predDom.has(id)) {
              newDom.delete(id);
            }
          }
        }
        newDom.add(block.id);

        const oldDom = dominators.get(block.id);
        if (newDom.size !== oldDom.size || ![...newDom].every(id => oldDom.has(id))) {
          dominators.set(block.id, newDom);
          changed = true;
        }
      }
    }

    for (const block of this.exitBlocks) {
      postDominators.set(block.id, new Set([block.id]));
    }

    changed = true;
    while (changed) {
      changed = false;
      for (const block of [...blockList].reverse()) {
        if (this.exitBlocks.includes(block)) continue;

        const newPostDom = new Set(blockList.map(b => b.id));
        for (const succ of block.successors) {
          const succPostDom = postDominators.get(succ.id);
          for (const id of [...newPostDom]) {
            if (!succPostDom.has(id)) {
              newPostDom.delete(id);
            }
          }
        }
        newPostDom.add(block.id);

        const oldPostDom = postDominators.get(block.id);
        if (newPostDom.size !== oldPostDom.size || ![...newPostDom].every(id => oldPostDom.has(id))) {
          postDominators.set(block.id, newPostDom);
          changed = true;
        }
      }
    }

    this.dominators = dominators;
    this.postDominators = postDominators;

    this.immediateDominators = new Map();
    this.immediatePostDominators = new Map();

    for (const block of blockList) {
      const doms = [...dominators.get(block.id)].filter(id => id !== block.id);
      let idom = null;
      for (const domId of doms) {
        if (idom === null) {
          idom = domId;
        } else {
          const domIdDoms = dominators.get(domId);
          const idomDoms = dominators.get(idom);
          // The immediate dominator is the one closest to the node
          // - it dominates the node but is dominated by all other dominators
          // Choose the dominator with the LARGER dominator set (closer to node)
          if (domIdDoms && domIdDoms.has(idom)) {
            // domId dominates idom, so idom is closer - keep idom
          } else if (idomDoms && idomDoms.has(domId)) {
            // idom dominates domId, so domId is closer - switch to domId
            idom = domId;
          }
        }
      }
      this.immediateDominators.set(block.id, idom);

      const postDoms = [...postDominators.get(block.id)].filter(id => id !== block.id);
      let ipdom = null;
      for (const pdomId of postDoms) {
        if (ipdom === null) {
          ipdom = pdomId;
        } else {
          const pdomIdPostDoms = postDominators.get(pdomId);
          const ipdomPostDoms = postDominators.get(ipdom);
          // The immediate post-dominator is the one closest to the node
          // Choose the post-dominator with the LARGER post-dominator set (closer to node)
          if (pdomIdPostDoms && pdomIdPostDoms.has(ipdom)) {
            // pdomId post-dominates ipdom, so ipdom is closer - keep ipdom
          } else if (ipdomPostDoms && ipdomPostDoms.has(pdomId)) {
            // ipdom post-dominates pdomId, so pdomId is closer - switch to pdomId
            ipdom = pdomId;
          }
        }
      }
      this.immediatePostDominators.set(block.id, ipdom);
    }

    return this;
  }

  /**
   * Detect structured control flow regions (if-else, loops) from the CFG.
   *
   * Uses immediate post-dominators to identify merge points where control
   * flow paths reconverge. For an if-else structure:
   * - Condition block has two successors (true/false branches)
   * - Immediate post-dominator is the merge point (join node)
   * - Blocks between condition and merge form the if/else bodies
   *
   * This structural analysis enables reconstruction of high-level control
   * flow statements from the flat bytecode representation.
   */
  detectStructuredRegions() {
    this.regions = [];
    const processed = new Set();

    for (const [blockId, block] of this.blocks) {
      if (processed.has(blockId)) continue;

      if (block.isConditional && block.trueSuccessor && block.falseSuccessor) {
        const ipdom = this.immediatePostDominators.get(blockId);

        if (ipdom !== null && ipdom !== undefined) {
          const mergeBlock = this.blocks.get(ipdom);

          const trueBlocks = this.collectBlocksUntil(block.trueSuccessor, mergeBlock, processed);
          const falseBlocks = this.collectBlocksUntil(block.falseSuccessor, mergeBlock, processed);

          if (trueBlocks.length > 0 || falseBlocks.length > 0) {
            const region = {
              type: 'if-else',
              conditionBlock: block,
              trueBlocks: trueBlocks,
              falseBlocks: falseBlocks,
              mergeBlock: mergeBlock,
              startIdx: block.startIdx,
              endIdx: mergeBlock ? mergeBlock.startIdx : block.endIdx
            };

            this.regions.push(region);
            processed.add(blockId);
            for (const b of trueBlocks) processed.add(b.id);
            for (const b of falseBlocks) processed.add(b.id);
          }
        }
      }
    }

    return this;
  }

  /**
   * Collect all basic blocks reachable from startBlock until reaching endBlock.
   * Used to gather blocks belonging to a structured region (e.g., if-body, else-body).
   * BFS traversal ensures all blocks in the region are captured.
   */
  collectBlocksUntil(startBlock, endBlock, excludeSet) {
    if (!startBlock || startBlock === endBlock) return [];

    const result = [];
    const visited = new Set();
    const queue = [startBlock];

    while (queue.length > 0) {
      const block = queue.shift();
      if (visited.has(block.id) || block === endBlock || excludeSet.has(block.id)) continue;

      visited.add(block.id);
      result.push(block);

      for (const succ of block.successors) {
        if (!visited.has(succ.id) && succ !== endBlock) {
          queue.push(succ);
        }
      }
    }

    return result.sort((a, b) => a.startIdx - b.startIdx);
  }
}
