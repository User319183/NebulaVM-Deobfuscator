#!/usr/bin/env node

/**
 * NebulaVM Deobfuscator - CLI Entry Point
 * =========================================
 * 
 * This tool implements a complete deobfuscation pipeline for JavaScript code
 * protected by the NebulaVM obfuscator. The pipeline transforms virtualized
 * bytecode back into readable JavaScript source code.
 * 
 * Deobfuscation Pipeline Overview:
 * 
 * ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
 * │  Obfuscated JS  │───▶│   Extraction    │───▶│  Disassembly    │───▶│ Code Generation │
 * │    (Input)      │    │     Phase       │    │     Phase       │    │     Phase       │
 * └─────────────────┘    └─────────────────┘    └─────────────────┘    └─────────────────┘
 *                               │                      │                      │
 *                               ▼                      ▼                      ▼
 *                        - Bytecode blob        - Instruction      - CFG construction
 *                        - String table           decoding         - Stack simulation
 *                        - Opcode mapping       - Operand fetch    - AST reconstruction
 *                        - VM dispatcher        - Nested functions - Semantic recovery
 * 
 * Phase 1: Bytecode Extraction
 * - Parse obfuscated JavaScript to locate VM dispatcher
 * - Extract embedded bytecode array (compressed or raw)
 * - Recover string table for string literal resolution
 * - Decode shuffled opcode mapping table
 * 
 * Phase 2: Disassembly
 * - Decompress bytecode if zlib-compressed
 * - Decode instruction stream using opcode dispatch
 * - Extract operands for each instruction type
 * - Handle nested VM contexts (embedded functions)
 * 
 * Phase 3: Code Generation (Semantic Recovery)
 * - Build Control Flow Graph from instruction stream
 * - Simulate stack machine to recover expressions
 * - Reconstruct high-level control structures
 * - Emit JavaScript AST and generate source code
 */

import fs from 'fs';
import path from 'path';
import { program } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { extractFromCode } from './lib/extractor.js';
import { Disassembler } from './lib/disassembler.js';
import { CodeGenerator } from './lib/codeGenerator.js';

const VERSION = '1.0.0';

program
  .name('nebula-deob')
  .description('Deobfuscate JavaScript code obfuscated with NebulaVM')
  .version(VERSION)
  .argument('[input]', 'Input file path (obfuscated JavaScript)')
  .option('-o, --output <file>', 'Output file path (default: stdout)')
  .option('-v, --verbose', 'Enable verbose output with debug information')
  .option('--disasm', 'Output disassembled bytecode instead of JavaScript')
  .option('--dump-strings', 'Dump extracted strings table')
  .option('--dump-opcodes', 'Dump extracted opcode mapping')
  .action(async (inputPath, options) => {
    try {
      if (!inputPath) {
        console.log(chalk.cyan(`
╔═══════════════════════════════════════════════════════════╗
║         ${chalk.bold('NebulaVM Deobfuscator')} v${VERSION}                   ║
║                                                           ║
║  Deobfuscate JavaScript code obfuscated with NebulaVM   ║
╚═══════════════════════════════════════════════════════════╝
`));
        console.log(chalk.yellow('Usage:'));
        console.log('  nebula-deob <input-file> [options]\n');
        console.log(chalk.yellow('Examples:'));
        console.log('  nebula-deob obfuscated.js');
        console.log('  nebula-deob obfuscated.js -o clean.js');
        console.log('  nebula-deob obfuscated.js --verbose');
        console.log('  nebula-deob obfuscated.js --disasm\n');
        console.log(chalk.yellow('Options:'));
        console.log('  -o, --output <file>  Output to file instead of stdout');
        console.log('  -v, --verbose        Show debug information');
        console.log('  --disasm             Output disassembled bytecode');
        console.log('  --dump-strings       Show extracted strings');
        console.log('  --dump-opcodes       Show opcode mapping');
        console.log('  -h, --help           Show this help\n');
        return;
      }

      const resolvedPath = path.resolve(inputPath);
      
      if (!fs.existsSync(resolvedPath)) {
        console.error(chalk.red(`Error: File not found: ${resolvedPath}`));
        process.exit(1);
      }

      const spinner = ora({
        text: 'Reading obfuscated file...',
        color: 'cyan'
      }).start();

      const code = fs.readFileSync(resolvedPath, 'utf-8');
      
      if (options.verbose) {
        spinner.info(`Input file size: ${(code.length / 1024).toFixed(2)} KB`);
      }

      spinner.text = 'Extracting bytecode and strings...';
      
      let extracted;
      try {
        extracted = extractFromCode(code);
      } catch (e) {
        spinner.fail(chalk.red('Failed to extract bytecode'));
        console.error(chalk.red(`Error: ${e.message}`));
        process.exit(1);
      }

      const { bytecode, strings, opcodeMap, returnOpcode } = extracted;

      if (options.verbose) {
        spinner.info(`Bytecode size: ${bytecode.length} bytes`);
        spinner.info(`Strings count: ${strings.length}`);
        spinner.info(`Opcodes mapped: ${Object.keys(opcodeMap).length}`);
      }

      if (options.dumpStrings) {
        spinner.stop();
        console.log(chalk.cyan('\n=== Extracted Strings ===\n'));
        strings.forEach((str, i) => {
          console.log(chalk.gray(`[${i}]`) + ' ' + chalk.green(JSON.stringify(str)));
        });
        return;
      }

      if (options.dumpOpcodes) {
        spinner.stop();
        console.log(chalk.cyan('\n=== Opcode Mapping ===\n'));
        for (const [opcode, name] of Object.entries(opcodeMap)) {
          console.log(chalk.gray(`${opcode}:`) + ' ' + chalk.yellow(name));
        }
        return;
      }

      spinner.text = 'Disassembling bytecode...';

      const disassembler = new Disassembler(bytecode, strings, opcodeMap, returnOpcode);
      let instructions;
      
      try {
        instructions = disassembler.disassemble();
      } catch (e) {
        spinner.fail(chalk.red('Failed to disassemble bytecode'));
        console.error(chalk.red(`Error: ${e.message}`));
        process.exit(1);
      }

      if (options.verbose) {
        spinner.info(`Instructions decoded: ${instructions.length}`);
      }

      if (options.disasm) {
        spinner.succeed(chalk.green('Disassembly complete'));
        console.log(chalk.cyan('\n=== Disassembled Bytecode ===\n'));
        
        for (const instr of instructions) {
          let line = chalk.gray(`${String(instr.addr).padStart(6, '0')}:`) + ' ';
          line += chalk.yellow(instr.opName.padEnd(30));
          
          if (instr.args.length > 0) {
            const argStr = instr.args.map(a => {
              if (a.type === 'string_index') {
                return chalk.green(`"${strings[a.value] || ''}"`.substring(0, 40));
              }
              return chalk.cyan(String(a.value));
            }).join(', ');
            line += argStr;
          }
          
          if (instr.error) {
            line += chalk.red(` [ERROR: ${instr.error}]`);
          }
          
          console.log(line);
        }
        return;
      }

      spinner.text = 'Generating JavaScript code...';

      const generator = new CodeGenerator(instructions, strings, opcodeMap, returnOpcode);
      let output;
      
      try {
        output = generator.generate();
      } catch (e) {
        spinner.fail(chalk.red('Failed to generate JavaScript'));
        console.error(chalk.red(`Error: ${e.message}`));
        process.exit(1);
      }

      output = cleanupOutput(output);

      spinner.succeed(chalk.green('Deobfuscation complete'));

      if (options.output) {
        const outputPath = path.resolve(options.output);
        fs.writeFileSync(outputPath, output, 'utf-8');
        console.log(chalk.green(`\nOutput written to: ${outputPath}`));
        console.log(chalk.gray(`Output size: ${(output.length / 1024).toFixed(2)} KB`));
      } else {
        console.log(chalk.cyan('\n=== Deobfuscated JavaScript ===\n'));
        console.log(output);
      }

    } catch (e) {
      console.error(chalk.red(`\nUnexpected error: ${e.message}`));
      if (options.verbose) {
        console.error(e.stack);
      }
      process.exit(1);
    }
  });

function cleanupOutput(code) {
  if (!code || typeof code !== 'string') {
    return '// No code generated';
  }
  
  let lines = code.split('\n');
  
  lines = lines.filter(line => {
    const trimmed = line.trim();
    if (trimmed === 'undefined;' || trimmed === 'null;') return false;
    if (trimmed.match(/^-?\d+(\.\d+)?;$/)) return false;
    return true;
  });

  const seen = new Set();
  lines = lines.map(line => {
    if (line.trim().startsWith('var ')) {
      const match = line.match(/var\s+(\w+)\s*=/);
      if (match) {
        const varName = match[1];
        if (seen.has(varName)) {
          return line.replace(/^(\s*)var\s+/, '$1');
        }
        seen.add(varName);
      }
    }
    return line;
  });

  return lines.join('\n');
}

program.parse();
