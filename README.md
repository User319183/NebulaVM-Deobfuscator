# NebulaVM Deobfuscator

A command-line tool that reverses JavaScript obfuscation performed by the [NebulaVM](https://github.com/x676w/nebula-vm) obfuscator.

## Overview

NebulaVM is a JavaScript obfuscator that converts code into custom bytecode executed by an embedded virtual machine interpreter. This tool analyzes obfuscated output and reconstructs readable JavaScript.

## Features

- **Automatic Opcode Detection** - Fingerprints shuffled opcodes through AST analysis
- **Bytecode Disassembly** - Converts VM bytecode to intermediate representation
- **Code Reconstruction** - Generates clean JavaScript from disassembled instructions
- **Control Flow Recovery** - Reconstructs loops and conditionals using CFG analysis
- **Compression Support** - Handles both compressed and uncompressed bytecode

## Installation

```bash
npm install
```

## Usage

```bash
# Basic deobfuscation (output to stdout)
node src/index.js obfuscated.js

# Save output to file
node src/index.js obfuscated.js -o clean.js

# Verbose mode with debug info
node src/index.js obfuscated.js --verbose

# Show disassembled bytecode
node src/index.js obfuscated.js --disasm

# Dump extracted strings
node src/index.js obfuscated.js --dump-strings

# Dump detected opcode mapping
node src/index.js obfuscated.js --dump-opcodes
```

## How It Works

### NebulaVM Obfuscation

1. JavaScript is transpiled to ES5
2. Code is compiled into custom bytecode
3. Opcodes are randomized per obfuscation
4. Bytecode is XOR'd (0x80) and Base64 encoded
5. Strings are stored separately with XOR encoding
6. An interpreter executes the bytecode at runtime

### Deobfuscation Process

1. **Extraction** - Parse the IIFE to extract encoded bytecode and strings
2. **Decode** - Base64 decode, XOR, and optionally decompress
3. **Map Opcodes** - Fingerprint interpreter handlers to identify opcodes
4. **Disassemble** - Convert bytecode stream to instruction IR
5. **Generate** - Rebuild JavaScript using symbolic stack execution

## Project Structure

```
src/
├── index.js                 # CLI entry point
├── runtime/
│   └── bytecodeReader.js    # Bytecode decoding utilities
├── analysis/
│   └── interpreterAnalyzer.js # VM dispatcher analysis
├── emission/
│   ├── stackMachine.js      # Symbolic stack emulation
│   ├── statementEmitter.js  # JavaScript generation
│   └── controlFlowReconstructor.js # Loop/conditional recovery
└── lib/
    ├── opcodes.js           # NebulaVM ISA definitions
    ├── extractor.js         # Extraction facade
    ├── disassembler.js      # Bytecode to IR
    ├── codeGenerator.js     # Code generation orchestrator
    └── cfg.js               # Control flow graph analysis
```

## Limitations

- Variable names cannot be recovered (uses generated names like `var_0`)
- Comments and original formatting are lost
- Complex nested control flow may use label-based fallback
- Works best with standard NebulaVM output

## Disclaimer

This tool is provided for **educational and security research purposes only**. 

- Do not use this tool to circumvent software protections in violation of applicable laws
- Do not redistribute deobfuscated code that you do not have rights to
- Users are responsible for ensuring their use complies with all applicable laws and terms of service

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
