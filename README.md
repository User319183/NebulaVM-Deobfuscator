# NebulaVM Deobfuscator

Reverses JavaScript obfuscation from [NebulaVM](https://github.com/x676w/nebula-vm).

## What it does

NebulaVM compiles JavaScript into custom bytecode that runs on an embedded VM interpreter. This tool takes that obfuscated output and reconstructs readable JavaScript.

Supports both V1 (pre-Jan 21, 2026) and V2 (Jan 21, 2026+) formats. Version is detected automatically.

## Installation

```bash
npm install
```

## Usage

```bash
node src/index.js obfuscated.js              # output to stdout
node src/index.js obfuscated.js -o clean.js  # save to file
node src/index.js obfuscated.js --verbose    # debug info
node src/index.js obfuscated.js --disasm     # show disassembled bytecode
node src/index.js obfuscated.js --dump-strings
node src/index.js obfuscated.js --dump-opcodes
```

## How it works

NebulaVM obfuscation:
1. Transpiles to ES5
2. Compiles to custom bytecode
3. Randomizes opcodes per build
4. XORs (0x80) and Base64 encodes the bytecode
5. Stores strings separately with XOR encoding
6. Bundles an interpreter that executes it all at runtime

Deobfuscation:
1. Parse the IIFE, extract the encoded bytecode and strings
2. Decode (Base64, XOR, decompress if needed)
3. Analyze the interpreter's switch handlers to figure out which opcode does what
4. Disassemble the bytecode into an IR
5. Rebuild JavaScript by emulating the stack symbolically

## Project structure

```
src/
├── index.js                    # CLI
├── runtime/
│   └── bytecodeReader.js       # decoding (Base64, XOR, LZ77/zlib)
├── analysis/
│   └── interpreterAnalyzer.js  # opcode fingerprinting
├── emission/
│   ├── stackMachine.js         # symbolic stack
│   ├── statementEmitter.js     # JS generation
│   └── controlFlowReconstructor.js
└── lib/
    ├── opcodes.js              # opcode definitions
    ├── extractor.js            # bytecode/string extraction
    ├── disassembler.js         # bytecode → IR
    ├── codeGenerator.js        # orchestrates code generation
    └── cfg.js                  # control flow graph, dominators
```

## Limitations

- Original variable names are gone; output uses `var_0`, `var_1`, etc.
- Comments don't survive
- Weird control flow sometimes falls back to labels/gotos
- Only tested against standard NebulaVM output

## V2 support

V2 broke the deobfuscator when it came out. We updated it to handle:
- LZ77 compression (V1 used zlib)
- Compression flag moved to end of bytecode
- New opcodes for try-catch and regex
- Different operand formats
- Changed loop compilation pattern

See [V2_SUPPORT.md](V2_SUPPORT.md) for details.

## Changelog

**2026-01-25**: V2 support. LZ77 decompression, new opcode fingerprints, fixed CFG post-dominator calculation, both V1 and V2 loop patterns now detected.

**2026-01-04**: Operand order randomization support (NebulaVM randomizes operand order in binary ops, not just opcodes). Ternary expression reconstruction. Cleaned up unused code.

## Disclaimer

For research and education. Don't use it to bypass protections illegally or redistribute code you don't own.

## License

MIT

## Contributing

Issues and PRs welcome.
