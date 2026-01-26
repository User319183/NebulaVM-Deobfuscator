# V2 Support

## Did V2 break this deobfuscator?

Yes, initially. The January 2026 update broke several parts of the deobfuscator:

- Bytecode decoding failed (different compression algorithm and flag position)
- New opcodes weren't recognized (no fingerprints for try-catch, regex, etc.)
- Operand parsing read wrong values (format changes for BUILD_REGEXP, TRY_PUSH)
- Loop reconstruction broke (V2 uses a different compilation pattern)
- Control flow analysis produced incorrect output

We had to update the deobfuscator to handle all of these. It works now, but only because we added V2-specific support. If the author makes more changes, it'll likely break again until updated.

## What changed in V2

**Compression**: Switched from zlib to a custom LZ77 implementation. The compression flag also moved from the start of the bytecode to the end. Both are handled.

**New opcodes**: V2 added try-catch support (`TRY_PUSH`, `TRY_POP`, `TRY_CATCH`, `TRY_FINALLY`), regex construction (`BUILD_REGEXP`), and a sequence pop for comma expressions. All fingerprinted and working.

**Operand formats**: Some instructions read operands differently now. `BUILD_REGEXP` in V1 read two dwords from bytecode; V2 reads one byte and pops the rest from stack. The disassembler checks the version and handles both.

**Loop compilation**: V1 compiled while loops with a post-test pattern (jump to bottom, evaluate condition, jump back). V2 uses pre-test (evaluate first, jump-if-false to exit, body, jump back to top). The CFG analyzer recognizes both.

**Opcode shuffling**: Still randomizes opcode numbers per obfuscation, same as V1. The fingerprinter identifies handlers by their AST structure, not their assigned number, so this doesn't matter.

## Why it still works

The VM architecture didn't change. It's still a stack machine with a switch-based dispatcher, readable property names, predictable instruction lengths, and XOR'd strings. Those are the things this deobfuscator exploits.

Changing the compression algorithm or adding new opcodes doesn't help when the new opcodes have the same recognizable patterns as the old ones.

## How to actually break it

If you want to make static deobfuscation harder, you need to attack what the tool relies on. Here's what actually matters:

**Make handlers unrecognizable.** The fingerprinter looks at each handler's AST and matches patterns - "this one pushes twice and accesses the string table, so it's STACK_PUSH_STRING." Break that by:
- Having multiple handler implementations per opcode (polymorphism)
- Merging several opcodes into one handler that branches on a sub-opcode from bytecode
- Accessing properties through computed names (`vm[x]` instead of `vm.stack`)
- Routing operations through an indirection table instead of inline code

**Make disassembly require emulation.** The disassembler reads instructions linearly because it knows each instruction's length. Break that with:
- Encrypted operands that depend on previous execution state
- Variable-length instruction encoding
- Operands that decode differently based on runtime values

**Make control flow unanalyzable.** Jump targets are currently immediate values in bytecode. Use computed jumps instead - `pc = decrypt(operand) ^ lastResult`. Or switch to threaded code where each handler directly calls the next instead of returning to a dispatcher.

## What won't help

- **Hiding the bytecode**: An attacker can trace execution or use dynamic analysis to find it. Extraction is trivial once you have the code running.
- **Dead code**: Parsers strip it automatically
- **String encryption**: The XOR is already reversed; a different scheme just means updating one function
- **Anti-debugging**: Doesn't affect static analysis
- **More opcode shuffling**: Already defeated by fingerprinting
- **Control flow flattening on the output**: The VM runs the flattened code fine, but deobfuscation happens before that

## Limitations

The deobfuscator works, but output isn't perfect:
- Variable names are generated (`var_0`, `var_1`, etc.) - originals are gone
- Comments don't survive compilation
- Some nested if-else gets rendered as ternary (same behavior, different structure)
- Stray labels sometimes appear in output
- Weird control flow patterns might have artifacts
