/**
 * NebulaVM Instruction Set Architecture (ISA) Definitions
 * =========================================================
 * 
 * This module defines the complete opcode set for the Nebula Virtual Machine.
 * NebulaVM is a stack-based virtual machine that executes JavaScript semantics
 * through a custom bytecode format. Understanding this ISA is essential for
 * reverse engineering obfuscated code.
 * 
 * Stack Machine Architecture:
 * - Operands are pushed onto an evaluation stack before operations
 * - Operations pop operands, compute results, and push results back
 * - No general-purpose registers; all computation uses the stack
 * 
 * Opcode Handler Taxonomy:
 * 
 * 1. STACK OPERATIONS (0-7): Stack manipulation primitives
 *    - Push literals (string, number, boolean, null, undefined)
 *    - Stack management (duplicate, pop)
 * 
 * 2. ARITHMETIC OPERATIONS (8-12): Binary math operators
 *    - Instruction semantics: pop two operands, push result
 *    - Implements: +, -, *, /, %
 * 
 * 3. COMPARISON OPERATIONS (13-20): Relational operators
 *    - Instruction semantics: pop two operands, push boolean result
 *    - Implements: ==, ===, !=, !==, <, <=, >, >=
 * 
 * 4. BINARY/BITWISE OPERATIONS (21-28): Bit manipulation and type operators
 *    - Shift operations: <<, >>, >>>
 *    - Logical: ^, &, |
 *    - Type operators: in, instanceof
 * 
 * 5. UNARY OPERATIONS (29-35): Single-operand operators
 *    - Arithmetic: +x, -x
 *    - Logical: !x, ~x
 *    - Type/control: typeof, void, throw
 * 
 * 6. UPDATE OPERATIONS (36-41): Increment/decrement operators
 *    - Variable updates: ++x, x++, --x, x--
 *    - Property updates: obj.prop++, obj.prop--
 *    - Complex property updates: obj[expr]++
 * 
 * 7. VARIABLE OPERATIONS (42-55): Variable access and assignment
 *    - Load/store by scope ID and slot index
 *    - Compound assignments: +=, -=, *=, /=, etc.
 * 
 * 8. CONTEXT OPERATIONS (56-60): Execution context access
 *    - Global object, this binding, arguments object
 * 
 * 9. CALL OPERATIONS (61-63): Function invocation
 *    - Function calls, method calls, constructor calls (new)
 * 
 * 10. PROPERTY OPERATIONS (64-65): Object property access
 *     - Get and set object properties
 * 
 * 11. BUILD OPERATIONS (66-68): Object/function construction
 *     - Array literals, object literals, function expressions
 *     - BUILD_FUNCTION contains nested VM context (embedded bytecode)
 * 
 * 12. CONTROL FLOW (69-71): Branch and jump instructions
 *     - Unconditional jump, conditional branches
 *     - Target addresses are bytecode offsets
 * 
 * 13. RETURN (72): Function exit
 *     - Pops return value (if any) and exits current VM context
 * 
 * 14. DEBUG (73): Debugger statement
 *     - Triggers debugger breakpoint
 */

export const OperationCode = {
  STACK_PUSH_STRING: 0,
  STACK_PUSH_DWORD: 1,
  STACK_PUSH_DOUBLE: 2,
  STACK_PUSH_BOOLEAN: 3,
  STACK_PUSH_NULL: 4,
  STACK_PUSH_UNDEFINED: 5,
  STACK_PUSH_DUPLICATE: 6,
  STACK_POP: 7,
  ARITHMETIC_ADD: 8,
  ARITHMETIC_SUB: 9,
  ARITHMETIC_MUL: 10,
  ARITHMETIC_DIV: 11,
  ARITHMETIC_MOD: 12,
  COMPARISON_EQUAL: 13,
  COMPARISON_STRICT_EQUAL: 14,
  COMPARISON_NOT_EQUAL: 15,
  COMPARISON_STRICT_NOT_EQUAL: 16,
  COMPARISON_LESS: 17,
  COMPARISON_LESS_OR_EQUAL: 18,
  COMPARISON_GREATER: 19,
  COMPARISON_GREATER_OR_EQUAL: 20,
  BINARY_BIT_SHIFT_LEFT: 21,
  BINARY_BIT_SHIFT_RIGHT: 22,
  BINARY_UNSIGNED_BIT_SHIFT_RIGHT: 23,
  BINARY_BIT_XOR: 24,
  BINARY_BIT_AND: 25,
  BINARY_BIT_OR: 26,
  BINARY_IN: 27,
  BINARY_INSTANCEOF: 28,
  UNARY_PLUS: 29,
  UNARY_MINUS: 30,
  UNARY_NOT: 31,
  UNARY_BIT_NOT: 32,
  UNARY_TYPEOF: 33,
  UNARY_VOID: 34,
  UNARY_THROW: 35,
  UPDATE_PLUS: 36,
  UPDATE_MINUS: 37,
  PROP_UPDATE_PLUS: 38,
  PROP_UPDATE_MINUS: 39,
  COMPLEX_PROP_UPDATE_PLUS: 40,
  COMPLEX_PROP_UPDATE_MINUS: 41,
  LOAD_VARIABLE: 42,
  STORE_VARIABLE: 43,
  ASSIGN_VARIABLE: 44,
  ADD_ASSIGN_VARIABLE: 45,
  SUB_ASSIGN_VARIABLE: 46,
  MUL_ASSIGN_VARIABLE: 47,
  DIV_ASSIGN_VARIABLE: 48,
  MOD_ASSIGN_VARIABLE: 49,
  BIT_SHIFT_LEFT_ASSIGN_VARIABLE: 50,
  BIT_SHIFT_RIGHT_ASSIGN_VAIRABLE: 51,
  UNSIGNED_BIT_SHIFT_RIGHT_ASSIGN_VARIABLE: 52,
  BIT_XOR_ASSIGN_VARIABLE: 53,
  BIT_AND_ASSIGN_VARIABLE: 54,
  BIT_OR_ASSIGN_VARIABLE: 55,
  LOAD_GLOBAL: 56,
  LOAD_GLOBAL_PROP: 57,
  LOAD_THIS: 58,
  LOAD_ARGUMENT: 59,
  LOAD_ARGUMENTS: 60,
  CALL_FUNCTION: 61,
  CALL_METHOD: 62,
  CONSTRUCT: 63,
  GET_PROPERTY: 64,
  SET_PROPERTY: 65,
  BUILD_ARRAY: 66,
  BUILD_OBJECT: 67,
  BUILD_FUNCTION: 68,
  JUMP: 69,
  JUMP_IF_TRUE: 70,
  JUMP_IF_FALSE: 71,
  RETURN: 72,
  DEBUGGER: 73,
};

/**
 * Reverse lookup table: Maps numeric opcode values to their symbolic names.
 * Used during disassembly for human-readable instruction output.
 */
export const OpcodeNames = Object.fromEntries(
  Object.entries(OperationCode).map(([k, v]) => [v, k])
);
