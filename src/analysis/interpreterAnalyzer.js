/**
 * =============================================================================
 * INTERPRETER ANALYZER MODULE
 * =============================================================================
 * 
 * This module provides static analysis capabilities for reverse engineering
 * JavaScript Virtual Machine (VM) based obfuscators. These obfuscators work by:
 * 
 * 1. Compiling JavaScript source code to custom bytecode
 * 2. Embedding a VM interpreter that executes the bytecode at runtime
 * 3. Using opaque naming and control flow to hide the original logic
 * 
 * =============================================================================
 * VM DISPATCHER ARCHITECTURE
 * =============================================================================
 * 
 * The VM interpreter typically uses one of two dispatcher patterns:
 * 
 * PATTERN A: Switch-based Dispatcher
 * ----------------------------------
 * while (running) {
 *   const opcode = bytecode[ip++];
 *   switch (opcode) {
 *     case 0: pushValue(); break;
 *     case 1: popValue(); break;
 *     // ... more handlers
 *   }
 * }
 * 
 * PATTERN B: Object Property Lookup (more common in obfuscators)
 * --------------------------------------------------------------
 * const handlers = {
 *   0: function() { pushValue(); },
 *   1: function() { popValue(); },
 *   // ... more handlers
 * };
 * while (running) {
 *   const opcode = bytecode[ip++];
 *   handlers[opcode]();
 * }
 * 
 * This module targets Pattern B, where opcodes map to handler functions stored
 * as numeric keys in an object. The handler functions reveal their purpose
 * through structural patterns (stack operations, arithmetic, etc.).
 * 
 * =============================================================================
 * VM STATE LAYOUT
 * =============================================================================
 * 
 * A typical VM maintains several state components in a state object:
 * 
 * {
 *   ip: 0,              // Instruction pointer - current position in bytecode
 *   stack: [],          // Operand stack - holds intermediate values
 *   scopes: [{}],       // Scope chain - array of scope objects for variables
 *   arguments: [],      // Function arguments array (for LOAD_ARGUMENT)
 *   thisRef: null,      // The 'this' binding for the current context
 *   global: globalThis, // Reference to global object
 *   strings: [],        // String table - decoded from bytecode header
 *   bytecode: Uint8Array// The raw bytecode being executed
 * }
 * 
 * Properties are identified by their access patterns:
 * - stack: has push()/pop() calls
 * - scopes: double bracket access like scopes[depth][varIndex]
 * - strings: single bracket with readDword index like strings[readDword()]
 * - arguments: single bracket with index like arguments[index]
 * - global: named 'global' or accessed via Reflect.get
 * 
 * =============================================================================
 * HANDLER TAXONOMY
 * =============================================================================
 * 
 * STACK OPERATIONS (push/pop values)
 * ----------------------------------
 * - STACK_PUSH_STRING:    push(strings[readDword()])  - reads string table index
 * - STACK_PUSH_DWORD:     push(readDword())           - pushes 32-bit integer
 * - STACK_PUSH_DOUBLE:    push(Float64Array...)       - pushes 64-bit float
 * - STACK_PUSH_BOOLEAN:   push(readInstr() === 1)     - reads 1 byte, pushes bool
 * - STACK_PUSH_NULL:      push(null)                  - literal null
 * - STACK_PUSH_UNDEFINED: push(void 0)                - literal undefined
 * - STACK_POP:            pop()                       - discards top of stack
 * 
 * ARITHMETIC OPERATIONS (binary math)
 * -----------------------------------
 * - ARITHMETIC_ADD: push(pop() + pop())
 * - ARITHMETIC_SUB: push(pop() - pop())
 * - ARITHMETIC_MUL: push(pop() * pop())
 * - ARITHMETIC_DIV: push(pop() / pop())
 * - ARITHMETIC_MOD: push(pop() % pop())
 * 
 * COMPARISON OPERATIONS (produce boolean)
 * ---------------------------------------
 * - COMPARISON_LESS:            push(pop() < pop())
 * - COMPARISON_GREATER:         push(pop() > pop())
 * - COMPARISON_STRICT_EQUAL:    push(pop() === pop())
 * - COMPARISON_STRICT_NOT_EQUAL: push(pop() !== pop())
 * - etc.
 * 
 * BITWISE OPERATIONS
 * ------------------
 * - BINARY_BIT_SHIFT_LEFT:  push(pop() << pop())
 * - BINARY_BIT_SHIFT_RIGHT: push(pop() >> pop())
 * - BINARY_BIT_XOR:         push(pop() ^ pop())
 * - BINARY_BIT_AND:         push(pop() & pop())
 * - BINARY_BIT_OR:          push(pop() | pop())
 * 
 * UNARY OPERATIONS
 * ----------------
 * - UNARY_NOT:    push(!pop())
 * - UNARY_TYPEOF: push(typeof pop())
 * - UNARY_VOID:   push(void pop())
 * - UNARY_THROW:  throw pop()
 * 
 * VARIABLE ACCESS (scope chain)
 * -----------------------------
 * - LOAD_VARIABLE:  push(scopes[depth][index])     - read from scope
 * - STORE_VARIABLE: scopes[depth][index] ??= pop() - write to scope (declare)
 * - ASSIGN_VARIABLE: scopes[depth][index] = pop(); push(val) - assign & push
 * 
 * UPDATE OPERATIONS (increment/decrement)
 * ---------------------------------------
 * - UPDATE_PLUS:  scopes[d][i]++  (on variable)
 * - UPDATE_MINUS: scopes[d][i]--  (on variable)
 * - PROP_UPDATE_PLUS:  obj[prop]++ (on property)
 * - PROP_UPDATE_MINUS: obj[prop]-- (on property)
 * 
 * PROPERTY ACCESS
 * ---------------
 * - GET_PROPERTY: push(pop()[pop()])   - obj[key]
 * - SET_PROPERTY: obj[key] = val       - pop value, key, obj; assign
 * 
 * FUNCTION CALLS
 * --------------
 * - CALL_FUNCTION: func.apply(thisArg, args)  - normal call
 * - CALL_METHOD:   obj.method.apply(...)      - method call with receiver
 * - CONSTRUCT:     new Ctor(...args)          - constructor call
 * 
 * CONTROL FLOW
 * ------------
 * - JUMP:          ip = readDword()                    - unconditional jump
 * - JUMP_IF_TRUE:  if (pop()) ip = readDword()         - conditional jump
 * - JUMP_IF_FALSE: if (!pop()) ip = readDword()        - conditional jump
 * - RETURN:        return pop()                        - exit function
 * 
 * OBJECT/ARRAY CONSTRUCTION
 * -------------------------
 * - BUILD_ARRAY:    [...] with loop collecting elements
 * - BUILD_OBJECT:   {...} with loop collecting key/value pairs
 * - BUILD_FUNCTION: Creates closure capturing current scope
 * 
 * SPECIAL
 * -------
 * - LOAD_GLOBAL:    push(globalThis)
 * - LOAD_THIS:      push(thisRef)
 * - LOAD_ARGUMENT:  push(arguments[index])
 * - LOAD_ARGUMENTS: push(arguments)
 * - DEBUGGER:       debugger statement
 * 
 * =============================================================================
 * FINGERPRINTING HEURISTICS
 * =============================================================================
 * 
 * Each opcode handler has distinctive patterns that allow identification:
 * 
 * Stack Push Operations:
 * - String push: reads from string table using double-bracket access + readDword
 * - Dword push: calls readDword, no string table access, simple body
 * - Boolean push: uses === 1 comparison, single byte read
 * - Null/undefined: single statement pushing literal
 * 
 * Arithmetic/Comparison:
 * - Specific operator in BinaryExpression
 * - 2 pops + 1 push pattern
 * - Small body (≤4 statements)
 * - No loops
 * 
 * Variable Operations:
 * - Double bracket access on scopes: scopes[depth][index]
 * - LOAD: has push, no assignment
 * - STORE: has ??= (nullish assign) or assignment without push
 * - UPDATE: has ++ or -- operator
 * 
 * Control Flow:
 * - JUMP: reads index (readDword), has assignment to IP, no pop
 * - JUMP_IF_*: pops value, reads index, conditional (&& or ||)
 * - RETURN: identified by === N comparison where N is return opcode
 * 
 * Function Calls:
 * - CALL: has spread, for loop, pops, pushes
 * - CONSTRUCT: same + 'new' expression
 * - METHOD: uses .apply()
 * 
 * Object Builders:
 * - Arrays: ArrayExpression or new Array, for loop, no function expr
 * - Objects: ObjectExpression, for loop
 * - Functions: FunctionExpression/Arrow, try-finally or Array.from
 */

import _traverse from '@babel/traverse';
import * as t from '@babel/types';

const traverse = typeof _traverse === 'object' ? _traverse.default : _traverse;

/**
 * =============================================================================
 * HELPER FUNCTION SCANNER
 * =============================================================================
 * 
 * The VM uses several helper functions for common operations:
 * 
 * - push(value): Pushes value onto operand stack
 *   Pattern: single param, calls array.push() internally
 * 
 * - pop(): Pops and returns top of operand stack
 *   Pattern: no params, calls array.pop() internally
 * 
 * - readDword(): Reads 4 bytes from bytecode as 32-bit integer
 *   Pattern: no params, bit shifts by 8/16/24, combines bytes
 *   Used for: string indices, jump targets, variable indices
 * 
 * - readInstr(): Reads single byte and advances instruction pointer
 *   Pattern: no params, ++ operator, member access, no bit shifts
 *   Used for: opcodes, boolean values, small operands
 * 
 * - readDouble(): Reads 8 bytes as IEEE 754 double
 *   Pattern: uses Float64Array
 */
export function findHelperFunctionsAST(ast) {
  const helpers = {
    push: null,
    pop: null,
    readDword: null,
    readInstr: null,
    readDouble: null,
  };
  
  traverse(ast, {
    FunctionDeclaration(path) {
      analyzeHelperFunction(path.node, path.node.id?.name, helpers);
    },
    VariableDeclarator(path) {
      const init = path.node.init;
      const name = path.node.id?.name;
      if (name && (t.isFunctionExpression(init) || t.isArrowFunctionExpression(init))) {
        analyzeHelperFunction(init, name, helpers);
      }
    },
  });
  
  if (!helpers.push) helpers.push = 't';
  if (!helpers.pop) helpers.pop = 'o';
  if (!helpers.readDword) helpers.readDword = 'I';
  if (!helpers.readInstr) helpers.readInstr = 'r';
  
  return helpers;
}

/**
 * Analyzes a function to determine if it matches known VM helper patterns.
 * 
 * Detection heuristics:
 * - push: has .push() call, exactly 1 parameter
 * - pop: has .pop() call, no parameters  
 * - readDword: bit shifts by 8, 16, 24 (little-endian dword reconstruction)
 * - readInstr: has ++ increment, computed member access, no bit shifts
 */
function analyzeHelperFunction(funcNode, name, helpers) {
  if (!funcNode.body) return;
  
  const params = funcNode.params || [];
  const hasOneParam = params.length === 1;
  const hasNoParams = params.length === 0;
  
  let hasPush = false;
  let hasPop = false;
  let shiftAmounts = new Set();
  let hasIncrement = false;
  let hasMemberAccess = false;
  
  const bodyNode = t.isBlockStatement(funcNode.body) ? funcNode.body : t.blockStatement([t.returnStatement(funcNode.body)]);
  
  traverse(bodyNode, {
    noScope: true,
    
    CallExpression(path) {
      const callee = path.node.callee;
      if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
        if (callee.property.name === 'push') hasPush = true;
        if (callee.property.name === 'pop') hasPop = true;
      }
    },
    
    BinaryExpression(path) {
      if (path.node.operator === '<<' && t.isNumericLiteral(path.node.right)) {
        shiftAmounts.add(path.node.right.value);
      }
    },
    
    UpdateExpression(path) {
      if (path.node.operator === '++') hasIncrement = true;
    },
    
    MemberExpression(path) {
      if (path.node.computed) hasMemberAccess = true;
    },
  });
  
  const hasBitShifts = shiftAmounts.has(8) && shiftAmounts.has(16) && shiftAmounts.has(24);
  
  if (hasPush && hasOneParam && !helpers.push) {
    helpers.push = name;
  }
  if (hasPop && hasNoParams && !helpers.pop) {
    helpers.pop = name;
  }
  if (hasBitShifts && hasNoParams && !helpers.readDword) {
    helpers.readDword = name;
  }
  if (hasIncrement && hasMemberAccess && hasNoParams && !hasBitShifts && !helpers.readInstr) {
    helpers.readInstr = name;
  }
}

/**
 * =============================================================================
 * VM STATE PROPERTY SCANNER
 * =============================================================================
 * 
 * Locates and identifies VM state object properties by analyzing:
 * 
 * 1. State Object Detection:
 *    - Finds object expressions with 5+ null-initialized properties
 *    - These nulls are placeholders filled at VM initialization
 * 
 * 2. Property Identification (by usage patterns):
 *    - stack: has push()/pop() method calls on it
 *    - scopes: double bracket access pattern (scopes[depth][varIndex])
 *    - strings/stringTable: single bracket with readDword (strings[readDword()])
 *    - arguments: single bracket access, often named 'a' or contains 'arg'
 *    - global: contains 'global' in name or stores globalThis
 *    - thisRef: direct access only, no bracket notation
 * 
 * 3. Handler Object Detection:
 *    - Finds object with 10+ numeric keys mapping to FunctionExpressions
 *    - This is the opcode handler dispatch table
 */
export function findVMStateProperties(ast) {
  const vmState = {
    stringTable: null,
    stack: null,
    scopes: null,
    arguments: null,
    thisRef: null,
    global: null,
    bytecode: null,
    stateObject: null,
    stateObjName: null,
  };
  
  let candidateProps = new Set();
  let stateObjName = null;
  
  function checkObjectForStateProps(objExpr, varName) {
    if (!t.isObjectExpression(objExpr)) return false;
    
    const props = objExpr.properties;
    const nullProps = props.filter(p => 
      t.isObjectProperty(p) && t.isNullLiteral(p.value) && t.isIdentifier(p.key)
    );
    
    if (nullProps.length >= 5) {
      stateObjName = varName;
      vmState.stateObjName = stateObjName;
      vmState.stateObject = objExpr;
      for (const prop of nullProps) {
        candidateProps.add(prop.key.name);
      }
      
      for (const prop of nullProps) {
        const keyName = prop.key.name;
        const lowerKey = keyName.toLowerCase();
        if (lowerKey.includes('global')) {
          vmState.global = keyName;
        }
      }
      return true;
    }
    return false;
  }
  
  traverse(ast, {
    VariableDeclarator(path) {
      if (stateObjName) return;
      
      const init = path.node.init;
      const varName = path.node.id?.name;
      
      if (t.isObjectExpression(init)) {
        checkObjectForStateProps(init, varName);
      } else if (t.isSequenceExpression(init)) {
        for (const expr of init.expressions) {
          if (checkObjectForStateProps(expr, varName)) break;
        }
      }
    },
  });
  
  if (!stateObjName || candidateProps.size === 0) {
    return vmState;
  }
  
  const propUsage = {};
  for (const prop of candidateProps) {
    propUsage[prop] = {
      hasPush: false,
      hasPop: false,
      singleBracketAccess: false,
      doubleBracketAccess: false,
      directAccess: false,
      lengthAccess: false,
    };
  }
  
  traverse(ast, {
    FunctionDeclaration(path) {
      const funcBody = path.node.body;
      if (!funcBody) return;
      
      traverse(funcBody, {
        noScope: true,
        CallExpression(innerPath) {
          const callee = innerPath.node.callee;
          if (!t.isMemberExpression(callee)) return;
          
          const obj = callee.object;
          const prop = callee.property;
          
          if (t.isMemberExpression(obj) && 
              t.isIdentifier(obj.object) && obj.object.name === stateObjName &&
              t.isIdentifier(obj.property) && t.isIdentifier(prop)) {
            const vmProp = obj.property.name;
            const methodName = prop.name;
            if (propUsage[vmProp]) {
              if (methodName === 'push') propUsage[vmProp].hasPush = true;
              if (methodName === 'pop') propUsage[vmProp].hasPop = true;
            }
          }
        }
      });
    },
    VariableDeclarator(path) {
      const init = path.node.init;
      if (!t.isFunctionExpression(init) && !t.isArrowFunctionExpression(init)) return;
      
      const funcBody = init.body;
      if (!funcBody) return;
      
      const bodyToTraverse = t.isBlockStatement(funcBody) ? funcBody : t.blockStatement([t.returnStatement(funcBody)]);
      
      traverse(bodyToTraverse, {
        noScope: true,
        CallExpression(innerPath) {
          const callee = innerPath.node.callee;
          if (!t.isMemberExpression(callee)) return;
          
          const obj = callee.object;
          const prop = callee.property;
          
          if (t.isMemberExpression(obj) && 
              t.isIdentifier(obj.object) && obj.object.name === stateObjName &&
              t.isIdentifier(obj.property) && t.isIdentifier(prop)) {
            const vmProp = obj.property.name;
            const methodName = prop.name;
            if (propUsage[vmProp]) {
              if (methodName === 'push') propUsage[vmProp].hasPush = true;
              if (methodName === 'pop') propUsage[vmProp].hasPop = true;
            }
          }
        }
      });
    },
  });
  
  let opcodeHandlerObject = null;
  traverse(ast, {
    ObjectExpression(path) {
      const props = path.node.properties;
      const numericHandlers = props.filter(p => 
        t.isProperty(p) && t.isNumericLiteral(p.key) && t.isFunctionExpression(p.value)
      ).length;
      if (numericHandlers >= 10 && !opcodeHandlerObject) {
        opcodeHandlerObject = path.node;
      }
    },
  });
  
  if (!opcodeHandlerObject) {
    return vmState;
  }
  
  for (const prop of opcodeHandlerObject.properties) {
    if (!t.isProperty(prop) || !t.isFunctionExpression(prop.value)) continue;
    
    const funcBody = prop.value.body;
    
    traverse(funcBody, {
      noScope: true,
      MemberExpression(path) {
        if (!t.isIdentifier(path.node.object) || path.node.object.name !== stateObjName) return;
        if (!t.isIdentifier(path.node.property)) return;
        
        const propName = path.node.property.name;
        if (!propUsage[propName]) return;
        
        const parent = path.parent;
        
        if (t.isMemberExpression(parent) && parent.object === path.node) {
          if (t.isIdentifier(parent.property)) {
            const accessedProp = parent.property.name;
            if (accessedProp === 'length') propUsage[propName].lengthAccess = true;
          }
          
          if (parent.computed) {
            propUsage[propName].singleBracketAccess = true;
            
            const grandParent = path.parentPath?.parent;
            if (t.isMemberExpression(grandParent) && grandParent.computed) {
              propUsage[propName].doubleBracketAccess = true;
            }
          }
        } else {
          propUsage[propName].directAccess = true;
        }
      },
    });
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (usage.hasPush && usage.hasPop && !vmState.stack) {
      vmState.stack = prop;
    }
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (prop === vmState.stack || prop === vmState.global) continue;
    if (usage.lengthAccess && !vmState.stack) {
      vmState.stack = prop;
    }
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (prop === vmState.stack || prop === vmState.global) continue;
    
    if (usage.doubleBracketAccess && !vmState.scopes) {
      vmState.scopes = prop;
    }
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (prop === vmState.stack || prop === vmState.global || prop === vmState.scopes) continue;
    
    if (usage.singleBracketAccess && !usage.doubleBracketAccess && !vmState.stringTable) {
      const lowerProp = prop.toLowerCase();
      if (lowerProp !== 'a' && !lowerProp.includes('arg')) {
        vmState.stringTable = prop;
      }
    }
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (prop === vmState.stack || prop === vmState.global || prop === vmState.scopes || prop === vmState.stringTable) continue;
    
    if (usage.singleBracketAccess && !usage.doubleBracketAccess && !vmState.arguments) {
      vmState.arguments = prop;
    }
  }
  
  for (const [prop, usage] of Object.entries(propUsage)) {
    if (prop === vmState.stack || prop === vmState.global || prop === vmState.scopes || 
        prop === vmState.stringTable || prop === vmState.arguments) continue;
    
    if (usage.directAccess && !usage.singleBracketAccess && !vmState.thisRef) {
      vmState.thisRef = prop;
    }
  }
  
  return vmState;
}

/**
 * =============================================================================
 * OPCODE CLASSIFIER
 * =============================================================================
 * 
 * Fingerprints opcode handlers by analyzing their AST structure.
 * Each handler has characteristic patterns that reveal its semantic operation.
 */

/**
 * Extracts structural features from an opcode handler function.
 * These features form the fingerprint used for opcode classification.
 * 
 * Features extracted:
 * - pushCount/popCount: Number of stack operations
 * - readsFromStringTable: Accesses strings[index]
 * - readsIndex/readsDword/readsInstr: Reads bytecode operands
 * - operators: Binary/unary operators used (+, -, ===, etc.)
 * - Control flow: loops, try-finally, throw
 * - Special accesses: global, this, arguments, scopes
 * - Construction: new, array literals, object literals, functions
 */
function extractHandlerFeatures(funcNode, helpers, vmState) {
  const features = {
    pushCount: 0,
    popCount: 0,
    readsFromStringTable: false,
    readsIndex: false,
    readsDword: false,
    readsInstr: false,
    hasForLoop: false,
    hasWhileLoop: false,
    operators: new Set(),
    callsApply: false,
    callsNew: false,
    accessesGlobal: false,
    usesReflectGet: false,
    accessesThis: false,
    accessesArguments: false,
    accessesScopes: false,
    accessesScopesWithBracket: false,
    hasAssignment: false,
    hasNullaryAssign: false,
    pushesNull: false,
    pushesUndefined: false,
    pushesFloat64: false,
    hasEqualsOne: false,
    hasIncrement: false,
    hasDecrement: false,
    hasArrayLiteral: false,
    hasObjectLiteral: false,
    hasSpread: false,
    hasFunctionExpr: false,
    hasTryFinally: false,
    hasThrow: false,
    hasDebugger: false,
    bodyStmtCount: 0,
    memberAccesses: new Set(),
    calledFunctions: new Set(),
    hasArrayFrom: false,
    hasNestedComputedAccess: false,
    hasDoubleNestedAccess: false,
  };
  
  if (!funcNode.body || !funcNode.body.body) return features;
  
  features.bodyStmtCount = funcNode.body.body.length;
  
  const helperPush = helpers.push;
  const helperPop = helpers.pop;
  const helperReadDword = helpers.readDword;
  const helperReadInstr = helpers.readInstr;
  
  const vmStringTable = vmState?.stringTable;
  const vmScopes = vmState?.scopes;
  const vmArguments = vmState?.arguments;
  const vmThisRef = vmState?.thisRef;
  
  traverse(funcNode.body, {
    noScope: true,
    
    CallExpression(path) {
      const callee = path.node.callee;
      
      if (t.isIdentifier(callee)) {
        const name = callee.name;
        features.calledFunctions.add(name);
        
        if (name === helperPush) features.pushCount++;
        if (name === helperPop) features.popCount++;
        if (name === helperReadDword) {
          features.readsIndex = true;
          features.readsDword = true;
        }
        if (name === helperReadInstr) {
          features.readsInstr = true;
        }
      }
      
      if (t.isMemberExpression(callee)) {
        const propName = t.isIdentifier(callee.property) ? callee.property.name : null;
        
        if (propName === 'push') features.pushCount++;
        if (propName === 'pop') features.popCount++;
        if (propName === 'apply') features.callsApply = true;
        if (propName === 'get' && t.isIdentifier(callee.object) && callee.object.name === 'Reflect') {
          features.usesReflectGet = true;
          features.accessesGlobal = true;
        }
        if (propName === 'from' && t.isIdentifier(callee.object) && callee.object.name === 'Array') {
          features.hasArrayFrom = true;
        }
      }
    },
    
    MemberExpression(path) {
      const obj = path.node.object;
      const prop = path.node.property;
      
      if (t.isIdentifier(prop) && !path.node.computed) {
        const propName = prop.name;
        const lowerName = propName.toLowerCase();
        features.memberAccesses.add(propName);
        
        if (lowerName === 'global' || propName === 'globalThis') {
          features.accessesGlobal = true;
        }
        
        if (vmThisRef && propName === vmThisRef) {
          features.accessesThis = true;
        } else if (lowerName === 'this' || lowerName.includes('this')) {
          features.accessesThis = true;
        }
        
        if (vmArguments && propName === vmArguments) {
          features.accessesArguments = true;
        } else if (lowerName === 'arguments' || lowerName.includes('arg')) {
          features.accessesArguments = true;
        }
      }
      
      if (path.node.computed) {
        features.hasNestedComputedAccess = true;
        
        if (t.isMemberExpression(obj)) {
          features.hasDoubleNestedAccess = true;
          const innerProp = t.isIdentifier(obj.property) ? obj.property.name : null;
          
          if (innerProp) {
            if (vmScopes && innerProp === vmScopes) {
              features.accessesScopes = true;
              features.accessesScopesWithBracket = true;
            } else if (vmStringTable && innerProp === vmStringTable) {
              features.readsFromStringTable = true;
            } else if (vmArguments && innerProp === vmArguments) {
              features.accessesArguments = true;
            } else {
              const lower = innerProp.toLowerCase();
              if (lower === 'scopes' || lower.includes('scope')) {
                features.accessesScopes = true;
                features.accessesScopesWithBracket = true;
              } else if (lower === 'strings' || lower.includes('string')) {
                features.readsFromStringTable = true;
              } else if (lower === 'arguments' || lower.includes('arg')) {
                features.accessesArguments = true;
              } else {
                const isStringTableAccess = detectStringTableAccessPattern(path.node, helperReadDword, features.calledFunctions);
                if (isStringTableAccess) {
                  features.readsFromStringTable = true;
                }
                const isScopeAccess = detectScopeAccessPattern(path.node, features.calledFunctions);
                if (isScopeAccess) {
                  features.accessesScopes = true;
                  features.accessesScopesWithBracket = true;
                }
              }
            }
          }
        }
      }
    },
    
    BinaryExpression(path) {
      features.operators.add(path.node.operator);
      
      if (path.node.operator === '===') {
        const left = path.node.left;
        const right = path.node.right;
        if ((t.isNumericLiteral(left) && left.value === 1) ||
            (t.isNumericLiteral(right) && right.value === 1)) {
          features.hasEqualsOne = true;
        }
      }
    },
    
    LogicalExpression(path) {
      features.operators.add(path.node.operator);
    },
    
    UnaryExpression(path) {
      features.operators.add(path.node.operator);
      if (path.node.operator === 'void' && t.isNumericLiteral(path.node.argument) && path.node.argument.value === 0) {
        features.pushesUndefined = true;
      }
    },
    
    UpdateExpression(path) {
      if (path.node.operator === '++') features.hasIncrement = true;
      if (path.node.operator === '--') features.hasDecrement = true;
    },
    
    AssignmentExpression(path) {
      features.hasAssignment = true;
      if (path.node.operator === '??=') {
        features.hasNullaryAssign = true;
      }
    },
    
    NewExpression(path) {
      features.callsNew = true;
      if (t.isIdentifier(path.node.callee) && path.node.callee.name === 'Array') {
        features.hasArrayLiteral = true;
      }
      if (t.isIdentifier(path.node.callee) && path.node.callee.name === 'Float64Array') {
        features.pushesFloat64 = true;
      }
    },
    
    ArrayExpression(path) {
      features.hasArrayLiteral = true;
    },
    
    ObjectExpression(path) {
      features.hasObjectLiteral = true;
    },
    
    ForStatement(path) {
      features.hasForLoop = true;
    },
    
    WhileStatement(path) {
      features.hasWhileLoop = true;
    },
    
    FunctionExpression(path) {
      features.hasFunctionExpr = true;
    },
    
    ArrowFunctionExpression(path) {
      features.hasFunctionExpr = true;
    },
    
    TryStatement(path) {
      if (path.node.finalizer) {
        features.hasTryFinally = true;
      }
    },
    
    ThrowStatement(path) {
      features.hasThrow = true;
    },
    
    DebuggerStatement(path) {
      features.hasDebugger = true;
    },
    
    SpreadElement(path) {
      features.hasSpread = true;
    },
    
    Identifier(path) {
      if (path.node.name === 'undefined') {
        features.pushesUndefined = true;
      }
      if (path.node.name === 'globalThis') {
        features.accessesGlobal = true;
      }
      if (path.node.name === 'Float64Array') {
        features.pushesFloat64 = true;
      }
    },
    
    NullLiteral(path) {
      features.pushesNull = true;
    },
  });
  
  return features;
}

/**
 * Detects string table access pattern: state.strings[readDword()]
 * 
 * The string table stores all string literals from the original code.
 * Access pattern: obj.property[helperCall()] where helper reads index.
 */
function detectStringTableAccessPattern(memberExpr, helperReadDword, calledFunctions) {
  if (!t.isMemberExpression(memberExpr) || !memberExpr.computed) return false;
  if (!t.isMemberExpression(memberExpr.object)) return false;
  
  const property = memberExpr.property;
  if (t.isCallExpression(property)) {
    const callee = property.callee;
    if (t.isIdentifier(callee) && callee.name === helperReadDword) {
      return true;
    }
    if (calledFunctions.has(callee.name)) {
      return true;
    }
  }
  
  return false;
}

/**
 * Detects scope chain access pattern: state.scopes[depth][varIndex]
 * 
 * The scope chain is an array of scope objects. Each scope object
 * maps variable indices to their values. Access requires two bracket
 * operations: first to get the scope at depth, then to get the variable.
 */
function detectScopeAccessPattern(memberExpr, calledFunctions) {
  if (!t.isMemberExpression(memberExpr) || !memberExpr.computed) return false;
  if (!t.isMemberExpression(memberExpr.object)) return false;
  
  const property = memberExpr.property;
  if (t.isCallExpression(property)) {
    return true;
  }
  
  const innerObj = memberExpr.object;
  if (t.isMemberExpression(innerObj) && innerObj.computed) {
    return true;
  }
  
  return false;
}

/**
 * Maps extracted features to semantic opcode names.
 * 
 * This is the core fingerprinting logic. Each opcode has a unique
 * combination of features that distinguishes it from others:
 * 
 * - Debugger: contains DebuggerStatement
 * - Stack pushes: specific patterns for string/dword/bool/null/undefined
 * - Arithmetic: operator presence + pop/push pattern
 * - Variables: scope access + assignment/load pattern
 * - Control flow: jump target reads + conditional operators
 * - Calls: apply/spread/new patterns
 */
function mapFeaturesToOpcode(features) {
  const {
    pushCount, popCount, readsFromStringTable, readsIndex,
    readsDword, readsInstr,
    hasForLoop, operators, callsApply, callsNew, accessesGlobal,
    usesReflectGet, accessesThis, accessesArguments, accessesScopes,
    accessesScopesWithBracket, hasAssignment, hasNullaryAssign,
    pushesNull, pushesUndefined, pushesFloat64, hasEqualsOne,
    hasIncrement, hasDecrement, hasArrayLiteral, hasObjectLiteral,
    hasSpread, hasFunctionExpr, hasTryFinally, hasThrow, hasDebugger,
    bodyStmtCount, hasArrayFrom,
  } = features;
  
  if (hasDebugger) {
    return 'DEBUGGER';
  }
  
  if (readsFromStringTable && readsDword && pushCount >= 1 && popCount === 0) {
    return 'STACK_PUSH_STRING';
  }
  
  if (hasEqualsOne && pushCount >= 1 && readsInstr && !readsDword &&
      !hasIncrement && !hasDecrement && !hasForLoop && bodyStmtCount <= 2) {
    return 'STACK_PUSH_BOOLEAN';
  }
  
  if (pushCount >= 1 && readsDword && popCount === 0 && !readsFromStringTable &&
      bodyStmtCount <= 2 && !hasForLoop && !hasArrayLiteral && 
      !accessesArguments && !accessesScopesWithBracket && !accessesScopes) {
    return 'STACK_PUSH_DWORD';
  }
  
  if (pushesFloat64) {
    return 'STACK_PUSH_DOUBLE';
  }
  
  if (pushesNull && !popCount && pushCount >= 1 && bodyStmtCount === 1) {
    return 'STACK_PUSH_NULL';
  }
  
  if (pushesUndefined && !popCount && pushCount >= 1 && bodyStmtCount === 1) {
    return 'STACK_PUSH_UNDEFINED';
  }
  
  if (popCount === 1 && pushCount === 0 && bodyStmtCount === 1) {
    return 'STACK_POP';
  }
  
  if (accessesThis && pushCount >= 1 && popCount === 0 && bodyStmtCount <= 2) {
    return 'LOAD_THIS';
  }
  
  if (accessesGlobal || usesReflectGet) {
    if (popCount >= 1) {
      return 'LOAD_GLOBAL_PROP';
    }
    return 'LOAD_GLOBAL';
  }
  
  if (accessesArguments && readsIndex && pushCount >= 1 && !hasForLoop && !accessesScopesWithBracket) {
    return 'LOAD_ARGUMENT';
  }
  
  if (accessesScopesWithBracket) {
    if (pushCount >= 1 && readsIndex && !hasAssignment && !hasIncrement && !hasDecrement) {
      return 'LOAD_VARIABLE';
    }
    if (hasNullaryAssign || (hasAssignment && !pushCount)) {
      return 'STORE_VARIABLE';
    }
    if (hasAssignment && pushCount >= 1) {
      return 'ASSIGN_VARIABLE';
    }
    if (hasIncrement) {
      if (popCount >= 1) {
        return 'PROP_UPDATE_PLUS';
      }
      return 'UPDATE_PLUS';
    }
    if (hasDecrement) {
      if (popCount >= 1) {
        return 'PROP_UPDATE_MINUS';
      }
      return 'UPDATE_MINUS';
    }
  }
  
  if (accessesArguments && pushCount >= 1 && !popCount && !readsIndex) {
    return 'LOAD_ARGUMENTS';
  }
  
  if (callsApply) {
    return 'CALL_METHOD';
  }
  
  if (hasFunctionExpr && (hasTryFinally || hasArrayFrom || hasForLoop)) {
    return 'BUILD_FUNCTION';
  }
  
  if (hasSpread && popCount >= 1 && pushCount >= 1 && hasForLoop) {
    if (callsNew && !hasArrayLiteral) {
      return 'CONSTRUCT';
    }
    return 'CALL_FUNCTION';
  }
  
  if (callsNew && popCount >= 1 && pushCount >= 1 && !hasFunctionExpr && !hasArrayLiteral) {
    return 'CONSTRUCT';
  }
  
  if (hasArrayLiteral && hasForLoop && !hasFunctionExpr && !hasArrayFrom) {
    if (hasObjectLiteral) {
      return 'BUILD_OBJECT';
    }
    return 'BUILD_ARRAY';
  }
  
  if (hasObjectLiteral && hasForLoop) {
    return 'BUILD_OBJECT';
  }
  
  if (operators.has('+') && !hasIncrement && popCount >= 1 && pushCount >= 1 && 
      bodyStmtCount <= 4 && !hasForLoop) {
    return 'ARITHMETIC_ADD';
  }
  
  if (operators.has('-') && !hasDecrement && popCount >= 1 && pushCount >= 1 && 
      bodyStmtCount <= 4 && !hasForLoop && !operators.has('+')) {
    return 'ARITHMETIC_SUB';
  }
  
  if (operators.has('*') && popCount >= 1 && pushCount >= 1 && 
      bodyStmtCount <= 4 && !hasForLoop) {
    return 'ARITHMETIC_MUL';
  }
  
  if (operators.has('/') && popCount >= 1 && pushCount >= 1 && 
      bodyStmtCount <= 4 && !hasForLoop) {
    return 'ARITHMETIC_DIV';
  }
  
  if (operators.has('%') && popCount >= 1 && pushCount >= 1) {
    return 'ARITHMETIC_MOD';
  }
  
  if (operators.has('<') && !operators.has('<<') && !operators.has('<=') && 
      popCount >= 1 && pushCount >= 1 && !hasForLoop) {
    return 'COMPARISON_LESS';
  }
  
  if (operators.has('<=') && popCount >= 1 && pushCount >= 1) {
    return 'COMPARISON_LESS_OR_EQUAL';
  }
  
  if (operators.has('>') && !operators.has('>>') && !operators.has('>=') && 
      popCount >= 1 && pushCount >= 1 && !hasForLoop) {
    return 'COMPARISON_GREATER';
  }
  
  if (operators.has('>=') && popCount >= 1 && pushCount >= 1) {
    return 'COMPARISON_GREATER_OR_EQUAL';
  }
  
  if (operators.has('===') && popCount >= 1 && pushCount >= 1 && !hasForLoop) {
    return 'COMPARISON_STRICT_EQUAL';
  }
  
  if (operators.has('!==') && popCount >= 1 && pushCount >= 1) {
    return 'COMPARISON_STRICT_NOT_EQUAL';
  }
  
  if (operators.has('==') && !operators.has('===') && popCount >= 1 && pushCount >= 1) {
    return 'COMPARISON_EQUAL';
  }
  
  if (operators.has('!=') && !operators.has('!==') && popCount >= 1 && pushCount >= 1) {
    return 'COMPARISON_NOT_EQUAL';
  }
  
  if (operators.has('<<') && popCount >= 1) {
    return 'BINARY_BIT_SHIFT_LEFT';
  }
  
  if (operators.has('>>>') && popCount >= 1) {
    return 'BINARY_UNSIGNED_BIT_SHIFT_RIGHT';
  }
  
  if (operators.has('>>') && !operators.has('>>>') && popCount >= 1) {
    return 'BINARY_BIT_SHIFT_RIGHT';
  }
  
  if (operators.has('^') && popCount >= 1) {
    return 'BINARY_BIT_XOR';
  }
  
  if (operators.has('&') && !operators.has('&&') && popCount >= 1) {
    return 'BINARY_BIT_AND';
  }
  
  if (operators.has('|') && !operators.has('||') && popCount >= 1) {
    return 'BINARY_BIT_OR';
  }
  
  if (operators.has('in')) {
    return 'BINARY_IN';
  }
  
  if (operators.has('instanceof')) {
    return 'BINARY_INSTANCEOF';
  }
  
  if (operators.has('typeof')) {
    return 'UNARY_TYPEOF';
  }
  
  if (operators.has('void')) {
    return 'UNARY_VOID';
  }
  
  if (hasThrow) {
    return 'UNARY_THROW';
  }
  
  if (operators.has('~') && popCount >= 1 && pushCount >= 1) {
    return 'UNARY_BIT_NOT';
  }
  
  if (operators.has('!') && popCount >= 1 && pushCount >= 1 && bodyStmtCount <= 3) {
    return 'UNARY_NOT';
  }
  
  if (readsIndex && !popCount && hasAssignment) {
    return 'JUMP';
  }
  
  if ((operators.has('&&') || operators.has('||')) && readsIndex && popCount >= 1) {
    if (operators.has('||')) {
      return 'JUMP_IF_FALSE';
    }
    return 'JUMP_IF_TRUE';
  }
  
  if (popCount >= 1 && pushCount >= 1 && !hasAssignment) {
    return 'GET_PROPERTY';
  }
  
  if (popCount >= 1 && hasAssignment && !pushCount) {
    return 'SET_PROPERTY';
  }
  
  if (hasIncrement && popCount >= 1 && pushCount >= 1) {
    return 'COMPLEX_PROP_UPDATE_PLUS';
  }
  
  if (hasDecrement && popCount >= 1 && pushCount >= 1) {
    return 'COMPLEX_PROP_UPDATE_MINUS';
  }
  
  return null;
}

/**
 * Main entry point for analyzing an opcode handler function.
 * 
 * Extracts features from the handler and maps them to a semantic opcode.
 * Falls back to pattern-based detection if primary classification fails.
 * 
 * @param {Object} funcNode - Babel AST node of the handler function
 * @param {Object} helperFns - Map of helper function names (push, pop, etc.)
 * @param {Object} vmState - Identified VM state properties
 * @returns {string|null} Semantic opcode name or null if unidentified
 */
export function analyzeHandlerStructure(funcNode, helperFns, vmState) {
  const features = extractHandlerFeatures(funcNode, helperFns, vmState || {});
  const opcode = mapFeaturesToOpcode(features);
  
  if (opcode) {
    return opcode;
  }
  
  if (features.hasDoubleNestedAccess && features.readsIndex && features.pushCount >= 1 && features.popCount === 0) {
    return 'STACK_PUSH_STRING';
  }
  
  if (features.hasDoubleNestedAccess && features.pushCount >= 1 && features.readsIndex && !features.hasAssignment) {
    return 'LOAD_VARIABLE';
  }
  
  if (features.hasDoubleNestedAccess && features.hasAssignment && !features.pushCount) {
    return 'STORE_VARIABLE';
  }
  
  if (features.accessesArguments && features.readsIndex && features.pushCount >= 1) {
    return 'LOAD_ARGUMENT';
  }
  
  if (features.accessesThis && features.pushCount >= 1 && features.popCount === 0) {
    return 'LOAD_THIS';
  }
  
  return null;
}
