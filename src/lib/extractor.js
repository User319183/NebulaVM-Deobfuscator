import { parse } from '@babel/parser';
import _traverse from '@babel/traverse';
import { decodeBytecode, decodeStringsBytes } from '../runtime/bytecodeReader.js';
import {
  findHelperFunctionsAST,
  findVMStateProperties,
  analyzeHandlerStructure
} from '../analysis/interpreterAnalyzer.js';

const traverse = typeof _traverse === 'object' ? _traverse.default : _traverse;

export function extractFromCode(code) {
  let bytecodeBase64 = null;
  let stringsBytes = null;
  let opcodeMap = {};
  let returnOpcode = null;
  
  let ast;
  let helperFns = {
    push: 't',
    pop: 'o',
    readDword: 'I',
    readInstr: 'r',
  };
  let vmState = {};
  
  const returnMatchRight = code.match(/===\s*(\d+)\s*\)/);
  const returnMatchLeft = code.match(/\((\d+)\s*===/);
  const returnMatch = returnMatchRight || returnMatchLeft;
  if (returnMatch) {
    returnOpcode = parseInt(returnMatch[1], 10);
    opcodeMap[returnOpcode] = 'RETURN';
  }

  try {
    ast = parse(code, { sourceType: 'script' });
    
    helperFns = findHelperFunctionsAST(ast);
    vmState = findVMStateProperties(ast);

    traverse(ast, {
      CallExpression(path) {
        const callee = path.node.callee;
        const isFunctionCallee = callee.type === 'FunctionExpression' || 
                                  callee.type === 'ArrowFunctionExpression';
        
        if (isFunctionCallee && path.node.arguments.length >= 1) {
          const args = path.node.arguments;
          
          for (const arg of args) {
            if (arg.type === 'StringLiteral' && arg.value.length > 50 && 
                /^[A-Za-z0-9+/=]+$/.test(arg.value) && !bytecodeBase64) {
              bytecodeBase64 = arg.value;
            }
            if (arg.type === 'ArrayExpression' && arg.elements.length > 10 && !stringsBytes) {
              const allNumbers = arg.elements.every(el => 
                !el || el.type === 'NumericLiteral' || 
                (el.type === 'UnaryExpression' && el.operator === '-')
              );
              if (allNumbers) {
                stringsBytes = arg.elements.map(el => {
                  if (!el) return 0;
                  if (el.type === 'NumericLiteral') return el.value;
                  if (el.type === 'UnaryExpression' && el.operator === '-' && 
                      el.argument.type === 'NumericLiteral') {
                    return -el.argument.value;
                  }
                  return 0;
                });
              }
            }
          }
        }
      },

      ObjectExpression(path) {
        const props = path.node.properties;
        if (props.length < 3) return;

        const hasNumericKeys = props.filter(p => 
          p.key && p.key.type === 'NumericLiteral' && 
          p.value && p.value.type === 'FunctionExpression'
        ).length >= 3;

        if (!hasNumericKeys) return;

        for (const prop of props) {
          if (prop.key && prop.key.type === 'NumericLiteral' && 
              prop.value && prop.value.type === 'FunctionExpression') {
            const opcode = prop.key.value;
            
            if (opcode in opcodeMap) continue;
            
            try {
              const identified = analyzeHandlerStructure(prop.value, helperFns, vmState);
              
              if (identified) {
                opcodeMap[opcode] = identified;
              }
            } catch (e) {
            }
          }
        }
      },
    });

  } catch (e) {
    const bytecodeMatch = code.match(/\("([A-Za-z0-9+/=]{20,})"/);
    if (bytecodeMatch) {
      bytecodeBase64 = bytecodeMatch[1];
    }
    
    const stringsMatch = code.match(/\[([\d,\s-]+)\]\s*\)/);
    if (stringsMatch) {
      stringsBytes = stringsMatch[1].split(',').map(s => parseInt(s.trim(), 10) || 0);
    }
  }

  if (!bytecodeBase64) {
    const fallbackMatch = code.match(/\("([A-Za-z0-9+/=]{20,})"/);
    if (fallbackMatch) {
      bytecodeBase64 = fallbackMatch[1];
    }
  }

  if (!bytecodeBase64) {
    throw new Error('Could not extract bytecode from obfuscated code');
  }

  const bytecode = decodeBytecode(bytecodeBase64);

  const strings = stringsBytes && stringsBytes.length > 0 ? decodeStringsBytes(stringsBytes) : [];

  return {
    bytecode,
    strings,
    opcodeMap,
    returnOpcode
  };
}
