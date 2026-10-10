# Project Scope

## Supported Language Subset

This analyzer works on a simplified, C-like subset. It is NOT a full C
compiler or parser — it intentionally supports only what is needed to
demonstrate compiler-integrated security analysis.

### Supported constructs
- Variable declarations: `int x;`, `char buffer[10];`
- Assignment: `x = 5;`, `buffer[2] = 'a';`
- Function calls: `gets(buffer);`, `strcpy(a, b);`, `execute(query);`
- String concatenation: `query = "SELECT..." + user;`
- Source functions treated as untrusted input: `input()`, `scanf()`
- Sink functions treated as dangerous if tainted data reaches them:
  `execute()`, `system()`, `eval()`

### NOT supported
- Pointers and pointer arithmetic
- Structs / classes
- Multi-file programs or `#include`
- Preprocessor macros
- Full C type system and type checking
- Loops and conditionals (parsed as statements only, not analyzed for
  control flow in this version)
- Interprocedural analysis (taint tracking does not cross function
  boundaries)

## Security Checks Implemented
1. Dangerous function detection (`gets`, `strcpy`, `sprintf`, `system`)
2. Hardcoded credential detection (pattern match on `password =`, `secret =`, etc.)
3. Array bounds checking (constant-index violations, via symbol table)
4. Taint analysis (source → propagation → sink tracking for SQL
   injection, command injection, code injection)
5. Risk scoring (weighted severity score with LOW/MEDIUM/HIGH labels)
6. Auto-fix (AST-level rewrite for `gets()` → `fgets()`)