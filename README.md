# Compiler Security Analyzer

A compiler-integrated static security analyzer that uses lexical analysis,
parsing, AST construction, and symbol-table-based semantic analysis to
detect common security vulnerabilities in source code — before execution.

## Why this is different from a regular linter

Most static analysis tools (Cppcheck, Semgrep, Flawfinder) pattern-match
over raw text. This project performs its checks as phases of a compiler
pipeline — using the AST and symbol table the same way a real compiler
would — and adds taint analysis to track untrusted data from source to
sink, rather than just flagging dangerous function names in isolation.

## Pipeline
Source Code
|
Lexical Analysis (lexer.py)
|
Parsing (parser.py) -> AST (ast_nodes.py)
|
Semantic Analysis (semantic_analyzer.py) -> Symbol Table + Bounds Checks
|
Taint Analysis (taint_analyzer.py) -> Source-to-Sink Tracking
|
Security Rules (security_rules.py) -> Dangerous Functions, Hardcoded Secrets
|
Risk Scoring (risk_scorer.py)
|
Report Generation (report_generator.py)
|
Auto-Fix (autofix.py)


## How to run
python3 main.py test_cases/buffer_overflow.c


## How to run tests
python3 test_analyzer.py


## Project structure

- `lexer.py` — tokenizer
- `ast_nodes.py` — AST node definitions
- `parser.py` — recursive descent parser
- `semantic_analyzer.py` — symbol table + array bounds checking
- `taint_analyzer.py` — taint tracking for injection vulnerabilities
- `security_rules.py` — dangerous function + hardcoded secret detection
- `risk_scorer.py` — weighted risk scoring
- `report_generator.py` — text and JSON report output
- `autofix.py` — AST-level auto-fix for unsafe calls
- `main.py` — full pipeline entry point
- `test_analyzer.py` — automated test suite
- `test_cases/` — sample vulnerable and safe code files
- `SCOPE.md` — exact language subset and feature scope

## Limitations

See `SCOPE.md` for the full list of what this analyzer does and does not
support.