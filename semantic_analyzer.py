from ast_nodes import Declaration, Assignment, FunctionCall, Literal, Identifier


class SymbolTable:
    def __init__(self):
        self.symbols = {}

    def declare(self, decl):
        self.symbols[decl.name] = {
            "type": decl.var_type,
            "array_size": decl.array_size,
            "line": decl.line
        }

    def lookup(self, name):
        return self.symbols.get(name)


class BoundsChecker:
    def __init__(self, symtab):
        self.symtab = symtab
        self.findings = []

    def check(self, node):
        if isinstance(node, Assignment) and node.index is not None:
            self._check_index(node)
        if isinstance(node, FunctionCall):
            self._check_call(node)

    def _check_index(self, node):
        info = self.symtab.lookup(node.target)
        if info and info["array_size"] is not None:
            if isinstance(node.index, Literal) and isinstance(node.index.value, int):
                if node.index.value >= info["array_size"] or node.index.value < 0:
                    self.findings.append({
                        "line": node.line,
                        "type": "Buffer Overflow",
                        "severity": "HIGH",
                        "message": f"Index {node.index.value} out of bounds for "
                                   f"'{node.target}' (size {info['array_size']})",
                        "suggestion": "Check array bounds before indexing."
                    })

    def _check_call(self, node):
        if node.name == "strcpy" and len(node.args) == 2:
            target_name = node.args[0].name if isinstance(node.args[0], Identifier) else None
            info = self.symtab.lookup(target_name) if target_name else None
            src = node.args[1]
            if info and info["array_size"] and isinstance(src, Literal) and isinstance(src.value, str):
                if len(src.value) >= info["array_size"]:
                    self.findings.append({
                        "line": node.line,
                        "type": "Buffer Overflow",
                        "severity": "HIGH",
                        "message": f"strcpy source string ({len(src.value)} chars) "
                                   f"exceeds destination '{target_name}' size "
                                   f"({info['array_size']})",
                        "suggestion": "Use strncpy with explicit length."
                    })


if __name__ == "__main__":
    from lexer import tokenize
    from parser import Parser

    sample = 'char buffer[10];\nbuffer[15] = 1;'
    tokens = tokenize(sample)
    ast = Parser(tokens).parse_program()

    symtab = SymbolTable()
    for stmt in ast.statements:
        if isinstance(stmt, Declaration):
            symtab.declare(stmt)

    checker = BoundsChecker(symtab)
    for stmt in ast.statements:
        checker.check(stmt)

    for finding in checker.findings:
        print(finding)