from ast_nodes import Assignment, FunctionCall, BinaryOp, Identifier

SOURCES = {"input", "scanf", "gets"}
SINKS = {
    "execute": "SQL Injection",
    "system": "Command Injection",
    "eval": "Code Injection",
}


class TaintAnalyzer:
    def __init__(self):
        self.tainted = {}
        self.findings = []

    def analyze(self, statements):
        for stmt in statements:
            self._visit(stmt)
        return self.findings

    def _visit(self, stmt):
        if isinstance(stmt, Assignment):
            self._visit_assignment(stmt)
        elif isinstance(stmt, FunctionCall):
            self._check_sink(stmt)

    def _visit_assignment(self, stmt):
        if self._expr_is_tainted(stmt.value):
            origin_name = self._first_tainted_name(stmt.value)
            origin = self.tainted.get(origin_name, [stmt.line, stmt.line])
            self.tainted[stmt.target] = [stmt.line, origin[1]]
        if isinstance(stmt.value, FunctionCall) and stmt.value.name in SOURCES:
            self.tainted[stmt.target] = [stmt.line, stmt.line]

    def _expr_is_tainted(self, expr):
        if isinstance(expr, Identifier):
            return expr.name in self.tainted
        if isinstance(expr, BinaryOp):
            return self._expr_is_tainted(expr.left) or self._expr_is_tainted(expr.right)
        if isinstance(expr, FunctionCall):
            return expr.name in SOURCES
        return False

    def _first_tainted_name(self, expr):
        if isinstance(expr, Identifier) and expr.name in self.tainted:
            return expr.name
        if isinstance(expr, BinaryOp):
            return self._first_tainted_name(expr.left) or self._first_tainted_name(expr.right)
        return None

    def _check_sink(self, call):
        if call.name in SINKS:
            for arg in call.args:
                name = arg.name if isinstance(arg, Identifier) else self._first_tainted_name(arg)
                if name and name in self.tainted:
                    origin_line = self.tainted[name][1]
                    self.findings.append({
                        "line": call.line,
                        "type": SINKS[call.name],
                        "severity": "HIGH",
                        "message": f"Tainted variable '{name}' (from line {origin_line}) "
                                   f"reaches sink '{call.name}' at line {call.line}",
                        "suggestion": "Sanitize or use parameterized queries before this call.",
                        "taint_path": [origin_line, call.line]
                    })


if __name__ == "__main__":
    from lexer import tokenize
    from parser import Parser

    sample = 'user = input();\nquery = user;\nexecute(query);'
    tokens = tokenize(sample)
    ast = Parser(tokens).parse_program()

    findings = TaintAnalyzer().analyze(ast.statements)
    for f in findings:
        print(f)