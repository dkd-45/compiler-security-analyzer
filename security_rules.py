import re
from ast_nodes import Literal

DANGEROUS_FUNCTIONS = {
    "gets":    ("Buffer Overflow", "HIGH", "Use fgets(buf, size, stdin) instead."),
    "strcpy":  ("Buffer Overflow", "MEDIUM", "Use strncpy with explicit length."),
    "sprintf": ("Buffer Overflow", "MEDIUM", "Use snprintf with size limit."),
    "system":  ("Command Injection", "HIGH", "Avoid system(); use safer APIs."),
}

PASSWORD_PATTERN = re.compile(r'(password|passwd|pwd|secret|api_key)\s*=', re.IGNORECASE)


def check_dangerous_functions(call_node):
    if call_node.name in DANGEROUS_FUNCTIONS:
        category, severity, fix = DANGEROUS_FUNCTIONS[call_node.name]
        return {
            "line": call_node.line,
            "type": category,
            "severity": severity,
            "message": f"'{call_node.name}()' is unsafe and may cause {category.lower()}.",
            "suggestion": fix
        }
    return None


def check_hardcoded_secret(assignment_node, raw_source_line):
    if PASSWORD_PATTERN.search(raw_source_line) and isinstance(assignment_node.value, Literal):
        return {
            "line": assignment_node.line,
            "type": "Hardcoded Credential",
            "severity": "HIGH",
            "message": f"Hardcoded secret assigned to '{assignment_node.target}'.",
            "suggestion": "Load secrets from environment variables or a secrets manager."
        }
    return None


if __name__ == "__main__":
    from lexer import tokenize
    from parser import Parser
    from ast_nodes import FunctionCall, Assignment

    sample = 'gets(buffer);\npassword = "12345";'
    source_lines = sample.splitlines()
    tokens = tokenize(sample)
    ast = Parser(tokens).parse_program()

    for stmt in ast.statements:
        if isinstance(stmt, FunctionCall):
            result = check_dangerous_functions(stmt)
            if result:
                print(result)
        if isinstance(stmt, Assignment):
            result = check_hardcoded_secret(stmt, source_lines[stmt.line - 1])
            if result:
                print(result)