import sys

from lexer import tokenize
from parser import Parser
from ast_nodes import Declaration, Assignment, FunctionCall
from semantic_analyzer import SymbolTable, BoundsChecker
from taint_analyzer import TaintAnalyzer
from security_rules import check_dangerous_functions, check_hardcoded_secret
from risk_scorer import compute_risk_score
from report_generator import generate_report


def analyze_file(filepath):
    with open(filepath) as f:
        source = f.read()
    source_lines = source.splitlines()

    tokens = tokenize(source)
    ast = Parser(tokens).parse_program()

    symtab = SymbolTable()
    for stmt in ast.statements:
        if isinstance(stmt, Declaration):
            symtab.declare(stmt)

    findings = []

    bounds_checker = BoundsChecker(symtab)
    for stmt in ast.statements:
        bounds_checker.check(stmt)
    findings += bounds_checker.findings

    taint_findings = TaintAnalyzer().analyze(ast.statements)
    findings += taint_findings

    for stmt in ast.statements:
        if isinstance(stmt, FunctionCall):
            result = check_dangerous_functions(stmt)
            if result:
                findings.append(result)
        if isinstance(stmt, Assignment):
            result = check_hardcoded_secret(stmt, source_lines[stmt.line - 1])
            if result:
                findings.append(result)

    score, label = compute_risk_score(findings)
    report = generate_report(findings, score, label)
    print(report)
    return findings, score, label


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 main.py <path_to_file>")
        sys.exit(1)
    analyze_file(sys.argv[1])