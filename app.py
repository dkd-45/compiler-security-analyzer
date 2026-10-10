from flask import Flask, request, jsonify, render_template_string

from lexer import tokenize
from parser import Parser
from ast_nodes import Declaration, Assignment, FunctionCall
from semantic_analyzer import SymbolTable, BoundsChecker
from taint_analyzer import TaintAnalyzer
from security_rules import check_dangerous_functions, check_hardcoded_secret
from risk_scorer import compute_risk_score

app = Flask(__name__)

HTML_PAGE = """
<!DOCTYPE html>
<html>
<head>
  <title>Compiler Security Analyzer</title>
  <style>
    body { font-family: monospace; max-width: 800px; margin: 40px auto; }
    textarea { width: 100%; height: 200px; font-family: monospace; font-size: 14px; }
    button { padding: 10px 20px; font-size: 16px; margin-top: 10px; cursor: pointer; }
    .finding { border-left: 4px solid #cc0000; padding: 8px; margin: 8px 0; background: #fff0f0; }
    .score { font-size: 20px; font-weight: bold; margin: 10px 0; }
  </style>
</head>
<body>
  <h1>Compiler Security Analyzer</h1>
  <textarea id="code" placeholder="Paste code here, e.g.:&#10;char buffer[10];&#10;gets(buffer);"></textarea>
  <br>
  <button onclick="analyze()">Analyze</button>
  <div id="output"></div>

  <script>
    async function analyze() {
      const code = document.getElementById('code').value;
      const res = await fetch('/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({code: code})
      });
      const data = await res.json();
      let html = `<div class="score">Risk Score: ${data.risk_score} (${data.risk_label})</div>`;
      if (data.error) {
        html += `<div class="finding">Parse error: ${data.error}</div>`;
      } else if (data.findings.length === 0) {
        html += `<div>No issues found.</div>`;
      } else {
        for (const f of data.findings) {
          html += `<div class="finding">
            <b>${f.type}</b> - Line ${f.line} - Severity: ${f.severity}<br>
            ${f.message}<br>
            <i>Suggestion: ${f.suggestion}</i>
          </div>`;
        }
      }
      document.getElementById('output').innerHTML = html;
    }
  </script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/analyze", methods=["POST"])
def analyze():
    code = request.json.get("code", "")
    try:
        tokens = tokenize(code)
        ast = Parser(tokens).parse_program()
    except SyntaxError as e:
        return jsonify({"error": str(e), "findings": [], "risk_score": 0, "risk_label": "ERROR"})

    source_lines = code.splitlines()
    symtab = SymbolTable()
    for stmt in ast.statements:
        if isinstance(stmt, Declaration):
            symtab.declare(stmt)

    findings = []
    bounds_checker = BoundsChecker(symtab)
    for stmt in ast.statements:
        bounds_checker.check(stmt)
    findings += bounds_checker.findings

    findings += TaintAnalyzer().analyze(ast.statements)

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
    return jsonify({"findings": findings, "risk_score": score, "risk_label": label})


if __name__ == "__main__":
    app.run(debug=True, port=5000)