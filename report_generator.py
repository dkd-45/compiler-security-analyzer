import json


def generate_report(findings, risk_score, risk_label):
    lines = ["Security Analysis Report", "=" * 40, f"Risk Score: {risk_score} ({risk_label})", ""]
    for f in sorted(findings, key=lambda x: x["line"]):
        lines.append(f"⚠ {f['type']} — Line {f['line']}")
        lines.append(f"  {f['message']}")
        lines.append(f"  Severity: {f['severity']}")
        lines.append(f"  Suggestion: {f['suggestion']}")
        lines.append("")
    return "\n".join(lines)


def generate_json_report(findings, risk_score, risk_label):
    return json.dumps(
        {"risk_score": risk_score, "risk_label": risk_label, "findings": findings},
        indent=2
    )


if __name__ == "__main__":
    sample_findings = [{
        "line": 2,
        "type": "Buffer Overflow",
        "severity": "HIGH",
        "message": "'gets()' is unsafe and may cause buffer overflow.",
        "suggestion": "Use fgets(buf, size, stdin) instead."
    }]
    print(generate_report(sample_findings, 5, "LOW RISK"))