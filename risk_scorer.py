SEVERITY_WEIGHT = {"LOW": 1, "MEDIUM": 3, "HIGH": 5}


def compute_risk_score(findings):
    total = sum(SEVERITY_WEIGHT[f["severity"]] for f in findings)
    if total == 0:
        return 0, "SAFE"
    if total <= 5:
        return total, "LOW RISK"
    if total <= 12:
        return total, "MEDIUM RISK"
    return total, "HIGH RISK"


if __name__ == "__main__":
    sample_findings = [
        {"severity": "HIGH"},
        {"severity": "HIGH"},
        {"severity": "MEDIUM"},
    ]
    score, label = compute_risk_score(sample_findings)
    print(f"Score: {score}, Label: {label}")