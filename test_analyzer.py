from main import analyze_file


def test_gets_detected():
    findings, score, label = analyze_file("test_cases/buffer_overflow.c")
    assert any(f["type"] == "Buffer Overflow" for f in findings), "gets() should be flagged"
    print("PASS: test_gets_detected")


def test_sql_injection_detected():
    findings, score, label = analyze_file("test_cases/sql_injection.c")
    assert any(f["type"] == "SQL Injection" for f in findings), "SQL injection should be flagged"
    print("PASS: test_sql_injection_detected")


def test_hardcoded_password_detected():
    findings, score, label = analyze_file("test_cases/hardcoded_password.c")
    assert any(f["type"] == "Hardcoded Credential" for f in findings), "hardcoded password should be flagged"
    print("PASS: test_hardcoded_password_detected")


def test_array_bounds_detected():
    findings, score, label = analyze_file("test_cases/array_bounds.c")
    assert any(f["type"] == "Buffer Overflow" for f in findings), "out-of-bounds index should be flagged"
    print("PASS: test_array_bounds_detected")


def test_safe_code_clean():
    findings, score, label = analyze_file("test_cases/safe_code.c")
    assert len(findings) == 0, "safe code should have zero findings"
    assert label == "SAFE", "safe code should be labeled SAFE"
    print("PASS: test_safe_code_clean")


if __name__ == "__main__":
    test_gets_detected()
    test_sql_injection_detected()
    test_hardcoded_password_detected()
    test_array_bounds_detected()
    test_safe_code_clean()
    print("\nAll tests passed.")