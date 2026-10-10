def autofix(source_lines, findings):
    fixed = list(source_lines)
    for f in findings:
        line_idx = f["line"] - 1
        if line_idx < 0 or line_idx >= len(fixed):
            continue
        if "gets(" in fixed[line_idx]:
            var = fixed[line_idx].split("gets(")[1].split(")")[0]
            fixed[line_idx] = fixed[line_idx].replace(
                f"gets({var})", f"fgets({var}, sizeof({var}), stdin)"
            )
    return fixed


if __name__ == "__main__":
    from main import analyze_file

    with open("test_cases/buffer_overflow.c") as f:
        source_lines = f.read().splitlines()

    findings, score, label = analyze_file("test_cases/buffer_overflow.c")
    fixed_lines = autofix(source_lines, findings)

    print("\n--- Original ---")
    print("\n".join(source_lines))
    print("\n--- Fixed ---")
    print("\n".join(fixed_lines))