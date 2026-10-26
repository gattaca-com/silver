#!/usr/bin/env python3
"""Replay decoder mutations against the live generated-code and specification ties."""

from pathlib import Path
import re
import subprocess
import tempfile


LEAN = Path(__file__).resolve().parents[1]
DECLARATION = r"^(?:(?:private|noncomputable)\s+)?(?:def|abbrev|theorem)\s+"


def declaration(source, name):
    match = re.search(DECLARATION + re.escape(name) + r"\b.*?(?=" + DECLARATION + r"|\Z)",
                      source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing declaration: {name}")
    return match


def replace_in(source, name, pattern, replacement):
    match = declaration(source, name)
    changed, count = re.subn(pattern, replacement, match[0])
    if count != 1:
        raise AssertionError(f"{name}: expected one mutation site, found {count}")
    return source[:match.start()] + changed + source[match.end():]


def check(path, source, expected):
    path.write_text(source)
    result = subprocess.run(
        ["lake", "env", "lean", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
    )
    if not expected:
        if result.returncode != 0:
            raise AssertionError(f"positive control failed:\n{result.stdout}")
        print(f"{path.stem}: compiles")
        return

    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or len(errors) != len(expected)
            or re.search(r"timeout|heartbeat|maximum recursion depth|out of memory", result.stdout, re.I)):
        raise AssertionError(f"expected decoder proof errors, not another failure:\n{result.stdout}")
    for (line, message), (name, diagnostic) in zip(errors, expected):
        match = declaration(source, name)
        first = source.count("\n", 0, match.start()) + 1
        last = source.count("\n", 0, match.end()) + 1
        if not first <= int(line) <= last or not message.startswith(diagnostic):
            raise AssertionError(f"expected {name}: {diagnostic}, not another error:\n{result.stdout}")
    print(f"{path.stem}: rejected by " + ", ".join(name for name, _ in expected))


def main():
    zero_check = r"\bif\s+bytesVal\s+\(clearFlags\s+b\)\.toList\s*=\s*0\s+then\s+none\s+else\s+"
    cases = (
        ("Ordinary", "LeanBlsSimd/Portable/Decode/Ordinary.lean", "ordinary", zero_check,
         "if bytesVal (clearFlags b).toList  =  0 then none\n    else ", "",
         (("ordinary_refines", "unsolved goals"),)),
        ("Scott", "LeanBlsSimd/Portable/G1/Scott.lean", "scottComparison", r"-\s*ty\b",
         "- ty", "ty",
         (("is_minus_sigma_squared_fields", "unsolved goals"),
          ("comparison_iff", "Application type mismatch"))),
        ("G1Admission", "LeanBlsSimd/Refines/CheckedPoints.lean", "g1Spec",
         r"if\s+Kzg\.G1AffineValid\s+raw\s+then\s+some\s+raw\s+else\s+none",
         "if Kzg.G1AffineValid raw then\n    some raw else none", "some raw",
         (("g1_from_blst_some_iff", "Type mismatch"),)),
        ("G2Admission", "LeanBlsSimd/Refines/CheckedPoints.lean", "g2Spec",
         r"if\s+Kzg\.G2AffineValid\s+raw\s+then\s+some\s+raw\s+else\s+none",
         "if Kzg.G2AffineValid raw then\n    some raw else none", "some raw",
         (("g2_from_blst_some_iff", "Type mismatch"),)),
    )
    with tempfile.TemporaryDirectory(prefix="decoder-mutation-") as directory:
        for label, filename, name, pattern, formatting, mutation, expected in cases:
            original = (LEAN / filename).read_text()
            reformatted = replace_in(original, name, pattern, formatting)
            for variant, source in (("Original", original), ("Reformatted", reformatted)):
                check(Path(directory) / f"{label}{variant}.lean", source, ())
                check(Path(directory) / f"{label}{variant}Mutated.lean",
                      replace_in(source, name, pattern, mutation), expected)


if __name__ == "__main__":
    main()
