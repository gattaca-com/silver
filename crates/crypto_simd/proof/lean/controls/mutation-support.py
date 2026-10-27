#!/usr/bin/env python3
"""Shared compilation and rejection checks for generated-code mutations."""

from pathlib import Path
import re
import subprocess


LEAN = Path(__file__).resolve().parents[1]
GENERATED = LEAN / "LeanBlsSimd/Extracted/Funs.lean"
DECLARATION = r"^(?:@\[simp\]\s+)?(?:private\s+)?(?:def|theorem)\s+"


def generated_declaration(name):
    source = GENERATED.read_text()
    match = re.search(r"^def " + re.escape(name) + r"\b.*?(?=\n/--|\Z)", source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing generated declaration {name}")
    return match[0].strip()


def check(path, source, expected=None):
    path.write_text(source)
    result = subprocess.run(
        ["lake", "env", "lean", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180,
    )
    if expected is None:
        if result.returncode != 0:
            raise AssertionError(f"{path.stem}: positive control failed:\n{result.stdout}")
        print(f"{path.stem}: compiles", flush=True)
        return
    theorem = re.search(DECLARATION + re.escape(expected) + r"\b.*?(?=" + DECLARATION + r"|\Z)",
                        source, re.M | re.S)
    if theorem is None:
        raise AssertionError(f"missing proof {expected}")
    first = source.count("\n", 0, theorem.start()) + 1
    last = source.count("\n", 0, theorem.end()) + 1
    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or not any(first <= int(line) <= last for line, _ in errors)
            or re.search(r"timeout|heartbeat|recursion|out of memory|SIGKILL", result.stdout, re.I)):
        raise AssertionError(f"{path.stem}: expected rejection by {expected}:\n{result.stdout}")
    print(f"{path.stem}: {expected} rejects the generated mutation", flush=True)
