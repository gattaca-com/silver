#!/usr/bin/env python3
"""Replay a SHA round mutation against the actual specification proof source."""

from pathlib import Path
import re
import subprocess
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SOURCE = LEAN / "LeanBlsSimd/Spec/Sha256.lean"


def replace_round_operand(source, replacement):
    declaration = re.search(r"^def round\b.*?(?=^def )", source, re.M | re.S)
    if declaration is None:
        raise AssertionError("missing SHA round declaration")
    changed, count = re.subn(r"\bd\s*\+\s*t1\b", replacement, declaration[0])
    if count != 1:
        raise AssertionError(f"expected one round d+t1 operand, found {count}")
    return source[:declaration.start()] + changed + source[declaration.end():]


def check(path, source, mutated):
    path.write_text(source)
    result = subprocess.run(
        ["lake", "env", "lean", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
    )
    if not mutated:
        if result.returncode != 0:
            raise AssertionError(f"positive control failed:\n{result.stdout}")
        print(f"{path.stem}: compiles")
        return

    theorem = re.search(r"^theorem compressBlock_eq\b.*?(?=^def )", source, re.M | re.S)
    if theorem is None:
        raise AssertionError("missing compressBlock_eq proof")
    first = source.count("\n", 0, theorem.start()) + 1
    last = source.count("\n", 0, theorem.end()) + 1
    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or len(errors) != 1
            or not first <= int(errors[0][0]) <= last
            or errors[0][1] != "unsolved goals"
            or re.search(r"timeout|maximum recursion depth", result.stdout, re.I)):
        raise AssertionError(f"expected compressBlock_eq's unsolved goal, not another failure:\n{result.stdout}")
    print(f"{path.stem}: compressBlock_eq rejects d+t1 -> c+t1 with unsolved goals")


def main():
    original = SOURCE.read_text()
    reformatted = replace_round_operand(original, "d + t1")
    with tempfile.TemporaryDirectory(prefix="sha-mutation-") as directory:
        for label, source in (("Original", original), ("Reformatted", reformatted)):
            check(Path(directory) / f"{label}.lean", source, mutated=False)
            check(Path(directory) / f"{label}Mutated.lean",
                  replace_round_operand(source, "c+t1"), mutated=True)


if __name__ == "__main__":
    main()
