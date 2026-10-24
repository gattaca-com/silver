#!/usr/bin/env python3
"""Reject changes to the cyclotomic formula, inverse sign and Frobenius radix."""

from pathlib import Path
import re
import subprocess
import tempfile


LEAN = Path(__file__).resolve().parents[1]


def check(path, source, theorem=None):
    path.write_text(source)
    result = subprocess.run(
        ["lake", "env", "lean", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
    )
    if theorem is None:
        if result.returncode != 0:
            raise AssertionError(f"{path.stem}: positive control failed:\n{result.stdout}")
        print(f"{path.stem}: compiles", flush=True)
        return
    match = re.search(rf"^(?:private )?theorem {theorem}\b.*?(?=\n(?:private )?(?:theorem|def|end) |\Z)",
                      source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing theorem {theorem}")
    first = source.count("\n", 0, match.start()) + 1
    last = source.count("\n", 0, match.end()) + 1
    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or not any(first <= int(line) <= last for line, _ in errors)
            or re.search(r"timeout|heartbeat|recursion|out of memory|SIGKILL", result.stdout, re.I)):
        raise AssertionError(f"{path.stem}: expected failure in {theorem}:\n{result.stdout}")
    print(f"{path.stem}: {theorem} rejects the mutation", flush=True)


def main():
    cases = [
        ("Pair", "LeanBlsSimd/Spec/Cyclotomic/Schedule.lean",
         "fp4Square xi x.c10 x.c02", "fp4Square xi x.c10 x.c01", "raw_c"),
        ("Sign", "LeanBlsSimd/Spec/Cyclotomic/Schedule.lean",
         "plus (xi * t2.2) x.c10", "less (xi * t2.2) x.c10", "raw_b"),
        ("Inverse", "LeanBlsSimd/Spec/Fp12.lean",
         "-(b * (a * a - (b * b) * Fp6Field.v)⁻¹)",
         "(b * (a * a - (b * b) * Fp6Field.v)⁻¹)", "inv_mk"),
        ("Radix", "LeanBlsSimd/Refines/FrobeniusConstants.lean",
         "limbValue 52 (laneRow j 0) = (words j).1 * 2^416 % p",
         "limbValue 52 (laneRow j 0) = (words j).1 * 2^384 % p", "table_certificates"),
    ]
    with tempfile.TemporaryDirectory(prefix="tower-mutation-") as directory:
        checked = set()
        for label, filename, old, new, theorem in cases:
            original = (LEAN / filename).read_text()
            if original.count(old) != 1:
                raise AssertionError(f"{label}: expected one mutation site")
            for suffix, source in (("Original", original),
                                   ("Reformatted", original.replace("\n\n", "\n\n\n"))):
                if (filename, suffix) not in checked:
                    check(Path(directory) / f"{label}{suffix}.lean", source)
                    checked.add((filename, suffix))
                check(Path(directory) / f"{label}{suffix}Mutated.lean",
                      source.replace(old, new), theorem)


if __name__ == "__main__":
    main()
