#!/usr/bin/env python3
"""Check that the portable finish proof rejects skipping a rejected-round refill."""

from pathlib import Path
import re
import subprocess
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SOURCE = LEAN / "LeanBlsSimd/Portable/Msm/Finish.lean"
REFILL = r"next\.buckets\.fill\s+\(alloc\.vec\.Vec\.deref\s+next\.halves\)\s+127#usize"


def replace_refill(source, replacement):
    match = re.search(r"^def finish\b.*?(?=^theorem )", source, re.M | re.S)
    if match is None:
        raise AssertionError("missing portable finish schedule")
    changed, count = re.subn(REFILL, replacement, match[0])
    if count != 1:
        raise AssertionError(f"expected one refill, found {count}")
    return source[:match.start()] + changed + source[match.end():]


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
    first = source.count("\n", 0, source.index("theorem finish_correct")) + 1
    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or len(errors) != 1 or int(errors[0][0]) < first
            or errors[0][1] != "unsolved goals"
            or re.search(r"timeout|heartbeat|recursion|out of memory", result.stdout, re.I)):
        raise AssertionError(f"expected finish_correct's proof failure:\n{result.stdout}")
    print(f"{path.stem}: finish_correct rejects an omitted refill with unsolved goals")


def main():
    original = SOURCE.read_text()
    reformatted = replace_refill(original,
        "next.buckets.fill\n      (alloc.vec.Vec.deref next.halves) 127#usize")
    with tempfile.TemporaryDirectory(prefix="msm-mutation-") as directory:
        for label, source in (("Original", original), ("Reformatted", reformatted)):
            check(Path(directory) / f"{label}.lean", source, False)
            check(Path(directory) / f"{label}Mutated.lean",
                  replace_refill(source, "ok next.buckets"), True)


if __name__ == "__main__":
    main()
