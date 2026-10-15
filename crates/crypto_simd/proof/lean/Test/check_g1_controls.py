#!/usr/bin/env python3
"""Check the differential CLI's value and parsing failure boundaries.

Run after `lake build differential`: python3 Test/check_g1_controls.py.
The positive control permits comments, blank lines, and surrounding whitespace.
Negative controls require rejection of corrupt kernel/spec/wrapper values,
truncated input, and out-of-range references.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile


def controls(fixture: Path) -> dict[str, tuple[str, int, tuple[str, ...]]]:
    lines = [line.strip() for line in fixture.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    start = next(i for i, line in enumerate(lines) if line.startswith("batch "))
    stop = lines.index("end", start)
    batch = lines[start:stop + 1]
    assert batch[0].split()[1] == "0", "fixture must start at batch 0"
    recorded = next(line.split()[2:] for line in batch if line.startswith("blst 0 "))
    assert len(recorded) == 12, "control needs a successful scalar verdict"
    base = ["seed control", "batches 1", *batch, "wrappers 1",
            "wrapper 0 control 1", "ref 0 0", "out 0 " + " ".join(recorded),
            "end", "endfile"]
    good = "# formatting control\n\n" + "\n\n".join(f"  {line}  " for line in base) + "\n"
    bad = []
    for line in base:
        parts = line.split()
        if parts[0] == "valid":
            parts[1] = f"{int(parts[1], 16) ^ 1:x}"
        elif parts[:2] in (["pt", "0"], ["blst", "0"], ["out", "0"]):
            # Give the oracle and expected wrapper distinct corruptions.
            mask = 2 if parts[0] == "out" else 1
            parts[2] = f"{int(parts[2], 16) ^ mask:x}"
        bad.append(" ".join(parts))
    return {
        "formatting": (good, 0, ("all G1 values match",)),
        "values": ("\n".join(bad) + "\n", 1,
                   ("MISMATCH G1 model batch 0", "MISMATCH G1 extraction batch 0",
                    "MISMATCH G1 spec/blst batch 0", "MISMATCH G1 wrapper 0")),
        "truncated": ("\n".join(base[:-1]) + "\n", 2, ("unexpected end of file",)),
        "reference": ("\n".join(base).replace("ref 0 0", "ref 1 0") + "\n",
                      2, ("reference out of range",)),
    }


def main() -> None:
    lean = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=lean / ".lake/build/bin/differential")
    parser.add_argument("--fixture", type=Path, default=lean.parent / "decompress_g1_vectors.txt")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="g1-differential-controls-") as directory:
        for name, (contents, expected, markers) in controls(args.fixture).items():
            path = Path(directory) / f"{name}.txt"
            path.write_text(contents)
            result = subprocess.run([str(args.binary.resolve()), "--g1", str(path)],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=120, check=False)
            print(f"{name}: exit {result.returncode}")
            print(result.stdout, end="")
            if result.returncode != expected or any(marker not in result.stdout for marker in markers):
                raise SystemExit(f"{name}: expected exit {expected} and diagnostics {markers!r}")
    print("all G1 differential controls passed")


if __name__ == "__main__":
    main()
