#!/usr/bin/env python3
"""Check G2 differential value, infinity and parser failure boundaries.

Invoked by check_g1_controls.py so the existing CI command checks both groups.
Run this script directly to check G2 alone.
"""

import argparse
from pathlib import Path
import subprocess
import tempfile


def controls(fixture: Path) -> dict[str, tuple[str, int, tuple[str, ...]]]:
    lines = [line.strip() for line in fixture.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith("#")]
    batches = []
    for index, kind in enumerate(("edge-members", "edge-infinity-canonical")):
        start = next(i for i, line in enumerate(lines)
                     if line.startswith("batch ") and line.split()[2] == kind)
        stop = lines.index("end", start)
        batch = lines[start:stop + 1]
        batch[0] = f"batch {index} {kind}"
        batches.append(batch)
    recorded = [next(line.split()[2:] for line in batch if line.startswith("blst 0 "))
                for batch in batches]
    assert all(len(words) == 24 for words in recorded), "controls need accepted points"
    assert all(int(word, 16) == 0 for word in recorded[1]), "infinity must have zero limbs"
    assert "undecided ff" in batches[1], "infinity must exercise an undecided lane"
    base = ["seed control", "batches 2", *batches[0], *batches[1], "wrappers 1",
            "wrapper 0 control 3", "ref 0 0", "ref 1 0", "ref 0 1",
            "out 0 " + " ".join(recorded[0]), "out 1 " + " ".join(recorded[1]),
            next(line.replace("blst 1", "out 2", 1) for line in batches[0]
                 if line.startswith("blst 1 ")), "end", "endfile"]
    good = "# formatting control\n\n" + "\n\n".join(f"  {line}  " for line in base) + "\n"
    bad = []
    for line in base:
        parts = line.split()
        if parts[0] == "valid":
            parts[1] = f"{int(parts[1], 16) ^ 1:02x}"
        elif parts[:2] in (["pt", "0"], ["blst", "0"], ["out", "0"]):
            mask = 2 if parts[0] == "out" else 1
            parts[2] = f"{int(parts[2], 16) ^ mask:x}"
        bad.append(" ".join(parts))
    text = "\n".join(base) + "\n"
    return {
        "formatting": (good, 0, ("all G2 values match",)),
        "values": ("\n".join(bad) + "\n", 1,
                   ("MISMATCH G2 model batch 0", "MISMATCH G2 extraction batch 0",
                    "MISMATCH G2 spec/blst batch 0", "MISMATCH G2 spec/blst batch 1",
                    "MISMATCH G2 wrapper 0")),
        "truncated": ("\n".join(base[:-1]) + "\n", 2, ("unexpected end of file",)),
        "reference": (text.replace("ref 0 0", "ref 2 0"), 2, ("reference out of range",)),
        "lane": (text.replace("ref 0 0", "ref 0 8"), 2, ("reference out of range",)),
        "missing_wrappers": (text[:text.index("wrappers 1")] + "wrappers 0\nendfile\n",
                             2, ("no wrapper cases",)),
        "count": (text.replace("wrappers 1", "wrappers 2"), 2,
                  ("expected `wrapper <index> <kind> <length>`",)),
        "point_length": (text.replace("out 0 " + " ".join(recorded[0]), "out 0 0"),
                         2, ("expected 24 point words",)),
        "trailing": (text + "extra\n", 2, ("text after endfile",)),
    }


def main() -> None:
    lean = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=lean / ".lake/build/bin/differential")
    parser.add_argument("--fixture", type=Path, default=lean.parent / "decompress_g2_vectors.txt")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="g2-differential-controls-") as directory:
        for name, (contents, expected, markers) in controls(args.fixture).items():
            path = Path(directory) / f"{name}.txt"
            path.write_text(contents)
            result = subprocess.run([str(args.binary.resolve()), str(path)],
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=180, check=False)
            print(f"G2 {name}: exit {result.returncode}")
            print(result.stdout, end="")
            if result.returncode != expected or any(marker not in result.stdout for marker in markers):
                raise SystemExit(f"G2 {name}: expected exit {expected} and diagnostics {markers!r}")
    print("all G2 differential controls passed")


if __name__ == "__main__":
    main()
