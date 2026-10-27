#!/usr/bin/env python3
"""Compare production Rust G2 literals with their Lean kernel certificates."""
import argparse
from pathlib import Path
import re


def validate(rust, lean):
    for source, target in (("G2_S_POW_CELL", "g2_s_pow_cell"),
                           ("G2_NEG_GENERATOR", "g2_neg_generator")):
        rust_match = re.search(r"pub const " + source + r":.*?\n};", rust, re.S)
        lean_match = re.search(r"^def " + target + r" :.*?(?=\n\n)", lean, re.S | re.M)
        if rust_match is None or lean_match is None:
            raise ValueError(f"missing literal declaration: {source}/{target}")
        source_words = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", rust_match[0])]
        target_words = [int(x, 16) for x in re.findall(r"(0x[0-9a-fA-F]+)#u64", lean_match[0])]
        if len(source_words) != 24 or source_words != target_words:
            raise ValueError(f"G2 literal differs: {source}/{target}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust", type=Path,
                        default=Path(__file__).resolve().parents[3] / "src/kzg/setup.rs")
    parser.add_argument("--lean", type=Path,
                        default=Path(__file__).resolve().parents[1] / "LeanBlsSimd/Kzg/SetupLiterals.lean")
    args = parser.parse_args()
    rust, lean = args.rust.read_text(), args.lean.read_text()
    validate(rust, lean)
    # Both source declarations are independently sensitive to a changed limb.
    for target in ("g2_s_pow_cell", "g2_neg_generator"):
        match = re.search(r"^def " + target + r" :.*?(0x[0-9a-fA-F]+)#u64", lean, re.S | re.M)
        assert match is not None
        mutated = lean[:match.start(1)] + hex(int(match[1], 16) ^ 1) + lean[match.end(1):]
        try:
            validate(rust, mutated)
        except ValueError:
            pass
        else:
            raise AssertionError(f"changed {target} limb was accepted")
    print("48 G2 literal limbs match Rust; both single-limb mutations rejected")


if __name__ == "__main__":
    main()
