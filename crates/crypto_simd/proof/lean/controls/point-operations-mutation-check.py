#!/usr/bin/env python3
"""Check scalar interpretation and opaque point-operation wiring against their contracts."""

from pathlib import Path
import re
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
helpers = runpy.run_path(str(LEAN / "controls/decoder-mutation-check.py"))
declaration = helpers["declaration"]
replace_in = helpers["replace_in"]
check = helpers["check"]


def body(source, name):
    return re.split(r"(?m)^example\b|^end ", declaration(source, name)[0], maxsplit=1)[0].rstrip() + "\n\n"


def main():
    externals = (LEAN / "LeanBlsSimd/Extracted/FunsExternal.lean").read_text()
    contracts = (LEAN / "LeanBlsSimd/Refines/PointOperations.lean").read_text()
    controls = (LEAN / "controls/PointOperations.lean").read_text()
    prefix = """import LeanBlsSimd.Refines.PointOperations
open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls LeanBlsSimd LeanBlsSimd.PointOperations
open EthLib.Cryptography.Bls
namespace PointOperationMutation
"""
    cases = []
    scalar = prefix + body(contracts, "scalar64")
    for theorem in ("scalar_little_endian", "scalar_max"):
        scalar += body(controls, theorem).replace("PointOperations.scalar64", "scalar64")
    cases.append(("ScalarEndian", scalar, "scalar64", r"256\s*\*\s*acc", "255 * acc",
                  (("scalar_little_endian", "Tactic `decide` proved that the proposition"),
                   ("scalar_max", "Tactic `decide` proved that the proposition"))))

    for group in ("g1", "g2"):
        method = f"{group}_point.{group.upper()}Point.weighted_sum"
        full = "silver_crypto_simd.bls." + method
        definition = body(externals, full).replace(full, "weightedSum")
        length_theorem = f"{group}_weighted_sum_length_mismatch"
        source = prefix + definition + body(contracts, length_theorem).replace(method, "weightedSum")
        cases.append((f"{group.upper()}Length", source, "weightedSum",
                      r"points\.val\.length\s*\*\s*8", "points.val.length * 7",
                      ((length_theorem, "unsolved goals"),)))
        sum_theorem = f"{group}_weighted_sum_eq_spec"
        source = prefix + definition + body(contracts, sum_theorem).replace(method, "weightedSum")
        cases.append((f"{group.upper()}Scalars", source, "weightedSum",
                      rf"PointOperationExternals\.sum{group.upper()}\s+points\s+scalars",
                      f"PointOperationExternals.sum{group.upper()} points ⟨[], by simp⟩",
                      ((sum_theorem, "unsolved goals"),)))

    method = "g2_point.G2Point.hash_to_curve"
    full = "silver_crypto_simd.bls." + method
    source = prefix + body(externals, full).replace(full, "hashToCurve")
    source += body(contracts, "hash_to_curve_eq_spec").replace(method, "hashToCurve")
    cases.append(("HashDst", source, "hashToCurve",
                  r"PointOperationExternals\.hashG2\s+message\s+dst",
                  "PointOperationExternals.hashG2 message message",
                  (("hash_to_curve_eq_spec", "Application type mismatch"),)))

    method = "g1_point.G1Point.negative_generator"
    full = "silver_crypto_simd.bls." + method
    source = prefix + body(externals, full).replace(full, "negativeGenerator")
    source += body(contracts, "negative_generator_eq_spec").replace(method, "negativeGenerator")
    cases.append(("NegativeGenerator", source, "negativeGenerator",
                  r"ok\s+PointOperationExternals\.negativeG1", "fail .assertionFailure",
                  (("negative_generator_eq_spec", "Application type mismatch"),)))

    with tempfile.TemporaryDirectory(prefix="point-operation-mutation-") as directory:
        for label, original, name, pattern, mutation, expected in cases:
            original += "\nend PointOperationMutation\n"
            reformatted = replace_in(original, name, r":=", ":=\n ")
            for variant, source in (("Original", original), ("Reformatted", reformatted)):
                check(Path(directory) / f"{label}{variant}.lean", source, ())
                check(Path(directory) / f"{label}{variant}Mutated.lean",
                      replace_in(source, name, pattern, mutation), expected)


if __name__ == "__main__":
    main()
