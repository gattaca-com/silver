#!/usr/bin/env python3
"""Recheck final-exponent refinements against mutations of live generated schedules."""

from pathlib import Path
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/pairing-loop-mutation-check.py"))
CHECK = SUPPORT["check_cases"]


def main():
    with tempfile.TemporaryDirectory(prefix="final-exponent-mutation-") as temporary:
        directory = Path(temporary)
        CHECK(directory, "LeanBlsSimd/Pairing/PortableExponent.lean",
              "portable.fp12.Fp12.cyclotomic_exp_loop.body", "exponent_body",
              "theorem exponent_encoded", "\nend LeanBlsSimd.Pairing.FinalExponent.Portable\n", [
                  ("PortableBit", "bit - 1#u32", "bit - 2#u32"),
              ])
        CHECK(directory, "LeanBlsSimd/Pairing/LaneExponent.lean",
              "bls.fp12.Fp12.cyclotomic_exp_loop.body", "exponent_body",
              "theorem exponent_refines", "\nend LeanBlsSimd.Pairing.FinalExponent.Lanes\n", [
                  ("LaneBase", "bls.fp12.Fp12.mul r1 self", "bls.fp12.Fp12.mul r1 r1"),
              ])
        CHECK(directory, "LeanBlsSimd/Pairing/PortableExponent.lean",
              "portable.fp12.Fp12.cyclotomic_exp", "exponent_encoded",
              "end LeanBlsSimd.Pairing.FinalExponent.Portable", "\nend LeanBlsSimd.Pairing.FinalExponent.Portable\n", [
                  ("PortableParameterSign", "portable.fp12.Fp12.conjugate r", "ok r"),
              ])
        CHECK(directory, "LeanBlsSimd/Pairing/LaneExponent.lean",
              "bls.fp12.Fp12.cyclotomic_exp", "exponent_refines",
              "end LeanBlsSimd.Pairing.FinalExponent.Lanes", "\nend LeanBlsSimd.Pairing.FinalExponent.Lanes\n", [
                  ("LaneParameterSign", "bls.fp12.Fp12.conjugate r", "ok r"),
              ])
        CHECK(directory, "LeanBlsSimd/Pairing/PortableFinal.lean",
              "portable.fp12.Fp12.final_exponentiation", "generated_schedule",
              "theorem final_cube_encoded", "\nend LeanBlsSimd.Pairing.FinalExponent.Portable\n", [
                  ("PortableInverse", "portable.fp12.Fp12.inverse self", "portable.fp12.Fp12.conjugate self"),
                  ("PortableFrobenius", "portable.fp12.Fp12.frobenius f7", "portable.fp12.Fp12.conjugate f7"),
              ])
        CHECK(directory, "LeanBlsSimd/Pairing/LaneFinal.lean",
              "bls.fp12.Fp12.final_exponentiation", "generated_schedule",
              "theorem final_cube_refines", "\nend LeanBlsSimd.Pairing.FinalExponent.Lanes\n", [
                  ("LaneLastProduct", "bls.fp12.Fp12.mul f12 t42", "bls.fp12.Fp12.mul f12 t41"),
                  ("LaneSquareInput", "bls.fp12.Fp12.cyclotomic_square t3", "bls.fp12.Fp12.cyclotomic_square t21"),
              ])


if __name__ == "__main__":
    main()
