#!/usr/bin/env python3
"""Recheck runtime pairing refinements against mutations of live generated loops."""

from pathlib import Path
import re
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/portable-tower-mutation-check.py"))


def check_cases(directory, filename, name, proof, stop, closing, cases):
    declaration = SUPPORT["generated_declaration"](name)
    original = (LEAN / filename).read_text()
    imports = re.match(r"(?:import [^\n]+\n)+", original)[0]
    body = original[len(imports):original.index(stop)]
    names = [name, name.removeprefix("bls.")]
    reference = r"(?<![\w.])(?:" + "|".join(map(re.escape, names)) + r")(?![\w.])"
    body = re.sub(reference, "proofPairingBody", body) + closing
    prefix = (imports + "\nopen Aeneas Aeneas.Std Result ControlFlow\n"
              "namespace silver_crypto_simd\nnoncomputable section\nvariable [RuntimeFeatures]\n")
    for label, old, new in cases:
        if declaration.count(old) != 1:
            raise AssertionError(f"{label}: expected one generated mutation site")
        changed = declaration.replace(old, new)
        for variant, reformat in (("Original", lambda s: s),
                                  ("Reformatted", lambda s: s.replace("\n", "\n\n"))):
            def source(text):
                return (prefix + reformat(text).replace("def " + name, "def proofPairingBody", 1)
                        + "\nend\nend silver_crypto_simd\n" + body)
            SUPPORT["check"](directory / f"{label}{variant}.lean", source(declaration))
            SUPPORT["check"](directory / f"{label}{variant}Mutated.lean", source(changed), proof)


def main():
    with tempfile.TemporaryDirectory(prefix="pairing-loop-mutation-") as temporary:
        directory = Path(temporary)
        check_cases(directory, "LeanBlsSimd/Pairing/PortableLines.lean",
                    "portable.pairing.PairingLines.times_lines_loop.body", "body_step",
                    "theorem times_lines", "\nend PortableLines\nend LeanBlsSimd.Pairing\n", [
                        ("XFactor", "Array.index_usize a1 1#usize", "Array.index_usize a1 2#usize"),
                        ("Present", "if b\n", "if !b\n"),
                        ("TableRow", "Array.index_usize self step", "Array.index_usize self 0#usize"),
                        ("LoopBound", "k < 2#usize", "k < 1#usize"),
                    ])
        check_cases(directory, "LeanBlsSimd/Pairing/PortableFactors.lean",
                    "portable.pairing.PairingLines.miller_loop_loop0.body", "factors_body",
                    "theorem factors_loop", "\nend LeanBlsSimd.Pairing.PortableLines\n", [
                        ("ZFactor", "portable.fp.Fp.square p.z", "portable.fp.Fp.square p.x"),
                    ])

        check_cases(directory, "LeanBlsSimd/Pairing/PortableMillerStep.lean",
                    "portable.pairing.PairingLines.miller_loop_loop1.body", "miller_body",
                    "end LeanBlsSimd.Pairing.PortableLines", "\nend LeanBlsSimd.Pairing.PortableLines\n", [
                        ("PortableFirstSquare", "step > 0#usize", "step > 1#usize"),
                        ("PortableStep", "let step1 ← step + 1#usize", "let step1 ← step + 2#usize"),
                    ])
        check_cases(directory, "LeanBlsSimd/Pairing/PortableMiller.lean",
                    "portable.pairing.PairingLines.miller_loop", "miller_encoded",
                    "end LeanBlsSimd.Pairing.PortableLines", "\nend LeanBlsSimd.Pairing.PortableLines\n", [
                        ("PortableConjugate", "portable.fp12.Fp12.conjugate f", "ok f"),
                    ])

        check_cases(directory, "LeanBlsSimd/Pairing/LaneLine.lean",
                    "bls.pairing.line", "line_refines",
                    "end LeanBlsSimd.Pairing.LaneLines", "\nend LeanBlsSimd.Pairing.LaneLines\n", [
                        ("LanePermutation", "bls.fp8.Fp8.permute2 z_cubed products a",
                         "bls.fp8.Fp8.permute2 products z_cubed a"),
                    ])
        check_cases(directory, "LeanBlsSimd/Pairing/LaneLines.lean",
                    "bls.pairing.MillerLines.times_lines", "times_lines",
                    "end LeanBlsSimd.Pairing.LaneLines", "\nend LeanBlsSimd.Pairing.LaneLines\n", [
                        ("LaneRow", "Array.index_usize self step", "Array.index_usize self 0#usize"),
                        ("LanePresent", "present &&& 2#u8", "present &&& 4#u8"),
                    ])
        check_cases(directory, "LeanBlsSimd/Pairing/LaneMillerStep.lean",
                    "bls.pairing.MillerLines.miller_loop_loop.body", "miller_body",
                    "end LeanBlsSimd.Pairing.LaneLines", "\nend LeanBlsSimd.Pairing.LaneLines\n", [
                        ("LaneBit", "bit - 1#u32", "bit - 2#u32"),
                    ])
        check_cases(directory, "LeanBlsSimd/Pairing/LaneMiller.lean",
                    "bls.pairing.MillerLines.miller_loop", "miller_refines",
                    "end LeanBlsSimd.Pairing.LaneLines", "\nend LeanBlsSimd.Pairing.LaneLines\n", [
                        ("LanePresenceComplement", "lift (~~~ i)", "lift i"),
                        ("LaneConjugate", "bls.fp12.Fp12.conjugate f3", "ok f3"),
                    ])


        check_cases(directory, "LeanBlsSimd/Kzg/PairingCorrect.lean",
                    "portable.pairing.PairingLines.pairing_check", "PortableLines.pairing_check",
                    "theorem LaneLines.pairing_check", "\nend LeanBlsSimd.Pairing\n", [
                        ("PortableFinalPower", "portable.fp12.Fp12.final_exponentiation f", "ok f"),
                    ])
        check_cases(directory, "LeanBlsSimd/Kzg/PairingCorrect.lean",
                    "bls.pairing.MillerLines.pairing_check", "LaneLines.pairing_check",
                    "end LeanBlsSimd.Pairing", "\nend LeanBlsSimd.Pairing\n", [
                        ("LaneFinalPower", "bls.fp12.Fp12.final_exponentiation f", "ok f"),
                    ])


if __name__ == "__main__":
    main()
