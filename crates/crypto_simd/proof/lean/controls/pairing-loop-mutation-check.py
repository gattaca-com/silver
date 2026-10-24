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
    body = body.replace(name, "proofPairingBody") + closing
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


if __name__ == "__main__":
    main()
