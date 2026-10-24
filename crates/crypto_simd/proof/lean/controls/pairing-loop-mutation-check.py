#!/usr/bin/env python3
"""Recheck runtime pairing refinements against mutations of live generated loops."""

from pathlib import Path
import re
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/portable-tower-mutation-check.py"))


def main():
    name = "portable.pairing.PairingLines.times_lines_loop.body"
    declaration = SUPPORT["generated_declaration"](name)
    original = (LEAN / "LeanBlsSimd/Pairing/PortableLines.lean").read_text()
    imports = re.match(r"(?:import [^\n]+\n)+", original)[0]
    body = original[len(imports):original.index("theorem times_lines")]
    body = body.replace(name, "proofPairingLineBody")
    body += "\nend PortableLines\nend LeanBlsSimd.Pairing\n"
    prefix = (imports + "\nopen Aeneas Aeneas.Std Result ControlFlow\n"
              "namespace silver_crypto_simd\nnoncomputable section\nvariable [RuntimeFeatures]\n")
    cases = [
        ("XFactor", "Array.index_usize a1 1#usize", "Array.index_usize a1 2#usize"),
        ("Present", "if b\n", "if !b\n"),
        ("TableRow", "Array.index_usize self step", "Array.index_usize self 0#usize"),
        ("LoopBound", "k < 2#usize", "k < 1#usize"),
    ]
    with tempfile.TemporaryDirectory(prefix="pairing-loop-mutation-") as directory:
        for label, old, new in cases:
            if declaration.count(old) != 1:
                raise AssertionError(f"{label}: expected one generated mutation site")
            changed = declaration.replace(old, new)
            for variant, reformat in (("Original", lambda s: s),
                                      ("Reformatted", lambda s: s.replace("\n", "\n\n"))):
                def source(text):
                    return (prefix + reformat(text).replace("def " + name,
                            "def proofPairingLineBody", 1)
                            + "\nend\nend silver_crypto_simd\n" + body)
                SUPPORT["check"](Path(directory) / f"{label}{variant}.lean", source(declaration))
                SUPPORT["check"](Path(directory) / f"{label}{variant}Mutated.lean",
                                 source(changed), "body_step")


if __name__ == "__main__":
    main()
