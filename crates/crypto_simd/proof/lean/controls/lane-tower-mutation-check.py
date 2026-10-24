#!/usr/bin/env python3
"""Recheck lane proofs against mutated generated packing and arithmetic schedules."""

from pathlib import Path
import re
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/portable-tower-mutation-check.py"))


def main():
    cases = [
        ("Difference", "Pairs", "bls.fp12.fp2_from_products",
         "bls.fp8.Fp8.sub_raw m0 m1 f", "bls.fp8.Fp8.sub_raw m1 m0 f", "raw_from_products"),
        ("Xi", "Pairs", "bls.fp2x8.Fp2x8.mul_by_xi_raw",
         "bls.fp8.Fp8.sub_raw self.c0 self.c1 offset",
         "bls.fp8.Fp8.sub_raw self.c1 self.c0 offset", "raw2_xi"),
        ("Pack", "Packing", "bls.fp12.pack_nine",
         "let f1 ← Array.index_usize l 7#usize", "let f1 ← Array.index_usize l 6#usize", "pack_nine"),
        ("Unpack", "Packing", "bls.fp12.unpack_six",
         "let f2 ← Array.index_usize q 2#usize", "let f2 ← Array.index_usize q 3#usize", "unpack_six"),
        ("ProductLoop", "Products", "bls.fp12.Fp12.mul_loop.body",
         "Array.index_usize right i", "Array.index_usize left i", "mul_loop_eq"),
    ]
    with tempfile.TemporaryDirectory(prefix="lane-tower-mutation-") as directory:
        for label, module, name, old, new, proof in cases:
            declaration = SUPPORT["generated_declaration"](name)
            if declaration.count(old) != 1:
                raise AssertionError(f"{label}: expected one generated mutation site")
            original = (LEAN / f"LeanBlsSimd/LaneTower/{module}.lean").read_text()
            target = re.search(SUPPORT["DECLARATION"] + re.escape(proof)
                               + r"\b.*?(?=" + SUPPORT["DECLARATION"] + r"|\Z)", original, re.M | re.S)
            if target is None:
                raise AssertionError(f"{label}: missing proof {proof}")
            original = original[:target.end()].rstrip()
            if original.endswith("-/"):
                original = original[:original.rfind("/--")].rstrip()
            original += "\nend LeanBlsSimd.LaneTower\n"
            imports = re.match(r"(?:import [^\n]+\n)+", original)
            if imports is None:
                raise AssertionError(f"{label}: missing imports")
            alias = f"proofMutation{label}"
            body = original[imports.end():].replace(name.removeprefix("bls."), alias)
            # A loop theorem unfolds its generated wrapper, which refers to the body by name.
            if name.endswith(".body"):
                wrapper_name = name.removesuffix(".body")
                match = re.search(r"^def " + re.escape(wrapper_name)
                                  + r"(?=\s|:|\().*?(?=\n/--|\Z)",
                                  SUPPORT["GENERATED"].read_text(), re.M | re.S)
                if match is None:
                    raise AssertionError(f"{label}: missing wrapper {wrapper_name}")
                wrapper = match[0].strip()
                wrapper_alias = alias + "Loop"
                wrapper = wrapper.replace("def " + wrapper_name, "def " + wrapper_alias, 1)
                wrapper = wrapper.replace(name, alias)
                body = body.replace(wrapper_name.removeprefix("bls."), wrapper_alias)
            else:
                wrapper = ""
            prefix = (imports[0] + "\nopen Aeneas Aeneas.Std Result ControlFlow\n"
                      "namespace silver_crypto_simd\nnoncomputable section\n")
            for variant, generated in (("Original", declaration),
                                       ("Reformatted", declaration.replace("\n", "\n\n"))):
                def source(text):
                    return (prefix + text.replace("def " + name, "def " + alias, 1)
                            + "\n" + wrapper + "\nend\nend silver_crypto_simd\n" + body)
                SUPPORT["check"](Path(directory) / f"{label}{variant}.lean", source(generated))
                SUPPORT["check"](Path(directory) / f"{label}{variant}Mutated.lean",
                                 source(generated.replace(old, new)), proof)


if __name__ == "__main__":
    main()
