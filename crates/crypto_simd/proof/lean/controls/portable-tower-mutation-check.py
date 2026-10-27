#!/usr/bin/env python3
"""Mutate generated portable schedules and recheck their actual refinement proofs."""

from pathlib import Path
import re
import subprocess
import tempfile


LEAN = Path(__file__).resolve().parents[1]
GENERATED = LEAN / "LeanBlsSimd/Extracted/Funs.lean"
DECLARATION = r"^(?:@\[simp\]\s+)?(?:private\s+)?(?:def|theorem)\s+"


def generated_declaration(name):
    source = GENERATED.read_text()
    match = re.search(r"^def " + re.escape(name) + r"\b.*?(?=\n/--|\Z)", source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing generated declaration {name}")
    return match[0].strip()


def check(path, source, expected=None):
    path.write_text(source)
    result = subprocess.run(
        ["lake", "env", "lean", "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180,
    )
    if expected is None:
        if result.returncode != 0:
            raise AssertionError(f"{path.stem}: positive control failed:\n{result.stdout}")
        print(f"{path.stem}: compiles", flush=True)
        return
    theorem = re.search(DECLARATION + re.escape(expected) + r"\b.*?(?=" + DECLARATION + r"|\Z)",
                        source, re.M | re.S)
    if theorem is None:
        raise AssertionError(f"missing proof {expected}")
    first = source.count("\n", 0, theorem.start()) + 1
    last = source.count("\n", 0, theorem.end()) + 1
    errors = re.findall(r":(\d+):\d+: error: ([^\n]*)", result.stdout)
    if (result.returncode != 1 or not any(first <= int(line) <= last for line, _ in errors)
            or re.search(r"timeout|heartbeat|recursion|out of memory|SIGKILL", result.stdout, re.I)):
        raise AssertionError(f"{path.stem}: expected rejection by {expected}:\n{result.stdout}")
    print(f"{path.stem}: {expected} rejects the generated mutation", flush=True)


def main():
    cases = [
        ("Product", "LeanBlsSimd/Portable/Fp2/Product.lean", "portable.fp2.Fp2.product",
         "portable.fp.Wide.minus_mod t0 t1", "portable.fp.Wide.minus_mod t1 t0", "product_encoded"),
        ("Line", "LeanBlsSimd/Portable/Fp12/Arithmetic.lean", "portable.fp12.Fp12.mul_by_line",
         "portable.fp6.Fp6.mul_by_y self.c1 z", "portable.fp6.Fp6.mul_by_y self.c1 y",
         "mul_by_line_encoded"),
        ("Cyclotomic", "LeanBlsSimd/Portable/Fp12/Cyclotomic.lean", "portable.fp12.Fp12.cyclotomic_square",
         "portable.fp12.thrice_less_twice t10 self.c0.c1",
         "portable.fp12.thrice_plus_twice t10 self.c0.c1", "cyclotomic_raw_encoded"),
        ("Frobenius", "LeanBlsSimd/Portable/Fp12/Frobenius.lean", "portable.fp12.Fp12.frobenius",
         "self.c0.c1 2#usize", "self.c0.c1 4#usize", "frobenius_raw_encoded"),
        ("Table", "LeanBlsSimd/Portable/Fp12/Frobenius.lean", "portable.constants.FROBENIUS",
         "8505329371266088957#u64", "8505329371266088958#u64", "portable_table_certificates"),
    ]
    with tempfile.TemporaryDirectory(prefix="portable-tower-mutation-") as directory:
        for label, filename, name, old, new, proof in cases:
            declaration = generated_declaration(name)
            if declaration.count(old) != 1:
                raise AssertionError(f"{label}: expected one generated mutation site")
            original = (LEAN / filename).read_text()
            imports = re.match(r"(?:import [^\n]+\n)+", original)
            if imports is None:
                raise AssertionError(f"{label}: missing imports")
            alias = f"proofMutation{label}"
            body = original[imports.end():].replace(name, alias)
            prefix = (imports[0] + "\nopen Aeneas Aeneas.Std Result\n"
                      "namespace silver_crypto_simd\nnoncomputable section\nvariable [RuntimeFeatures]\n")
            for variant, generated in (("Original", declaration),
                                       ("Reformatted", declaration.replace("\n", "\n\n"))):
                def source(text):
                    return (prefix + text.replace("def " + name, "def " + alias, 1)
                            + "\nend\nend silver_crypto_simd\n" + body)
                check(Path(directory) / f"{label}{variant}.lean", source(generated))
                check(Path(directory) / f"{label}{variant}Mutated.lean",
                      source(generated.replace(old, new)), proof)


if __name__ == "__main__":
    main()
