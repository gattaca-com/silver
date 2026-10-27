#!/usr/bin/env python3
"""Recheck pairing-product proofs against mutations of live generated functions.

Swapping runtime dispatch or forcing the fallback are equivalent mutants here:
both arms satisfy the same verdict contract. CPU target-feature safety and route
performance are Rust-side properties.
"""

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import runpy
import subprocess
import tempfile
import time


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/mutation-support.py"))
DECLARATION = SUPPORT["DECLARATION"]
BASE = "LeanBlsSimd/PairingProduct/"
LANES = "bls.lane_pairs.LanePairs."
OWNER = "bls.pairing_product.PairingProduct."
INPUTS = "bls.pairing_product.PairingInputs."
AFFINE = "bls.pairing_product.AffinePair."


@dataclass(frozen=True)
class Case:
    label: str
    file: str
    name: str
    proof: str
    stop: str
    closing: str
    old: str
    new: str
    callers: tuple[str, ...] = ()


STEPS_END = "\nend LeanBlsSimd.PairingProduct.Lanes\n"
LANES_END = "\nend\nend LeanBlsSimd.PairingProduct.Lanes\n"
MILLER_END = "\nend Loop\nend\nend LeanBlsSimd.PairingProduct.LaneMiller\n"
PRODUCT_END = "\nend\nend LeanBlsSimd.PairingProduct.ProductLoop\n"
OWNER_END = "\nend\nend LeanBlsSimd.PairingProduct\n"


CASES = [
    Case("ActiveMask", "LaneSteps.lean", LANES + "active_mask", "active_mask_refines",
         "theorem at_p_refines", STEPS_END, "core.num.U8.MAX >>> i", "ok 1#u8"),
    Case("DoubleFlag", "LaneSteps.lean", LANES + "double", "double_refines",
         "theorem add_refines", STEPS_END, "lift (self.degenerate ||| i2)", "lift self.degenerate"),
    Case("AddFlag", "LaneSteps.lean", LANES + "add", "add_refines",
         "end LeanBlsSimd.PairingProduct.Lanes", STEPS_END,
         "lift (self.degenerate ||| i4)", "lift self.degenerate"),
    Case("InactiveMask", "LaneSteps.lean", LANES + "double", "double_refines",
         "theorem add_refines", STEPS_END, "lift (i &&& i1)", "lift i"),
    Case("EvaluationScale", "LaneSteps.lean", LANES + "at_p", "at_p_refines",
         "theorem double_refines", STEPS_END,
         "bls.fp8.Fp8.mul l1.c0 self.minus_two_px", "bls.fp8.Fp8.mul l1.c0 self.two_py"),
    Case("ConstructorCoordinate", "Inputs.lean", LANES + "new_loop.body", "write_body",
         "private def Filled", STEPS_END, "Array.update a lane pair.p.x.l", "Array.update a lane pair.p.y.l"),
    Case("SparseIndex", "LinePacking.lean", "bls.lane_pairs.Lines.multiply_into_loop.body", "body_cont",
         "theorem multiply_loop_refines", LANES_END, "let i1 ← 8#i64 + i", "let i1 ← 7#i64 + i"),
    Case("MillerBit", "LaneMiller.lean", LANES + "miller_loop_loop.body", "miller_body",
         "theorem miller_loop_refines", MILLER_END, "bit1 - 1#u32", "bit1 - 2#u32"),
    Case("MillerSquare", "LaneMiller.lean", LANES + "miller_loop_loop.body", "miller_body",
         "theorem miller_loop_refines", MILLER_END, "bls.fp12.Fp12.square value", "ok value"),
    Case("MillerCount", "LaneMiller.lean", LANES + "miller_loop_loop.body", "miller_body",
         "theorem miller_loop_refines", MILLER_END,
         "bls.lane_pairs.Lines.multiply_into l value1 self1.count",
         "bls.lane_pairs.Lines.multiply_into l value1 1#usize"),
    Case("MillerConjugate", "LaneMiller.lean", LANES + "miller_loop", "miller_refines_with_packing",
         "end Loop", MILLER_END, "bls.fp12.Fp12.conjugate value1", "ok value1"),
    Case("SetProduct", "ProductLoop.lean", INPUTS + "lane_is_one_loop.body", "lane_loop_refines",
         "theorem lane_is_one_refines", PRODUCT_END,
         "bls.fp12.Fp12.mul product result.value", "bls.fp12.Fp12.mul result.value result.value",
         (INPUTS + "lane_is_one_loop",)),
    Case("SetFlags", "ProductLoop.lean", INPUTS + "lane_is_one_loop.body", "lane_loop_refines",
         "theorem lane_is_one_refines", PRODUCT_END,
         "lift (degenerate ||| result.degenerate)", "lift degenerate", (INPUTS + "lane_is_one_loop",)),
    Case("SetIndex", "ProductLoop.lean", INPUTS + "lane_is_one_loop.body", "lane_loop_refines",
         "theorem lane_is_one_refines", PRODUCT_END,
         "s { start, «end» := i2 }", "s { start := 0#usize, «end» := i2 }", (INPUTS + "lane_is_one_loop",)),
    Case("Fallback", "ProductLoop.lean", INPUTS + "lane_is_one", "lane_is_one_refines",
         "theorem check_refines", PRODUCT_END, "if degenerate != 0#u8", "if false"),
    Case("FinalProduct", "ProductLoop.lean", INPUTS + "lane_is_one", "lane_is_one_refines",
         "theorem check_refines", PRODUCT_END,
         "bls.fp12.Fp12.final_exponentiation product1", "bls.fp12.Fp12.final_exponentiation product"),
    Case("FallbackVerdict", "ProductLoop.lean", INPUTS + "lane_is_one", "lane_is_one_refines",
         "theorem check_refines", PRODUCT_END, INPUTS + "blst_is_one self", "ok true"),
    Case("Infinity", "Infinity.lean", AFFINE + "is_infinite", "affinePair_is_infinite",
         "\nend\n", OWNER_END, "then ok true\n  else ok (q_bits = 0#u64)",
         "then ok (q_bits = 0#u64)\n  else ok false"),
    Case("PushFilter", "Owner.lean", OWNER + "push", "push_refines",
         "theorem push_preserves_valid", OWNER_END, "if b\n", "if !b\n"),
    Case("Clear", "Owner.lean", OWNER + "clear", "clear_empty",
         "theorem emptyOwner_pairs", OWNER_END, "ok { pairs := v }", "ok self"),
    Case("Empty", "ProductLoop.lean", INPUTS + "check", "check_refines",
         "\nend\n", PRODUCT_END, "then ok true", "then ok false"),
    Case("TwoFilter", "Owner.lean", OWNER + "two_pairs_are_one_loop.body", "two_loop_refines",
         "def filteredTwo", OWNER_END, "if b\n", "if !b\n", (OWNER + "two_pairs_are_one_loop",)),
]


def replace_references(text, names):
    for index, name in sorted(enumerate(names), key=lambda item: -len(item[1])):
        spellings = (name, name.removeprefix("bls."))
        pattern = r"(?<![\w.])(?:" + "|".join(map(re.escape, spellings)) + r")(?![\w.])"
        text = re.sub(pattern, f"proofProductMutation{index}", text)
    return text


def generated_declaration(name):
    source = SUPPORT["GENERATED"].read_text()
    match = re.search(r"^def " + re.escape(name) + r"(?=\s|\().*?(?=\n/--|\Z)",
                      source, re.M | re.S)
    if match is None:
        raise AssertionError(f"missing generated declaration {name}")
    return match[0].strip()


def source_for(case, mutated, reformatted):
    names = (case.name, *case.callers)
    declarations = [generated_declaration(name) for name in names]
    if declarations[0].count(case.old) != 1:
        raise AssertionError(f"{case.label}: expected exactly one generated mutation site")
    if mutated:
        declarations[0] = declarations[0].replace(case.old, case.new)
    generated = replace_references("\n\n".join(declarations), names)
    if reformatted:
        generated = generated.replace("\n", "\n\n")
    original = (LEAN / BASE / case.file).read_text()
    imports = re.match(r"(?:import [^\n]+\n)+", original)
    if imports is None:
        raise AssertionError(f"{case.label}: missing imports")
    body = replace_references(original[imports.end():original.index(case.stop)], names)
    if case.label == "Infinity":
        # Keep the raw refinement inside the theorem whose rejection is checked.
        start = body.index("private theorem infinity_raw ")
        end = body.index("\nprivate theorem fp2_ext", start)
        raw = body[start:end].replace("private theorem infinity_raw ", "have infinity_raw ", 1)
        body = body[:start] + body[end:]
        headline = body.index("theorem affinePair_is_infinite ")
        proof = body.index(" := by\n", headline) + len(" := by\n")
        body = body[:proof] + "\n".join("  " + line for line in raw.splitlines()) + "\n" + body[proof:]
    return (imports[0] + "\nopen Aeneas Aeneas.Std Result ControlFlow\n"
            "namespace silver_crypto_simd\nnoncomputable section\n"
            "variable [RuntimeFeatures] [bls.PairingExternals]\n" + generated
            + "\nend\nend silver_crypto_simd\nopen silver_crypto_simd\n" + body + case.closing)


def check(path, source, proof=None):
    available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                         if line.startswith("MemAvailable:"))) * 1024
    if available < 16 * 1024**3:
        raise AssertionError("Lean requires at least 16 GiB available memory")
    path.write_text(source)
    start = time.monotonic()
    result = subprocess.run(
        ["taskset", "-c", "0-11,16-27", "lake", "env", "lean",
         "-DautoImplicit=false", "-DrelaxedAutoImplicit=false", str(path)],
        cwd=LEAN, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600,
    )
    elapsed = time.monotonic() - start
    if proof is None:
        if result.returncode != 0:
            raise AssertionError(f"{path.stem}: positive control failed:\n{result.stdout}")
        print(f"{path.stem}: exit=0 compiles ({elapsed:.2f}s)", flush=True)
        return
    theorem = re.search(DECLARATION + re.escape(proof) + r"\b.*?(?=" + DECLARATION + r"|\Z)",
                        source, re.M | re.S)
    if theorem is None:
        raise AssertionError(f"missing proof {proof}")
    first = source.count("\n", 0, theorem.start()) + 1
    last = source.count("\n", 0, theorem.end()) + 1
    errors = re.findall(r":(\d+):\d+: error(?:\([^)]*\))?: ([^\n]*)", result.stdout)
    forbidden = (r"timeout|heartbeat|recursion|out of memory|SIGKILL|syntax|unexpected token|expected token|"
                 r"unterminated|unknown identifier|unknown constant|invalid field|failed to synthesize")
    if (result.returncode != 1 or not errors
            or not all(first <= int(line) <= last for line, _ in errors)
            or re.search(forbidden, result.stdout, re.I)):
        raise AssertionError(f"{path.stem}: expected proof rejection inside {proof}:\n{result.stdout}")
    print(f"{path.stem}: exit=1 {proof} rejects mutation ({elapsed:.2f}s); "
          f"lines {first}-{last}; {errors[0][1]}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", nargs="*", help="Case labels; omit to run the complete suite")
    args = parser.parse_args()
    unknown = set(args.cases) - {case.label for case in CASES}
    if unknown:
        parser.error(f"unknown cases: {', '.join(sorted(unknown))}")
    selected = [case for case in CASES if not args.cases or case.label in args.cases]
    positives = set()
    with tempfile.TemporaryDirectory(prefix="pairing-product-mutation-") as temporary:
        directory = Path(temporary)
        for case in selected:
            for variant, reformatted in (("Original", False), ("Reformatted", True)):
                original = source_for(case, False, reformatted)
                if original not in positives:
                    check(directory / f"{case.label}{variant}.lean", original)
                    positives.add(original)
                check(directory / f"{case.label}{variant}Mutated.lean",
                      source_for(case, True, reformatted), case.proof)
    print(f"PASS: {len(selected)} mutations, {len(positives)} positive controls, "
          f"{2 * len(selected)} proof rejections", flush=True)


if __name__ == "__main__":
    main()
