#!/usr/bin/env python3
"""Recheck the fixed-line certificates against live table and affine-step mutations."""

from pathlib import Path
import re
import runpy
import tempfile


LEAN = Path(__file__).resolve().parents[1]
SUPPORT = runpy.run_path(str(LEAN / "controls/mutation-support.py"))


def main():
    literals = (LEAN / "LeanBlsSimd/Extracted/Literals.lean").read_text()
    first = literals.index("private def kzg.pairing_lines.PAIRING_LINES_step_0_lane_0")
    table = literals[first:literals.rindex("end silver_crypto_simd")]
    table = table.replace("kzg.pairing_lines.PAIRING_LINES", "proofPairingTable")
    word = re.search(r"\d+#u64", table)[0]
    changed_word = str(int(word.removesuffix("#u64")) + 1) + "#u64"
    model = (LEAN / "LeanBlsSimd/Pairing/FixedTableModel.lean").read_text()
    imports = re.match(r"(?:import [^\n]+\n)+", model)[0]
    body = model[len(imports):].replace("Kzg.pairingRaw step", "mutationRaw step")
    raw = """
def mutationRaw (step : Fin 68) (lane : Fin 8) : Aeneas.Std.Array Aeneas.Std.U64 8#usize :=
  (silver_crypto_simd.proofPairingTable.val[step.val]'(by simp)).val[lane.val]'(by simp)
"""
    body = body.replace("namespace LeanBlsSimd.Pairing", "namespace LeanBlsSimd.Pairing\n" + raw, 1)
    witnesses = (LEAN / "LeanBlsSimd/Pairing/FixedTable.lean").read_text()
    witnesses = witnesses.split("\n", 1)[1]
    witnesses = witnesses[:witnesses.index("private theorem certificate_0_1")]
    witnesses += "end LeanBlsSimd.Pairing.FixedTable\n"
    cases = [
        ("TableLimb", table.replace(word, changed_word, 1), body, witnesses),
        ("Tangent", table, body.replace("Fp.ofNat 3", "Fp.ofNat 2"), witnesses),
        ("Normalizer", table, body.replace("slope * before.1 - before.2",
                                          "slope * before.1 + before.2"), witnesses),
        ("Denominator", table, body.replace("denominator.isZero = false",
                                           "denominator.isZero = true"), witnesses),
    ]
    with tempfile.TemporaryDirectory(prefix="pairing-table-mutation-") as directory:
        for label, changed_table, changed_body, changed_witnesses in cases:
            for variant, reformat in (("Original", lambda s: s),
                                      ("Reformatted", lambda s: s.replace("\n", "\n\n"))):
                def source(t, b, w):
                    return (imports + "\nopen Aeneas Aeneas.Std\nnamespace silver_crypto_simd\n"
                            + reformat(t) + "\nend silver_crypto_simd\n" + b + w)
                SUPPORT["check"](Path(directory) / f"{label}{variant}.lean",
                                 source(table, body, witnesses))
                SUPPORT["check"](Path(directory) / f"{label}{variant}Mutated.lean",
                                 source(changed_table, changed_body, changed_witnesses),
                                 "certificate_0_0")


if __name__ == "__main__":
    main()
