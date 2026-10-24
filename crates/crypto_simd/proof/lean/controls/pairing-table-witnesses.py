#!/usr/bin/env python3
"""Emit untrusted affine witnesses; Lean checks every row against the extracted table."""

from pathlib import Path
import contextlib
import io
import runpy
import sys


crate = Path(__file__).resolve().parents[3]
sys.argv = [str(crate / "gen_pairing_lines.py"), str(crate / "src/kzg/setup.rs")]
with contextlib.redirect_stdout(io.StringIO()):
    generator = runpy.run_path(sys.argv[0])
mul, add, sub, inv, chord, line = (
    generator[key] for key in ["mul", "add", "sub", "inverse", "chord", "line"]
)


def fp2(value):
    return f"⟨Fp.ofNat {value[0]}, Fp.ofNat {value[1]}⟩"


def pair(value):
    return "(" + fp2(value[0]) + ",\n    " + fp2(value[1]) + ")"


parts = []
for j, name in enumerate(["G2_S_POW_CELL", "G2_NEG_GENERATOR"]):
    q = generator["g2_literal"](generator["source"], name)
    t = q
    points, slopes, coeffs = [q], [], []
    for bit in range(62, -1, -1):
        slope = mul(mul((3, 0), mul(t[0], t[0])), inv(add(t[1], t[1])))
        slopes.append(slope)
        coeffs.append(line(t, slope))
        t = chord(t, t, slope)
        points.append(t)
        if generator["X_ABS"] >> bit & 1:
            slope = mul(sub(q[1], t[1]), inv(sub(q[0], t[0])))
            slopes.append(slope)
            coeffs.append(line(t, slope))
            t = chord(t, q, slope)
            points.append(t)
    assert len(points) == 69 and len(slopes) == 68
    parts.append(f"private def points{j} : Array Affine := #[\n  "
                 + ",\n  ".join(pair(p) for p in points) + "]\n")
    parts.append(f"private def slopes{j} : Array Fp2 := #[\n  "
                 + ",\n  ".join(fp2(s) for s in slopes) + "]\n")
    parts.append(f"private def coefficients{j} : Array (Fp2 × Fp2) := #[\n  "
                 + ",\n  ".join(pair(p) for p in coeffs) + "]\n")

header = '''import LeanBlsSimd.Pairing.FixedTableModel

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing.FixedTable

/-! Explicit witnesses, checked against each generated table row below. -/

'''
footer = '''
def point (pair : Fin 2) (i : Fin 69) : Affine :=
  (if pair = 0 then points0 else points1)[i.val]!

def slope (pair : Fin 2) (i : Fin 68) : Fp2 :=
  (if pair = 0 then slopes0 else slopes1)[i.val]!

def lines (pair : Fin 2) (i : Fin 68) : Fp2 × Fp2 :=
  (if pair = 0 then coefficients0 else coefficients1)[i.val]!

def Certificate (step : Fin 68) (pair : Fin 2) : Prop :=
  RowCertificate step pair (point pair ⟨step.val, by omega⟩)
    (point pair ⟨step.val + 1, by omega⟩) (slope pair step)
    (lines pair step).1 (lines pair step).2

set_option maxRecDepth 8000
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 4096

theorem initial (pair : Fin 2) :
    (point pair 0).1.beq (fixedPoint pair).1 = true ∧
    (point pair 0).2.beq (fixedPoint pair).2 = true := by
  fin_cases pair <;> decide +kernel

'''
for i in range(68):
    for j in range(2):
        footer += f'private theorem certificate_{i}_{j} : Certificate {i} {j} := by\n  unfold Certificate RowCertificate\n  decide +kernel\n\n'
footer += 'theorem certificates (step : Fin 68) (pair : Fin 2) : Certificate step pair := by\n  fin_cases step <;> fin_cases pair\n'
for i in range(68):
    for j in range(2):
        footer += f'  · exact certificate_{i}_{j}\n'
footer += '\nend LeanBlsSimd.Pairing.FixedTable\n'
print(header + '\n'.join(parts) + footer, end='')
