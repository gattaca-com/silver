import LeanBlsSimd.Model.DecompressG1
import LeanBlsSimd.Proofs.DecompressG2
import EthCryptographySpecs.Proofs.Bls.G1Order
import EthCryptographySpecs.Kzg.Core

namespace LeanBlsSimd.G1Spec

open EthCryptographySpecs Bls
open WeierstrassCurve
open DecompressG1

abbrev E := G1.curve.toAffine

theorem nonsingular_sigma {x y : ZMod Fp.modulus} (h : E.Nonsingular x y) :
    E.Nonsingular (beta * x) y := by
  sorry

def sigma : E.Point → E.Point
  | 0 => 0
  | .some x y h => .some (beta * x) y (nonsingular_sigma h)

theorem sigma_add (P Q : E.Point) : sigma (P + Q) = sigma P + sigma Q := by
  sorry

theorem sigma_polynomial (P : E.Point) : P + sigma P + sigma (sigma P) = 0 := by
  sorry

theorem scott_sound (P : E.Point) (h : sigma (sigma P) = (-(z ^ 2)) • P) :
    Fr.modulus • P = 0 := by
  sorry

theorem sigma2_generator :
    sigma (sigma (G1.toPoint G1.generator)) = (-(z ^ 2)) • G1.toPoint G1.generator := by
  sorry

theorem point_count_bound : Nat.card E.Point ≤ 2 * Fp.modulus + 1 := by
  sorry

theorem point_count_lt_r_squared : Nat.card E.Point < Fr.modulus ^ 2 := by
  sorry

theorem r_torsion_cyclic (P : E.Point) (h : Fr.modulus • P = 0) :
    ∃ k : ℕ, P = k • G1.toPoint G1.generator := by
  sorry

theorem scott_complete (P : E.Point) (h : Fr.modulus • P = 0) :
    sigma (sigma P) = (-(z ^ 2)) • P := by
  sorry

theorem inSubgroup_iff (P : G1) (h : G1.Valid P) :
    G1.inSubgroup P = true ↔ Fr.modulus • G1.toPoint P = 0 := by
  sorry

def toBytes (b : Encoding) : ByteArray := ⟨b.toArray⟩

/-- `toAffine` maps infinity to (0, 0), the blst affine infinity sentinel. -/
def blstLimbs (P : G1) : BlstP1Affine :=
  let (x, y) := P.toAffine
  ⟨DecompressG2.blstFp x, DecompressG2.blstFp y⟩

def verdict (bytes : Encoding) : Option BlstP1Affine :=
  match Kzg.bytesToKzgProof (toBytes bytes) with
  | .error _ => none
  | .ok validated =>
    match G1.uncompress validated with
    | .error _ => none
    | .ok P => some (blstLimbs P)

theorem verdict_eq_decode (bytes : Encoding) :
    verdict bytes =
      match G1.uncompress (toBytes bytes) with
      | .error _ => none
      | .ok P => if G1.inSubgroup P then some (blstLimbs P) else none := by
  sorry

theorem verdict_some_iff (bytes : Encoding) (p : BlstP1Affine) :
    verdict bytes = some p ↔
      (Kzg.bytesToKzgProof (toBytes bytes)).isOk = true ∧
      ∃ P, G1.uncompress (toBytes bytes) = .ok P ∧ p = blstLimbs P := by
  sorry

theorem verdict_accepts_iff (bytes : Encoding) :
    (verdict bytes).isSome = (Kzg.bytesToKzgProof (toBytes bytes)).isOk := by
  sorry

theorem commitment_accepts_iff (bytes : Encoding) :
    (Kzg.bytesToKzgCommitment (toBytes bytes)).isOk = (verdict bytes).isSome := by
  sorry

def infinity : Encoding := (Vector.replicate 48 0).set 0 0xc0

theorem infinity_verdict : verdict infinity = some (DecompressG1.point (.replicate 6 0)
    (.replicate 6 0)) := by
  sorry

theorem infinity_decoding_iff (bytes : Encoding) :
    G1.uncompress (toBytes bytes) = .ok G1.zero ↔ bytes = infinity := by
  sorry

end LeanBlsSimd.G1Spec
