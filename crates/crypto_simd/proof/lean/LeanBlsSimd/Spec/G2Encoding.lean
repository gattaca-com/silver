import LeanBlsSimd.Proofs.DecompressG2

namespace LeanBlsSimd.G2Spec

open EthLib.Cryptography.Bls DecompressG2

/-- Affine infinity uses zero coordinates, as in blst's affine representation. -/
def blstLimbs (P : G2) : BlstP2Affine :=
  let (x, y) := P.toAffine
  blstPoint (Fp2.toField x) (Fp2.toField y)

/-- The kernel's direct-coordinate conversion agrees with affine conversion at z = 1. -/
theorem blstLimbs_eq_of_z_one {P : G2} (hz : P.z = Fp2.one) :
    blstLimbs P = DecompressG2.blstLimbs P := by
  have hnonzero : ¬ (1 : Fp2).isZero = true := by
    rw [Fp2.isZero_iff]
    simp
  simp [blstLimbs, DecompressG2.blstLimbs, G2.toAffine, hz, hnonzero,
    map_mul, Fp2.toField_inverse]

def verdict (bytes : Vector UInt8 G2_COMPRESSED_LEN) : Option BlstP2Affine :=
  match G2.uncompress (toBytes bytes) with
  | .error _ => none
  | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none

theorem verdict_some_iff (bytes : Vector UInt8 G2_COMPRESSED_LEN) (p : BlstP2Affine) :
    verdict bytes = some p ↔
      ∃ P, G2.uncompress (toBytes bytes) = .ok P ∧
        G2.inSubgroup P = true ∧ p = blstLimbs P := by
  unfold verdict
  cases hd : G2.uncompress (toBytes bytes) with
  | error e => simp
  | ok P =>
    dsimp only
    by_cases hg : G2.inSubgroup P = true <;> simp [hg]
    exact eq_comm

def infinity : Vector UInt8 G2_COMPRESSED_LEN := (Vector.replicate 96 0).set 0 0xc0

end LeanBlsSimd.G2Spec
