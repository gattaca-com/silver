import LeanBlsSimd.Proofs.DecompressG2

namespace LeanBlsSimd.G2Spec

open EthLib.Cryptography.Bls DecompressG2
open EthLib.Cryptography.IdLoops

/-- Affine infinity uses zero coordinates, as in blst's affine representation. -/
def blstLimbs (P : G2) : BlstP2Affine :=
  let (x, y) := P.toAffine
  blstPoint (Fp2.toField x) (Fp2.toField y)

/-- The kernel's direct-coordinate conversion agrees with affine conversion at z = 1. -/
theorem blstLimbs_eq_of_z_one {P : G2} (hz : P.z = Fp2.one) :
    blstLimbs P = DecompressG2.blstLimbs P := by
  have hnonzero : ¬ Fp2.one.isZero = true := by
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

private def tailZero (bytes : ByteArray) (start : Nat) : Bool := Id.run do
  let mut ok := true
  for i in [start : bytes.size] do
    if bytes.get! i ≠ 0 then ok := false
  return ok

private theorem zeroLoop (b : ByteArray) (l : List Nat) (v : Bool) :
    (forIn (m := Id) l v (fun i r =>
      if b.get! i ≠ 0 then ForInStep.yield false else ForInStep.yield r)) = true ↔
      v = true ∧ ∀ i ∈ l, b.get! i = 0 := by
  induction l generalizing v with
  | nil => simp [List.forIn_nil, id_pure]; rfl
  | cons i l ih =>
    rw [List.forIn_cons]
    by_cases h : b.get! i = 0
    · simp only [h, ne_eq, not_true_eq_false, ↓reduceIte, id_bind]
      rw [ih]
      simp [h]
    · simp only [h, ne_eq, not_false_eq_true, ↓reduceIte, id_bind]
      rw [ih]
      simp [h]

private theorem tailZero_iff (b : ByteArray) (s : Nat) :
    tailZero b s = true ↔ ∀ i, s ≤ i → i < b.size → b.get! i = 0 := by
  unfold tailZero
  dsimp only [Id.run, id_pure, id_bind]
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  change (forIn (m := Id) (List.range' s ([s:b.size].size)) true (fun i r =>
    if b.get! i ≠ 0 then ForInStep.yield false else ForInStep.yield r)) = true ↔ _
  rw [zeroLoop]
  simp only [true_and]
  simp [Std.Legacy.Range.size, List.mem_range']
  constructor
  · intro h i hlo hhi
    exact h i (i - s) (by omega) (by omega)
  · intro h i j hj heq
    apply h i <;> omega

theorem infinity_verdict : verdict infinity = some (DecompressG2.point (.replicate 6 0)
    (.replicate 6 0) (.replicate 6 0) (.replicate 6 0)) := by
  have hd : G2.uncompress (toBytes infinity) = .ok G2.zero := by
    have h128 : (192 : UInt8) &&& 128 ≠ 0 := by decide
    have h64 : (192 : UInt8) &&& 64 ≠ 0 := by decide
    have h32 : (192 : UInt8) &&& 32 = 0 := by decide
    unfold G2.uncompress
    simp [toBytes, infinity, ByteArray.size, ByteArray.get!, h128, h64, h32]
    change tailZero _ 1 = true
    rw [tailZero_iff]
    intro i hlo hhi
    simp [ByteArray.get!, getElem!_pos, show 0 ≠ i by omega,
      show i < 96 by simpa [ByteArray.size] using hhi]
  have hz : blstFp (0 : ZMod Fp.modulus) = ⟨.replicate 6 0⟩ := by
    unfold blstFp
    apply congrArg BlstFp.mk
    apply Vector.ext
    intro i hi
    simp
  rw [verdict, hd]
  change some (blstPoint (0 : Fp2Field) 0) = _
  simp only [blstPoint, QuadraticAlgebra.re_zero, QuadraticAlgebra.im_zero, hz]
  rfl

end LeanBlsSimd.G2Spec
