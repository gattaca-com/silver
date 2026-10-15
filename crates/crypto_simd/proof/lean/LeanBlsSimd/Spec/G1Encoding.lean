import LeanBlsSimd.Spec.G1Curve

namespace LeanBlsSimd.G1Spec

open EthCryptographySpecs Bls
open WeierstrassCurve
open DecompressG1
open EthCryptographySpecs.IdLoops

def toBytes (b : Encoding) : ByteArray := ⟨b.toArray⟩

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

theorem uncompress_infinity : G1.uncompress Kzg.Constants.G1_POINT_AT_INFINITY = .ok G1.zero := by
  have h128 : (192 : UInt8) &&& 128 ≠ 0 := by decide
  have h64 : (192 : UInt8) &&& 64 ≠ 0 := by decide
  have h32 : (192 : UInt8) &&& 32 = 0 := by decide
  unfold G1.uncompress
  simp [Kzg.Constants.G1_POINT_AT_INFINITY, ByteArray.size, ByteArray.get!, h128, h64, h32]
  change tailZero _ 1 = true
  rw [tailZero_iff]
  intro i hlo hhi
  simp [ByteArray.get!, getElem!_pos, show 0 ≠ i by omega,
    show i < 48 by simpa [ByteArray.size] using hhi]

theorem uncompress_infinity_only (b : ByteArray)
    (h : G1.uncompress b = .ok G1.zero) : b = Kzg.Constants.G1_POINT_AT_INFINITY := by
  unfold G1.uncompress at h
  generalize Fp.sqrt = sq at h
  split at h
  · contradiction
  rename_i hs
  have hsize : b.size = 48 := by simpa using hs
  dsimp only at h
  split at h
  · contradiction
  split at h
  · split at h
    · contradiction
    rename_i hf
    have hz : b.get! 0 = 192 ∧ tailZero b 1 = true := by
      change ¬ (decide (b.get! 0 &&& 32 ≠ 0) || decide (b.get! 0 ≠ 192) || !tailZero b 1) = true at hf
      have hf' : (b.get! 0 &&& 32 = 0 ∧ b.get! 0 = 192) ∧ tailZero b 1 = true := by simpa using hf
      exact ⟨hf'.1.2, hf'.2⟩
    apply ByteArray.ext
    apply Array.ext
    · simpa [Kzg.Constants.G1_POINT_AT_INFINITY] using hsize
    · intro i hi hj
      have hget : b.get! i = b.data[i] := by rw [ByteArray.get!, getElem!_pos]
      rw [← hget]
      by_cases hi0 : i = 0
      · subst i
        simpa [Kzg.Constants.G1_POINT_AT_INFINITY] using hz.1
      · have hi48 : i < 48 := by change i < b.size at hi; omega
        rw [(tailZero_iff b 1).mp hz.2 i (by omega) hi]
        simp [Kzg.Constants.G1_POINT_AT_INFINITY, hi48, show 0 ≠ i from Ne.symm hi0]
  · split at h
    · contradiction
    split at h
    · contradiction
    have hz := congrArg (fun p : G1 => p.z.val) (Except.ok.inj h)
    norm_num [G1.zero, Fp.one, Fp.zero, Fp.ofNat] at hz

theorem uncompress_eq_zero_of_infinity {b : ByteArray} {P : G1}
    (hd : G1.uncompress b = .ok P) (hi : P.isInfinity = true) : P = G1.zero := by
  unfold G1.uncompress at hd
  generalize Fp.sqrt = sq at hd
  split at hd
  · contradiction
  dsimp only at hd
  split at hd
  · contradiction
  split at hd
  · split at hd
    · contradiction
    exact (Except.ok.inj hd).symm
  · split at hd
    · contradiction
    split at hd
    · contradiction
    cases Except.ok.inj hd
    norm_num [G1.isInfinity, Fp.isZero, Fp.one, Fp.ofNat] at hi

theorem byteArray_beq_iff (a b : ByteArray) : (a == b) = true ↔ a = b := by
  rcases a with ⟨a⟩
  rcases b with ⟨b⟩
  change (a == b) = true ↔ _
  rw [beq_iff_eq]
  simp only [ByteArray.mk.injEq]

theorem validate_eq_decode (b : ByteArray) : Kzg.validateKzgG1 b =
      match G1.uncompress b with
      | .error _ => false
      | .ok P => G1.inSubgroup P := by
  unfold Kzg.validateKzgG1
  by_cases hb : b = Kzg.Constants.G1_POINT_AT_INFINITY
  · subst b
    rw [if_pos ((byteArray_beq_iff _ _).mpr rfl), uncompress_infinity]
    rfl
  · rw [if_neg (mt (byteArray_beq_iff _ _).mp hb)]
    unfold G1.keyValidate
    cases hd : G1.uncompress b with
    | error e => rfl
    | ok P =>
      have hi : P.isInfinity = false := by
        by_contra hc
        have hp := uncompress_eq_zero_of_infinity hd (Bool.eq_true_of_not_eq_false hc)
        subst P
        exact hb (uncompress_infinity_only b hd)
      change (if P.isInfinity then _ else _ : Except BlsError Unit).isOk = _
      simp only [hi, Bool.false_eq_true, ↓reduceIte]
      cases hg : G1.inSubgroup P <;> simp <;> rfl

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
  unfold verdict Kzg.bytesToKzgProof
  rw [validate_eq_decode]
  cases hd : G1.uncompress (toBytes bytes) with
  | error e => rfl
  | ok P => cases hg : G1.inSubgroup P <;> simp [hg, hd]

theorem verdict_some_iff (bytes : Encoding) (p : BlstP1Affine) :
    verdict bytes = some p ↔
      (Kzg.bytesToKzgProof (toBytes bytes)).isOk = true ∧
      ∃ P, G1.uncompress (toBytes bytes) = .ok P ∧ p = blstLimbs P := by
  rw [verdict_eq_decode]
  unfold Kzg.bytesToKzgProof
  rw [validate_eq_decode]
  cases hd : G1.uncompress (toBytes bytes) with
  | error e => simp
  | ok P =>
    dsimp only
    by_cases hg : G1.inSubgroup P = true <;> simp [hg, Except.isOk, Except.toBool]
    exact eq_comm

theorem verdict_accepts_iff (bytes : Encoding) :
    (verdict bytes).isSome = (Kzg.bytesToKzgProof (toBytes bytes)).isOk := by
  rw [verdict_eq_decode]
  unfold Kzg.bytesToKzgProof
  rw [validate_eq_decode]
  cases hd : G1.uncompress (toBytes bytes) with
  | error e => rfl
  | ok P =>
    dsimp only
    by_cases hg : G1.inSubgroup P = true <;> simp only [hg, ↓reduceIte] <;> rfl

theorem commitment_accepts_iff (bytes : Encoding) :
    (Kzg.bytesToKzgCommitment (toBytes bytes)).isOk = (verdict bytes).isSome := by
  rw [verdict_accepts_iff]
  unfold Kzg.bytesToKzgCommitment Kzg.bytesToKzgProof
  cases Kzg.validateKzgG1 (toBytes bytes) <;> rfl

def infinity : Encoding := (Vector.replicate 48 0).set 0 0xc0

theorem toBytes_infinity : toBytes infinity = Kzg.Constants.G1_POINT_AT_INFINITY := by
  simp [toBytes, infinity, Kzg.Constants.G1_POINT_AT_INFINITY, Array.setIfInBounds_def]

theorem blstLimbs_zero : blstLimbs G1.zero = DecompressG1.point (.replicate 6 0) (.replicate 6 0) := by
  have hz : DecompressG2.blstFp (0 : ZMod Fp.modulus) = ⟨.replicate 6 0⟩ := by
    unfold DecompressG2.blstFp
    apply congrArg DecompressG2.BlstFp.mk
    apply Vector.ext
    intro i hi
    simp
  change DecompressG1.BlstP1Affine.mk (DecompressG2.blstFp (0 : ZMod Fp.modulus))
    (DecompressG2.blstFp (0 : ZMod Fp.modulus)) = _
  rw [hz]
  rfl

theorem infinity_verdict : verdict infinity = some (DecompressG1.point (.replicate 6 0)
    (.replicate 6 0)) := by
  rw [verdict_eq_decode, toBytes_infinity, uncompress_infinity]
  change (if true then _ else _) = _
  simpa using congrArg some blstLimbs_zero

theorem infinity_decoding_iff (bytes : Encoding) :
    G1.uncompress (toBytes bytes) = .ok G1.zero ↔ bytes = infinity := by
  constructor
  · intro h
    have heq := uncompress_infinity_only _ h
    rw [← toBytes_infinity] at heq
    exact Vector.toArray_inj.mp (congrArg ByteArray.data heq)
  · rintro rfl
    rw [toBytes_infinity, uncompress_infinity]

end LeanBlsSimd.G1Spec
