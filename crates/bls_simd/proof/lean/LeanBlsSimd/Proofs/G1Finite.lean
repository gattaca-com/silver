import LeanBlsSimd.Proofs.DecodeG1
import LeanBlsSimd.Spec.G1Encoding

namespace LeanBlsSimd.DecompressG1

open EthCryptographySpecs.Bls
open G1Spec (toBytes)

theorem size_toBytes (bytes : Encoding) : (toBytes bytes).size = 48 := by
  simp [toBytes, ByteArray.size]

theorem get!_toBytes_zero (bytes : Encoding) : (toBytes bytes).get! 0 = bytes[0] := by
  show bytes.toArray[0]! = _
  rw [getElem!_pos bytes.toArray 0 (by simp)]
  simp

theorem bytesBEToNat_x (bytes : Encoding) :
    Fp.bytesBEToNat ((toBytes bytes).set! 0 ((toBytes bytes).get! 0 &&& 0x1f)) =
      bytesVal (clearFlags bytes).toList := by
  rw [bytesBEToNat_eq, get!_toBytes_zero]
  simp [toBytes, ByteArray.set!, clearFlags, Vector.toList_set]
  rfl

theorem uncompress_eq {b : Encoding}
    (hc : ¬(b[0] &&& 0x80 = 0))
    (hi : ¬(b[0] &&& 0x40 ≠ 0))
    (h1 : bytesVal (clearFlags b).toList < Fp.modulus) :
    G1.uncompress (toBytes b) =
      let x : Fp := ⟨_, h1⟩
      match Fp.sqrt (x * x * x + Fp.ofNat 4) with
      | .error _ => .error .invalidG1Point
      | .ok yPos =>
        .ok ⟨x, if Fp.signBit yPos = decide (b[0] &&& 0x20 ≠ 0) then yPos
          else -yPos, Fp.one⟩ := by
  unfold G1.uncompress
  generalize Fp.sqrt = sq
  rw [if_neg (by rw [size_toBytes]; decide)]
  dsimp only
  have e1 := bytesBEToNat_x b
  rw [get!_toBytes_zero] at e1 ⊢
  have hsz : ((toBytes b).set! 0 (b[0] &&& 0x1f)).size = 48 := by
    simp [toBytes, ByteArray.set!, ByteArray.size]
  rw [if_neg (by simpa using hc), if_neg hi, DecompressG2.fromBytesBE_ok hsz e1 h1]
  dsimp only
  split <;> rename_i heq <;> rw [heq]
  rename_i yPos
  dsimp only
  congr 2
  by_cases hs : Fp.signBit yPos = decide (b[0] &&& 0x20 ≠ 0)
  · rw [if_pos hs, if_pos (by rw [hs]; simp)]
  · rw [if_neg hs, if_neg (fun h => hs (by rw [Bool.eq_iff_iff, decide_eq_true_iff, ← h]))]

/-- An encoding that `decode` marks invalid, and not undecided, fails `G1.uncompress`. -/
theorem uncompress_of_invalid {b : Encoding}
    (hu : (decodeLane b).undecided = false) (hv : (decodeLane b).invalid = true) :
    ∀ P, G1.uncompress (toBytes b) ≠ .ok P := by
  intro P hP
  unfold G1.uncompress at hP
  generalize Fp.sqrt = sq at hP
  rw [if_neg (by rw [size_toBytes]; decide)] at hP
  dsimp only at hP
  have e1 := bytesBEToNat_x b
  rw [get!_toBytes_zero] at e1 hP
  unfold decodeLane at hu hv
  dsimp only at hu hv
  by_cases hc : b[0] &&& 0x80 = 0
  · rw [if_pos (by simpa using hc)] at hP
    cases hP
  rw [if_neg hc] at hu hv
  rw [if_neg (by simpa using hc)] at hP
  by_cases hi : b[0] &&& 0x40 ≠ 0
  · rw [if_pos hi] at hu
    cases hu
  rw [if_neg hi] at hv hP
  by_cases hok : bytesVal (clearFlags b).toList < Fp.modulus
  · rw [if_pos hok] at hv
    cases hv
  revert hP
  cases hf : Fp.fromBytesBE ((toBytes b).set! 0 (b[0] &&& 0x1f)) with
  | error e => intro hP; cases hP
  | ok c => exact absurd hf (DecompressG2.fromBytesBE_error e1 hok c)

theorem decodeLane_ok {b : Encoding}
    (hu : (decodeLane b).undecided = false) (hv : (decodeLane b).invalid = false) :
    ∃ (_ : ¬(b[0] &&& 0x80 = 0))
      (_ : ¬(b[0] &&& 0x40 ≠ 0))
      (_ : bytesVal (clearFlags b).toList < Fp.modulus),
      decodeLane b = ⟨bytesVal (clearFlags b).toList,
        decide (b[0] &&& 0x20 ≠ 0), false, false⟩ := by
  unfold decodeLane at hu hv ⊢
  dsimp only at hu hv ⊢
  by_cases hc : b[0] &&& 0x80 = 0
  · rw [if_pos hc] at hv
    cases hv
  rw [if_neg hc] at hu hv ⊢
  by_cases hi : b[0] &&& 0x40 ≠ 0
  · rw [if_pos hi] at hu
    cases hu
  rw [if_neg hi] at hv ⊢
  by_cases hok : bytesVal (clearFlags b).toList < Fp.modulus
  · rw [if_pos hok]
    exact ⟨hc, hi, hok, rfl⟩
  · rw [if_neg hok] at hv
    cases hv

def laneX (b : Encoding) : ZMod Fp.modulus := (decodeLane b).x

def laneRoot (b : Encoding) : ZMod Fp.modulus :=
  Kernel.sqrtCandidate (laneX b ^ 2 * laneX b + 4)

def laneY (b : Encoding) : ZMod Fp.modulus :=
  if Kernel.isLargerRootFp (laneRoot b) ^^ (decodeLane b).largerRoot then
    -laneRoot b else laneRoot b

def lanePoint (b : Encoding) : G1 := ⟨laneX b, laneY b, Fp.one⟩

theorem candidate_eq_pow (a : ZMod Fp.modulus) :
    a ^ ((Fp.modulus + 1) / 4) = Kernel.sqrtCandidate a := by
  rw [show (Fp.modulus + 1) / 4 = (Fp.modulus - 3) / 4 + 1 by decide, pow_succ]
  rfl

private theorem sqrt_candidate_aux (a : Fp) (c : ZMod Fp.modulus)
    (hc : Fp.powNat a ((Fp.modulus + 1) / 4) = c) : Fp.sqrt a =
    (if c ^ 2 = a then .ok c else .error .notASquare : Except BlsError Fp) := by
  unfold Fp.sqrt
  rw [hc]
  dsimp only
  simp only [G1.beq_iff]
  congr 1
  change ((c * c : ZMod Fp.modulus) = a) = ((c ^ 2 : ZMod Fp.modulus) = a)
  rw [pow_two]

theorem sqrt_eq (a : Fp) : Fp.sqrt a =
    if Kernel.sqrtCandidate a ^ 2 = a then .ok (Kernel.sqrtCandidate a)
    else .error .notASquare :=
  sqrt_candidate_aux a (Kernel.sqrtCandidate a)
    ((Fp.powNat_eq_zmod_pow a _).trans (candidate_eq_pow a))

private theorem fp_rhs_eq (x : Fp) :
    (x * x * x + Fp.ofNat 4 : Fp) = (fun t : ZMod Fp.modulus => t ^ 2 * t + 4) x := by
  change (fun t : ZMod Fp.modulus => t * t * t + 4) x = _
  simp only [sq]
  rfl

theorem uncompress_decoded {b : Encoding}
    (hu : (decodeLane b).undecided = false) (hv : (decodeLane b).invalid = false) :
    G1.uncompress (toBytes b) =
      if laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4 then .ok (lanePoint b)
      else .error .invalidG1Point := by
  obtain ⟨hc, hi, hp, hd⟩ := decodeLane_ok hu hv
  rw [uncompress_eq hc hi hp]
  dsimp only
  rw [sqrt_eq]
  have hx : (⟨bytesVal (clearFlags b).toList, hp⟩ : Fp) = laneX b := by
    rw [laneX, hd]
    exact DecompressG2.fp_mk_eq_natCast hp
  rw [hx]
  rw [fp_rhs_eq]
  unfold lanePoint laneY
  have hsign : (decodeLane b).largerRoot = decide (b[0] &&& 0x20 ≠ 0) := by rw [hd]
  rw [hsign, Kernel.isLargerRootFp_eq]
  generalize hroot : Kernel.sqrtCandidate ((fun t : ZMod Fp.modulus => t ^ 2 * t + 4) (laneX b)) = root
  have hroot' : laneRoot b = root := hroot
  rw [hroot']
  generalize laneX b = x
  change (match (if root ^ 2 = x ^ 2 * x + 4 then
      Except.ok root else Except.error BlsError.notASquare : Except BlsError Fp) with
    | .error _ => Except.error BlsError.invalidG1Point
    | .ok y => Except.ok (G1.mk x
      (if Fp.signBit y = decide (b[0] &&& 0x20 ≠ 0) then y else -y) Fp.one)) =
    (if root ^ 2 = x ^ 2 * x + 4 then
      Except.ok (G1.mk x (if Fp.signBit root ^^ decide (b[0] &&& 0x20 ≠ 0) then -root else root) Fp.one)
      else Except.error BlsError.invalidG1Point)
  clear hu hv hc hi hd hx hsign hroot hroot'
  generalize hsg : Fp.signBit root = sign
  generalize decide (b[0] &&& 0x20 ≠ 0) = desired
  cases sign <;> cases desired <;> split_ifs <;> first | rfl | contradiction | (simp [hsg] <;> rfl)

theorem invalid_undecided {b : Encoding} (h : (decodeLane b).invalid = true) :
    (decodeLane b).undecided = false := by
  unfold decodeLane at h ⊢
  dsimp only at h ⊢
  split_ifs at h ⊢ <;> simp_all

private theorem mk_one_valid (x y : ZMod Fp.modulus) (h : y ^ 2 = x ^ 3 + 4) :
    G1.Valid ⟨x, y, Fp.one⟩ := by
  exact (WeierstrassCurve.Jacobian.nonsingular_some x y).mpr
    ((G1Spec.nonsingular_iff x y).mpr h)

theorem lanePoint_valid {b : Encoding}
    (h : laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4) : G1.Valid (lanePoint b) := by
  apply mk_one_valid
  have hy : laneY b ^ 2 = laneRoot b ^ 2 := by
    unfold laneY
    split <;> ring
  rw [hy, h]
  ring

private theorem blstLimbs_mk_one (x y : ZMod Fp.modulus) :
    G1Spec.blstLimbs ⟨x, y, Fp.one⟩ =
      ⟨DecompressG2.blstFp x, DecompressG2.blstFp y⟩ := by
  have hi : Fp.inverse Fp.one = Fp.one := by
    rw [Fp.inverse_eq_inv]
    change (1 : ZMod Fp.modulus)⁻¹ = 1
    exact inv_one
  unfold G1Spec.blstLimbs G1.toAffine
  rw [show Fp.one.isZero = false by decide, if_neg (by decide), hi]
  change (⟨DecompressG2.blstFp (x * (1 * 1)),
    DecompressG2.blstFp (y * (1 * 1 * 1))⟩ : BlstP1Affine) = _
  simp only [mul_one]

theorem blstLimbs_lanePoint (b : Encoding) : G1Spec.blstLimbs (lanePoint b) =
    ⟨DecompressG2.blstFp (laneX b), DecompressG2.blstFp (laneY b)⟩ :=
  blstLimbs_mk_one _ _

end LeanBlsSimd.DecompressG1
