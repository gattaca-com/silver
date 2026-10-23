import LeanBlsSimd.Msm8.StorePush
import LeanBlsSimd.Msm8.Conversion
import LeanBlsSimd.Proofs.G1x8

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd
open EthLib.Cryptography.Bls

@[simp] theorem ofU8_or (a b : U8) : ofU8 (a ||| b) = ofU8 a ||| ofU8 b := rfl

theorem signBit_singleton (negated : Bool) (i l : Fin 8) :
    (ofU8 (⟨(UScalar.cast_fromBool .U8 negated).bv.shiftLeft i⟩ : U8)).toNat.testBit l =
      (decide (l = i) && negated) := by
  revert negated i l
  decide

theorem gather_fold_sign (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (lanes : List (Fin 8))
    (b : GatheredBatch) (l : Fin 8) :
    (ofU8 (lanes.foldl (gatherStep points negated base offset count) b).negate).toNat.testBit l =
      ((ofU8 b.negate).toNat.testBit l ||
        (decide (l ∈ lanes) && negated[batchSource offset count l]!)) := by
  induction lanes generalizing b with
  | nil => simp
  | cons j lanes ih =>
    rw [List.foldl_cons, ih]
    simp only [gatherStep, ofU8_or, Mmask8.testBit_or, signBit_singleton,
      List.mem_cons, Bool.decide_or]
    by_cases h : l = j
    · subst j
      simp only [decide_true, Bool.true_and, Bool.true_or]
      cases (ofU8 b.negate).toNat.testBit l <;>
        cases negated[batchSource offset count l]! <;> simp
    · simp only [h, decide_false, Bool.false_and, Bool.false_or, Bool.or_false]

theorem gatherBatch_sign (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (l : Fin 8) :
    (ofU8 (gatherBatch points negated base offset count emptyGathered).negate).toNat.testBit l =
      negated[batchSource offset count l]! := by
  rw [gatherBatch, gather_fold_sign]
  simp [emptyGathered]

theorem fromBlstFactor_eq :
    fromBlstFactor = Fp8.splat_limbs (.ofList TWO_POW_448_MOD_P) := by
  unfold fromBlstFactor constants.TWO_POW_448_MOD_P
  rfl

theorem endomorphismFactor_holds (l : Fin 8) :
    endomorphismFactor.Holds l (beta : ZMod Fp.modulus) := by
  have he : endomorphismFactor = Fp8.splat_limbs (.ofList BETA_MONT) := by
    unfold endomorphismFactor constants.BETA_MONT
    rfl
  rw [he]
  exact (Fp8.holds_splat_limbs (t := .ofList BETA_MONT)
    ⟨by decide, by decide +kernel⟩ l).of_eq (decode_of_val BETA_MONT_eq)

theorem convertedBatch_holds (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (endomorphism : Bool) (l : Fin 8)
    (x y : ZMod Fp.modulus)
    (hx : val64 points[batchSource offset count l]!.1 = (x * 2 ^ 384).val)
    (hy : val64 points[batchSource offset count l]!.2 = (y * 2 ^ 384).val) :
    let converted := convertedBatch (gatherBatch points negated base offset count emptyGathered)
      fromBlstFactor endomorphismFactor endomorphism
    converted.1.Holds l (if endomorphism then x * beta else x) ∧
    converted.2.Holds l (if negated[batchSource offset count l]! then -y else y) := by
  let wx : Vector (Vector UInt64 6) 8 := .ofFn fun j => points[batchSource offset count j]!.1
  let wy : Vector (Vector UInt64 6) 8 := .ofFn fun j => points[batchSource offset count j]!.2
  have hx' := Fp8.from_blst_holds wx l x (by simpa [wx] using hx)
  have hy' := Fp8.from_blst_holds wy l y (by simpa [wy] using hy)
  have hxs : (gatherBatch points negated base offset count emptyGathered).xs = wx.map unpack52 := by
    rw [gatherBatch_xs]
    ext j hj
    simp [wx]
  have hys : (gatherBatch points negated base offset count emptyGathered).ys = wy.map unpack52 := by
    rw [gatherBatch_ys]
    ext j hj
    simp [wy]
  dsimp only [convertedBatch]
  rw [hxs, hys, fromBlstFactor_eq]
  constructor
  · cases endomorphism
    · exact hx'
    · exact hx'.mul (endomorphismFactor_holds l)
  · have h := hy'.select (ofU8 (gatherBatch points negated base offset count emptyGathered).negate) hy'.neg
    simpa only [gatherBatch_sign] using h

end LeanBlsSimd

namespace LeanBlsSimd

def negateLimbs (a : Limbs) : Limbs :=
  let st := Lane.sub_limbs (Vector.replicate LIMBS 0) a
  if st.2 = 0xffffffffffffffff then (Lane.add_limbs st.1 (.ofList (limbs52 (2 * EthLib.Cryptography.Bls.Fp.modulus)))).1 else st.1

theorem lane_negateLimbs (a : Fp8) (l : Fin 8) : a.neg.lane l = negateLimbs (a.lane l) := by
  have hs := Simd.sub_limbs_lane Fp8.zero.limbs a.limbs l
  rw [← Fp8.lane_eq, ← Fp8.lane_eq, Fp8.lane_zero] at hs
  have hd := congrArg Prod.fst hs
  have hb := congrArg Prod.snd hs
  simp only at hd hb
  simp only [Fp8.neg, Fp8.sub, Fp8.lane_mk, Simd.laneOf_blend,
    Simd.testBit_borrowed, Simd.add_limbs_lane, Fp8.multiple_of_p_two, Simd.laneOf_two_p]
  rw [hd, hb]
  unfold negateLimbs
  simp only [decide_eq_true_eq]

end LeanBlsSimd

namespace LeanBlsSimd

def convertedPoint (point : Vector UInt64 6 × Vector UInt64 6) (negated endomorphism : Bool) :
    Limbs × Limbs :=
  let x := Lane.mul (unpack52 point.1) (.ofList TWO_POW_448_MOD_P)
  let y := Lane.mul (unpack52 point.2) (.ofList TWO_POW_448_MOD_P)
  (if endomorphism then Lane.mul x (.ofList BETA_MONT) else x,
   if negated then negateLimbs y else y)

theorem endomorphismFactor_eq : endomorphismFactor = Fp8.splat_limbs (.ofList BETA_MONT) := by
  unfold endomorphismFactor constants.BETA_MONT
  rfl

theorem convertedBatch_lane (points : List (Vector UInt64 6 × Vector UInt64 6))
    (negated : List Bool) (base offset count : ℕ) (endomorphism : Bool) (l : Fin 8) :
    let converted := convertedBatch (gatherBatch points negated base offset count emptyGathered)
      fromBlstFactor endomorphismFactor endomorphism
    (converted.1.lane l, converted.2.lane l) =
      convertedPoint points[batchSource offset count l]! negated[batchSource offset count l]! endomorphism := by
  dsimp only [convertedBatch]
  simp only [Fp8.lane_select, gatherBatch_sign, lane_negateLimbs,
    Fp8.lane_mul, Fp8.lane_load, gatherBatch_xs, gatherBatch_ys,
    fromBlstFactor_eq, endomorphismFactor_eq, Fp8.lane_splat_limbs, Fin.getElem_fin, Vector.getElem_ofFn]
  cases endomorphism <;>
    simp only [Bool.false_eq_true, if_false, if_true, Fp8.lane_mul, Fp8.lane_load,
      Fp8.lane_splat_limbs, convertedPoint, Fin.getElem_fin, Vector.getElem_ofFn]

end LeanBlsSimd
