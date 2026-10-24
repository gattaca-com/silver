import LeanBlsSimd.Portable.Decode.Fields
import LeanBlsSimd.Portable.Decode.Spec
import LeanBlsSimd.Portable.Fp.PairSqrt
import LeanBlsSimd.Portable.G1.PairScott

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Decode
open DecompressG1
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

def curvePoint (b : Encoding) : Bool :=
  decide (laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4) && !Bls.Fp.isZero (laneY b)

def curveVerdict (b : Encoding) : Option blst.blst_p1_affine :=
  if curvePoint b then if Bls.G1.inSubgroup (lanePoint b) then
    some (toBlstP1Affine (G1Spec.blstLimbs (lanePoint b))) else none else none

theorem curvePoint_valid {b : Encoding} (h : curvePoint b = true) : Bls.G1.Valid (lanePoint b) := by
  have hr : laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4 := by
    have ht : (laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4) ∧ Bls.Fp.isZero (laneY b) = false := by
      simpa [curvePoint] using h
    exact ht.1
  exact lanePoint_valid hr

theorem curveVerdict_spec {b : Encoding} (ho : Ordinary b) :
    curveVerdict b = (G1Spec.verdict b).map toBlstP1Affine := by
  rw [G1Spec.verdict_eq_decode,uncompress_decoded ho.1 ho.2.1]
  unfold curveVerdict curvePoint
  by_cases hr : laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4
  · simp only [hr,if_true,decide_true,Bool.true_and]
    by_cases hy : Bls.Fp.isZero (laneY b) = true
    · simp only [hy,Bool.not_true,Bool.false_eq_true,if_false,y_zero_rejected b (lanePoint_valid hr) hy,
        Option.map_none]
    · have hyf : Bls.Fp.isZero (laneY b) = false := Bool.eq_false_iff.mpr hy
      simp only [hyf,Bool.not_false,if_true]
      split <;> rfl
  · simp only [hr,if_false,decide_false,Bool.false_and,Bool.false_eq_true,Option.map_none]

theorem mul_words_pair [RuntimeFeatures] {a b : Encoding} (ha : Ordinary a) (hb : Ordinary b) :
    portable.fp.Fp.mul_pair (Array.make 2#usize [words a,words b] (by rfl))
      (Array.make 2#usize [portable.constants.R2,portable.constants.R2] (by rfl)) =
      ok (Fp.pairEncode (laneX a) (laneX b)) := by
  simp (disch := decide) only [portable.fp.Fp.mul_pair,index_usize_eq,bind_tc_ok]
  change (do let x ← portable.fp.Fp.mul (words a) portable.constants.R2
             let y ← portable.fp.Fp.mul (words b) portable.constants.R2
             ok (Array.make 2#usize [x,y] (by rfl))) = _
  simp only [Fp.mul_eq_product,Fp.canonical_words_refines _ (words_bound ha.1 ha.2.1),
    Fp.canonical_words_refines _ (words_bound hb.1 hb.2.1),words_field ha.1 ha.2.1,
    words_field hb.1 hb.2.1,bind_tc_ok,Fp.pairEncode]

theorem curve_check [RuntimeFeatures] (b : Encoding) :
    (if decide (laneRoot b ^ 2 = laneX b ^ 2 * laneX b + 4) then
      do let z ← portable.fp.Fp.is_zero (Kzg.fpEncode (laneY b)).l; ok (!z)
    else ok false) = ok (curvePoint b) := by
  simp only [Fp.is_zero_encoded,bind_tc_ok,curvePoint]
  split <;> simp_all

theorem pair_bool_zero (a b : Bool) :
    Array.index_usize (Array.make 2#usize [a,b] (by rfl)) 0#usize = ok a :=
  G1.Pair.flags_zero a b

theorem pair_bool_one (a b : Bool) :
    Array.index_usize (Array.make 2#usize [a,b] (by rfl)) 1#usize = ok b :=
  G1.Pair.flags_one a b

end LeanBlsSimd.Portable.Decode
