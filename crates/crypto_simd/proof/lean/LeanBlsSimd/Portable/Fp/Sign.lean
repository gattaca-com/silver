import LeanBlsSimd.Portable.Fp.Conversion
import LeanBlsSimd.Spec.Sqrt

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem neg_encoded (x : Bls.Fp) :
    portable.fp.Fp.neg (Kzg.fpEncode x).l = ok (Kzg.fpEncode (-x)).l := by
  unfold portable.fp.Fp.neg
  rw [rep_eq_encode Kzg.portableFpRep_zero]
  simpa only [show Bls.Fp.zero = (0 : Bls.Fp) from rfl,zero_sub] using sub_encoded 0 x

theorem square_encoded [RuntimeFeatures] (x : Bls.Fp) :
    portable.fp.Fp.square (Kzg.fpEncode x).l = ok (Kzg.fpEncode (x*x)).l :=
  mul_encoded x x

theorem is_larger_root_refines [RuntimeFeatures] (x : Bls.Fp) :
    portable.fp.Fp.is_larger_root (Kzg.fpEncode x).l = ok (Bls.Fp.signBit x) := by
  have hx : x.val < 2^384 := lt_trans x.isLt (by decide)
  obtain ⟨doubled,hadd,hd⟩ := add_words_refines (Kzg.words 6#usize x.val) (Kzg.words 6#usize x.val)
  rw [ordinary_words_value x.val hx] at hadd hd
  have hsmall : (x.val : ℤ)+x.val < (radix : ℤ)^6 := by
    have := x.isLt
    norm_num [Bls.Fp.modulus,radix] at this ⊢
    omega
  rw [Int.emod_eq_of_lt (by positivity) hsmall] at hd
  obtain ⟨difference,hsub,hv⟩ := sub_words_refines doubled bls.constants.P_U64
  rw [modulus_words,hd] at hsub
  simp only [portable.fp.Fp.is_larger_root,to_plain_encoded,bind_tc_ok,hadd,
    not_le.mpr hsmall,decide_false]
  change (do
    let (_,borrow) ← portable.fp.sub_words doubled bls.constants.P_U64
    if false then ok true else ok (decide (¬borrow = true))) = _
  rw [hsub,bind_tc_ok]
  change ok (decide (¬decide ((x.val : ℤ)+x.val < Bls.Fp.modulus) = true)) = ok (Bls.Fp.signBit x)
  apply congrArg ok
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq,Bls.Fp.signBit]
  have := x.isLt
  norm_num [Bls.Fp.modulus] at this ⊢
  omega

theorem signed_refines [RuntimeFeatures] (x : Bls.Fp) (larger : Bool) :
    portable.decompress.signed (Kzg.fpEncode x).l larger =
      ok (Kzg.fpEncode (if Bls.Fp.signBit x = larger then x else -x)).l := by
  simp only [portable.decompress.signed,is_larger_root_refines,bind_tc_ok]
  split <;> simp_all only [neg_encoded]

end LeanBlsSimd.Portable.Fp
