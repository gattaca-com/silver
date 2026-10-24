import LeanBlsSimd.Portable.Fp.Encoding

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem add_value_refines (a b : portable.fp.Fp)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus) :
    ∃ out, portable.fp.Fp.add a b = ok out ∧
      value out = (value a+value b) % (Bls.Fp.modulus : ℤ) := by
  obtain ⟨sum,hadd,hvalue⟩ := add_words_refines a b
  have ha0 := (value_bounds a).1
  have hb0 := (value_bounds b).1
  have hfit : value a+value b < (radix : ℤ)^6 := by
    norm_num [Bls.Fp.modulus,radix] at ha hb ⊢
    omega
  rw [Int.emod_eq_of_lt (by omega) hfit] at hvalue
  obtain ⟨out,hbelow,hout⟩ := below_p_refines sum (by omega)
  refine ⟨out,?_,?_⟩
  · simp only [portable.fp.Fp.add,hadd,bind_tc_ok]
    change (do let a ← portable.fp.below_p sum; ok a) = _
    rw [hbelow,bind_tc_ok]
  · simpa only [hvalue] using hout

theorem sub_value_refines (a b : portable.fp.Fp)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus) :
    ∃ out, portable.fp.Fp.sub a b = ok out ∧
      value out = (value a-value b) % (Bls.Fp.modulus : ℤ) := by
  obtain ⟨difference,hsub,hvalue⟩ := sub_words_refines a b
  have ha0 := (value_bounds a).1
  have hb0 := (value_bounds b).1
  by_cases hborrow : value a < value b
  · obtain ⟨out,hadd,hout⟩ := add_words_refines difference bls.constants.P_U64
    rw [modulus_words] at hout
    refine ⟨out,?_,?_⟩
    · simp only [portable.fp.Fp.sub,hsub,bind_tc_ok]
      change (do
        let correction ← portable.fp.p_if (decide (value a < value b))
        let (a1,_) ← portable.fp.add_words difference correction
        ok a1) = _
      simp only [hborrow,decide_true,p_if_refines,ite_true,bind_tc_ok,hadd]
    · norm_num [radix,Bls.Fp.modulus] at ha hb hvalue hout ⊢
      omega
  · obtain ⟨out,hadd,hout⟩ := add_words_refines difference (Array.repeat 6#usize 0#u64)
    have hz : value (Array.repeat 6#usize 0#u64) = 0 := rfl
    rw [hz,add_zero] at hout
    refine ⟨out,?_,?_⟩
    · simp only [portable.fp.Fp.sub,hsub,bind_tc_ok]
      change (do
        let correction ← portable.fp.p_if (decide (value a < value b))
        let (a1,_) ← portable.fp.add_words difference correction
        ok a1) = _
      simp only [hborrow,decide_false,p_if_refines,Bool.false_eq_true,ite_false,bind_tc_ok,hadd]
    · norm_num [radix,Bls.Fp.modulus] at ha hb hvalue hout ⊢
      omega

theorem add_encoded (x y : Bls.Fp) :
    portable.fp.Fp.add (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x+y)).l := by
  obtain ⟨out,hr,hvalue⟩ := add_value_refines (Kzg.fpEncode x).l (Kzg.fpEncode y).l
    (encode_bound x) (encode_bound y)
  have hbound : value out < Bls.Fp.modulus := by
    rw [hvalue]
    exact Int.emod_lt_of_pos _ (by decide)
  have heq : out = (Kzg.fpEncode (x+y)).l := by
    apply eq_encode_of_field out (x+y) hbound
    rw [hvalue,ZMod.intCast_mod,Int.cast_add,encode_field,encode_field,encode_field,map_add]
    ring
  rw [hr,heq]

theorem sub_encoded (x y : Bls.Fp) :
    portable.fp.Fp.sub (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x-y)).l := by
  obtain ⟨out,hr,hvalue⟩ := sub_value_refines (Kzg.fpEncode x).l (Kzg.fpEncode y).l
    (encode_bound x) (encode_bound y)
  have hbound : value out < Bls.Fp.modulus := by
    rw [hvalue]
    exact Int.emod_lt_of_pos _ (by decide)
  have heq : out = (Kzg.fpEncode (x-y)).l := by
    apply eq_encode_of_field out (x-y) hbound
    rw [hvalue,ZMod.intCast_mod,Int.cast_sub,encode_field,encode_field,encode_field]
    have hsub : Bls.Fp.toZMod (x-y) = Bls.Fp.toZMod x-Bls.Fp.toZMod y := by rfl
    rw [hsub]
    ring
  rw [hr,heq]

theorem product_encoded (x y : Bls.Fp) :
    portable.fp.Fp.product (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l := by
  obtain ⟨out,hr,hbound,k,hvalue⟩ := product_refines (Kzg.fpEncode x).l
    (Kzg.fpEncode y).l (encode_bound x)
  have hpow : (radix : ZMod Bls.Fp.modulus)^6 = (2^384 : ZMod Bls.Fp.modulus) := by
    norm_num [radix]
  have hfield : (value out : ZMod Bls.Fp.modulus)*(2^384 : ZMod Bls.Fp.modulus) =
      (value (Kzg.fpEncode x).l : ZMod Bls.Fp.modulus)*(value (Kzg.fpEncode y).l : ZMod Bls.Fp.modulus) := by
    have h := congrArg (fun n : ℤ => (n : ZMod Bls.Fp.modulus)) hvalue
    dsimp only at h
    simpa only [Int.cast_mul,Int.cast_add,Int.cast_pow,Int.cast_natCast,
      ZMod.natCast_self,mul_zero,add_zero,hpow] using h
  rw [encode_field,encode_field] at hfield
  have hne : (2^384 : ZMod Bls.Fp.modulus) ≠ 0 := by decide +kernel
  have heq : out = (Kzg.fpEncode (x*y)).l := by
    apply eq_encode_of_field out (x*y) hbound
    apply mul_right_cancel₀ hne
    rw [hfield,encode_field,map_mul]
    ring
  rw [hr,heq]

theorem mul_baseline_encoded (x y : Bls.Fp) :
    portable.fp.Fp.mul_on_baseline (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l :=
  product_encoded x y

theorem mul_bmi2_encoded (x y : Bls.Fp) :
    portable.fp.Fp.mul_on_bmi2 (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l :=
  product_encoded x y

theorem mul_encoded [RuntimeFeatures] (x y : Bls.Fp) :
    portable.fp.Fp.mul (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (Kzg.fpEncode (x*y)).l := by
  simp only [portable.fp.Fp.mul,bmi2_available,bind_tc_ok]
  split <;> exact product_encoded x y

end LeanBlsSimd.Portable.Fp
