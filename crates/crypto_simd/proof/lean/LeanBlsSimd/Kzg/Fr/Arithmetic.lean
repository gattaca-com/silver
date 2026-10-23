import LeanBlsSimd.Kzg.Fr.Encoding
import LeanBlsSimd.Kzg.ScalarContracts

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fr

namespace LeanBlsSimd.FrScalar
open Word64

theorem add_value_refines (a b : blst.blst_fr)
    (ha : value a.l < Fr.modulus) (hb : value b.l < Fr.modulus) :
    ∃ out, fr.fr_add a b = ok (blst.blst_fr.mk out) ∧
      value out = (value a.l+value b.l) % (Fr.modulus : ℤ) := by
  obtain ⟨sum,hadd,hvalue⟩ := add_words_refines a.l b.l
  have ha0 := (value_bounds a.l).1
  have hb0 := (value_bounds b.l).1
  have hfit : value a.l+value b.l < (radix : ℤ)^4 := by
    norm_num [Fr.modulus,radix] at ha hb ⊢
    omega
  rw [Int.emod_eq_of_lt (by omega) hfit] at hvalue
  obtain ⟨out,hbelow,hout⟩ := below_r_refines sum (by omega)
  refine ⟨out,?_,?_⟩
  · simp only [fr.fr_add,hadd,hbelow,bind_tc_ok]
  · simpa only [hvalue] using hout

theorem sub_value_refines (a b : blst.blst_fr)
    (ha : value a.l < Fr.modulus) (hb : value b.l < Fr.modulus) :
    ∃ out, fr.fr_sub a b = ok (blst.blst_fr.mk out) ∧
      value out = (value a.l-value b.l) % (Fr.modulus : ℤ) := by
  obtain ⟨difference,hsub,hvalue⟩ := sub_words_refines a.l b.l
  have ha0 := (value_bounds a.l).1
  have hb0 := (value_bounds b.l).1
  by_cases hborrow : value a.l < value b.l
  · obtain ⟨out,hadd,hout⟩ := add_words_refines difference fr.R
    rw [modulus_words] at hout
    refine ⟨out,?_,?_⟩
    · simp [fr.fr_sub,hsub,hborrow,hadd]
    · norm_num [radix,Fr.modulus] at ha hb hvalue hout ⊢
      omega
  · refine ⟨difference,?_,?_⟩
    · simp [fr.fr_sub,hsub,hborrow]
    · norm_num [radix,Fr.modulus] at ha hb hvalue ⊢
      omega

theorem fr_add_refines (x y : Fr) :
    fr.fr_add (Kzg.frEncode x) (Kzg.frEncode y) = ok (Kzg.frEncode (x+y)) := by
  obtain ⟨out,hr,hvalue⟩ := add_value_refines (Kzg.frEncode x) (Kzg.frEncode y)
    (encode_bound x) (encode_bound y)
  have hbound : value out < Fr.modulus := by
    rw [hvalue]
    exact Int.emod_lt_of_pos _ (by decide)
  have heq : out = (Kzg.frEncode (x+y)).l := by
    apply eq_encode_of_field out (x+y) hbound
    rw [hvalue,ZMod.intCast_mod,Int.cast_add,encode_field,encode_field,encode_field,map_add]
    ring
  rw [hr,heq]

theorem fr_sub_refines (x y : Fr) :
    fr.fr_sub (Kzg.frEncode x) (Kzg.frEncode y) = ok (Kzg.frEncode (x-y)) := by
  obtain ⟨out,hr,hvalue⟩ := sub_value_refines (Kzg.frEncode x) (Kzg.frEncode y)
    (encode_bound x) (encode_bound y)
  have hbound : value out < Fr.modulus := by
    rw [hvalue]
    exact Int.emod_lt_of_pos _ (by decide)
  have heq : out = (Kzg.frEncode (x-y)).l := by
    apply eq_encode_of_field out (x-y) hbound
    rw [hvalue,ZMod.intCast_mod,Int.cast_sub,encode_field,encode_field,encode_field]
    have hsub : Fr.toZMod (x-y) = Fr.toZMod x-Fr.toZMod y := by rfl
    rw [hsub]
    ring
  rw [hr,heq]

theorem fr_mul_refines (x y : Fr) :
    fr.fr_mul (Kzg.frEncode x) (Kzg.frEncode y) = ok (Kzg.frEncode (x*y)) := by
  obtain ⟨out,hr,hbound,k,hvalue⟩ := montgomery_product_refines (Kzg.frEncode x).l
    (Kzg.frEncode y).l (encode_bound x)
  have hpow : (radix : ZMod Fr.modulus)^4 = (2^256 : ZMod Fr.modulus) := by
    norm_num [radix]
  have hfield : (value out : ZMod Fr.modulus)*(2^256 : ZMod Fr.modulus) =
      (value (Kzg.frEncode x).l : ZMod Fr.modulus)*(value (Kzg.frEncode y).l : ZMod Fr.modulus) := by
    have h := congrArg (fun n : ℤ => (n : ZMod Fr.modulus)) hvalue
    dsimp only at h
    simpa only [Int.cast_mul,Int.cast_add,Int.cast_pow,Int.cast_natCast,
      ZMod.natCast_self,mul_zero,add_zero,hpow] using h
  rw [encode_field,encode_field] at hfield
  have hne : (2^256 : ZMod Fr.modulus) ≠ 0 := by decide +kernel
  have heq : out = (Kzg.frEncode (x*y)).l := by
    apply eq_encode_of_field out (x*y) hbound
    apply mul_right_cancel₀ hne
    rw [hfield,encode_field,map_mul]
    ring
  simp only [fr.fr_mul,hr,bind_tc_ok]
  rw [heq]

theorem fr_correct : Kzg.FrCorrect :=
  ⟨fr_add_refines,fr_sub_refines,fr_mul_refines⟩

end LeanBlsSimd.FrScalar
