import LeanBlsSimd.Kzg.Fr.Arithmetic

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrScalar
open Word64

theorem montgomery_field_refines (a b : Array U64 4#usize)
    (ha : value a < Fr.modulus) :
    ∃ out, fr.montgomery_product a b = ok out ∧ value out < Fr.modulus ∧
      (value out : ZMod Fr.modulus)*(2^256 : ZMod Fr.modulus) =
        (value a : ZMod Fr.modulus)*(value b : ZMod Fr.modulus) := by
  obtain ⟨out,hr,hbound,k,hvalue⟩ := montgomery_product_refines a b ha
  refine ⟨out,hr,hbound,?_⟩
  have hpow : (radix : ZMod Fr.modulus)^4 = (2^256 : ZMod Fr.modulus) := by norm_num [radix]
  have h := congrArg (fun n : ℤ => (n : ZMod Fr.modulus)) hvalue
  dsimp only at h
  simpa only [Int.cast_mul,Int.cast_add,Int.cast_pow,Int.cast_natCast,
    ZMod.natCast_self,mul_zero,add_zero,hpow] using h

theorem array_eq_of_field (a b : Array U64 4#usize)
    (ha : value a < Fr.modulus) (hb : value b < Fr.modulus)
    (h : (value a : ZMod Fr.modulus) = (value b : ZMod Fr.modulus)) : a = b := by
  apply value_injective
  have hval := congrArg (fun z : ZMod Fr.modulus => (z.val : ℤ)) h
  dsimp only at hval
  rw [ZMod.val_intCast,ZMod.val_intCast] at hval
  rw [Int.emod_eq_of_lt (value_bounds a).1 ha,Int.emod_eq_of_lt (value_bounds b).1 hb] at hval
  exact hval

theorem ordinary_words_value (n : Nat) (hn : n < 2^256) :
    value (Kzg.words 4#usize n) = (n : ℤ) := by
  rw [value_eq_limbs,Kzg.limbs_words_four n hn]

theorem fr_to_words_refines (x : Fr) :
    fr.fr_to_words (Kzg.frEncode x) = ok (Kzg.words 4#usize x.val) := by
  let one : Array U64 4#usize := Array.make 4#usize [1#u64,0#u64,0#u64,0#u64] (by rfl)
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines (Kzg.frEncode x).l one (encode_bound x)
  have hone : value one = 1 := by rfl
  rw [hone,Int.cast_one,mul_one,encode_field] at hfield
  have heqfield : (value out : ZMod Fr.modulus) = Fr.toZMod x :=
    mul_right_cancel₀ (by decide +kernel : (2^256 : ZMod Fr.modulus) ≠ 0) hfield
  have hx : x.val < 2^256 := lt_trans x.isLt (by decide)
  have hwords : value (Kzg.words 4#usize x.val) < Fr.modulus := by
    rw [ordinary_words_value x.val hx]
    exact_mod_cast x.isLt
  have heq : out = Kzg.words 4#usize x.val := by
    apply array_eq_of_field out _ hbound hwords
    rw [heqfield,ordinary_words_value x.val hx,Int.cast_natCast]
    exact (ZMod.natCast_zmod_val (Fr.toZMod x)).symm
  simpa only [fr.fr_to_words,heq] using hr

theorem r_squared_eq : fr.R_SQUARED = (Kzg.frEncode (Fr.ofNat (2^256))).l := by
  unfold fr.R_SQUARED
  rfl

theorem r_squared_bound : value fr.R_SQUARED < Fr.modulus := by
  rw [r_squared_eq]
  exact encode_bound _

theorem ofNat_field (n : Nat) : Fr.toZMod (Fr.ofNat n) = (n : ZMod Fr.modulus) := by rfl

theorem ordinary_field (a : Array U64 4#usize) :
    (value a : ZMod Fr.modulus) = Fr.toZMod (Fr.ofNat (Kzg.limbs a.val)) := by
  rw [value_eq_limbs,Int.cast_natCast,ofNat_field]

theorem r_squared_field : (value fr.R_SQUARED : ZMod Fr.modulus) = (2^256 : ZMod Fr.modulus)^2 := by
  rw [r_squared_eq,encode_field,ofNat_field,Nat.cast_pow,Nat.cast_ofNat]
  ring

theorem reduce_words_refines (a : Array U64 4#usize) :
    fr.montgomery_product fr.R_SQUARED a = ok (Kzg.frEncode (Fr.ofNat (Kzg.limbs a.val))).l := by
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines fr.R_SQUARED a r_squared_bound
  have heq : out = (Kzg.frEncode (Fr.ofNat (Kzg.limbs a.val))).l := by
    apply eq_encode_of_field out _ hbound
    apply mul_right_cancel₀ (by decide +kernel : (2^256 : ZMod Fr.modulus) ≠ 0)
    rw [hfield,r_squared_field,ordinary_field,encode_field]
    ring
  rw [hr,heq]

theorem canonical_words_refines (a : Array U64 4#usize) (ha : value a < Fr.modulus) :
    fr.montgomery_product a fr.R_SQUARED = ok (Kzg.frEncode (Fr.ofNat (Kzg.limbs a.val))).l := by
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines a fr.R_SQUARED ha
  have heq : out = (Kzg.frEncode (Fr.ofNat (Kzg.limbs a.val))).l := by
    apply eq_encode_of_field out _ hbound
    apply mul_right_cancel₀ (by decide +kernel : (2^256 : ZMod Fr.modulus) ≠ 0)
    rw [hfield,r_squared_field,ordinary_field,encode_field]
    ring
  rw [hr,heq]

end LeanBlsSimd.FrScalar
