import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem mul_eq_product [RuntimeFeatures] (a b : portable.fp.Fp) :
    portable.fp.Fp.mul a b = portable.fp.Fp.product a b := by
  simp only [portable.fp.Fp.mul,bmi2_available,bind_tc_ok]
  split <;> rfl

theorem montgomery_field_refines (a b : Array U64 6#usize)
    (ha : value a < Bls.Fp.modulus) :
    ∃ out, portable.fp.Fp.product a b = ok out ∧ value out < Bls.Fp.modulus ∧
      (value out : ZMod Bls.Fp.modulus)*(2^384 : ZMod Bls.Fp.modulus) =
        (value a : ZMod Bls.Fp.modulus)*(value b : ZMod Bls.Fp.modulus) := by
  obtain ⟨out,hr,hbound,k,hvalue⟩ := product_refines a b ha
  refine ⟨out,hr,hbound,?_⟩
  have hpow : (radix : ZMod Bls.Fp.modulus)^6 = (2^384 : ZMod Bls.Fp.modulus) := by norm_num [radix]
  have h := congrArg (fun n : ℤ => (n : ZMod Bls.Fp.modulus)) hvalue
  dsimp only at h
  simpa only [Int.cast_mul,Int.cast_add,Int.cast_pow,Int.cast_natCast,
    ZMod.natCast_self,mul_zero,add_zero,hpow] using h

theorem array_eq_of_field (a b : Array U64 6#usize)
    (ha : value a < Bls.Fp.modulus) (hb : value b < Bls.Fp.modulus)
    (h : (value a : ZMod Bls.Fp.modulus) = (value b : ZMod Bls.Fp.modulus)) : a = b := by
  apply value_injective
  have hval := congrArg (fun z : ZMod Bls.Fp.modulus => (z.val : ℤ)) h
  dsimp only at hval
  rw [ZMod.val_intCast,ZMod.val_intCast] at hval
  rw [Int.emod_eq_of_lt (value_bounds a).1 ha,Int.emod_eq_of_lt (value_bounds b).1 hb] at hval
  exact hval

theorem ordinary_words_value (n : Nat) (hn : n < 2^384) :
    value (Kzg.words 6#usize n) = (n : ℤ) := by
  rw [value_eq_limbs,Kzg.limbs_words_six n hn]

theorem to_plain_encoded [RuntimeFeatures] (x : Bls.Fp) :
    portable.fp.Fp.to_plain (Kzg.fpEncode x).l = ok (Kzg.words 6#usize x.val) := by
  let one : Array U64 6#usize := Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines (Kzg.fpEncode x).l one (encode_bound x)
  have hone : value one = 1 := by rfl
  rw [hone,Int.cast_one,mul_one,encode_field] at hfield
  have heqfield : (value out : ZMod Bls.Fp.modulus) = Bls.Fp.toZMod x :=
    mul_right_cancel₀ (by decide +kernel : (2^384 : ZMod Bls.Fp.modulus) ≠ 0) hfield
  have hx : x.val < 2^384 := lt_trans x.isLt (by decide)
  have hwords : value (Kzg.words 6#usize x.val) < Bls.Fp.modulus := by
    rw [ordinary_words_value x.val hx]
    exact_mod_cast x.isLt
  have heq : out = Kzg.words 6#usize x.val := by
    apply array_eq_of_field out _ hbound hwords
    rw [heqfield,ordinary_words_value x.val hx,Int.cast_natCast]
    exact (ZMod.natCast_zmod_val (Bls.Fp.toZMod x)).symm
  simpa only [portable.fp.Fp.to_plain,mul_eq_product,heq] using hr

theorem r_squared_eq : portable.constants.R2 = (Kzg.fpEncode (Bls.Fp.ofNat (2^384))).l := by
  unfold portable.constants.R2
  rfl

theorem r_squared_bound : value portable.constants.R2 < Bls.Fp.modulus := by
  rw [r_squared_eq]
  exact encode_bound _

theorem ofNat_field (n : Nat) : Bls.Fp.toZMod (Bls.Fp.ofNat n) = (n : ZMod Bls.Fp.modulus) := by rfl

theorem ordinary_field (a : Array U64 6#usize) :
    (value a : ZMod Bls.Fp.modulus) = Bls.Fp.toZMod (Bls.Fp.ofNat (Kzg.limbs a.val)) := by
  rw [value_eq_limbs,Int.cast_natCast,ofNat_field]

theorem r_squared_field : (value portable.constants.R2 : ZMod Bls.Fp.modulus) = (2^384 : ZMod Bls.Fp.modulus)^2 := by
  rw [r_squared_eq,encode_field,ofNat_field,Nat.cast_pow,Nat.cast_ofNat]
  ring

theorem reduce_words_refines (a : Array U64 6#usize) :
    portable.fp.Fp.product portable.constants.R2 a = ok (Kzg.fpEncode (Bls.Fp.ofNat (Kzg.limbs a.val))).l := by
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines portable.constants.R2 a r_squared_bound
  have heq : out = (Kzg.fpEncode (Bls.Fp.ofNat (Kzg.limbs a.val))).l := by
    apply eq_encode_of_field out _ hbound
    apply mul_right_cancel₀ (by decide +kernel : (2^384 : ZMod Bls.Fp.modulus) ≠ 0)
    rw [hfield,r_squared_field,ordinary_field,encode_field]
    ring
  rw [hr,heq]

theorem canonical_words_refines (a : Array U64 6#usize) (ha : value a < Bls.Fp.modulus) :
    portable.fp.Fp.product a portable.constants.R2 = ok (Kzg.fpEncode (Bls.Fp.ofNat (Kzg.limbs a.val))).l := by
  obtain ⟨out,hr,hbound,hfield⟩ := montgomery_field_refines a portable.constants.R2 ha
  have heq : out = (Kzg.fpEncode (Bls.Fp.ofNat (Kzg.limbs a.val))).l := by
    apply eq_encode_of_field out _ hbound
    apply mul_right_cancel₀ (by decide +kernel : (2^384 : ZMod Bls.Fp.modulus) ≠ 0)
    rw [hfield,r_squared_field,ordinary_field,encode_field]
    ring
  rw [hr,heq]

theorem from_plain_refines [RuntimeFeatures] (a : Array U64 6#usize)
    (ha : value a < Bls.Fp.modulus) :
    portable.fp.Fp.from_plain a = ok (Kzg.fpEncode (Bls.Fp.ofNat (Kzg.limbs a.val))).l := by
  simpa only [portable.fp.Fp.from_plain,mul_eq_product] using canonical_words_refines a ha

end LeanBlsSimd.Portable.Fp
