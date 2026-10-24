import LeanBlsSimd.Portable.Fp.Montgomery
import LeanBlsSimd.Kzg.RepresentationLemmas

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64

set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem encode_value (x : Bls.Fp) :
    value (Kzg.fpEncode x).l = (((x.val*2^384)%Bls.Fp.modulus : Nat) : ℤ) := by
  rw [value_eq_limbs]
  unfold Kzg.fpEncode
  rw [Kzg.limbs_words_six _ (Nat.lt_trans (Nat.mod_lt _ Bls.Fp.modulus_pos) (by decide))]

theorem encode_bound (x : Bls.Fp) : value (Kzg.fpEncode x).l < Bls.Fp.modulus := by
  rw [encode_value]
  exact_mod_cast Nat.mod_lt (x.val*2^384) Bls.Fp.modulus_pos

theorem encode_field (x : Bls.Fp) :
    (value (Kzg.fpEncode x).l : ZMod Bls.Fp.modulus) = Bls.Fp.toZMod x*(2^384 : ZMod Bls.Fp.modulus) := by
  rw [encode_value]
  push_cast
  have hx : (x.val : ZMod Bls.Fp.modulus) = Bls.Fp.toZMod x := ZMod.natCast_zmod_val (Bls.Fp.toZMod x)
  rw [hx]
  norm_num

theorem eq_encode_of_field (a : Array U64 6#usize) (x : Bls.Fp)
    (ha : value a < Bls.Fp.modulus)
    (h : (value a : ZMod Bls.Fp.modulus) = (value (Kzg.fpEncode x).l : ZMod Bls.Fp.modulus)) :
    a = (Kzg.fpEncode x).l := by
  apply value_injective
  have hval := congrArg (fun z : ZMod Bls.Fp.modulus => (z.val : ℤ)) h
  dsimp only at hval
  rw [ZMod.val_intCast,ZMod.val_intCast] at hval
  rw [Int.emod_eq_of_lt (value_bounds a).1 ha,
    Int.emod_eq_of_lt (value_bounds (Kzg.fpEncode x).l).1 (encode_bound x)] at hval
  exact hval

theorem rep_bound {a : portable.fp.Fp} {x : Bls.Fp} (h : Rep a x) : value a < Bls.Fp.modulus := by
  rw [value_eq_limbs]
  have hr : Kzg.limbs a.val < Bls.Fp.modulus := h.1
  exact_mod_cast hr

theorem rep_eq_encode {a : portable.fp.Fp} {x : Bls.Fp} (h : Rep a x) : a = (Kzg.fpEncode x).l := by
  apply eq_encode_of_field a x (rep_bound h)
  rw [encode_field]
  have hr := h.2
  change Bls.Fp.ofNat (Kzg.limbs a.val)*(Bls.Fp.ofNat (2^384)).inverse = x at hr
  rw [Bls.Fp.inverse_eq_inv,Bls.Fp.ofNat_eq_natCast,Bls.Fp.ofNat_eq_natCast] at hr
  have hz : (value a : ZMod Bls.Fp.modulus)*(2^384 : ZMod Bls.Fp.modulus)⁻¹ = Bls.Fp.toZMod x := by
    rw [value_eq_limbs]
    exact congrArg Bls.Fp.toZMod hr
  have hR : (2^384 : ZMod Bls.Fp.modulus) ≠ 0 := by decide +kernel
  calc
    (value a : ZMod Bls.Fp.modulus) =
        ((value a : ZMod Bls.Fp.modulus)*(2^384 : ZMod Bls.Fp.modulus)⁻¹)*(2^384 : ZMod Bls.Fp.modulus) := by
      rw [mul_assoc,inv_mul_cancel₀ hR,mul_one]
    _ = _ := by rw [hz]

theorem rep_injective {a b : portable.fp.Fp} {x : Bls.Fp} (ha : Rep a x) (hb : Rep b x) : a = b :=
  (rep_eq_encode ha).trans (rep_eq_encode hb).symm

end LeanBlsSimd.Portable.Fp
