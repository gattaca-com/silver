import LeanBlsSimd.Portable.Fp.InverseLoops
import LeanBlsSimd.Portable.Fp.Conversion

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp
open Word64
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

theorem r_cubed_eq : portable.constants.R3 =
    (Kzg.fpEncode (Bls.Fp.ofNat (2^768))).l := by
  unfold portable.constants.R3
  rfl

theorem r_cubed_bound : value portable.constants.R3 < Bls.Fp.modulus := by
  rw [r_cubed_eq]
  exact encode_bound _

theorem r_cubed_field : (value portable.constants.R3 : ZMod Bls.Fp.modulus) =
    (2^384 : ZMod Bls.Fp.modulus)^3 := by
  rw [r_cubed_eq,encode_field,ofNat_field,Nat.cast_pow,Nat.cast_ofNat]
  rw [show (768 : Nat) = 384*2 from rfl,pow_mul]
  ring

private theorem inverse_scale {K : Type} [Field K] (x r : K) (hr : r ≠ 0) :
    (x*r)⁻¹*r^3 = (x⁻¹*r)*r := by
  rw [mul_inv_rev]
  calc
    (r⁻¹*x⁻¹)*r^3 = x⁻¹*(r⁻¹*r)*r*r := by ring
    _ = (x⁻¹*r)*r := by rw [inv_mul_cancel₀ hr]; ring

theorem inverse_encoded [RuntimeFeatures] (x : ZMod Bls.Fp.modulus) :
    portable.fp.Fp.inverse (Kzg.fpEncode x).l = ok (Kzg.fpEncode x⁻¹).l := by
  obtain ⟨raw,hi,hb,hf⟩ := inverse_words_refines (Kzg.fpEncode x).l (encode_bound x)
  obtain ⟨out,hm,hob,hom⟩ := montgomery_field_refines raw portable.constants.R3 hb
  have hout : out = (Kzg.fpEncode x⁻¹).l := by
    apply eq_encode_of_field out _ hob
    apply mul_right_cancel₀ (by decide +kernel : (2^384 : ZMod Bls.Fp.modulus) ≠ 0)
    rw [hom,hf,r_cubed_field,encode_field,encode_field]
    exact inverse_scale x _ (by decide +kernel)
  simp only [portable.fp.Fp.inverse,hi,bind_tc_ok,mul_eq_product,hm,hout]

theorem inverse_zero [RuntimeFeatures] :
    portable.fp.Fp.inverse (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l =
      ok (Kzg.fpEncode (0 : ZMod Bls.Fp.modulus)).l := by
  simpa only [inv_zero] using inverse_encoded (0 : ZMod Bls.Fp.modulus)

end LeanBlsSimd.Portable.Fp
