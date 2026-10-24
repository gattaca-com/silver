import LeanBlsSimd.Portable.Fp.Correct

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp.Controls

theorem add_wraps_at_p :
    portable.fp.Fp.add (Kzg.fpEncode (-1)).l (Kzg.fpEncode 1).l = ok (Kzg.fpEncode 0).l := by
  simpa using add_encoded (-1) 1

theorem baseline_preserves_montgomery_one :
    portable.fp.Fp.mul_on_baseline portable.constants.ONE portable.constants.ONE = ok portable.constants.ONE := by
  have h := rep_eq_encode Kzg.portableFpRep_one
  rw [h]
  simpa only [show Bls.Fp.one = (1 : Bls.Fp) from rfl,one_mul] using mul_baseline_encoded 1 1

theorem bmi2_preserves_montgomery_one :
    portable.fp.Fp.mul_on_bmi2 portable.constants.ONE portable.constants.ONE = ok portable.constants.ONE := by
  have h := rep_eq_encode Kzg.portableFpRep_one
  rw [h]
  simpa only [show Bls.Fp.one = (1 : Bls.Fp) from rfl,one_mul] using mul_bmi2_encoded 1 1

theorem plain_one_is_not_montgomery_product :
    portable.fp.Fp.product portable.constants.ONE portable.constants.ONE ≠
      ok (Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)) := by
  intro h
  have he := baseline_preserves_montgomery_one
  have hout := Result.ok.inj (he.symm.trans h)
  have hne : Word64.value portable.constants.ONE ≠
      Word64.value (Array.make 6#usize [1#u64,0#u64,0#u64,0#u64,0#u64,0#u64] (by rfl)) := by decide +kernel
  exact hne (congrArg Word64.value hout)

theorem modulus_is_not_a_field_representative (x : Bls.Fp) : ¬ Rep bls.constants.P_U64 x := by
  intro h
  have hb := rep_bound h
  rw [modulus_words] at hb
  exact lt_irrefl _ hb

#print axioms product_refines
#print axioms mul_baseline_encoded
#print axioms mul_bmi2_encoded
#print axioms portable_fp_correct

end LeanBlsSimd.Portable.Fp.Controls
