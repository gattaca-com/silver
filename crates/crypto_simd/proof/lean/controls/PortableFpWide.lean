import LeanBlsSimd.Portable.Fp.WideReduction

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open LeanBlsSimd.Word64

namespace LeanBlsSimd.Portable.Fp.Controls
set_option maxRecDepth 4096
set_option exponentiation.threshold 4096

private def wideOne : portable.fp.Wide :=
  Wide.pack (Kzg.words 6#usize 1) (Array.repeat 6#usize 0#u64)

private theorem wideOne_value : value wideOne = 1 := by decide +kernel

private theorem wideZero_value : value (Array.repeat 12#usize 0#u64) = 0 := rfl

theorem modular_borrow_is_not_dropped :
    portable.fp.Wide.minus_mod (Array.repeat 12#usize 0#u64) wideOne ≠
      ok (Array.repeat 12#usize 0#u64) := by
  intro h
  obtain ⟨out,he,hv⟩ := Wide.minus_mod_refines (Array.repeat 12#usize 0#u64) wideOne
    (by rw [wideZero_value]; norm_num [Bls.Fp.modulus,radix])
    (by rw [wideOne_value]; norm_num [Bls.Fp.modulus,radix])
  have hout := Result.ok.inj (he.symm.trans h)
  rw [hout,wideZero_value,wideOne_value] at hv
  norm_num [Bls.Fp.modulus,radix] at hv

theorem ordered_subtraction_rejects_underflow :
    portable.fp.Wide.minus (Array.repeat 12#usize 0#u64) wideOne ≠
      ok (Array.repeat 12#usize 0#u64) := by
  obtain ⟨out,he,hv⟩ := sub_words_refines (Array.repeat 12#usize 0#u64) wideOne
  rw [wideZero_value,wideOne_value] at he
  simp only [portable.fp.Wide.minus,he,bind_tc_ok]
  change (do massert (¬decide ((0 : ℤ) < 1) = true); ok out) ≠ _
  simp [massert]

theorem wide_reduction_cannot_return_modulus :
    portable.fp.Wide.reduce (Array.repeat 12#usize 0#u64) ≠ ok bls.constants.P_U64 := by
  intro h
  obtain ⟨out,he,hb,k,hv⟩ := Wide.reduce_refines (Array.repeat 12#usize 0#u64)
    (by rw [wideZero_value]; norm_num [Bls.Fp.modulus,radix])
  have hout := Result.ok.inj (he.symm.trans h)
  rw [hout,modulus_words] at hb
  exact lt_irrefl _ hb

#print axioms Wide.minus_refines
#print axioms Wide.minus_mod_refines
#print axioms Wide.cross_term_bounds
#print axioms Wide.reduce_refines

end LeanBlsSimd.Portable.Fp.Controls
