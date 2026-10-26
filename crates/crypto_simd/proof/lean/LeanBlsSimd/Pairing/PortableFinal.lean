import LeanBlsSimd.Pairing.PortableExponent
import LeanBlsSimd.Pairing.FinalRun
import LeanBlsSimd.Pairing.FinalVerdict

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing.FinalExponent.Portable

open LeanBlsSimd.Portable.Fp12

set_option maxRecDepth 4000

def operations [RuntimeFeatures] : Operations portable.fp12.Fp12 :=
  ⟨portable.fp12.Fp12.mul, portable.fp12.Fp12.cyclotomic_square,
    portable.fp12.Fp12.conjugate, portable.fp12.Fp12.cyclotomic_exp,
    portable.fp12.Fp12.frobenius, portable.fp12.Fp12.inverse⟩

theorem operations_refine [RuntimeFeatures] : operations.Refines (fun x a => x = encode a) where
  mul := by
    intro x y a b hx hy
    subst x; subst y
    exact ⟨_, mul_encoded a b, rfl⟩
  square := by
    intro x a hx ha
    subst x
    exact ⟨_, square_encoded a ha, rfl⟩
  conjugate := by
    intro x a hx
    subst x
    exact ⟨_, conjugate_encoded a, rfl⟩
  exp := by
    intro x a hx ha
    subst x
    exact ⟨_, exponent_encoded a ha, rfl⟩
  frobenius := by
    intro x a hx
    subst x
    exact ⟨_, frobenius_encoded a, rfl⟩
  inverse := by
    intro x a hx
    subst x
    exact ⟨_, inverse_encoded a, rfl⟩

attribute [local irreducible] portable.fp12.Fp12.mul portable.fp12.Fp12.cyclotomic_square portable.fp12.Fp12.conjugate portable.fp12.Fp12.cyclotomic_exp portable.fp12.Fp12.frobenius portable.fp12.Fp12.inverse in
theorem generated_schedule [RuntimeFeatures] (x : portable.fp12.Fp12) :
    portable.fp12.Fp12.final_exponentiation x = run operations x := by
  simp only [portable.fp12.Fp12.final_exponentiation, run, hardRun, operations]

theorem final_cube_encoded [RuntimeFeatures] (a : Bls.Fp12) :
    portable.fp12.Fp12.final_exponentiation (encode a) = ok (encode (optimized a)) := by
  obtain ⟨out, hout, he⟩ := run_refines operations_refine (x := encode a) (a := a) rfl
  rw [he] at hout
  rw [generated_schedule]
  exact hout

theorem final_verdict [RuntimeFeatures] (a : Bls.Fp12) :
    (do let out ← portable.fp12.Fp12.final_exponentiation (encode a)
        portable.fp12.Fp12.is_one out) = ok (finalExponentiation a).isOne := by
  simp only [final_cube_encoded, bind_tc_ok, is_one_encoded, verdict]

end LeanBlsSimd.Pairing.FinalExponent.Portable
