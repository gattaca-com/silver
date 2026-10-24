import LeanBlsSimd.Pairing.LaneExponent
import LeanBlsSimd.Pairing.FinalRun
import LeanBlsSimd.Pairing.FinalVerdict
import LeanBlsSimd.LaneTower.Frobenius
import LeanBlsSimd.LaneTower.Identity

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.FinalExponent.Lanes

open LaneTower

set_option maxRecDepth 4000

def operations : Operations fp2x8.Fp2x8 :=
  ⟨fp12.Fp12.mul, fp12.Fp12.cyclotomic_square,
    fp12.Fp12.conjugate, fp12.Fp12.cyclotomic_exp,
    fp12.Fp12.frobenius, fp12.Fp12.inverse⟩

theorem operations_refine : operations.Refines Rep where
  mul := mul_refines
  square := cyclotomic_square_refines
  conjugate := conjugate_refines
  exp := by
    intro x a hx ha
    exact exponent_refines x a hx ha
  frobenius := frobenius_refines
  inverse := inverse_refines

attribute [local irreducible] bls.fp12.Fp12.mul bls.fp12.Fp12.cyclotomic_square bls.fp12.Fp12.conjugate bls.fp12.Fp12.cyclotomic_exp bls.fp12.Fp12.frobenius bls.fp12.Fp12.inverse in
theorem generated_schedule (x : fp2x8.Fp2x8) :
    fp12.Fp12.final_exponentiation x = run operations x := by
  simp only [fp12.Fp12.final_exponentiation, run, hardRun, operations]

theorem final_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    ∃ out, fp12.Fp12.final_exponentiation x = ok out ∧ Rep out (optimized a) := by
  rw [generated_schedule]
  exact run_refines operations_refine hx

theorem final_verdict {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    (do let out ← fp12.Fp12.final_exponentiation x
        fp12.Fp12.is_one out) = ok (finalExponentiation a).isOne := by
  obtain ⟨out, hout, rout⟩ := final_refines hx
  simp only [hout, bind_tc_ok, is_one_refines rout, verdict]

end LeanBlsSimd.Pairing.FinalExponent.Lanes
