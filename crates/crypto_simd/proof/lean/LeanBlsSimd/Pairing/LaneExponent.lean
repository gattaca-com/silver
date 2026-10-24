import LeanBlsSimd.Pairing.ExponentLoop
import LeanBlsSimd.LaneTower.CyclotomicCoordinates

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.FinalExponent.Lanes

open LaneTower

set_option maxRecDepth 4000

theorem exponent_body (base x : fp2x8.Fp2x8) (a f : Bls.Fp12) (ha : Rep base a) (hx : Rep x f)
    (hf : Good f) (n : Fin 63) (bit : U32) (hb : bit.val = n.val + 1) :
    ∃ out bit', bit'.val = n.val ∧
      fp12.Fp12.cyclotomic_exp_loop.body base x bit = ok (cont (out, bit')) ∧
      Rep out (powerStep a f n.val) := by
  let bit' : U32 := UScalar.ofNatCore n.val (by change n.val < 2^32; have := n.isLt; omega)
  have hdec : bit - 1#u32 = ok bit' := by
    rw [sub_ok bit 1#u32 (by simp; omega)]
    apply congrArg ok
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq]
    change bit.val - 1 = n.val
    omega
  obtain ⟨sq, hsq, rsq⟩ := cyclotomic_square_refines hx hf
  have hrun : bit > 0#u32 := by simp only [UScalar.lt_equiv]; change 0 < bit.val; omega
  by_cases h : G1x8.is_lower_z_bit n.val = true
  · obtain ⟨out, hout, rout⟩ := mul_refines rsq ha
    refine ⟨out, bit', rfl, ?_, ?_⟩
    · simp only [fp12.Fp12.cyclotomic_exp_loop.body, hrun, if_true, hdec, bind_tc_ok, hsq,
        G1x8.is_lower_z_bit_refines]
      change (if G1x8.is_lower_z_bit n.val then do
        let r ← fp12.Fp12.mul sq base
        ok (cont (r, bit')) else ok (cont (sq, bit'))) = _
      simp only [h, if_true, hout, bind_tc_ok]
    · simpa only [powerStep, h, if_true] using rout
  · refine ⟨sq, bit', rfl, ?_, ?_⟩
    · simp only [fp12.Fp12.cyclotomic_exp_loop.body, hrun, if_true, hdec, bind_tc_ok, hsq,
        G1x8.is_lower_z_bit_refines]
      change (if G1x8.is_lower_z_bit n.val then do
        let r ← fp12.Fp12.mul sq base
        ok (cont (r, bit')) else ok (cont (sq, bit'))) = _
      rw [if_neg h]
    · simpa only [powerStep, if_neg h] using rsq

theorem exponent_refines (base : fp2x8.Fp2x8) (a : Bls.Fp12) (ha : Rep base a) (hg : Good a) :
    ∃ out, fp12.Fp12.cyclotomic_exp base = ok out ∧ Rep out (exp a) := by
  let body := fun (state : fp2x8.Fp2x8 × U32) => fp12.Fp12.cyclotomic_exp_loop.body base state.1 state.2
  have hdone : ∀ x bit, bit.val = 0 → body (x, bit) = ok (done x) := by
    intro x bit hb
    simp only [body, fp12.Fp12.cyclotomic_exp_loop.body, UScalar.lt_equiv, hb, Nat.not_lt_zero, if_false]
  have hstep : ∀ (n : Fin 63) x f bit, Rep x f → Good f → bit.val = n.val + 1 →
      ∃ out bit', body (x, bit) = ok (cont (out, bit')) ∧ bit'.val = n.val ∧
        Rep out (powerStep a f n.val) := by
    intro n x f bit hx hf hb
    obtain ⟨out, bit', hb', he, ho⟩ := exponent_body base x a f ha hx hf n bit hb
    exact ⟨out, bit', he, hb', ho⟩
  obtain ⟨out, hout, rout⟩ := power_loop_refines body Rep a hg hdone hstep 63 (by omega) base a 63#u32 ha hg rfl
  rw [power_loop_eq] at rout
  obtain ⟨last, hlast, rlast⟩ := conjugate_refines rout
  have hbit : Array.index_usize constants.Z_BITS 0#usize = ok 63#u32 := by
    rw [Z_BITS_index 0#usize (by decide)]; rfl
  refine ⟨last, ?_, rlast⟩
  simp only [fp12.Fp12.cyclotomic_exp, hbit, bind_tc_ok]
  change (do let out ← loop body (base, 63#u32); fp12.Fp12.conjugate out) = _
  rw [hout]
  simp only [bind_tc_ok, hlast]

end LeanBlsSimd.Pairing.FinalExponent.Lanes
