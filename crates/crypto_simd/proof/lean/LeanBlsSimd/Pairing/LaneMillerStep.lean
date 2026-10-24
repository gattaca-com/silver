import LeanBlsSimd.Pairing.LaneLines
import LeanBlsSimd.LaneTower.Square

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.Pairing.LaneLines

open LaneTower

set_option maxRecDepth 2000

theorem miller_body (factors z : fp8.Fp8) (v : Factors) (hv : FactorsRep factors z v)
    (present : U8) (n : Fin 63) (x : fp2x8.Fp2x8) (f : Bls.Fp12) (hx : Rep x f)
    (step : Usize) (bit : U32) (hs : step.val = consumed (n.val + 1))
    (hb : bit.val = n.val + 1) (hfirst : n.val + 1 = 63 → f = Bls.Fp12.one) :
    ∃ out step' bit',
      pairing.MillerLines.miller_loop_loop.body kzg.pairing_lines.PAIRING_LINES
        present factors z x step bit = ok (cont (out, step', bit')) ∧
      step'.val = consumed n.val ∧ bit'.val = n.val ∧
      Rep out (bitStep v (maskPresence present) n f) := by
  let bit' : U32 := UScalar.ofNatCore n.val (by change n.val < 2^32; have := n.isLt; omega)
  have hdec : bit - 1#u32 = ok bit' := by
    rw [sub_ok bit 1#u32 (by simp; omega)]
    apply congrArg ok
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq]
    change bit.val - 1 = n.val
    omega
  have hstep : step.val < 68 := by rw [hs]; exact double_row_bound n
  have hin : step.val + 1 < 2^UScalarTy.Usize.numBits := by
    have := two_pow_32_le_usize
    omega
  let next : Usize := UScalar.ofNatCore (step.val + 1) hin
  have hinc : step + 1#usize = ok next := add_ok _ _ hin
  obtain ⟨square, hsquare, rsquare⟩ : ∃ square,
      (if step > 0#usize then fp12.Fp12.square x else ok x) = ok square ∧ Rep square (f * f) := by
    by_cases hpos : step > 0#usize
    · obtain ⟨out, hout, rout⟩ := square_refines hx
      exact ⟨out, by rw [if_pos hpos]; exact hout, rout⟩
    · refine ⟨x, by rw [if_neg hpos], ?_⟩
      have hc : ¬ consumed (n.val + 1) > 0 := by simpa only [UScalar.lt_equiv, hs] using hpos
      have he := initial_square n f hfirst
      simp only [if_neg hc] at he
      exact he ▸ hx
  have hdrow : (⟨step.val, hstep⟩ : Fin 68) = doubleRow n := Fin.ext hs
  obtain ⟨first, hlines, rfirst⟩ := times_lines step hstep factors z v hv present rsquare
  rw [hdrow] at rfirst
  have hbit : constants.is_lower_z_bit bit' = ok (blsX.testBit n.val) := by
    rw [G1x8.is_lower_z_bit_refines]
    exact congrArg ok (lower_bit_agrees n)
  have hrun : bit > 0#u32 := by simp only [UScalar.lt_equiv]; change 0 < bit.val; omega
  by_cases h : blsX.testBit n.val = true
  · have hnext : next.val < 68 := by
      change step.val + 1 < 68
      rw [hs]
      exact add_row_bound n h
    have hin2 : next.val + 1 < 2^UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      omega
    let next2 : Usize := UScalar.ofNatCore (next.val + 1) hin2
    have hinc2 : next + 1#usize = ok next2 := add_ok _ _ hin2
    have harow : (⟨next.val, hnext⟩ : Fin 68) = addRow n h := by
      apply Fin.ext
      change step.val + 1 = consumed (n.val + 1) + 1
      rw [hs]
    obtain ⟨out, hlines2, rout⟩ := times_lines next hnext factors z v hv present rfirst
    refine ⟨out, next2, bit', ?_, ?_, rfl, ?_⟩
    · simp only [pairing.MillerLines.miller_loop_loop.body, hrun, if_true,
        hdec, bind_tc_ok, hsquare, hlines, hinc, hbit, h, hlines2, hinc2]
    · change step.val + 1 + 1 = consumed n.val
      rw [consumed_step, hs, h]
      rfl
    · rw [bit_step_eq, dif_pos h]
      rw [harow] at rout
      exact rout
  · refine ⟨first, next, bit', ?_, ?_, rfl, ?_⟩
    · simp only [pairing.MillerLines.miller_loop_loop.body, hrun, if_true,
        hdec, bind_tc_ok, hsquare, hlines, hinc, hbit, h, Bool.false_eq_true, if_false]
    · change step.val + 1 = consumed n.val
      rw [consumed_step, hs, if_neg h, Nat.add_zero]
    · rw [bit_step_eq, dif_neg h]
      exact rfirst

end LeanBlsSimd.Pairing.LaneLines
