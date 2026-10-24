import LeanBlsSimd.Pairing.MillerSchedule

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing.PortableLines

set_option maxRecDepth 2000
set_option exponentiation.threshold 4096

theorem miller_body [RuntimeFeatures] (lines : portable.pairing.PairingLines)
    (hl : Kzg.PortableLinesRep lines)
    (factors : Array (Array portable.fp.Fp 3#usize) 2#usize) (v : Factors)
    (hf : FactorsRep factors v) (present : Array Bool 2#usize)
    (n : Fin 63) (f : Fp12) (step : Usize) (bit : U32)
    (hs : step.val = consumed (n.val + 1)) (hb : bit.val = n.val + 1)
    (hfirst : n.val + 1 = 63 → f = Fp12.one) :
    ∃ step' bit', portable.pairing.PairingLines.miller_loop_loop1.body
        lines factors present (Portable.Fp12.encode f) step bit =
        ok (cont (Portable.Fp12.encode (bitStep v present n f), step', bit')) ∧
      step'.val = consumed n.val ∧ bit'.val = n.val := by
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
  have hsquare : (if step > 0#usize then portable.fp12.Fp12.square (Portable.Fp12.encode f)
      else ok (Portable.Fp12.encode f)) = ok (Portable.Fp12.encode (f * f)) := by
    by_cases hpos : step > 0#usize
    · rw [if_pos hpos, Portable.Fp12.square_encoded]
      rfl
    · rw [if_neg hpos]
      have hc : ¬ consumed (n.val + 1) > 0 := by simpa only [UScalar.lt_equiv, hs] using hpos
      have he := initial_square n f hfirst
      simp only [if_neg hc] at he
      exact congrArg (fun g => ok (Portable.Fp12.encode g)) he
  have hdrow : (⟨step.val, hstep⟩ : Fin 68) = doubleRow n := Fin.ext hs
  have hlines := times_lines lines hl step hstep factors v hf present (f * f)
  change portable.pairing.PairingLines.times_lines lines (Portable.Fp12.encode (f * f))
    step factors present = ok (Portable.Fp12.encode (applyLines v present ⟨step.val, hstep⟩ (f * f))) at hlines
  rw [hdrow] at hlines
  have hbit : bls.constants.is_lower_z_bit bit' = ok (blsX.testBit n.val) := by
    rw [G1x8.is_lower_z_bit_refines]
    exact congrArg ok (lower_bit_agrees n)
  have hrun : bit > 0#u32 := by simp only [UScalar.lt_equiv]; change 0 < bit.val; omega
  simp only [portable.pairing.PairingLines.miller_loop_loop1.body, hrun, if_true,
    hdec, bind_tc_ok, hsquare, hlines, hinc, hbit]
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
    have hlines2 := times_lines lines hl next hnext factors v hf present
      (applyLines v present (doubleRow n) (f * f))
    change portable.pairing.PairingLines.times_lines lines
      (Portable.Fp12.encode (applyLines v present (doubleRow n) (f * f))) next factors present =
      ok (Portable.Fp12.encode (applyLines v present ⟨next.val, hnext⟩
        (applyLines v present (doubleRow n) (f * f)))) at hlines2
    rw [harow] at hlines2
    refine ⟨next2, bit', ?_, ?_, rfl⟩
    · rw [bit_step_eq, dif_pos h]
      simp only [h, if_true, hlines2, hinc2, bind_tc_ok]
    · change step.val + 1 + 1 = consumed n.val
      rw [consumed_step, hs, h]
      rfl
  · refine ⟨next, bit', ?_, ?_, rfl⟩
    · rw [bit_step_eq, dif_neg h]
      simp only [h, Bool.false_eq_true, if_false]
    · change step.val + 1 = consumed n.val
      rw [consumed_step, hs, if_neg h, Nat.add_zero]

end LeanBlsSimd.Pairing.PortableLines
