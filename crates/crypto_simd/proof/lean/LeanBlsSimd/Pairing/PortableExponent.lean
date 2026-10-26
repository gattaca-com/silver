import LeanBlsSimd.Pairing.ExponentLoop
import LeanBlsSimd.Portable.Fp12.Frobenius

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls
open silver_crypto_simd

namespace LeanBlsSimd.Pairing.FinalExponent.Portable

open LeanBlsSimd.Portable.Fp12

set_option maxRecDepth 4000

theorem cyclotomic_square_encoded [RuntimeFeatures] (a : Bls.Fp12) (ha : Good a) :
    portable.fp12.Fp12.cyclotomic_square (encode a) = ok (encode a.square) := by
  rcases ha with ha | ha
  · have hz : a = Bls.Fp12.zero := (Fp12.toField_eq_zero_iff a).mp ha
    subst a
    have h := cyclotomic_raw_encoded (Cyclotomic.specCoeffs Bls.Fp12.zero)
    rw [ofCoeffs_spec] at h
    have he : ofCoeffs (Cyclotomic.Schedule.raw Fp6Field.xi (Cyclotomic.specCoeffs Bls.Fp12.zero)) =
        Bls.Fp12.zero.square := by
      apply Fp12.toField.injective
      rw [ofCoeffs_field, Fp12.toField_square, Fp12.toField_zero]
      simp [Cyclotomic.fieldDecode, Cyclotomic.Schedule.raw, Cyclotomic.specCoeffs,
        Cyclotomic.Schedule.fp4Square, Cyclotomic.Schedule.less, Cyclotomic.Schedule.plus,
        Bls.Fp12.zero, Bls.Fp6.zero, Fp6Field.assemble]
      rfl
    rwa [he] at h
  · exact LeanBlsSimd.Portable.Fp12.cyclotomic_square_encoded a ha

theorem exponent_body [RuntimeFeatures] (a f : Bls.Fp12) (hf : Good f)
    (n : Fin 63) (bit : U32) (hb : bit.val = n.val + 1) :
    ∃ bit', bit'.val = n.val ∧
      portable.fp12.Fp12.cyclotomic_exp_loop.body (encode a) (encode f) bit =
        ok (cont (encode (powerStep a f n.val), bit')) := by
  let bit' : U32 := UScalar.ofNatCore n.val (by change n.val < 2^32; have := n.isLt; omega)
  have hdec : bit - 1#u32 = ok bit' := by
    rw [sub_ok bit 1#u32 (by simp; omega)]
    apply congrArg ok
    apply UScalar.eq_of_val_eq
    simp only [UScalar.ofNatCore_val_eq]
    change bit.val - 1 = n.val
    omega
  refine ⟨bit', rfl, ?_⟩
  simp only [portable.fp12.Fp12.cyclotomic_exp_loop.body,
    show bit > 0#u32 from by simp only [UScalar.lt_equiv]; change 0 < bit.val; omega,
    if_true, hdec, bind_tc_ok, cyclotomic_square_encoded f hf, G1x8.is_lower_z_bit_refines]
  change (do
    let r ← if G1x8.is_lower_z_bit n.val then portable.fp12.Fp12.mul (encode f.square) (encode a)
      else ok (encode f.square)
    ok (cont (r, bit'))) = _
  cases h : G1x8.is_lower_z_bit n.val <;>
    simp only [h, Bool.false_eq_true, if_false, if_true, mul_encoded, bind_tc_ok, powerStep]

theorem exponent_encoded [RuntimeFeatures] (a : Bls.Fp12) (ha : Good a) :
    portable.fp12.Fp12.cyclotomic_exp (encode a) = ok (encode (exp a)) := by
  let body := fun (state : portable.fp12.Fp12 × U32) =>
    portable.fp12.Fp12.cyclotomic_exp_loop.body (encode a) state.1 state.2
  have hdone : ∀ x bit, bit.val = 0 → body (x, bit) = ok (done x) := by
    intro x bit hb
    simp only [body, portable.fp12.Fp12.cyclotomic_exp_loop.body,
      UScalar.lt_equiv, hb, Nat.not_lt_zero, if_false]
  have hstep : ∀ (n : Fin 63) x f bit, x = encode f → Good f → bit.val = n.val + 1 →
      ∃ out bit', body (x, bit) = ok (cont (out, bit')) ∧ bit'.val = n.val ∧
        out = encode (powerStep a f n.val) := by
    intro n x f bit hx hf hb
    subst x
    obtain ⟨bit', hb', he⟩ := exponent_body a f hf n bit hb
    exact ⟨_, bit', he, hb', rfl⟩
  obtain ⟨out, hout, rout⟩ := power_loop_refines body (fun x f => x = encode f) a ha hdone hstep
    63 (by omega) (encode a) a 63#u32 rfl ha rfl
  rw [rout, power_loop_eq] at hout
  have hbit : Array.index_usize bls.constants.Z_BITS 0#usize = ok 63#u32 := by
    rw [Z_BITS_index 0#usize (by decide)]; rfl
  simp only [portable.fp12.Fp12.cyclotomic_exp, hbit, bind_tc_ok]
  change (do
    let out ← loop body (encode a, 63#u32)
    portable.fp12.Fp12.conjugate out) = _
  rw [hout]
  simp only [bind_tc_ok, conjugate_encoded, exp]

end LeanBlsSimd.Pairing.FinalExponent.Portable
