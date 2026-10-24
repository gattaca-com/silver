import LeanBlsSimd.LaneTower.Cyclotomic

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

theorem shuffle_cycleRe {α : Type} (a b : V α) :
    shuffle cycleRe a b = ![a 7, a 7, a 7, a 2, a 7, a 0, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleIm {α : Type} (a b : V α) :
    shuffle cycleIm a b = ![a 7, a 7, a 7, a 3, a 7, a 1, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleNPos {α : Type} (a b : V α) :
    shuffle cycleNPos a b = ![a 0, a 1, a 2, a 7, a 6, b 5, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleNNeg0 {α : Type} (a b : V α) :
    shuffle cycleNNeg0 a b = ![a 7, a 7, a 7, a 7, a 0, a 1, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleNNeg1 {α : Type} (a b : V α) :
    shuffle cycleNNeg1 a b = ![a 7, a 7, a 7, a 7, a 3, a 4, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleMPos {α : Type} (a b : V α) :
    shuffle cycleMPos a b = ![a 3, a 4, a 5, b 3, a 7, a 7, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleMNeg0 {α : Type} (a b : V α) :
    shuffle cycleMNeg0 a b = ![a 7, a 7, a 7, a 2, a 7, a 7, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleMNeg1 {α : Type} (a b : V α) :
    shuffle cycleMNeg1 a b = ![a 7, a 7, a 7, a 5, a 7, a 7, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleInput0 {α : Type} (a b : V α) :
    shuffle cycleInput0 a b = ![a 0, a 3, a 1, a 4, a 2, a 5, a 0, b 0] := by
  unfold cycleInput0 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleInput1 {α : Type} (a b : V α) :
    shuffle cycleInput1 a b = ![b 0, b 0, b 0, b 0, b 0, b 0, a 4, b 0] := by
  unfold cycleInput1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleSum0 {α : Type} (a b : V α) :
    shuffle cycleSum0 a b = ![a 3, a 1, b 0, b 0, b 0, b 0, b 0, b 0] := by
  unfold cycleSum0 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_cycleSum1 {α : Type} (a b : V α) :
    shuffle cycleSum1 a b = ![a 2, a 5, b 0, b 0, b 0, b 0, b 0, b 0] := by
  unfold cycleSum1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_cyclePack {α : Type} (a b : V α) :
    shuffle cyclePack a b = ![a 0, b 0, a 1, b 1, a 7, a 7, a 7, a 7] := by
  funext l
  fin_cases l <;> rfl

theorem select_middle {α : Type} (a b : V α) :
    select 56#u8 a b = ![a 0, a 1, a 2, b 3, b 4, b 5, a 6, a 7] := by
  funext l
  fin_cases l <;> rfl

private theorem coeffs_ext {x y : Cyclotomic.Schedule.Coeffs Fp2Field}
    (h0 : x.c00 = y.c00) (h1 : x.c01 = y.c01) (h2 : x.c02 = y.c02)
    (h3 : x.c10 = y.c10) (h4 : x.c11 = y.c11) (h5 : x.c12 = y.c12) : x = y := by
  cases x; cases y; cases h0; cases h1; cases h2; cases h3; cases h4; cases h5; rfl

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem cyclotomic_coefficients (a : P F) :
    Cyclotomic.specCoeffs (value (cyclotomicValues a)) =
      Cyclotomic.Schedule.raw Fp6Field.xi (Cyclotomic.specCoeffs (value a)) := by
  apply coeffs_ext <;> apply QuadraticAlgebra.ext
  all_goals
    simp only [Cyclotomic.specCoeffs, value, cyclotomicValues, cyclotomicSum, cyclotomicT,
      cycleQ, cycleM, cycleInput, cycleSums, add2, sub2, shuffle2, select2, select_middle,
      shuffle_cycleRe, shuffle_cycleIm, shuffle_cycleNPos, shuffle_cycleNNeg0, shuffle_cycleNNeg1,
      shuffle_cycleMPos, shuffle_cycleMNeg0, shuffle_cycleMNeg1, shuffle_cycleInput0,
      shuffle_cycleInput1, shuffle_cycleSum0, shuffle_cycleSum1, shuffle_cyclePack,
      Matrix.cons_val, zero_add, add_zero, zero_mul, mul_zero]
    simp [Cyclotomic.Schedule.raw, Cyclotomic.Schedule.fp4Square,
      Cyclotomic.Schedule.less, Cyclotomic.Schedule.plus, Fp2.toField, Fp6Field.xi,
      show (1 : Fp2Field).re = 1 from rfl, show (1 : Fp2Field).im = 0 from rfl]
    ring

set_option maxHeartbeats 1000000 in
theorem cyclotomic_value (a : P F)
    (hphi : Fp12.toField (value a) = 0 ∨
      Fp12.toField (value a) ^ (Fp.modulus ^ 4 - Fp.modulus ^ 2 + 1) = 1) :
    value (cyclotomicValues a) = (value a).square := by
  apply Fp12.toField.injective
  rw [← Cyclotomic.fieldDecode_spec, cyclotomic_coefficients, Fp12.toField_square]
  rcases hphi with hzero | hphi
  · have ha : value a = Bls.Fp12.zero := Fp12.toField.injective (by simpa using hzero)
    rw [ha]
    simp [Cyclotomic.specCoeffs, Cyclotomic.Schedule.raw, Cyclotomic.Schedule.fp4Square,
      Cyclotomic.Schedule.less, Cyclotomic.Schedule.plus, Cyclotomic.fieldDecode,
      Bls.Fp12.zero, Bls.Fp6.zero, Fp6Field.assemble]
    change (0 : Fp12Field) = 0 ^ 2
    simp
  · exact Cyclotomic.field_cyclotomic_square _ hphi

theorem cyclotomic_square_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12}
    (hx : Rep x a) (hphi : Fp12.toField a = 0 ∨
      Fp12.toField a ^ (Fp.modulus ^ 4 - Fp.modulus ^ 2 + 1) = 1) :
    ∃ out, fp12.Fp12.cyclotomic_square x = ok out ∧ Rep out a.square := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := cyclotomic_raw ⟨fun l => (h0 l).capped, fun l => (h1 l).capped⟩
  exact ⟨out, hout, cyclotomicValues v, rout.1, rout.2, cyclotomic_value v hphi⟩

end LeanBlsSimd.LaneTower
