import LeanBlsSimd.LaneTower.Line

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

theorem shuffle_linePack0 {α : Type} (a b : V α) :
    shuffle linePack0 a b = ![a 0, a 1, a 2, a 3, a 4, b 0, b 1, b 2] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_linePack1 {α : Type} (a b : V α) :
    shuffle linePack1 a b = ![a 0, a 1, a 2, a 3, a 4, b 3, b 4, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineTail {α : Type} (a b : V α) :
    shuffle lineTail a b = ![a 5, a 6, a 7, b 5, b 6, b 7, b 7, b 7] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNPos0 {α : Type} (a b : V α) :
    shuffle lineNPos0 a b = ![a 0, a 2, a 3, b 0, b 2, b 3, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNPos1 {α : Type} (a b : V α) :
    shuffle lineNPos1 a b = ![b 5, b 5, a 1, b 5, b 5, b 1, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNPos2 {α : Type} (a b : V α) :
    shuffle lineNPos2 a b = ![b 5, b 5, a 6, b 5, b 5, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNNeg0 {α : Type} (a b : V α) :
    shuffle lineNNeg0 a b = ![b 5, a 0, a 0, b 5, b 0, b 0, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNNeg1 {α : Type} (a b : V α) :
    shuffle lineNNeg1 a b = ![b 5, a 1, b 5, b 5, b 1, a 7, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineNNeg2 {α : Type} (a b : V α) :
    shuffle lineNNeg2 a b = ![b 5, b 5, b 5, b 5, a 6, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineMPos0 {α : Type} (a b : V α) :
    shuffle lineMPos0 a b = ![a 4, a 5, b 5, b 4, b 5, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineMPos1 {α : Type} (a b : V α) :
    shuffle lineMPos1 a b = ![a 7, b 5, b 5, b 5, b 5, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineMNeg0 {α : Type} (a b : V α) :
    shuffle lineMNeg0 a b = ![a 1, b 5, b 5, b 1, b 5, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineMNeg1 {α : Type} (a b : V α) :
    shuffle lineMNeg1 a b = ![b 5, b 5, b 5, a 5, b 5, b 5, b 5, b 5] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineLeftA0 {α : Type} (a b : V α) :
    shuffle lineLeftA0 a b = ![a 0, a 1, a 0, a 0, a 1, a 5, a 3, a 4] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineLeftA1 {α : Type} (a b : V α) :
    shuffle lineLeftA1 a b = ![b 0, b 0, a 1, a 2, a 2, b 0, b 0, b 0] := by
  unfold lineLeftA1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineRightA0 {α : Type} (a b : V α) :
    shuffle lineRightA0 a b = ![a 0, a 1, a 0, a 0, a 1, a 2, a 2, a 2] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineRightA1 {α : Type} (a b : V α) :
    shuffle lineRightA1 a b = ![b 0, b 0, a 1, b 0, b 0, b 0, b 0, b 0] := by
  unfold lineRightA1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineLeftSum {α : Type} (a b : V α) :
    shuffle lineLeftSum a b = ![a 3, a 4, a 5, b 0, b 0, b 0, b 0, b 0] := by
  unfold lineLeftSum fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineLeftB0 {α : Type} (a b : V α) :
    shuffle lineLeftB0 a b = ![a 0, a 1, a 0, a 0, a 1, b 0, b 0, b 0] := by
  unfold lineLeftB0 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineLeftB1 {α : Type} (a b : V α) :
    shuffle lineLeftB1 a b = ![b 0, b 0, a 1, a 2, a 2, b 0, b 0, b 0] := by
  unfold lineLeftB1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineRightSum {α : Type} (a b : V α) :
    shuffle lineRightSum a b = ![b 0, a 2, b 0, b 0, b 0, b 0, b 0, b 0] := by
  unfold lineRightSum fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineRightB0 {α : Type} (a b : V α) :
    shuffle lineRightB0 a b = ![a 0, a 1, a 0, a 0, a 1, b 0, b 0, b 0] := by
  unfold lineRightB0 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_lineRightB1 {α : Type} (a b : V α) :
    shuffle lineRightB1 a b = ![b 0, b 0, a 1, b 0, b 0, b 0, b 0, b 0] := by
  unfold lineRightB1 fp12.Z
  funext l
  fin_cases l <;> rfl

theorem clear_five {α : Type} [Zero α] (a : P α) :
    select2 224#u8 a (fun _ => 0, fun _ => 0) =
      (![a.1 0, a.1 1, a.1 2, a.1 3, a.1 4, 0, 0, 0],
       ![a.2 0, a.2 1, a.2 2, a.2 3, a.2 4, 0, 0, 0]) := by
  apply Prod.ext <;> funext l <;> fin_cases l <;> rfl

def sparseLine (a : P F) : P F :=
  (![a.1 0, a.1 1, 0, 0, a.1 2, 0, 0, 0], ![a.2 0, a.2 1, 0, 0, a.2 2, 0, 0, 0])

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem line_value (a b : P F) :
    value (lineValues a b) = (value a).mul (value (sparseLine b)) := by
  rw [← product_value a (sparseLine b)]
  have p0 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 0 (by decide)
  have p1 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 1 (by decide)
  have p2 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 2 (by decide)
  have p3 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 3 (by decide)
  have p4 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 4 (by decide)
  have p5 (j : Fin 9) := unpack9_products (productInputs a) (productInputs (sparseLine b)) j 5 (by decide)
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext
  all_goals
    change (_ : F) = _
    simp only [value, lineValues, productValues, lineRecombine, productRecombine,
      fromTriple, xi2, clear2_eq, clear_five, slices, add2, sub2, shuffle2,
      shuffle_Z0_POS_0, shuffle_Z0_POS_1, shuffle_Z0_NEG_0, shuffle_Z0_NEG_1,
      shuffle_V_Z0_POS_0, shuffle_V_Z0_POS_1, shuffle_V_Z0_NEG_0, shuffle_V_Z0_NEG_1,
      shuffle_Z3_POS_0, shuffle_Z3_POS_1, shuffle_Z3_NEG_0, shuffle_Z3_NEG_1,
      shuffle_lineTail, shuffle_lineNPos0, shuffle_lineNPos1, shuffle_lineNPos2, shuffle_lineNNeg0, shuffle_lineNNeg1, shuffle_lineNNeg2, shuffle_lineMPos0, shuffle_lineMPos1, shuffle_lineMNeg0, shuffle_lineMNeg1,
      Matrix.cons_val, zero_add, add_zero]
    simp only [p0, p1, p2, p3, p4, p5]
    simp only [lineLeft, lineRight, lineOperands, lineGroupA, lineGroupB,
      productInputs, sparseLine, operands, kara2, add2, shuffle2,
      shuffle_karaFirst_0, shuffle_karaFirst_1, shuffle_karaSecond_0, shuffle_karaSecond_1,
      shuffle_linePack0, shuffle_linePack1, shuffle_lineLeftA0, shuffle_lineLeftA1, shuffle_lineRightA0, shuffle_lineRightA1, shuffle_lineLeftSum, shuffle_lineLeftB0, shuffle_lineLeftB1, shuffle_lineRightSum, shuffle_lineRightB0, shuffle_lineRightB1,
      Matrix.cons_val, zero_add, add_zero, mul_zero]
    ring

theorem mul_by_line_refines {x y : fp2x8.Fp2x8} {a : Bls.Fp12} {b : P F}
    (hx : Rep x a) (hy : Strict2 256 y b) :
    ∃ out, fp12.Fp12.mul_by_line x y = ok out ∧ Rep out (a.mul (value (sparseLine b))) := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := mul_by_line_raw
    ⟨fun l => (h0 l).capped, fun l => (h1 l).capped⟩ hy.normal
  exact ⟨out, hout, lineValues v b,
    fun l => (rout.1 l).boundRep (by change 120 < 256; decide),
    fun l => (rout.2 l).boundRep (by change 120 < 256; decide), line_value v b⟩

end LeanBlsSimd.LaneTower
