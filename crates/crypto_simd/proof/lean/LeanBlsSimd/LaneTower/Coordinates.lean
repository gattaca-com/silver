import LeanBlsSimd.LaneTower.Mul

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

theorem shuffle_Z0_POS_0 {α : Type} (a b : V α) :
    shuffle fp12.Z0_POS.val[0] a b = ![a 0, a 3, a 4, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.Z0_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z0_POS_1 {α : Type} (a b : V α) :
    shuffle fp12.Z0_POS.val[1] a b = ![b 5, b 2, a 1, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.Z0_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z0_NEG_0 {α : Type} (a b : V α) :
    shuffle fp12.Z0_NEG.val[0] a b = ![b 1, a 0, a 0, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.Z0_NEG
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z0_NEG_1 {α : Type} (a b : V α) :
    shuffle fp12.Z0_NEG.val[1] a b = ![b 2, a 1, a 2, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.Z0_NEG
  funext l
  fin_cases l <;> rfl

theorem shuffle_V_Z0_POS_0 {α : Type} (a b : V α) :
    shuffle fp12.V_Z0_POS.val[0] a b = ![b 4, a 0, a 3, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.V_Z0_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_V_Z0_POS_1 {α : Type} (a b : V α) :
    shuffle fp12.V_Z0_POS.val[1] a b = ![b 1, b 5, b 2, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.V_Z0_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_V_Z0_NEG_0 {α : Type} (a b : V α) :
    shuffle fp12.V_Z0_NEG.val[0] a b = ![b 0, b 1, a 0, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.V_Z0_NEG
  funext l
  fin_cases l <;> rfl

theorem shuffle_V_Z0_NEG_1 {α : Type} (a b : V α) :
    shuffle fp12.V_Z0_NEG.val[1] a b = ![b 2, b 2, a 1, a 6, a 6, a 6, a 6, a 6] := by
  unfold fp12.V_Z0_NEG
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z3_POS_0 {α : Type} (a b : V α) :
    shuffle fp12.Z3_POS.val[0] a b = ![a 6, a 6, a 6, a 0, a 3, a 4, a 6, a 6] := by
  unfold fp12.Z3_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z3_POS_1 {α : Type} (a b : V α) :
    shuffle fp12.Z3_POS.val[1] a b = ![a 6, a 6, a 6, b 5, b 2, a 1, a 6, a 6] := by
  unfold fp12.Z3_POS
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z3_NEG_0 {α : Type} (a b : V α) :
    shuffle fp12.Z3_NEG.val[0] a b = ![a 6, a 6, a 6, b 1, a 0, a 0, a 6, a 6] := by
  unfold fp12.Z3_NEG
  funext l
  fin_cases l <;> rfl

theorem shuffle_Z3_NEG_1 {α : Type} (a b : V α) :
    shuffle fp12.Z3_NEG.val[1] a b = ![a 6, a 6, a 6, b 2, a 1, a 2, a 6, a 6] := by
  unfold fp12.Z3_NEG
  funext l
  fin_cases l <;> rfl

theorem clear2_eq {α : Type} [Zero α] (a : P α) :
    clear2 a =
      (![a.1 0, a.1 1, a.1 2, a.1 3, a.1 4, a.1 5, 0, 0],
       ![a.2 0, a.2 1, a.2 2, a.2 3, a.2 4, a.2 5, 0, 0]) := by
  apply Prod.ext <;> funext l <;> fin_cases l <;> rfl

theorem fp2_add_0 (a b : Bls.Fp2) : (a + b).c0 = (a.c0 : F) + b.c0 := rfl

theorem fp2_add_1 (a b : Bls.Fp2) : (a + b).c1 = (a.c1 : F) + b.c1 := rfl

theorem fp2_sub_0 (a b : Bls.Fp2) : (a - b).c0 = (a.c0 : F) - b.c0 := rfl

theorem fp2_sub_1 (a b : Bls.Fp2) : (a - b).c1 = (a.c1 : F) - b.c1 := rfl

theorem fp6_add_0 (a b : Bls.Fp6) : (a + b).c0 = a.c0 + b.c0 := rfl

theorem fp6_add_1 (a b : Bls.Fp6) : (a + b).c1 = a.c1 + b.c1 := rfl

theorem fp6_add_2 (a b : Bls.Fp6) : (a + b).c2 = a.c2 + b.c2 := rfl

theorem fp2_xi (a : Bls.Fp2) : a.mulByOnePlusI =
    ⟨(a.c0 : F) - a.c1, (a.c0 : F) + a.c1⟩ := rfl

def cubicFrom (a : Fin 8 → Bls.Fp2) : Bls.Fp6 :=
  ⟨a 0 + (a 5 - a 1 - a 2).mulByOnePlusI,
   a 3 - a 0 - a 1 + (a 2).mulByOnePlusI,
   a 4 - a 0 - a 2 + a 1⟩

def tripleValue (a b c : V F) (l : Fin 8) : Bls.Fp2 :=
  ⟨a l - b l, c l - (a l + b l)⟩

def productFormula (a : Fin 9 → V F) : Bls.Fp12 :=
  let p := cubicFrom (tripleValue (a 0) (a 1) (a 2))
  let q := cubicFrom (tripleValue (a 3) (a 4) (a 5))
  let r := cubicFrom (tripleValue
    (fun l => a 6 l - (a 0 l + a 3 l))
    (fun l => a 7 l - (a 1 l + a 4 l))
    (fun l => a 8 l - (a 2 l + a 5 l)))
  ⟨p + q.mulByV, r⟩

theorem fp12_ext (x y : Bls.Fp12) (h0 : x.c0 = y.c0) (h1 : x.c1 = y.c1) : x = y := by
  cases x; cases y; cases h0; cases h1; rfl

theorem fp6_ext (x y : Bls.Fp6)
    (h0 : x.c0 = y.c0) (h1 : x.c1 = y.c1) (h2 : x.c2 = y.c2) : x = y := by
  cases x; cases y; cases h0; cases h1; cases h2; rfl

theorem fp2_ext (x y : Bls.Fp2) (h0 : x.c0 = y.c0) (h1 : x.c1 = y.c1) : x = y := by
  cases x; cases y; cases h0; cases h1; rfl

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem recombine_value (a : Fin 9 → V F) : value (productRecombine a) = productFormula a := by
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext
  all_goals
    change (_ : F) = _
    simp only [value, productRecombine, productFormula, cubicFrom, tripleValue,
      fromTriple, xi2, clear2_eq, slices, add2, sub2, shuffle2,
      shuffle_Z0_POS_0, shuffle_Z0_POS_1, shuffle_Z0_NEG_0, shuffle_Z0_NEG_1,
      shuffle_V_Z0_POS_0, shuffle_V_Z0_POS_1, shuffle_V_Z0_NEG_0, shuffle_V_Z0_NEG_1,
      shuffle_Z3_POS_0, shuffle_Z3_POS_1, shuffle_Z3_NEG_0, shuffle_Z3_NEG_1,
      Bls.Fp6.mulByV, fp2_xi,
      Matrix.cons_val, fp2_add_0, fp2_add_1, fp2_sub_0, fp2_sub_1, fp6_add_0, fp6_add_1, fp6_add_2,
      zero_add, add_zero]
    simp only [sub_eq_add_neg]
    abel

theorem shuffle_karaFirst_0 {α : Type} [Zero α] (a : V α) :
    shuffle (karaFirst 0) a (fun _ => 0) = ![a 0, a 1, a 2, a 0, a 0, a 1, 0, 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_karaSecond_0 {α : Type} [Zero α] (a : V α) :
    shuffle (karaSecond 0) a (fun _ => 0) = ![0, 0, 0, a 1, a 2, a 2, 0, 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_karaFirst_1 {α : Type} [Zero α] (a : V α) :
    shuffle (karaFirst 1) a (fun _ => 0) = ![a 3, a 4, a 5, a 3, a 3, a 4, 0, 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_karaSecond_1 {α : Type} [Zero α] (a : V α) :
    shuffle (karaSecond 1) a (fun _ => 0) = ![0, 0, 0, a 4, a 5, a 5, 0, 0] := by
  funext l
  fin_cases l <;> rfl

-- Keep coefficient calculations in one field instance while connecting to the Fin-based spec.
private abbrev C2 := F × F
private abbrev C6 := Fin 3 → C2
private def cadd (a b : C2) : C2 := (a.1 + b.1, a.2 + b.2)
private def csub (a b : C2) : C2 := (a.1 - b.1, a.2 - b.2)
private def cmul (a b : C2) : C2 := (a.1 * b.1 - a.2 * b.2, a.1 * b.2 + a.2 * b.1)
private def cxi (a : C2) : C2 := (a.1 - a.2, a.1 + a.2)
private def c6add (a b : C6) : C6 := fun i => cadd (a i) (b i)
private def c6sub (a b : C6) : C6 := fun i => csub (a i) (b i)
private def c6v (a : C6) : C6 := ![cxi (a 2), a 0, a 1]
private def c6mul (a b : C6) : C6 :=
  let t0 := cmul (a 0) (b 0)
  let t1 := cmul (a 1) (b 1)
  let t2 := cmul (a 2) (b 2)
  ![cadd (cxi (csub (csub (cmul (cadd (a 1) (a 2)) (cadd (b 1) (b 2))) t1) t2)) t0,
    cadd (csub (csub (cmul (cadd (a 0) (a 1)) (cadd (b 0) (b 1))) t0) t1) (cxi t2),
    cadd (csub (csub (cmul (cadd (a 0) (a 2)) (cadd (b 0) (b 2))) t0) t2) t1]
private def c6value (a : C6) : Bls.Fp6 :=
  ⟨⟨(a 0).1, (a 0).2⟩, ⟨(a 1).1, (a 1).2⟩, ⟨(a 2).1, (a 2).2⟩⟩
private def c12value (a b : C6) : Bls.Fp12 := ⟨c6value a, c6value b⟩
private def ccubic (a : Fin 8 → C2) : C6 :=
  ![cadd (a 0) (cxi (csub (csub (a 5) (a 1)) (a 2))),
    cadd (csub (csub (a 3) (a 0)) (a 1)) (cxi (a 2)),
    cadd (csub (csub (a 4) (a 0)) (a 2)) (a 1)]
private def ctriple (a b c : V F) (l : Fin 8) : C2 := (a l - b l, c l - (a l + b l))
private def uniformFormula (a : Fin 9 → V F) : Bls.Fp12 :=
  let p := ccubic (ctriple (a 0) (a 1) (a 2))
  let q := ccubic (ctriple (a 3) (a 4) (a 5))
  let r := ccubic (ctriple (fun l => a 6 l - (a 0 l + a 3 l))
    (fun l => a 7 l - (a 1 l + a 4 l)) (fun l => a 8 l - (a 2 l + a 5 l)))
  c12value (c6add p (c6v q)) r
private theorem formula_uniform (a : Fin 9 → V F) : productFormula a = uniformFormula a := rfl
private def uniformProduct (a b : P F) : Bls.Fp12 :=
  let a0 : C6 := ![(a.1 0, a.2 0), (a.1 1, a.2 1), (a.1 2, a.2 2)]
  let a1 : C6 := ![(a.1 3, a.2 3), (a.1 4, a.2 4), (a.1 5, a.2 5)]
  let b0 : C6 := ![(b.1 0, b.2 0), (b.1 1, b.2 1), (b.1 2, b.2 2)]
  let b1 : C6 := ![(b.1 3, b.2 3), (b.1 4, b.2 4), (b.1 5, b.2 5)]
  let t0 := c6mul a0 b0
  let t1 := c6mul a1 b1
  c12value (c6add t0 (c6v t1)) (c6sub (c6sub (c6mul (c6add a0 a1) (c6add b0 b1)) t0) t1)
private theorem product_uniform (a b : P F) : (value a).mul (value b) = uniformProduct a b := rfl

set_option maxHeartbeats 2000000 in
set_option maxRecDepth 4096 in
theorem product_value (a b : P F) : value (productValues a b) = (value a).mul (value b) := by
  rw [productValues, recombine_value, formula_uniform, product_uniform]
  have h0 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 0 (by decide)
  have h1 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 1 (by decide)
  have h2 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 2 (by decide)
  have h3 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 3 (by decide)
  have h4 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 4 (by decide)
  have h5 (j : Fin 9) := unpack9_products (productInputs a) (productInputs b) j 5 (by decide)
  apply fp12_ext <;> apply fp6_ext <;> apply fp2_ext
  all_goals
    change (_ : F) = _
    simp only [uniformFormula, ccubic, ctriple, c12value, c6value, c6add, c6v, cadd, csub, cxi, Matrix.cons_val]
    simp only [h0, h1, h2, h3, h4, h5]
    simp only [productInputs, operands, kara2, add2, shuffle2,
      shuffle_karaFirst_0, shuffle_karaFirst_1, shuffle_karaSecond_0, shuffle_karaSecond_1,
      uniformProduct, c12value, c6value, c6add, c6sub, c6v, c6mul, cadd, csub, cmul, cxi,
      Matrix.cons_val, add_zero]
    simp only [sub_eq_add_neg]
    ring

end LeanBlsSimd.LaneTower
