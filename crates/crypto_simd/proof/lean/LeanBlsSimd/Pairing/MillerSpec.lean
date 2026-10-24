import LeanBlsSimd.Pairing.EmbeddedSteps

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

def FinalEq (a b : Fp12) : Prop := Fp12.toField a ^ finalExpExponent = Fp12.toField b ^ finalExpExponent

theorem FinalEq.mul {a b c d : Fp12} (hab : FinalEq a b) (hcd : FinalEq c d) :
    FinalEq (a * c) (b * d) := by
  simp only [FinalEq, map_mul, mul_pow]
  rw [hab, hcd]

theorem FinalEq.conjugate {a b : Fp12} (h : FinalEq a b) : FinalEq a.conjugate b.conjugate := by
  simp only [FinalEq, Cyclotomic.spec_conjugate, ← pow_mul]
  rw [Nat.mul_comm _ finalExpExponent, pow_mul, h, ← pow_mul, Nat.mul_comm]

theorem testBit_iff (n : Nat) : blsX.testBit n = true ↔ (blsX >>> n) &&& 1 = 1 := by
  simp only [Nat.testBit_eq_decide_div_mod_eq, decide_eq_true_eq,
    Nat.and_one_is_mod, Nat.shiftRight_eq_div_pow]

theorem actions_steps (n : Nat) (q p t : Embedded.Point) (f : Fp12) :
    ((lineKinds n).foldl (fun state add => action q p add state) (t, f)).2 =
      millerSteps blsX q p n t f := by
  induction n generalizing t f with
  | zero => rfl
  | succ n ih =>
    rw [lineKinds, List.foldl_cons, List.foldl_append, SpecPairing.millerSteps_succ]
    by_cases hb : blsX.testBit n = true
    · have hbit := (testBit_iff n).mp hb
      simp only [hb, if_true, List.foldl_cons, List.foldl_nil, action, Bool.false_eq_true, if_false]
      rw [if_pos hbit]
      exact ih _ _
    · have hbit := mt (testBit_iff n).mpr hb
      simp only [hb, Bool.false_eq_true, if_false, List.foldl_nil, action]
      rw [if_neg hbit]
      exact ih _ _

namespace FixedTable

def normalizedStep (pair : Fin 2) (xp yp : Fp2) (f : Fp12) (step : Fin 68) : Fp12 :=
  (if lineKind step then f else f * f) * normalizedLine step pair xp yp

def actionAt (pair : Fin 2) (xp yp : Fp2) (state : Embedded.Point × Fp12)
    (step : Fin 68) : Embedded.Point × Fp12 :=
  action (untwist (fixedPoint pair)) (evaluationPoint xp yp) (lineKind step) state

def normalizedMiller (pair : Fin 2) (xp yp : Fp2) : Fp12 :=
  (List.finRange 68).foldl (normalizedStep pair xp yp) Fp12.one

theorem step_final_eq (step : Fin 68) (pair : Fin 2) (xp yp : Fp2)
    (f g : Fp12) (h : FinalEq f g) :
    FinalEq ((if lineKind step then f else f * f) * evaluatedLine step pair xp yp)
      (normalizedStep pair xp yp g step) := by
  apply FinalEq.mul
  · split_ifs
    · exact h
    · exact h.mul h
  · exact line_final_power step pair xp yp

theorem fold_final_eq (pair : Fin 2) (xp yp : Fp2) (i : Nat) (hi : i ≤ 68)
    (f g : Fp12) (h : FinalEq f g) :
    FinalEq (((List.finRange 68).drop i).foldl (actionAt pair xp yp)
        (untwist (point pair ⟨i, by omega⟩), f)).2
      (((List.finRange 68).drop i).foldl (normalizedStep pair xp yp) g) := by
  induction hn : 68 - i generalizing i f g with
  | zero =>
    have hi' : i = 68 := by omega
    subst i
    simpa only [List.drop_eq_nil_of_le (by simp : (List.finRange 68).length ≤ 68),
      List.foldl_nil] using h
  | succ n ih =>
    have hil : i < 68 := by omega
    let step : Fin 68 := ⟨i, hil⟩
    have hdrop : (List.finRange 68).drop i = step :: (List.finRange 68).drop (i + 1) := by
      rw [List.drop_eq_getElem_cons (by simpa using hil)]
      simp only [List.getElem_finRange]
      rfl
    rw [hdrop, List.foldl_cons, List.foldl_cons]
    have hs := action_step step pair xp yp f
    change actionAt pair xp yp (untwist (point pair ⟨i, by omega⟩), f) step = _ at hs
    rw [hs]
    exact ih (i + 1) (by omega) _ _ (step_final_eq step pair xp yp f g h) (by omega)

theorem kinds_eq : (List.finRange 68).map lineKind = lineKinds 63 := by decide +kernel

theorem miller_final_eq (pair : Fin 2) (xp yp : Fp2) :
    FinalEq (millerLoop blsX (untwist (fixedPoint pair)) (evaluationPoint xp yp))
      (normalizedMiller pair xp yp) := by
  have hf := fold_final_eq pair xp yp 0 (by omega) Fp12.one Fp12.one rfl
  have hzero : (⟨0, by omega⟩ : Fin 69) = 0 := rfl
  rw [List.drop_zero, hzero, point_initial] at hf
  have hs := actions_steps 63 (untwist (fixedPoint pair)) (evaluationPoint xp yp)
    (untwist (fixedPoint pair)) Fp12.one
  rw [← kinds_eq, List.foldl_map] at hs
  rw [SpecPairing.millerLoop_eq, show blsX.log2 = 63 from by decide +kernel, ← hs]
  exact hf

end FixedTable

end

end LeanBlsSimd.Pairing
