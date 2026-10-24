import LeanBlsSimd.Pairing.MillerFactors

open EthLib.Cryptography Bls
open Aeneas Aeneas.Std

namespace LeanBlsSimd.Pairing

noncomputable section

def activeStep (v : Factors) (present : Array Bool 2#usize) (pair : Fin 2)
    (f : Fp12) (step : Fin 68) : Fp12 :=
  pairApply step v present pair (if lineKind step then f else f * f)

def combinedStep (v : Factors) (present : Array Bool 2#usize)
    (f : Fp12) (step : Fin 68) : Fp12 :=
  pairApply step v present 1 (activeStep v present 0 f step)

theorem combined_step_field (v : Factors) (present : Array Bool 2#usize) (step : Fin 68)
    (f a b : Fp12) (h : Fp12.toField f = Fp12.toField a * Fp12.toField b) :
    Fp12.toField (combinedStep v present f step) =
      Fp12.toField (activeStep v present 0 a step) *
        Fp12.toField (activeStep v present 1 b step) := by
  unfold combinedStep activeStep pairApply
  split_ifs <;> simp only [map_mul, h] <;> ring

theorem combined_fold_field (steps : List (Fin 68)) (v : Factors) (present : Array Bool 2#usize)
    (f a b : Fp12) (h : Fp12.toField f = Fp12.toField a * Fp12.toField b) :
    Fp12.toField (steps.foldl (combinedStep v present) f) =
      Fp12.toField (steps.foldl (activeStep v present 0) a) *
        Fp12.toField (steps.foldl (activeStep v present 1) b) := by
  induction steps generalizing f a b with
  | nil => exact h
  | cons step steps ih =>
    simp only [List.foldl_cons]
    exact ih _ _ _ (combined_step_field v present step f a b h)

def presence (points : Fin 2 → G1) : Array Bool 2#usize :=
  Array.make 2#usize [!(points 0).isInfinity, !(points 1).isInfinity] (by rfl)

theorem presence_entry (points : Fin 2 → G1) (pair : Fin 2) :
    (presence points).val[pair.val]'(by simp; omega) = !(points pair).isInfinity := by
  fin_cases pair <;> rfl

private theorem one_square : Fp12.one * Fp12.one = Fp12.one := by
  apply Fp12.toField.injective
  simp only [map_mul, Fp12.toField_one, one_mul]

theorem absent_fold (steps : List (Fin 68)) (v : Factors) (present : Array Bool 2#usize)
    (pair : Fin 2) (hp : present.val[pair.val]'(by simp; omega) = false) :
    steps.foldl (activeStep v present pair) Fp12.one = Fp12.one := by
  induction steps with
  | nil => rfl
  | cons step steps ih =>
    rw [List.foldl_cons]
    have hs : activeStep v present pair Fp12.one step = Fp12.one := by
      simp only [activeStep, pairApply, hp, Bool.false_eq_true, if_false]
      split_ifs <;> simp only [one_square]
    rw [hs, ih]

theorem active_miller (points : Fin 2 → G1) (pair : Fin 2) :
    (List.finRange 68).foldl (activeStep (g1Factors points) (presence points) pair) Fp12.one =
      if (points pair).isInfinity then Fp12.one else homogeneousMiller points pair := by
  cases hp : (points pair).isInfinity
  · have hstep : activeStep (g1Factors points) (presence points) pair = homogeneousStep points pair := by
      funext f step
      simp only [activeStep, pairApply, presence_entry, hp, Bool.not_false, if_true]
      rfl
    simp only [Bool.false_eq_true, if_false, hstep, homogeneousMiller]
  · simp only [if_true]
    exact absent_fold _ _ _ pair (by rw [presence_entry, hp]; rfl)

def combinedMiller (points : Fin 2 → G1) : Fp12 :=
  (List.finRange 68).foldl (combinedStep (g1Factors points) (presence points)) Fp12.one

theorem combined_miller_field (points : Fin 2 → G1) :
    Fp12.toField (combinedMiller points).conjugate =
      Fp12.toField (homogeneousFactor points 0) * Fp12.toField (homogeneousFactor points 1) := by
  have hf := combined_fold_field (List.finRange 68) (g1Factors points) (presence points)
    Fp12.one Fp12.one Fp12.one (by simp only [Fp12.toField_one, one_mul])
  rw [active_miller, active_miller] at hf
  rw [Cyclotomic.spec_conjugate]
  change Fp12.toField ((List.finRange 68).foldl _ Fp12.one) ^ (Fp.modulus ^ 6) = _
  rw [hf, mul_pow]
  unfold homogeneousFactor
  cases h0 : (points 0).isInfinity <;> cases h1 : (points 1).isInfinity <;>
    simp only [Bool.false_eq_true, if_false, if_true, Cyclotomic.spec_conjugate,
      Fp12.toField_one, one_pow]

theorem combined_final_eq (points : Fin 2 → G1) :
    FinalEq (pairingFactor (points 0, setupPoint 0) * pairingFactor (points 1, setupPoint 1))
      (combinedMiller points).conjugate := by
  have h := (factor_final_eq points 0).mul (factor_final_eq points 1)
  change Fp12.toField _ ^ finalExpExponent = _ at h ⊢
  rw [combined_miller_field]
  simpa only [map_mul] using h

end

end LeanBlsSimd.Pairing
