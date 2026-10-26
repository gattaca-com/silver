import LeanBlsSimd.Pairing.ProjectiveLine
import LeanBlsSimd.Pairing.SetupEmbedding
import LeanBlsSimd.Spec.PairingProduct

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

def jacobianStep (points : Fin 2 → G1) (pair : Fin 2) (f : Fp12) (step : Fin 68) : Fp12 :=
  (if lineKind step then f else f * f) * factorLine step pair (g1Factors points)

def jacobianMiller (points : Fin 2 → G1) (pair : Fin 2) : Fp12 :=
  (List.finRange 68).foldl (jacobianStep points pair) Fp12.one

theorem jacobian_fold_final_eq (steps : List (Fin 68)) (points : Fin 2 → G1) (pair : Fin 2)
    (hp : (points pair).isInfinity = false) (f g : Fp12) (h : FinalEq f g) :
    FinalEq (steps.foldl (jacobianStep points pair) f)
      (steps.foldl (FixedTable.normalizedStep pair (Fp2.ofFp (points pair).toAffine.1)
        (Fp2.ofFp (points pair).toAffine.2)) g) := by
  induction steps generalizing f g with
  | nil => exact h
  | cons step steps ih =>
    simp only [List.foldl_cons]
    apply ih
    apply FinalEq.mul
    · split_ifs
      · exact h
      · exact h.mul h
    · exact g1_line_final_eq step pair points hp

theorem jacobian_miller_final_eq (points : Fin 2 → G1) (pair : Fin 2)
    (hp : (points pair).isInfinity = false) :
    FinalEq (millerLoop blsX (Embedded.ofG2 (setupPoint pair)) (Embedded.ofG1 (points pair)))
      (jacobianMiller points pair) := by
  rw [setup_untwist, ofG1_evaluationPoint _ hp]
  have hs := FixedTable.miller_final_eq pair (Fp2.ofFp (points pair).toAffine.1)
    (Fp2.ofFp (points pair).toAffine.2)
  have hh := jacobian_fold_final_eq (List.finRange 68) points pair hp Fp12.one Fp12.one rfl
  exact hs.trans hh.symm

def jacobianFactor (points : Fin 2 → G1) (pair : Fin 2) : Fp12 :=
  if (points pair).isInfinity then Fp12.one else (jacobianMiller points pair).conjugate

theorem factor_final_eq (points : Fin 2 → G1) (pair : Fin 2) :
    FinalEq (pairingFactor (points pair, setupPoint pair)) (jacobianFactor points pair) := by
  unfold pairingFactor jacobianFactor
  rw [setup_finite]
  simp only [Bool.or_false]
  cases hp : (points pair).isInfinity
  · simp only [Bool.false_eq_true, if_false]
    exact (jacobian_miller_final_eq points pair hp).conjugate
  · simp only [if_true]
    rfl

end

end LeanBlsSimd.Pairing
