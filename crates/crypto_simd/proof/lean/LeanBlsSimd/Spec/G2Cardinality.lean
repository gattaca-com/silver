import LeanBlsSimd.Spec.ScottCardinality
import EthLib.Cryptography.Proofs.Bls.G2SubgroupSpan

namespace LeanBlsSimd

open WeierstrassCurve EthLib.Cryptography.Bls
open EthLib.Cryptography.Bls.G2 (curve card_point_eq_candidate)

private def pointEquiv :
    curve.toAffine.Point ≃ E'.Point := by
  have hm : curve.toAffine.map Fp2.toField.toRingHom = E' := rfl
  refine (curve.toAffine.nonsingularPointEquiv.trans
    (Equiv.subtypeEquiv (Fp2.toField.toEquiv.prodCongr Fp2.toField.toEquiv) ?_).optionCongr).trans
      E'.nonsingularPointEquiv.symm
  intro xy
  change curve.toAffine.Nonsingular xy.1 xy.2 ↔
    E'.Nonsingular (Fp2.toField xy.1) (Fp2.toField xy.2)
  rw [← hm]
  exact (Affine.map_nonsingular _ (f := Fp2.toField.toRingHom) Fp2.toField.injective _ _).symm

theorem E'.card_eq_orderCandidate :
    Nat.card E'.Point = CofactorSpan.orderCandidate := by
  rw [← Nat.card_congr pointEquiv]
  exact card_point_eq_candidate

theorem scott_complete : ScottComplete := by
  apply scottComplete_of_card (CofactorSpan.orderCandidate / Fr.modulus)
  · rw [E'.card_eq_orderCandidate]
    decide +kernel
  · decide +kernel

end LeanBlsSimd
