import LeanBlsSimd.Spec.ScottCardinality
import EthLib.Cryptography.Proofs.Bls.G2SubgroupSpan

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

theorem E'.card_eq_orderCandidate :
    Nat.card E'.Point = CofactorSpan.orderCandidate := by
  rw [← Nat.card_congr G2.pointEquiv.toEquiv]
  exact EthLib.Cryptography.Bls.G2.card_point_eq_candidate

theorem scott_complete : ScottComplete := by
  apply scottComplete_of_card (CofactorSpan.orderCandidate / Fr.modulus)
  · rw [E'.card_eq_orderCandidate]
    decide +kernel
  · decide +kernel

end LeanBlsSimd
