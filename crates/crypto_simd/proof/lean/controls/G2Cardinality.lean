import LeanBlsSimd.Spec.G2Cardinality

open LeanBlsSimd

example : ScottComplete := scott_complete

example (P : E'.Point) : psi P = z • P ↔ EthLib.Cryptography.Bls.Fr.modulus • P = 0 :=
  ⟨scott_sound P, scott_complete P⟩

example : Nat.card E'.Point = EthLib.Cryptography.Bls.CofactorSpan.orderCandidate :=
  E'.card_eq_orderCandidate

example : ¬ EthLib.Cryptography.Bls.Fr.modulus ^ 2 ∣ Nat.card E'.Point := by
  rw [E'.card_eq_orderCandidate]
  decide +kernel

/-- info: 'LeanBlsSimd.E'.card_eq_orderCandidate' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms E'.card_eq_orderCandidate

/-- info: 'LeanBlsSimd.scott_complete' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in
#print axioms scott_complete
