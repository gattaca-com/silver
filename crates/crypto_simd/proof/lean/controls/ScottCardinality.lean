import LeanBlsSimd.Spec.ScottCardinality

/-! Exact generator order and the premises of the cardinality argument.

In (Z/2Z)², (1, 0) has order two but misses the two-torsion point (0, 1).
The actual cofactor two fails coprimality; the coprime candidate one fails the point count.
Thus generator order alone cannot replace either premise.
These mathematical counterexamples name no production declaration. -/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls

example : addOrderOf (G2.toPoint G2.generator) ≠ Fr.modulus ^ 2 := by
  rw [addOrderOf_generator]
  decide +kernel

example : addOrderOf ((1, 0) : ZMod 2 × ZMod 2) = 2 :=
  addOrderOf_eq_prime (by decide +kernel) (by decide +kernel)

example : Nat.card (ZMod 2 × ZMod 2) = 2 * 2 ∧ ¬ Nat.Coprime 2 2 := by
  constructor
  · simp [Nat.card_eq_fintype_card]
  · decide +kernel

example : Nat.Coprime 1 2 ∧ Nat.card (ZMod 2 × ZMod 2) ≠ 2 * 1 := by
  constructor
  · decide +kernel
  · simp [Nat.card_eq_fintype_card]

example : ¬ (∀ P : ZMod 2 × ZMod 2, 2 • P = 0 →
    ∃ k : ℤ, P = k • ((1, 0) : ZMod 2 × ZMod 2)) := by
  intro h
  obtain ⟨k, hk⟩ := h (0, 1) (by decide +kernel)
  have he := congrArg Prod.snd hk
  simp at he

end LeanBlsSimd
