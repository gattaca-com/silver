import LeanBlsSimd.Spec.ScottCardinality

/-! Controls for exact generator order and the two premises of the Hasse interval reduction.
Removing either bound admits a multiple of r², so the numerical exclusion would be false. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls

example : addOrderOf (G2.toPoint G2.generator) ≠ Fr.modulus ^ 2 := by
  rw [addOrderOf_generator]
  decide +kernel

example : ¬ (∀ n : ℕ, n ≤ (Fp.modulus + 1) ^ 2 → ¬ Fr.modulus ^ 2 ∣ n) := by
  intro h
  exact h 0 (Nat.zero_le _) (dvd_zero _)

example : ¬ (∀ n : ℕ, (Fp.modulus - 1) ^ 2 ≤ n → ¬ Fr.modulus ^ 2 ∣ n) := by
  intro h
  exact h (Fr.modulus ^ 2 * (Fp.modulus - 1) ^ 2) (by decide +kernel) (dvd_mul_right _ _)

end LeanBlsSimd
