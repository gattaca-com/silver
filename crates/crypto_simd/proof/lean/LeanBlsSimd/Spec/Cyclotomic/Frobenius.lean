import LeanBlsSimd.Spec.Cyclotomic.Cubic
import Mathlib.Algebra.CharP.Lemmas

namespace LeanBlsSimd.Cyclotomic

variable {R : Type*} [CommRing R]

theorem root_power (x xi : R) (n k : ℕ) (hn : n = 6 * k + 1) (hx : x ^ 6 = xi) :
    x ^ n = xi ^ k * x := by rw [hn, pow_succ, pow_mul, hx]

theorem monomial_frobenius (p n : ℕ) [Fact p.Prime] [CharP R p]
    (x xi a : R) (j k : ℕ) (hp : p ^ n = 6 * k + 1) (hx : x ^ 6 = xi) :
    (a * x ^ j) ^ (p ^ n) = a ^ (p ^ n) * xi ^ (j * k) * x ^ j := by
  rw [mul_pow, ← pow_mul, Nat.mul_comm j (p ^ n), pow_mul, root_power x xi _ k hp hx,
    mul_pow, ← pow_mul]
  rw [Nat.mul_comm k j]
  ring

theorem coefficient_frobenius (p n : ℕ) [Fact p.Prime] [CharP R p]
    (x xi : R) (a : Fin 6 → R) (k : ℕ) (hp : p ^ n = 6 * k + 1) (hx : x ^ 6 = xi) :
    (∑ j : Fin 6, a j * x ^ j.val) ^ (p ^ n) =
      ∑ j : Fin 6, a j ^ (p ^ n) * xi ^ (j.val * k) * x ^ j.val := by
  rw [sum_pow_char_pow]
  apply Finset.sum_congr rfl
  intro j _
  exact monomial_frobenius p n x xi (a j) j.val k hp hx

variable {G : Type*} [CommGroup G]

def easyPart (g : G) (p : ℕ) : G := (g ^ (p ^ 6) * g⁻¹) ^ (p ^ 2) * (g ^ (p ^ 6) * g⁻¹)

theorem easyPart_power (g : G) (p : ℕ) (hp : 1 ≤ p) :
    easyPart g p = g ^ ((p ^ 6 - 1) * (p ^ 2 + 1)) := by
  have hp6 : 1 ≤ p ^ 6 := one_le_pow₀ hp
  have h : g ^ (p ^ 6) * g⁻¹ = g ^ (p ^ 6 - 1) := by
    simpa only [pow_one] using (pow_sub g hp6).symm
  rw [easyPart, h, ← pow_succ, ← pow_mul]

theorem phi_factor (p : ℕ) (_hp : 1 ≤ p) :
    (p ^ 2 + 1) * (p ^ 4 - p ^ 2 + 1) = p ^ 6 + 1 := by
  have h24 : p ^ 2 ≤ p ^ 4 := by nlinarith [sq_nonneg (p ^ 2 - 1 : ℤ)]
  zify [h24]
  ring

theorem easyPart_cyclotomic (g : G) (p : ℕ) (hp : 1 ≤ p)
    (hperiod : g ^ (p ^ 12 - 1) = 1) :
    easyPart g p ^ (p ^ 4 - p ^ 2 + 1) = 1 := by
  rw [easyPart_power g p hp, ← pow_mul, Nat.mul_assoc, phi_factor p hp]
  have hp6 : 1 ≤ p ^ 6 := one_le_pow₀ hp
  have hexp : (p ^ 6 - 1) * (p ^ 6 + 1) = p ^ 12 - 1 := by
    have hp12 : 1 ≤ p ^ 12 := one_le_pow₀ hp
    zify [hp6, hp12]
    ring
  rw [hexp, hperiod]

end LeanBlsSimd.Cyclotomic
