import LeanBlsSimd.Constants
import Mathlib.Algebra.Order.Ring.Abs
import Mathlib.Tactic.Ring
import Mathlib.Tactic.NormNum

namespace LeanBlsSimd.Glv

def lambda : ℤ := 228988810152649578064853576960394133503
def zSquared : ℤ := 228988810152649578064853576960394133504
def modulus : ℤ := 52435875175126190479447740508185965837690552500527637822603658699938581184513
def reciprocal : ℤ := 505667019974147811778249931229775261232
def halfModulusUp : ℤ := 26217937587563095239723870254092982918845276250263818911301829349969290592257

theorem zSquared_eq : zSquared = z ^ 2 := by decide +kernel

theorem lambda_eq : lambda = z ^ 2 - 1 := by decide +kernel

theorem modulus_eq : modulus = (EthLib.Cryptography.Bls.Fr.modulus : ℤ) := by
  decide +kernel

theorem modulus_polynomial : modulus = lambda ^ 2 + lambda + 1 := by
  decide +kernel

theorem halfModulusUp_eq : halfModulusUp = (modulus + 1) / 2 := by
  decide +kernel

def c1 (k : ℤ) : ℤ := (k * reciprocal + 2 ^ 255) / 2 ^ 256
def c2 (k : ℤ) : ℤ := if halfModulusUp ≤ k then 1 else 0
def first (k : ℤ) : ℤ := k - c2 k - c1 k * lambda
def second (k : ℤ) : ℤ := c1 k - c2 k * zSquared

theorem decomposition (k : ℤ) : first k + lambda * second k = k - c2 k * modulus := by
  unfold first second lambda zSquared modulus
  ring

theorem congruent (k : ℤ) : (first k + lambda * second k) % modulus = k % modulus := by
  rw [decomposition]
  unfold modulus
  omega

theorem c1_bounded (k : ℤ) (hk0 : 0 ≤ k) (hk : k < 2 ^ 255) :
    0 ≤ c1 k ∧ c1 k < 2 ^ 128 := by
  unfold c1 reciprocal
  norm_num at *
  omega

theorem c2_cases (k : ℤ) : c2 k = 0 ∨ c2 k = 1 := by
  unfold c2
  split_ifs <;> simp

theorem halves_bounded (k : ℤ) (hk0 : 0 ≤ k) (hk : k < 2 ^ 255) :
    |first k| < 2 ^ 127 ∧ |second k| < 2 ^ 127 := by
  simp only [first, second, c1, c2, reciprocal, halfModulusUp, lambda, zSquared]
  split_ifs <;> rw [abs_lt, abs_lt] <;> norm_num at * <;> omega

end LeanBlsSimd.Glv
