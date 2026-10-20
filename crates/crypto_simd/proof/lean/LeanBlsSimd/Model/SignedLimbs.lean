import LeanBlsSimd.Model.Intrinsics
import Mathlib.Algebra.Order.Ring.Abs
import Mathlib.Algebra.BigOperators.Fin

/-! Signed radix-52 limbs shared by lazy prime-field arithmetic. -/

namespace LeanBlsSimd.SignedLimbs

def limb (x : UInt64) : ℤ := x.toInt64.toInt

def val {n : ℕ} (a : Vector UInt64 n) : ℤ :=
  ∑ j : Fin n, limb a[j] * (2 : ℤ) ^ (52 * j.val)

def Normalized {n : ℕ} (a : Vector UInt64 n) : Prop :=
  ∀ j : Fin n, a[j].toNat < 2 ^ 52

def Bounded {n : ℕ} (a : Vector UInt64 n) (m : ℤ) : Prop :=
  ∀ j : Fin n, |limb a[j]| < m * 2 ^ 52

def addRaw {n : ℕ} (a b : Vector UInt64 n) : Vector UInt64 n :=
  .ofFn fun j => a[j] + b[j]

def subRaw {n : ℕ} (a b offset : Vector UInt64 n) : Vector UInt64 n :=
  .ofFn fun j => a[j] + offset[j] - b[j]

def carryStep {n : ℕ} (a : Vector UInt64 n) (j : Fin (n - 1)) : Vector UInt64 n :=
  let a := a.set (j.val + 1) (a[j.val + 1] + srai 52 a[j.val])
  a.set j.val (a[j.val] &&& UInt64.ofNat (2 ^ 52 - 1))

def normalise {n : ℕ} (a : Vector UInt64 n) : Vector UInt64 n :=
  (List.finRange (n - 1)).foldl carryStep a

end LeanBlsSimd.SignedLimbs
