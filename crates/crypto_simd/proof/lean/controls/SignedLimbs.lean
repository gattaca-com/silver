import LeanBlsSimd.Proofs.SignedLimbs

/-! Controls for signed carry propagation and the magnitude growth of raw addition. -/

namespace LeanBlsSimd.SignedLimbs.Controls

set_option linter.unreachableTactic false

def nearRadix : Vector UInt64 5 := #v[UInt64.ofNat (2 ^ 52 - 1), 0, 0, 0, 0]

example : Normalized nearRadix ∧ Bounded nearRadix 1 := by
  unfold Normalized Bounded
  decide +kernel

example : val (addRaw nearRadix nearRadix) = val nearRadix + val nearRadix ∧
    Bounded (addRaw nearRadix nearRadix) 2 :=
  addRaw_spec (m := 1) (k := 1)
    (by unfold Bounded; decide +kernel) (by unfold Bounded; decide +kernel) (by norm_num)

/-- Keeping the input magnitude bound after a raw addition is false. -/
example : ¬ Bounded (addRaw nearRadix nearRadix) 1 := by
  unfold Bounded
  decide +kernel

example : True := by
  fail_if_success
    have : Bounded (addRaw nearRadix nearRadix) 1 :=
      (addRaw_spec (by unfold Bounded; decide +kernel : Bounded nearRadix 1)
        (by unfold Bounded; decide +kernel : Bounded nearRadix 1) (by norm_num)).2
  trivial

def normaliseWith (shift : UInt64 → UInt64) {n : Nat}
    (a : Vector UInt64 n) : Vector UInt64 n :=
  (List.finRange (n - 1)).foldl (init := a) fun a j =>
    let a := a.set (j.val + 1) (a[j.val + 1] + shift a[j.val])
    a.set j.val (a[j.val] &&& UInt64.ofNat (2 ^ 52 - 1))

example : (normaliseWith (srai 52) : Vector UInt64 5 → Vector UInt64 5) = normalise := rfl

/-- The first signed limb is -1; the represented integer is the positive 2^52-1. -/
def negativeLimb : Vector UInt64 5 := #v[UInt64.ofNat (2 ^ 64 - 1), 1, 0, 0, 0]

example : (∀ j : Fin 5, |limb negativeLimb[j]| < (2 : ℤ) ^ 62) ∧
    0 ≤ val negativeLimb ∧ val negativeLimb < 2 ^ 260 := by decide +kernel

example : val (normalise negativeLimb) = val negativeLimb ∧ Normalized (normalise negativeLimb) :=
  normalise_spec (by decide +kernel) (by decide +kernel) (by decide +kernel)

example : normaliseWith (srai 52) negativeLimb = nearRadix := by decide +kernel

/-- A logical carry adds 4095 rather than -1 into limb one, changing the integer. -/
example : val (normaliseWith (srli 52) negativeLimb) ≠ val negativeLimb := by decide +kernel

example : True := by
  fail_if_success
    have : val (normaliseWith (srli 52) negativeLimb) = val negativeLimb := by decide +kernel
  trivial

end LeanBlsSimd.SignedLimbs.Controls
