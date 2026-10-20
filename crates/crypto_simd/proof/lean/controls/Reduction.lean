import LeanBlsSimd.Proofs.Reduction

namespace LeanBlsSimd

private def rowInput (n : Nat) : Reduction.Acc n := (Vector.replicate (2 * n + 1) (0 : UInt64)).set 0 1

private def negOne (n : Nat) [NeZero n] : Vector UInt64 n :=
  (Vector.replicate n (0 : UInt64)).set 0 (.ofNat (2 ^ 52 - 1)) (Nat.pos_of_ne_zero (NeZero.ne n))

-- The dead limb differs even when the inverse premise holds, for both field widths.
example : (Reduction.earlyRow (rowInput 8) (negOne 8) 1 0)[0] = 1 ∧
    (Reduction.referenceRow (rowInput 8) (negOne 8) 1 0)[0] = 2 ^ 52 := by
  decide +kernel

example : (Reduction.earlyRow (rowInput 5) (negOne 5) 1 0)[0] = 1 ∧
    (Reduction.referenceRow (rowInput 5) (negOne 5) 1 0)[0] = 2 ^ 52 := by
  decide +kernel

example : (Reduction.earlyRow (rowInput 8) (negOne 8) 1 0)[1] =
    (Reduction.referenceRow (rowInput 8) (negOne 8) 1 0)[1] :=
  Reduction.earlyRow_agrees _ _ _ _ (by decide) 1 (by decide) (by decide)

-- Without the inverse premise, even a surviving limb may differ.
example : (Reduction.earlyRow (rowInput 8) (.replicate 8 0) 0 0)[1] = 1 ∧
    (Reduction.referenceRow (rowInput 8) (.replicate 8 0) 0 0)[1] = 0 := by
  decide +kernel

example : (Reduction.earlyRow (rowInput 5) (.replicate 5 0) 0 0)[1] = 1 ∧
    (Reduction.referenceRow (rowInput 5) (.replicate 5 0) 0 0)[1] = 0 := by
  decide +kernel

#print axioms Reduction.finish_rows_eq

end LeanBlsSimd
