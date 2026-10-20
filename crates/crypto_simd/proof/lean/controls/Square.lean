import LeanBlsSimd.Proofs.Square

namespace LeanBlsSimd.Lane

-- The doubling step must retain both orders of each off-diagonal product.
def squareWith (double : UInt64 → UInt64) (a : Limbs) : Acc :=
  let t : Acc := .replicate _ zero
  let t := square_row t a 0
  let t := square_row t a 1
  let t := square_row t a 2
  let t := square_row t a 3
  let t := square_row t a 4
  let t := square_row t a 5
  let t := square_row t a 6
  let t := t.map double
  (List.finRange LIMBS).foldl (fun t i => square_diag t a i) t

example : squareWith (fun x => x + x) = squareAcc := rfl

example (a : Limbs) : squareWith (fun x => x + x) a = productAcc a a :=
  squareAcc_eq_productAcc a

private def twoLimbs : Limbs := .ofList [1, 1, 0, 0, 0, 0, 0, 0]

example : (squareWith id twoLimbs)[1] = 1 ∧ (productAcc twoLimbs twoLimbs)[1] = 2 := by
  decide +kernel

example : ¬ (∀ a : Limbs, squareWith id a = productAcc a a) := by
  intro h
  have he := congrArg (fun t : Acc => t[1]) (h twoLimbs)
  have hn : (squareWith id twoLimbs)[1] ≠ (productAcc twoLimbs twoLimbs)[1] := by decide +kernel
  exact hn he

#print axioms squareAcc_eq_productAcc

end LeanBlsSimd.Lane
