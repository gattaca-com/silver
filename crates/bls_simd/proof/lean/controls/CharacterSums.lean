import LeanBlsSimd.Spec.CubicHasse

/-! The affine count on F₅ and a counterexample to omitting nontriviality from the Jacobi norm
identity. All arithmetic in these controls is checked by Lean's kernel. -/

open LeanBlsSimd
instance : Fact (Nat.Prime 5) := ⟨by decide⟩

example : (jacobiSum (1 : MulChar (ZMod 5) ℂ) 1) = 3 := by
  rw [jacobiSum_one_one (F := ZMod 5) (R := ℂ)]
  norm_num

example : ‖jacobiSum (1 : MulChar (ZMod 5) ℂ) 1‖ ^ 2 ≠ (Fintype.card (ZMod 5) : ℝ) := by
  rw [jacobiSum_one_one (F := ZMod 5) (R := ℂ)]
  norm_num

example : Nat.card {xy : ZMod 5 × ZMod 5 // xy.2 ^ 2 = xy.1 ^ 3 + 1} = 5 := by
  have h := card_solution_pairs (F := ZMod 5) (by norm_num [ringChar.eq (ZMod 5) 5]) 1
  have hs : ∑ x : ZMod 5, quadraticChar (ZMod 5) (x ^ 3 + 1) = 0 := by
    decide +kernel
  rw [hs] at h
  norm_num at h ⊢
  exact_mod_cast h
