import LeanBlsSimd.Spec.CubicHasse

/-! Scott completeness, cube fibers over F₇, the affine count over F₅, and counterexamples to
omitting the character hypotheses. All arithmetic is checked by Lean's kernel. -/

open LeanBlsSimd
instance : Fact (Nat.Prime 5) := ⟨by decide⟩
instance : Fact (Nat.Prime 7) := ⟨by decide⟩

example : ScottComplete := scott_complete

example (P : E'.Point) : psi P = z • P ↔ EthCryptographySpecs.Bls.Fr.modulus • P = 0 :=
  ⟨scott_sound P, scott_complete P⟩

example : Nat.card {x : ZMod 7 // x ^ 3 = 0} ≠ 3 := by
  rw [card_cube_fiber_zero]
  decide

example : Nat.card {x : ZMod 7 // x ^ 3 = 1} = 3 := by
  obtain ⟨ζ, hζ⟩ := exists_isPrimitiveRoot_three (F := ZMod 7) (by decide +kernel)
  exact card_cube_fiber_of_cube hζ (by decide +kernel) ⟨1, by decide +kernel⟩

example : Nat.card {x : ZMod 7 // x ^ 3 = 2} = 0 :=
  card_cube_fiber_of_not_cube (by decide +kernel)

example : (Nat.card {x : ZMod 7 // x ^ 3 = 2} : ℂ) ≠
    1 + (1 : MulChar (ZMod 7) ℂ) 2 + (1 : MulChar (ZMod 7) ℂ)⁻¹ 2 := by
  rw [card_cube_fiber_of_not_cube (by decide +kernel)]
  have hu : IsUnit (2 : ZMod 7) := isUnit_iff_ne_zero.mpr (by decide +kernel)
  simp only [inv_one, MulChar.one_apply hu, Nat.cast_zero]
  norm_num

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
