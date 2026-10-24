import Mathlib.RingTheory.AdjoinRoot
import Mathlib.Tactic

namespace LeanBlsSimd.Cyclotomic

open Polynomial

variable {S : Type*} [CommRing S] [Nontrivial S]

noncomputable abbrev cubicPolynomial (u : S) : S[X] := X ^ 3 - C u

abbrev Cubic (u : S) := AdjoinRoot (cubicPolynomial u)

noncomputable def w (u : S) : Cubic u := AdjoinRoot.root _

noncomputable def embed (u : S) : S →+* Cubic u := algebraMap S (Cubic u)

noncomputable def assemble (u a b c : S) : Cubic u :=
  embed u a + embed u b * w u + embed u c * w u ^ 2

omit [Nontrivial S] in
theorem w_cube (u : S) : w u ^ 3 = embed u u := by
  have h := AdjoinRoot.eval₂_root (cubicPolynomial u)
  rw [cubicPolynomial, Polynomial.eval₂_sub, Polynomial.eval₂_pow,
    Polynomial.eval₂_X, Polynomial.eval₂_C] at h
  exact sub_eq_zero.mp h

noncomputable def basis (u : S) : Module.Basis (Fin 3) S (Cubic u) :=
  (AdjoinRoot.powerBasis' (monic_X_pow_sub_C u (by decide : 3 ≠ 0))).basis.reindex
    (finCongr (natDegree_X_pow_sub_C (n := 3) (r := u)))

theorem basis_eq (u : S) (i : Fin 3) : basis u i = w u ^ i.val := by
  unfold basis
  simp only [Module.Basis.reindex_apply, PowerBasis.basis_eq_pow]
  rfl

theorem assemble_eq (u a b c : S) : assemble u a b c = a • basis u 0 + b • basis u 1 + c • basis u 2 := by
  simp [basis_eq, assemble, Algebra.smul_def, embed]

theorem assemble_injective (u a b c d e f : S)
    (h : assemble u a b c = assemble u d e f) : a = d ∧ b = e ∧ c = f := by
  have h0 := congrArg (fun x => (basis u).repr x 0) h
  have h1 := congrArg (fun x => (basis u).repr x 1) h
  have h2 := congrArg (fun x => (basis u).repr x 2) h
  simp only [assemble_eq, map_add, map_smul, Module.Basis.repr_self,
    Finsupp.add_apply, Finsupp.smul_apply, Finsupp.single_apply, smul_eq_mul] at h0 h1 h2
  norm_num [show (2 : Fin 3) ≠ 0 by decide, show (2 : Fin 3) ≠ 1 by decide,
    show (0 : Fin 3) ≠ 2 by decide, show (1 : Fin 3) ≠ 2 by decide] at h0 h1 h2
  exact ⟨h0, h1, h2⟩

theorem assemble_surjective (u : S) (g : Cubic u) :
    ∃ a b c, assemble u a b c = g := by
  refine ⟨(basis u).repr g 0, (basis u).repr g 1, (basis u).repr g 2, ?_⟩
  rw [assemble_eq]
  simpa only [Fin.sum_univ_three] using (basis u).sum_repr g

omit [Nontrivial S] in
theorem assemble_mul (u a b c d e f : S) :
    assemble u a b c * assemble u d e f =
      assemble u (a * d + u * (b * f + c * e))
        (a * e + b * d + u * c * f) (a * f + b * e + c * d) := by
  have h3 := w_cube u
  have h4 : w u ^ 4 = embed u u * w u := by rw [show 4 = 3 + 1 by rfl, pow_succ, h3]
  simp only [assemble, map_add, map_mul]
  ring_nf
  rw [h4, h3]
  ring

omit [Nontrivial S] in
theorem assemble_square (u a b c : S) :
    assemble u a b c ^ 2 =
      assemble u (a ^ 2 + 2 * u * b * c) (2 * a * b + u * c ^ 2) (2 * a * c + b ^ 2) := by
  rw [sq, assemble_mul]
  congr 1 <;> ring

/-- No inverse or cancellation assumption on S occurs in this coefficient calculation. -/
theorem coefficient_constraints (u a b c abar bbar cbar delta : S)
    (hd : delta ^ 2 - delta + 1 = 0)
    (h : assemble u a b c * assemble u a (delta ^ 2 * b) (delta ^ 4 * c) =
      assemble u abar (delta * bbar) (delta ^ 2 * cbar)) :
    a ^ 2 - u * b * c = abar ∧ a * b - u * c ^ 2 = bbar ∧ b ^ 2 - a * c = cbar := by
  rw [assemble_mul] at h
  obtain ⟨ha, hb, hc⟩ := assemble_injective _ _ _ _ _ _ _ h
  constructor
  · linear_combination ha - u * b * c * (delta ^ 2 + delta + 1) * hd
  constructor
  · linear_combination (1 - delta) * hb +
      (a * b * delta + u * c ^ 2 * (delta ^ 3 - delta - 1) - bbar) * hd
  · linear_combination (-delta) * hc +
      (a * c * (delta ^ 3 + delta ^ 2 - 1) + (b ^ 2 - cbar) * (delta + 1)) * hd

theorem granger_scott_of_frobenius_relation (u a b c abar bbar cbar delta : S)
    (hd : delta ^ 2 - delta + 1 = 0)
    (h : assemble u a b c * assemble u a (delta ^ 2 * b) (delta ^ 4 * c) =
      assemble u abar (delta * bbar) (delta ^ 2 * cbar)) :
    assemble u a b c ^ 2 =
      assemble u (3 * a ^ 2 - 2 * abar) (3 * u * c ^ 2 + 2 * bbar) (3 * b ^ 2 - 2 * cbar) := by
  obtain ⟨ha, hb, hc⟩ := coefficient_constraints _ _ _ _ _ _ _ _ hd h
  rw [assemble_square]
  congr 1
  · linear_combination -2 * ha
  · linear_combination 2 * hb
  · linear_combination -2 * hc

theorem cyclotomic_relation {T : Type*} [Monoid T] (g : T) (q : ℕ) (hq : 1 ≤ q)
    (hphi : g ^ (q ^ 2 - q + 1) = 1) : g * g ^ (q ^ 2) = g ^ q := by
  have hle : q ≤ q ^ 2 := by nlinarith
  calc
    g * g ^ (q ^ 2) = g ^ (q ^ 2 + 1) := by exact (pow_succ' g (q ^ 2)).symm
    _ = g ^ ((q ^ 2 - q + 1) + q) := by congr 1; omega
    _ = g ^ (q ^ 2 - q + 1) * g ^ q := pow_add _ _ _
    _ = g ^ q := by rw [hphi, one_mul]

/-- The Fp4 Frobenius formulas are explicit hypotheses; no field structure is used. -/
theorem granger_scott (u a b c abar bbar cbar delta : S) (q : ℕ) (hq : 1 ≤ q)
    (hd : delta ^ 2 - delta + 1 = 0)
    (hf1 : assemble u a b c ^ q = assemble u abar (delta * bbar) (delta ^ 2 * cbar))
    (hf2 : assemble u a b c ^ (q ^ 2) = assemble u a (delta ^ 2 * b) (delta ^ 4 * c))
    (hphi : assemble u a b c ^ (q ^ 2 - q + 1) = 1) :
    assemble u a b c ^ 2 =
      assemble u (3 * a ^ 2 - 2 * abar) (3 * u * c ^ 2 + 2 * bbar) (3 * b ^ 2 - 2 * cbar) := by
  apply granger_scott_of_frobenius_relation _ _ _ _ _ _ _ _ hd
  rw [← hf2, cyclotomic_relation _ _ hq hphi, hf1]

end LeanBlsSimd.Cyclotomic
