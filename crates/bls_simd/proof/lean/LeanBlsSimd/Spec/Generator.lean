import LeanBlsSimd.Spec.Membership

/-!
# ψ(G) = [z]G for the spec's generator

`ScottComplete` claims ψ(P) = [z]P for every point P with [r]P = O. A wrong ψ constant or the
opposite sign of z would make that claim false, and every theorem that assumes it vacuous.
`psi_generator` proves the claim for the spec's generator G, and `generator_torsion` shows that
[r]G = O, so G is one of the points the claim covers.

The proof runs `Kernel.scottMembership` on G in Lean's kernel (`decide +kernel`), then applies
`scottMembership_spec`. Mathlib's `dblXYZ` evaluates a polynomial, which Lean's kernel cannot do
in practice, so `timesMinusZ_eq_formula` first restates the chain with dbl-2009-l spelled out
(`dblFormula`).
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls WeierstrassCurve Jacobian

namespace Kernel

/-- Mathlib's `dblXYZ` on E′, as dbl-2009-l. -/
def dblFormula (t : Fin 3 → Fp2Field) : Fin 3 → Fp2Field :=
  let x' := 9 * t 0 ^ 4 - 8 * t 0 * t 1 ^ 2
  ![x', 3 * t 0 ^ 2 * (4 * t 0 * t 1 ^ 2 - x') - 8 * t 1 ^ 4, 2 * t 1 * t 2]

theorem dblXYZ_eq_dblFormula (t : Fin 3 → Fp2Field) : G2.curve.dblXYZ t = dblFormula t := by
  funext i
  fin_cases i <;>
    simp only [dblFormula, dblXYZ, dblX, dblY, dblZ, negDblY, dblU_eq, negY, E'.a₁_eq,
      E'.a₂_eq, E'.a₃_eq, E'.a₄_eq, Fin.zero_eta, Fin.mk_one, Fin.reduceFinMk,
      Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons,
      Matrix.tail_cons] <;>
    ring1

/-- One iteration of `timesMinusZ`'s loop, with `dblFormula` for `dblXYZ`. -/
def chainStepFormula (px py : Fp2Field) (s : (Fin 3 → Fp2Field) × Bool) (bit : ℕ) :
    (Fin 3 → Fp2Field) × Bool :=
  let s := (dblFormula s.1, s.2 || (decide (s.1 1 = 0) || decide (s.1 2 = 0)))
  if Z_BITS.contains bit then ((addAffine s.1 px py).1, s.2 || (addAffine s.1 px py).2) else s

theorem timesMinusZ_eq_formula (px py : Fp2Field) :
    timesMinusZ px py =
      (List.range Z_BITS[0]!).reverse.foldl (chainStepFormula px py) (![px, py, 1], false) := by
  have h : chainStep px py = chainStepFormula px py := by
    funext s bit
    rw [chainStep, chainStepFormula, double, dblXYZ_eq_dblFormula]
  rw [timesMinusZ, h]

end Kernel

open Kernel

theorem nonsingular_generator :
    E'.Nonsingular (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) :=
  (Affine.equation_iff_nonsingular_of_Δ_ne_zero E'.Δ_ne_zero).mp E'.equation_generator

theorem toPoint_generator : G2.toPoint G2.generator = .some _ _ nonsingular_generator :=
  G2.toPoint_mk_one (x := G2.generator.x) (y := G2.generator.y) nonsingular_generator

theorem scottMembership_generator :
    scottMembership (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) = (true, false) := by
  unfold scottMembership
  rw [timesMinusZ_eq_formula]
  decide +kernel

theorem psi_generator : psi (G2.toPoint G2.generator) = z • G2.toPoint G2.generator := by
  have h := scottMembership_spec nonsingular_generator (by rw [scottMembership_generator])
  rw [scottMembership_generator] at h
  rw [toPoint_generator]
  exact of_decide_eq_true h.symm

theorem generator_torsion : Fr.modulus • G2.toPoint G2.generator = 0 :=
  scott_sound _ psi_generator

/-- `ScottComplete` without ψ or z in its premise: it holds if every point of order r on E′ is a
multiple of G. -/
theorem scottComplete_of_cyclic
    (h : ∀ P : E'.Point, Fr.modulus • P = 0 → ∃ k : ℤ, P = k • G2.toPoint G2.generator) :
    ScottComplete := by
  intro P hP
  obtain ⟨k, rfl⟩ := h P hP
  rw [map_zsmul, psi_generator, smul_comm]

end LeanBlsSimd
