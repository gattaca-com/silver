import LeanBlsSimd.Spec.G2Group

/-!
# The kernel's membership test over the field

`Kernel` restates one lane of `g2x8.rs` over `Fp2Field`, as `Spec/Sqrt.lean` does for the root.
A lane mask is a `Bool`. `double` is dbl-2009-l, which is Mathlib's `dblXYZ`; `addAffine` is
madd-2007-bl, which is `addBL` with Z₂ = 1.

On a lane whose undecided bit stays clear, every step of the chain keeps Z ≠ 0, so each triple
represents the multiple of P that the chain has reached (`timesMinusZ_spec`). The chain ends at
[|z|]P, and the final comparison holds exactly when ψ(P) = [z]P (`scottMembership_spec`).
-/

namespace LeanBlsSimd

open EthLib.Cryptography.Bls WeierstrassCurve Jacobian

namespace Kernel

abbrev curve : Jacobian Fp2Field := E'.toJacobian

private theorem two_ne_zero' : (2 : Fp2Field) ≠ 0 := by decide +kernel

/-- add-2007-bl over `Fp2Field`. On nonsingular inputs with nonzero Z and distinct affine x,
it represents their sum. -/
def addBL (P Q : Fin 3 → Fp2Field) : Fin 3 → Fp2Field :=
  let z1z1 := P 2 * P 2
  let z2z2 := Q 2 * Q 2
  let u1 := P 0 * z2z2
  let u2 := Q 0 * z1z1
  let s1 := P 1 * Q 2 * z2z2
  let s2 := Q 1 * P 2 * z1z1
  let h := u2 - u1
  let i := 2 * h * (2 * h)
  let j := h * i
  let r := 2 * (s2 - s1)
  let v := u1 * i
  let x' := r * r - j - 2 * v
  ![x', r * (v - x') - 2 * s1 * j, ((P 2 + Q 2) * (P 2 + Q 2) - z1z1 - z2z2) * h]

private theorem equation_iff (P : Fin 3 → Fp2Field) :
    curve.Equation P ↔ P 1 ^ 2 = P 0 ^ 3 + bTwist * P 2 ^ 6 := by
  rw [Jacobian.equation_iff]
  simp only [E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq, E'.a₆_eq]
  constructor <;> intro h <;> linear_combination h

private theorem addBL_eq_smul {P Q : Fin 3 → Fp2Field}
    (hP : curve.Equation P) (hQ : curve.Equation Q) :
    addBL P Q = (-(2 * (P 2 * Q 2))) • curve.addXYZ P Q := by
  have hP' := (equation_iff P).mp hP
  have hQ' := (equation_iff Q).mp hQ
  rw [smul_fin3]
  funext i
  fin_cases i <;>
    simp only [addBL, addXYZ, addX, addY, negAddY, addZ, negY_eq, Fin.zero_eta, Fin.mk_one,
      Fin.reduceFinMk, Fin.isValue, Matrix.cons_val_zero, Matrix.cons_val_one,
      Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, E'.a₁_eq, E'.a₂_eq, E'.a₃_eq,
      E'.a₄_eq, E'.a₆_eq]
  · linear_combination (4 * Q 2 ^ 6) * hP' + (4 * P 2 ^ 6) * hQ'
  · linear_combination
      (8 * Q 2 ^ 6 * (P 1 * Q 2 ^ 3 - Q 1 * P 2 ^ 3)) * hP' +
        (8 * P 2 ^ 6 * (P 1 * Q 2 ^ 3 - Q 1 * P 2 ^ 3)) * hQ'
  · ring

private theorem isUnit_scale' {P Q : Fin 3 → Fp2Field} (hPz : P 2 ≠ 0) (hQz : Q 2 ≠ 0) :
    IsUnit (-(2 * (P 2 * Q 2))) :=
  (neg_ne_zero.mpr (mul_ne_zero two_ne_zero' (mul_ne_zero hPz hQz))).isUnit

private theorem nonsingular_addBL {P Q : Fin 3 → Fp2Field} (hP : curve.Nonsingular P)
    (hQ : curve.Nonsingular Q) (hPz : P 2 ≠ 0) (hQz : Q 2 ≠ 0)
    (hx : P 0 * Q 2 ^ 2 ≠ Q 0 * P 2 ^ 2) : curve.Nonsingular (addBL P Q) := by
  rw [addBL_eq_smul hP.1 hQ.1, nonsingular_smul _ (isUnit_scale' hPz hQz),
    ← add_of_not_equiv fun heq => hx (X_eq_of_equiv heq)]
  exact nonsingular_add hP hQ

private theorem toAffine_addBL {P Q : Fin 3 → Fp2Field} (hP : curve.Nonsingular P)
    (hQ : curve.Nonsingular Q) (hPz : P 2 ≠ 0) (hQz : Q 2 ≠ 0)
    (hx : P 0 * Q 2 ^ 2 ≠ Q 0 * P 2 ^ 2) :
    Point.toAffine curve (addBL P Q) =
      Point.toAffine curve P + Point.toAffine curve Q := by
  rw [addBL_eq_smul hP.1 hQ.1, Point.toAffine_of_equiv (smul_equiv _ (isUnit_scale' hPz hQz)),
    ← add_of_not_equiv fun heq => hx (X_eq_of_equiv heq)]
  exact Point.toAffine_add hP hQ

/-- `G2x8::double`: dbl-2009-l, and the undecided bit, set when y = 0 or z = 0. -/
noncomputable def double (P : Fin 3 → Fp2Field) : (Fin 3 → Fp2Field) × Bool :=
  (curve.dblXYZ P, decide (P 1 = 0) || decide (P 2 = 0))

/-- `G2x8::add_affine`: madd-2007-bl, and the undecided bit, set when H = 0 or z = 0. -/
def addAffine (P : Fin 3 → Fp2Field) (qx qy : Fp2Field) : (Fin 3 → Fp2Field) × Bool :=
  (addBL P ![qx, qy, 1], decide (qx * P 2 ^ 2 - P 0 = 0) || decide (P 2 = 0))

/-- One iteration of the loop of `G2x8::times_minus_z`. -/
noncomputable def chainStep (px py : Fp2Field) (s : (Fin 3 → Fp2Field) × Bool) (bit : ℕ) :
    (Fin 3 → Fp2Field) × Bool :=
  let s := ((double s.1).1, s.2 || (double s.1).2)
  if Z_BITS.contains bit then ((addAffine s.1 px py).1, s.2 || (addAffine s.1 px py).2) else s

/-- `G2x8::times_minus_z`: the triple the chain ends at, and whether the lane is undecided. -/
noncomputable def timesMinusZ (px py : Fp2Field) : (Fin 3 → Fp2Field) × Bool :=
  (List.range Z_BITS[0]!).reverse.foldl (chainStep px py) (![px, py, 1], false)

/-- `G2x8::scott_membership`: whether the lane passes, and whether it is undecided. -/
noncomputable def scottMembership (px py : Fp2Field) : Bool × Bool :=
  let mzp := (timesMinusZ px py).1
  let undecided := (timesMinusZ px py).2 || decide (mzp 2 = 0)
  let psiX' : Fp2Field := ⟨psiX * px.im, psiX * px.re⟩
  let psiY' : Fp2Field := star py * ⟨psiY.1, psiY.2⟩
  let xMatches := decide (mzp 0 = psiX' * mzp 2 ^ 2)
  let yMatches := decide (-mzp 1 = psiY' * (mzp 2 ^ 2 * mzp 2))
  (xMatches && yMatches && !undecided, undecided)

/-! ## The chain -/

variable {px py : Fp2Field}

/-- `t` is a nonsingular triple with Z ≠ 0 that represents `[k]P`. -/
structure Represents (P : E'.Point) (k : ℕ) (t : Fin 3 → Fp2Field) : Prop where
  nonsingular : curve.Nonsingular t
  z_ne_zero : t 2 ≠ 0
  toAffine_eq : Point.toAffine curve t = k • P

theorem represents_one (h : E'.Nonsingular px py) : Represents (.some px py h) 1 ![px, py, 1] := by
  have hq : curve.Nonsingular ![px, py, 1] := (nonsingular_some px py).mpr h
  refine ⟨hq, one_ne_zero, ?_⟩
  rw [Point.toAffine_some hq, one_nsmul]

theorem double_spec {P : E'.Point} {k : ℕ} {t : Fin 3 → Fp2Field} (ht : Represents P k t)
    (hu : (double t).2 = false) : Represents P (2 * k) (double t).1 := by
  simp only [double, Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu
  have hd : curve.Nonsingular (curve.dblXYZ t) := by
    rw [← add_of_equiv (Setoid.refl t)]
    exact nonsingular_add ht.nonsingular ht.nonsingular
  refine ⟨hd, ?_, ?_⟩
  · show curve.dblZ t ≠ 0
    rw [dblZ, negY, E'.a₁_eq, E'.a₃_eq, zero_mul, zero_mul, zero_mul, sub_zero, sub_zero,
      sub_neg_eq_add, ← two_mul]
    exact mul_ne_zero ht.z_ne_zero (mul_ne_zero two_ne_zero' hu.1)
  · show Point.toAffine curve (curve.dblXYZ t) = _
    rw [← add_of_equiv (Setoid.refl t), Point.toAffine_add ht.nonsingular ht.nonsingular,
      ht.toAffine_eq, two_mul, add_nsmul]

theorem addAffine_spec (h : E'.Nonsingular px py) {k : ℕ} {t : Fin 3 → Fp2Field}
    (ht : Represents (.some px py h) k t) (hu : (addAffine t px py).2 = false) :
    Represents (.some px py h) (k + 1) (addAffine t px py).1 := by
  simp only [addAffine, Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu
  have hq : curve.Nonsingular ![px, py, 1] := (nonsingular_some px py).mpr h
  have hx : t 0 * (![px, py, 1] : Fin 3 → Fp2Field) 2 ^ 2 ≠
      (![px, py, 1] : Fin 3 → Fp2Field) 0 * t 2 ^ 2 := by
    intro hx
    apply hu.1
    simp only [Matrix.cons_val_zero, Matrix.cons_val_two, Matrix.tail_cons, Matrix.head_cons,
      one_pow, mul_one] at hx
    rw [hx, sub_self]
  refine ⟨nonsingular_addBL ht.nonsingular hq ht.z_ne_zero one_ne_zero hx, ?_, ?_⟩
  · show addBL t ![px, py, 1] 2 ≠ 0
    have hz : addBL t ![px, py, 1] 2 = 2 * t 2 * (px * t 2 ^ 2 - t 0) := by
      simp only [addBL, Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two,
        Matrix.tail_cons, Matrix.head_cons]
      ring
    rw [hz]
    exact mul_ne_zero (mul_ne_zero two_ne_zero' ht.z_ne_zero) hu.1
  · show Point.toAffine curve (addBL t ![px, py, 1]) = _
    rw [toAffine_addBL ht.nonsingular hq ht.z_ne_zero one_ne_zero hx, ht.toAffine_eq,
      Point.toAffine_some hq, succ_nsmul]

/-- One step of the chain, as `chainSteps` lists them. -/
noncomputable def stepOf (px py : Fp2Field) (s : (Fin 3 → Fp2Field) × Bool) :
    Step → (Fin 3 → Fp2Field) × Bool
  | .double => ((double s.1).1, s.2 || (double s.1).2)
  | .add => ((addAffine s.1 px py).1, s.2 || (addAffine s.1 px py).2)

theorem timesMinusZ_eq (px py : Fp2Field) :
    timesMinusZ px py = chainSteps.foldl (stepOf px py) (![px, py, 1], false) := by
  rw [timesMinusZ, chainSteps, List.foldl_flatMap]
  congr 1
  funext s bit
  unfold chainStep
  by_cases hb : bit ∈ Z_BITS
  · rw [ite_eq_left (List.contains_iff_mem.mpr hb), ite_eq_left hb]
    rfl
  · rw [ite_eq_right (fun h => hb (List.contains_iff_mem.mp h)), ite_eq_right hb]
    rfl

theorem foldl_stepOf_spec (h : E'.Nonsingular px py) :
    ∀ (steps : List Step) (s : (Fin 3 → Fp2Field) × Bool) (k : ℕ),
      (steps.foldl (stepOf px py) s).2 = false → s.2 = false ∧
        (Represents (.some px py h) k s.1 →
          Represents (.some px py h) (Step.run steps k) (steps.foldl (stepOf px py) s).1)
  | [], s, k, hu => ⟨hu, fun hr => hr⟩
  | .double :: steps, s, k, hu => by
    rw [List.foldl_cons] at hu ⊢
    obtain ⟨h1, h2⟩ := foldl_stepOf_spec h steps _ (2 * k) hu
    simp only [stepOf, Bool.or_eq_false_iff] at h1
    exact ⟨h1.1, fun hr => h2 (double_spec hr h1.2)⟩
  | .add :: steps, s, k, hu => by
    rw [List.foldl_cons] at hu ⊢
    obtain ⟨h1, h2⟩ := foldl_stepOf_spec h steps _ (k + 1) hu
    simp only [stepOf, Bool.or_eq_false_iff] at h1
    exact ⟨h1.1, fun hr => h2 (addAffine_spec h hr h1.2)⟩

/-- On a lane that stays decided, `times_minus_z` ends at a nonsingular triple
with Z ≠ 0 that represents [|z|]P. -/
theorem timesMinusZ_spec (h : E'.Nonsingular px py) (hu : (timesMinusZ px py).2 = false) :
    Represents (.some px py h) blsX (timesMinusZ px py).1 := by
  rw [timesMinusZ_eq] at hu ⊢
  have := (foldl_stepOf_spec h chainSteps _ 1 hu).2 (represents_one h)
  rwa [chain_eq_blsX] at this

/-! ## The comparison -/

theorem psiX_mk_eq (v : Fp2Field) : (⟨psiX * v.im, psiX * v.re⟩ : Fp2Field) = cx * star v := by
  ext <;> simp [cx]

theorem psiY_mk_eq (v : Fp2Field) : star v * ⟨psiY.1, psiY.2⟩ = cy * star v := by
  rw [mul_comm]
  congr 1

/-- On a lane that stays decided, the kernel's comparison passes exactly when
ψ(P) = [z]P. -/
theorem scottMembership_spec (h : E'.Nonsingular px py) (hu : (scottMembership px py).2 = false) :
    (scottMembership px py).1 = decide (psi (.some px py h) = z • .some px py h) := by
  simp only [scottMembership, Bool.or_eq_false_iff, decide_eq_false_iff_not] at hu ⊢
  obtain ⟨hc, hz⟩ := hu
  have hr := timesMinusZ_spec h hc
  rw [hc, decide_eq_false hz, Bool.false_or, Bool.not_false, Bool.and_true, ← Bool.decide_and,
    psiX_mk_eq, psiY_mk_eq]
  refine decide_eq_decide.mpr ?_
  generalize (timesMinusZ px py).1 = t at hr hz
  have hpsi : psi (.some px py h) = .some (cx * star px) (cy * star py) (nonsingular_psi h) := rfl
  rw [hpsi, z, neg_smul, natCast_zsmul, ← hr.toAffine_eq,
    Point.toAffine_of_Z_ne_zero hr.nonsingular hr.z_ne_zero, Affine.Point.neg_some,
    Affine.Point.some.injEq, E'.negY_eq, eq_div_iff (pow_ne_zero 2 hz), ← neg_div,
    eq_div_iff (pow_ne_zero 3 hz), pow_succ (t 2) 2]
  constructor
  · rintro ⟨h1, h2⟩
    exact ⟨h1.symm, h2.symm⟩
  · rintro ⟨h1, h2⟩
    exact ⟨h1.symm, h2.symm⟩

end Kernel

end LeanBlsSimd
