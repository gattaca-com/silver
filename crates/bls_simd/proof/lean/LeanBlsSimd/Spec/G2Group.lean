import LeanBlsSimd.Spec.Scott
import EthCryptographySpecs.Bls.Compress
import Mathlib.AlgebraicGeometry.EllipticCurve.Jacobian.Point
import Mathlib.Tactic.Module

/-!
# The spec's G2 group law on E′

`G2.toPoint` maps a spec triple to Mathlib's point of E′, through `Jacobian.Point.toAffine`.
The map is total: it sends a triple off the curve to 0. So the theorems assume `G2.Valid`, that
the triple is a nonsingular Jacobian point.

The spec's dbl-2009-l doubling is Mathlib's `dblXYZ` as polynomials. Its add-2007-bl sum,
`addBL` over the field, is Mathlib's `addXYZ` scaled by −2·Z₁·Z₂, given both curve equations.
That factor is a unit, so the two triples name the same point. `toAffine_dblXYZ` and
`toAffine_addBL` state both formulas on field triples, for any code that computes them.
-/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls WeierstrassCurve Jacobian

namespace G2

theorem mulNat_def (P : G2) (k : ℕ) :
    G2.mulNat P k = if k = 0 then G2.zero
      else if k % 2 = 1 then G2.add P (G2.mulNat (G2.double P) (k / 2))
      else G2.mulNat (G2.double P) (k / 2) := by
  rw [G2.mulNat]

abbrev curve : Jacobian Fp2Field := E'.toJacobian

def rep (P : G2) : Fin 3 → Fp2Field := ![Fp2.toField P.x, Fp2.toField P.y, Fp2.toField P.z]

@[simp] theorem rep_x (P : G2) : rep P 0 = Fp2.toField P.x := rfl
@[simp] theorem rep_y (P : G2) : rep P 1 = Fp2.toField P.y := rfl
@[simp] theorem rep_z (P : G2) : rep P 2 = Fp2.toField P.z := rfl

def Valid (P : G2) : Prop := curve.Nonsingular (rep P)

noncomputable def toPoint (P : G2) : E'.Point := Point.toAffine curve (rep P)

private theorem toField_two : Fp2.toField (Fp2.ofFp (Fp.ofNat 2)) = 2 := by decide +kernel
private theorem toField_three : Fp2.toField (Fp2.ofFp (Fp.ofNat 3)) = 3 := by decide +kernel
private theorem toField_eight : Fp2.toField (Fp2.ofFp (Fp.ofNat 8)) = 8 := by decide +kernel

private theorem z_ne_zero {P : G2} (hz : ¬P.z.isZero = true) : rep P 2 ≠ 0 :=
  fun h => hz ((Fp2.isZero_iff P.z).mpr h)

/-! ## Zero and negation -/

theorem rep_zero : rep G2.zero = ![1, 1, 0] := by
  funext i
  fin_cases i <;> rfl

theorem valid_zero : Valid G2.zero := by
  rw [Valid, rep_zero]
  exact nonsingular_zero

theorem toPoint_zero : toPoint G2.zero = 0 := by
  rw [toPoint, rep_zero]
  exact Point.toAffine_zero

theorem rep_neg (P : G2) : rep (G2.neg P) = curve.neg (rep P) := by
  funext i
  fin_cases i
  · rfl
  · show Fp2.toField (-P.y) = curve.negY (rep P)
    simp only [negY, Fin.isValue, rep_x, rep_y, rep_z, E'.a₁_eq, E'.a₃_eq, zero_mul, sub_zero,
      Fp2.toField_neg]
  · rfl

theorem valid_neg {P : G2} (h : Valid P) : Valid (G2.neg P) := by
  rw [Valid, rep_neg]
  exact nonsingular_neg h

theorem toPoint_neg {P : G2} (h : Valid P) : toPoint (G2.neg P) = -toPoint P := by
  rw [toPoint, rep_neg]
  exact Point.toAffine_neg h

/-! ## Doubling -/

theorem rep_double {P : G2} (hz : ¬P.z.isZero = true) :
    rep (G2.double P) = curve.dblXYZ (rep P) := by
  rw [G2.double, if_neg hz]
  funext i
  fin_cases i <;>
  · simp only [rep, dblXYZ, dblX, dblY, dblZ, negDblY, dblU_eq, negY_eq, Fin.zero_eta,
      Fin.mk_one, Fin.reduceFinMk, Fin.isValue, Matrix.cons_val_zero, Matrix.cons_val_one,
      Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, map_mul, map_add,
      Fp2.toField_sub, toField_two, toField_three, toField_eight, E'.a₁_eq, E'.a₂_eq, E'.a₃_eq,
      E'.a₄_eq]
    ring

theorem valid_double {P : G2} (h : Valid P) : Valid (G2.double P) := by
  by_cases hz : P.z.isZero = true
  · rw [G2.double, if_pos hz]
    exact h
  · rw [Valid, rep_double hz, ← add_of_equiv (Setoid.refl (rep P))]
    exact nonsingular_add h h

theorem toPoint_double {P : G2} (h : Valid P) :
    toPoint (G2.double P) = toPoint P + toPoint P := by
  by_cases hz : P.z.isZero = true
  · have h0 : toPoint P = 0 :=
      Point.toAffine_of_Z_eq_zero ((Fp2.isZero_iff P.z).mp hz)
    rw [G2.double, if_pos hz, h0, add_zero]
  · rw [toPoint, rep_double hz, ← add_of_equiv (Setoid.refl (rep P))]
    exact Point.toAffine_add h h

/-! ## Addition -/

theorem valid_equation {P : G2} (h : Valid P) :
    Fp2.toField P.y ^ 2 = Fp2.toField P.x ^ 3 + bTwist * Fp2.toField P.z ^ 6 := by
  have heq := ((nonsingular_iff (rep P)).mp h).1
  rw [equation_iff] at heq
  simp only [E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq, E'.a₆_eq, rep_x, rep_y, rep_z] at heq
  linear_combination heq

private theorem add_of_left_zero {P Q : G2} (hz1 : P.z.isZero = true) : G2.add P Q = Q := by
  rw [G2.add]
  exact if_pos hz1

private theorem add_of_right_zero {P Q : G2} (hz1 : ¬P.z.isZero = true)
    (hz2 : Q.z.isZero = true) : G2.add P Q = P := by
  rw [G2.add, if_neg hz1]
  exact if_pos hz2

private theorem add_of_dbl {P Q : G2} (hz1 : ¬P.z.isZero = true) (hz2 : ¬Q.z.isZero = true)
    (hu : (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true)
    (hs : (P.y * Q.z * (Q.z * Q.z)).beq (Q.y * P.z * (P.z * P.z)) = true) :
    G2.add P Q = G2.double P := by
  rw [G2.add, if_neg hz1, if_neg hz2]
  exact (if_pos hu).trans (if_pos hs)

private theorem add_of_opp {P Q : G2} (hz1 : ¬P.z.isZero = true) (hz2 : ¬Q.z.isZero = true)
    (hu : (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true)
    (hs : ¬(P.y * Q.z * (Q.z * Q.z)).beq (Q.y * P.z * (P.z * P.z)) = true) :
    G2.add P Q = G2.zero := by
  rw [G2.add, if_neg hz1, if_neg hz2]
  exact (if_pos hu).trans (if_neg hs)

/-- add-2007-bl over the field: the spec's `G2.add` where Z₁ ≠ 0, Z₂ ≠ 0 and U₁ ≠ U₂. -/
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

theorem equation_iff (P : Fin 3 → Fp2Field) :
    curve.Equation P ↔ P 1 ^ 2 = P 0 ^ 3 + bTwist * P 2 ^ 6 := by
  rw [Jacobian.equation_iff]
  simp only [E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq, E'.a₆_eq]
  constructor <;> intro h <;> linear_combination h

theorem addBL_eq_smul {P Q : Fin 3 → Fp2Field} (hP : curve.Equation P) (hQ : curve.Equation Q) :
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
  (neg_ne_zero.mpr (mul_ne_zero (by decide +kernel) (mul_ne_zero hPz hQz))).isUnit

theorem nonsingular_addBL {P Q : Fin 3 → Fp2Field} (hP : curve.Nonsingular P)
    (hQ : curve.Nonsingular Q) (hPz : P 2 ≠ 0) (hQz : Q 2 ≠ 0)
    (hx : P 0 * Q 2 ^ 2 ≠ Q 0 * P 2 ^ 2) : curve.Nonsingular (addBL P Q) := by
  rw [addBL_eq_smul hP.1 hQ.1, nonsingular_smul _ (isUnit_scale' hPz hQz),
    ← add_of_not_equiv fun heq => hx (X_eq_of_equiv heq)]
  exact nonsingular_add hP hQ

theorem toAffine_addBL {P Q : Fin 3 → Fp2Field} (hP : curve.Nonsingular P)
    (hQ : curve.Nonsingular Q) (hPz : P 2 ≠ 0) (hQz : Q 2 ≠ 0)
    (hx : P 0 * Q 2 ^ 2 ≠ Q 0 * P 2 ^ 2) :
    Point.toAffine curve (addBL P Q) = Point.toAffine curve P + Point.toAffine curve Q := by
  rw [addBL_eq_smul hP.1 hQ.1, Point.toAffine_of_equiv (smul_equiv _ (isUnit_scale' hPz hQz)),
    ← add_of_not_equiv fun heq => hx (X_eq_of_equiv heq)]
  exact Point.toAffine_add hP hQ

theorem nonsingular_dblXYZ {P : Fin 3 → Fp2Field} (hP : curve.Nonsingular P) :
    curve.Nonsingular (curve.dblXYZ P) := by
  rw [← add_of_equiv (Setoid.refl P)]
  exact nonsingular_add hP hP

theorem toAffine_dblXYZ {P : Fin 3 → Fp2Field} (hP : curve.Nonsingular P) :
    Point.toAffine curve (curve.dblXYZ P) = Point.toAffine curve P + Point.toAffine curve P := by
  rw [← add_of_equiv (Setoid.refl P)]
  exact Point.toAffine_add hP hP

private theorem rep_add_general {P Q : G2} (hz1 : ¬P.z.isZero = true) (hz2 : ¬Q.z.isZero = true)
    (hu : ¬(P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true) :
    rep (G2.add P Q) = addBL (rep P) (rep Q) := by
  rw [G2.add, if_neg hz1, if_neg hz2]
  dsimp only
  rw [if_neg hu]
  funext i
  fin_cases i <;>
    simp only [rep, addBL, Fin.zero_eta, Fin.mk_one, Fin.reduceFinMk, Fin.isValue,
      Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons,
      Matrix.tail_cons, map_mul, map_add, Fp2.toField_sub, toField_two]

private theorem beq_x_iff {P Q : G2} :
    (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true ↔
      rep P 0 * (rep Q 2 * rep Q 2) = rep Q 0 * (rep P 2 * rep P 2) := by
  rw [Fp2.beq_iff, map_mul, map_mul, map_mul, map_mul]
  rfl

private theorem beq_y_iff {P Q : G2} :
    (P.y * Q.z * (Q.z * Q.z)).beq (Q.y * P.z * (P.z * P.z)) = true ↔
      rep P 1 * rep Q 2 * (rep Q 2 * rep Q 2) = rep Q 1 * rep P 2 * (rep P 2 * rep P 2) := by
  rw [Fp2.beq_iff, map_mul, map_mul, map_mul, map_mul, map_mul, map_mul]
  rfl

theorem valid_add {P Q : G2} (hP : Valid P) (hQ : Valid Q) : Valid (G2.add P Q) := by
  by_cases hz1 : P.z.isZero = true
  · rwa [Valid, add_of_left_zero hz1]
  by_cases hz2 : Q.z.isZero = true
  · rwa [Valid, add_of_right_zero hz1 hz2]
  by_cases hu : (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true
  · by_cases hs : (P.y * Q.z * (Q.z * Q.z)).beq (Q.y * P.z * (P.z * P.z)) = true
    · rw [add_of_dbl hz1 hz2 hu hs]
      exact valid_double hP
    · rw [add_of_opp hz1 hz2 hu hs]
      exact valid_zero
  · rw [Valid, rep_add_general hz1 hz2 hu]
    exact nonsingular_addBL hP hQ (z_ne_zero hz1) (z_ne_zero hz2) fun h =>
      hu (beq_x_iff.mpr (by linear_combination h))

theorem toPoint_add {P Q : G2} (hP : Valid P) (hQ : Valid Q) :
    toPoint (G2.add P Q) = toPoint P + toPoint Q := by
  by_cases hz1 : P.z.isZero = true
  · rw [add_of_left_zero hz1,
      show toPoint P = 0 from Point.toAffine_of_Z_eq_zero ((Fp2.isZero_iff P.z).mp hz1), zero_add]
  by_cases hz2 : Q.z.isZero = true
  · rw [add_of_right_zero hz1 hz2,
      show toPoint Q = 0 from Point.toAffine_of_Z_eq_zero ((Fp2.isZero_iff Q.z).mp hz2), add_zero]
  by_cases hu : (P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true
  · have hx : rep P 0 * rep Q 2 ^ 2 = rep Q 0 * rep P 2 ^ 2 := by
      linear_combination beq_x_iff.mp hu
    by_cases hs : (P.y * Q.z * (Q.z * Q.z)).beq (Q.y * P.z * (P.z * P.z)) = true
    · have hy : rep P 1 * rep Q 2 ^ 3 = rep Q 1 * rep P 2 ^ 3 := by
        linear_combination beq_y_iff.mp hs
      have hequiv : rep P ≈ rep Q :=
        equiv_of_X_eq_of_Y_eq (z_ne_zero hz1) (z_ne_zero hz2) hx hy
      rw [add_of_dbl hz1 hz2 hu hs, toPoint_double hP,
        show toPoint P = toPoint Q from Point.toAffine_of_equiv hequiv]
    · have hy : rep P 1 * rep Q 2 ^ 3 ≠ rep Q 1 * rep P 2 ^ 3 := fun heq =>
        hs (beq_y_iff.mpr (by linear_combination heq))
      have hyneg := Y_eq_of_Y_ne ((nonsingular_iff (rep P)).mp hP).1
        ((nonsingular_iff (rep Q)).mp hQ).1 hx hy
      have hequiv : rep P ≈ curve.neg (rep Q) := by
        refine equiv_of_X_eq_of_Y_eq (z_ne_zero hz1) (z_ne_zero hz2) ?_ ?_
        · rw [neg_X]
          exact hx
        · rw [neg_Y]
          exact hyneg
      rw [add_of_opp hz1 hz2 hu hs, toPoint_zero,
        show toPoint P = -toPoint Q from
          (Point.toAffine_of_equiv hequiv).trans (Point.toAffine_neg hQ),
        neg_add_cancel]
  · rw [toPoint, rep_add_general hz1 hz2 hu]
    exact toAffine_addBL hP hQ (z_ne_zero hz1) (z_ne_zero hz2) fun h =>
      hu (beq_x_iff.mpr (by linear_combination h))

/-! ## Scalar multiplication -/

theorem valid_mulNat {P : G2} (h : Valid P) (k : ℕ) : Valid (G2.mulNat P k) := by
  induction k using Nat.strongRecOn generalizing P with
  | _ k ih =>
    rw [mulNat_def]
    split
    · exact valid_zero
    · split
      · exact valid_add h (ih (k / 2) (by omega) (valid_double h))
      · exact ih (k / 2) (by omega) (valid_double h)

theorem toPoint_mulNat {P : G2} (h : Valid P) (k : ℕ) :
    toPoint (G2.mulNat P k) = k • toPoint P := by
  induction k using Nat.strongRecOn generalizing P with
  | _ k ih =>
    rw [mulNat_def]
    split
    · rename_i hk
      subst hk
      rw [toPoint_zero, zero_nsmul]
    · split
      · obtain ⟨m, rfl⟩ : ∃ m, k = 2 * m + 1 := ⟨k / 2, by omega⟩
        have hm : (2 * m + 1) / 2 = m := by omega
        rw [toPoint_add h (valid_mulNat (valid_double h) _), hm,
          ih m (by omega) (valid_double h), toPoint_double h]
        module
      · obtain ⟨m, rfl⟩ : ∃ m, k = 2 * m := ⟨k / 2, by omega⟩
        have hm : 2 * m / 2 = m := by omega
        rw [hm, ih m (by omega) (valid_double h), toPoint_double h]
        module

/-! ## The spec's subgroup test -/

theorem toPoint_eq_zero_iff {P : G2} (h : Valid P) : toPoint P = 0 ↔ P.z.isZero = true := by
  rw [Fp2.isZero_iff]
  refine ⟨fun h0 => ?_, fun hz => Point.toAffine_of_Z_eq_zero (P := rep P) hz⟩
  by_contra hz
  rw [toPoint, Point.toAffine_of_Z_ne_zero h hz] at h0
  exact Affine.Point.some_ne_zero _ h0

theorem inSubgroup_iff {P : G2} (h : Valid P) :
    G2.inSubgroup P = true ↔ Fr.modulus • toPoint P = 0 := by
  rw [G2.inSubgroup, G2.isInfinity, G2.isInfinity]
  by_cases hz : P.z.isZero = true
  · rw [if_pos hz, (toPoint_eq_zero_iff h).mpr hz, nsmul_zero]
    exact iff_of_true rfl rfl
  · rw [if_neg hz, ← toPoint_mulNat h, toPoint_eq_zero_iff (valid_mulNat h _)]

theorem inSubgroup_of_psi {P : G2} (h : Valid P) (hψ : psi (toPoint P) = z • toPoint P) :
    G2.inSubgroup P = true :=
  (inSubgroup_iff h).mpr (scott_sound _ hψ)

/-! ## Points with Z = 1, as `G2.uncompress` builds them -/

theorem valid_mk_one {x y : Fp2} (h : E'.Nonsingular (Fp2.toField x) (Fp2.toField y)) :
    Valid ⟨x, y, Fp2.one⟩ :=
  (nonsingular_some _ _).mpr h

theorem toPoint_mk_one {x y : Fp2} (h : E'.Nonsingular (Fp2.toField x) (Fp2.toField y)) :
    toPoint ⟨x, y, Fp2.one⟩ = .some _ _ h :=
  Point.toAffine_some (valid_mk_one h)

theorem inSubgroup_mk_one_of_psi {x y : Fp2}
    (h : E'.Nonsingular (Fp2.toField x) (Fp2.toField y))
    (hψ : psi (.some _ _ h) = z • .some _ _ h) : G2.inSubgroup ⟨x, y, Fp2.one⟩ = true := by
  rw [← toPoint_mk_one h] at hψ
  exact inSubgroup_of_psi (valid_mk_one h) hψ

end G2

end LeanBlsSimd
