import LeanBlsSimd.Spec.G2Group

/-! Negative controls for `LeanBlsSimd.Spec.G2Group`. Each `fail_if_success` wraps a claim that
must fail; each plain `example` must pass.

`doubleBad`, `addBad` and `mulNatBad` are copies of the spec's `G2.double`, `G2.add` and
`G2.mulNat`, each with one mutation. The library's proof, run against a mutant, must fail; a plain
example shows that the mutant is wrong on the spec's generator G. The mutated proofs close with
`ring1`, `linear_combination (norm := ring1)` or `module`, which all throw on failure. A failing
`ring` would instead fall back to `ring_nf` and leave its goal open. -/

namespace LeanBlsSimd

open EthCryptographySpecs.Bls WeierstrassCurve Jacobian

-- A mutated proof stops at its first failing step, so the linters flag the steps and simp
-- arguments after it.
set_option linter.unreachableTactic false
set_option linter.unusedSimpArgs false

/-- The weighted equation Y² = X³ + b′Z⁶ of E′, which `G2.valid_equation` derives from
`G2.Valid`. -/
abbrev OnE' (P : G2) : Prop :=
  Fp2.toField P.y ^ 2 = Fp2.toField P.x ^ 3 + bTwist * Fp2.toField P.z ^ 6

/-! ## Doubling with 4·C in place of 8·C in Y′ -/

def doubleBad (p : G2) : G2 :=
  if p.z.isZero then p else
    let two := Fp2.ofFp (Fp.ofNat 2)
    let three := Fp2.ofFp (Fp.ofNat 3)
    let four := Fp2.ofFp (Fp.ofNat 4)
    let A := p.x * p.x
    let B := p.y * p.y
    let C := B * B
    let D := two * ((p.x + B) * (p.x + B) - A - C)
    let E := three * A
    let F := E * E
    let x' := F - two * D
    let y' := E * (D - x') - four * C
    let z' := two * p.y * p.z
    ⟨x', y', z'⟩

example : True := by
  fail_if_success
    have : ∀ P : G2, ¬P.z.isZero = true →
        G2.rep (doubleBad P) = G2.curve.dblXYZ (G2.rep P) := by
      intro P hz
      have h2 : Fp2.toField (Fp2.ofFp (Fp.ofNat 2)) = 2 := by decide +kernel
      have h3 : Fp2.toField (Fp2.ofFp (Fp.ofNat 3)) = 3 := by decide +kernel
      have h4 : Fp2.toField (Fp2.ofFp (Fp.ofNat 4)) = 4 := by decide +kernel
      rw [doubleBad, if_neg hz]
      funext i
      fin_cases i <;>
      · simp only [G2.rep, dblXYZ, dblX, dblY, dblZ, negDblY, dblU_eq, negY_eq, Fin.zero_eta,
          Fin.mk_one, Fin.reduceFinMk, Fin.isValue, Matrix.cons_val_zero, Matrix.cons_val_one,
          Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, map_mul, map_add,
          Fp2.toField_sub, h2, h3, h4, E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq]
        ring1
  trivial

example : ¬G2.Valid (doubleBad G2.generator) := fun h =>
  absurd (G2.valid_equation h) (by decide +kernel)

example : OnE' (G2.double G2.generator) := by
  decide +kernel

/-! ## Addition with s₁·J in place of 2·s₁·J in Y′ -/

def addBad (p q : G2) : G2 :=
  if p.z.isZero then q else
  if q.z.isZero then p else
    let two := Fp2.ofFp (Fp.ofNat 2)
    let z1z1 := p.z * p.z
    let z2z2 := q.z * q.z
    let u1   := p.x * z2z2
    let u2   := q.x * z1z1
    let s1   := p.y * q.z * z2z2
    let s2   := q.y * p.z * z1z1
    if u1.beq u2 then
      if s1.beq s2 then G2.double p else G2.zero
    else
      let h := u2 - u1
      let i := (two * h) * (two * h)
      let j := h * i
      let r := two * (s2 - s1)
      let v := u1 * i
      let x' := r * r - j - two * v
      let y' := r * (v - x') - s1 * j
      let z' := ((p.z + q.z) * (p.z + q.z) - z1z1 - z2z2) * h
      ⟨x', y', z'⟩

example : True := by
  fail_if_success
    have : ∀ P Q : G2, G2.Valid P → G2.Valid Q → ¬P.z.isZero = true → ¬Q.z.isZero = true →
        ¬(P.x * (Q.z * Q.z)).beq (Q.x * (P.z * P.z)) = true →
        G2.rep (addBad P Q) =
          (-(2 * (G2.rep P 2 * G2.rep Q 2))) • G2.curve.addXYZ (G2.rep P) (G2.rep Q) := by
      intro P Q hP hQ hz1 hz2 hu
      have h2 : Fp2.toField (Fp2.ofFp (Fp.ofNat 2)) = 2 := by decide +kernel
      have hP' := G2.valid_equation hP
      have hQ' := G2.valid_equation hQ
      rw [addBad, if_neg hz1, if_neg hz2]
      dsimp only
      rw [if_neg hu, smul_fin3]
      funext i
      fin_cases i <;>
        simp only [G2.rep, addXYZ, addX, addY, negAddY, addZ, negY_eq, Fin.zero_eta, Fin.mk_one,
          Fin.reduceFinMk, Fin.isValue, Matrix.cons_val_zero, Matrix.cons_val_one,
          Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, map_mul, map_add,
          Fp2.toField_sub, h2, E'.a₁_eq, E'.a₂_eq, E'.a₃_eq, E'.a₄_eq, E'.a₆_eq]
      · linear_combination (norm := ring1)
          (4 * Fp2.toField Q.z ^ 6) * hP' + (4 * Fp2.toField P.z ^ 6) * hQ'
      · linear_combination (norm := ring1)
          (8 * Fp2.toField Q.z ^ 6 *
              (Fp2.toField P.y * Fp2.toField Q.z ^ 3 - Fp2.toField Q.y * Fp2.toField P.z ^ 3)) *
              hP' +
            (8 * Fp2.toField P.z ^ 6 *
              (Fp2.toField P.y * Fp2.toField Q.z ^ 3 - Fp2.toField Q.y * Fp2.toField P.z ^ 3)) * hQ'
      · ring1
  trivial

example : ¬G2.Valid (addBad G2.generator (G2.double G2.generator)) := fun h =>
  absurd (G2.valid_equation h) (by decide +kernel)

example : OnE' (G2.add G2.generator (G2.double G2.generator)) := by
  decide +kernel

/-! ## Scalar multiplication that halves k without doubling P

`mulNatBad P k` is [popcount k]P. Run against it, the proof of `G2.toPoint_mulNat` fails at its
`module` step. -/

def mulNatBad (p : G2) (k : ℕ) : G2 :=
  if k = 0 then G2.zero
  else
    let half := mulNatBad p (k / 2)
    if k % 2 = 1 then G2.add p half else half
termination_by k
decreasing_by omega

theorem mulNatBad_def (P : G2) (k : ℕ) :
    mulNatBad P k = if k = 0 then G2.zero
      else if k % 2 = 1 then G2.add P (mulNatBad P (k / 2)) else mulNatBad P (k / 2) := by
  rw [mulNatBad]

theorem valid_mulNatBad {P : G2} (h : G2.Valid P) (k : ℕ) : G2.Valid (mulNatBad P k) := by
  induction k using Nat.strongRecOn with
  | _ k ih =>
    rw [mulNatBad_def]
    split
    · exact G2.valid_zero
    · split
      · exact G2.valid_add h (ih (k / 2) (by omega))
      · exact ih (k / 2) (by omega)

example : True := by
  fail_if_success
    have : ∀ P : G2, G2.Valid P → ∀ k : ℕ, G2.toPoint (mulNatBad P k) = k • G2.toPoint P := by
      intro P h k
      induction k using Nat.strongRecOn with
      | _ k ih =>
        rw [mulNatBad_def]
        split
        · rename_i hk
          subst hk
          rw [G2.toPoint_zero, zero_nsmul]
        · split
          · obtain ⟨m, rfl⟩ : ∃ m, k = 2 * m + 1 := ⟨k / 2, by omega⟩
            have hm : (2 * m + 1) / 2 = m := by omega
            rw [G2.toPoint_add h (valid_mulNatBad h _), hm, ih m (by omega)]
            module
          · obtain ⟨m, rfl⟩ : ∃ m, k = 2 * m := ⟨k / 2, by omega⟩
            have hm : 2 * m / 2 = m := by omega
            rw [hm, ih m (by omega)]
            module
  trivial

theorem nonsingular_generator :
    E'.Nonsingular (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) :=
  (E'.nonsingular_iff _ _).mpr ((E'.equation_iff _ _).mp E'.equation_generator)

example : G2.toPoint (mulNatBad G2.generator 2) ≠ 2 • G2.toPoint G2.generator := by
  have h1 : mulNatBad G2.generator 1 = G2.generator := by
    rw [mulNatBad_def, if_neg one_ne_zero, if_pos rfl, mulNatBad_def, if_pos rfl]
    rfl
  have h2 : mulNatBad G2.generator 2 = G2.generator := by
    rw [mulNatBad_def, if_neg two_ne_zero, if_neg (by decide), h1]
  have hG : G2.toPoint G2.generator ≠ 0 := by
    rw [show G2.generator = ⟨G2.generator.x, G2.generator.y, Fp2.one⟩ from rfl,
      G2.toPoint_mk_one nonsingular_generator]
    exact Affine.Point.some_ne_zero _
  rw [h2, two_nsmul]
  intro h
  exact hG (by simpa using h)

/-! ## `G2.Valid` cannot be dropped

(0, 0, 1) is off E′, so `toPoint` sends it to 0, and both premises below hold. Its double has
Z = 2·Y·Z = 0, so [r]P comes out as P itself, and the spec's test rejects it. -/

def offCurve : G2 := ⟨Fp2.zero, Fp2.zero, Fp2.one⟩

theorem toPoint_offCurve : G2.toPoint offCurve = 0 := by
  refine Point.toAffine_of_singular fun h => ?_
  have h' := (E'.nonsingular_iff _ _).mp ((nonsingular_some _ _).mp h)
  revert h'
  decide +kernel

theorem mulNat_of_isZero (k : ℕ) {Q : G2} (hQ : Q.z.isZero = true) :
    (G2.mulNat Q k).z.isZero = true := by
  induction k using Nat.strongRecOn generalizing Q with
  | _ k ih =>
    rw [G2.mulNat_def]
    have hd : G2.double Q = Q := by rw [G2.double, if_pos hQ]
    split
    · rfl
    · rw [hd]
      split
      · rw [G2.add, if_pos hQ]
        exact ih (k / 2) (by omega) hQ
      · exact ih (k / 2) (by omega) hQ

theorem inSubgroup_offCurve : G2.inSubgroup offCurve = false := by
  have hd : (G2.double offCurve).z.isZero = true := by decide +kernel
  have hr : Fr.modulus ≠ 0 := by decide +kernel
  have hodd : Fr.modulus % 2 = 1 := by decide +kernel
  have hz : ¬offCurve.z.isZero = true := by decide +kernel
  have hm : G2.mulNat offCurve Fr.modulus = offCurve := by
    rw [G2.mulNat_def, if_neg hr, if_pos hodd, G2.add, if_neg hz,
      if_pos (mulNat_of_isZero _ hd)]
  rw [G2.inSubgroup, G2.isInfinity, if_neg hz, G2.isInfinity, hm]
  decide +kernel

example : ¬∀ P : G2, Fr.modulus • G2.toPoint P = 0 → G2.inSubgroup P = true := fun h => by
  have := h offCurve (by rw [toPoint_offCurve, nsmul_zero])
  rw [inSubgroup_offCurve] at this
  exact Bool.false_ne_true this

example : ¬∀ P : G2, psi (G2.toPoint P) = z • G2.toPoint P → G2.inSubgroup P = true := fun h => by
  have := h offCurve (by rw [toPoint_offCurve, map_zero, zsmul_zero])
  rw [inSubgroup_offCurve] at this
  exact Bool.false_ne_true this

/-! ## `G2.add` with its P = Q and P = −Q outcomes swapped

The mutant returns O at G + G, but 2G ≠ O, since y(G) ≠ −y(G). -/

section
open WeierstrassCurve Jacobian

/-- `G2.add` with the P = Q and P = −Q outcomes swapped. -/
def addSwapped (p q : G2) : G2 :=
  if p.z.isZero then q else
  if q.z.isZero then p else
    let two := Fp2.ofFp (Fp.ofNat 2)
    let z1z1 := p.z * p.z
    let z2z2 := q.z * q.z
    let u1   := p.x * z2z2
    let u2   := q.x * z1z1
    let s1   := p.y * q.z * z2z2
    let s2   := q.y * p.z * z1z1
    if u1.beq u2 then
      if s1.beq s2 then G2.zero else G2.double p
    else
      let h := u2 - u1
      let i := (two * h) * (two * h)
      let j := h * i
      let r := two * (s2 - s1)
      let v := u1 * i
      let x' := r * r - j - two * v
      let y' := r * (v - x') - two * s1 * j
      let z' := ((p.z + q.z) * (p.z + q.z) - z1z1 - z2z2) * h
      ⟨x', y', z'⟩

example : G2.toPoint (addSwapped G2.generator G2.generator) ≠
    G2.toPoint G2.generator + G2.toPoint G2.generator := by
  have hGG : addSwapped G2.generator G2.generator = G2.zero := by
    rw [addSwapped]
    simp only [show G2.generator.z.isZero = false by decide +kernel]
    simp only [show ((G2.generator.x * (G2.generator.z * G2.generator.z)).beq
      (G2.generator.x * (G2.generator.z * G2.generator.z))) = true by decide +kernel,
      show ((G2.generator.y * G2.generator.z * (G2.generator.z * G2.generator.z)).beq
      (G2.generator.y * G2.generator.z * (G2.generator.z * G2.generator.z))) = true by decide +kernel]
    rfl
  rw [hGG, G2.toPoint_zero,
    show G2.generator = ⟨G2.generator.x, G2.generator.y, Fp2.one⟩ from rfl,
    G2.toPoint_mk_one nonsingular_generator]
  have hy : Fp2.toField G2.generator.y ≠ E'.negY (Fp2.toField G2.generator.x) (Fp2.toField G2.generator.y) := by
    rw [E'.negY_eq]
    decide +kernel
  rw [Affine.Point.add_self_of_Y_ne hy]
  exact (Affine.Point.some_ne_zero _).symm

end

end LeanBlsSimd
