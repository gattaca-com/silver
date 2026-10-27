import LeanBlsSimd.Pairing.EmbeddedSteps

open EthLib.Cryptography Bls

namespace LeanBlsSimd.PairingProduct.Step

noncomputable section

abbrev Point := Fin 3 → Fp2Field

structure Output where
  point : Point
  line : Fin 3 → Fp2Field

def double (t : Point) : Output :=
  let x := t 0
  let y := t 1
  let z := t 2
  let a := x * x
  let b := y * y
  let zz := z * z
  let c := b * b
  let d := (x + b) * (x + b) - a - c
  let d := d + d
  let e := a + a + a
  let f := e * e
  let x3 := f - d - d
  let z3 := (y + z) * (y + z) - b - zz
  let c2 := c + c
  let c4 := c2 + c2
  let y3 := e * (d - x3) - (c4 + c4)
  let b2 := b + b
  let l0 := (e + x) * (e + x) - a - f - (b2 + b2)
  let l1 := e * zz
  let l2 := z3 * zz
  ⟨![x3, y3, z3], ![l0, l1, l2]⟩

def add (t : Point) (q : Fp2Field × Fp2Field) : Output :=
  let x := t 0
  let y := t 1
  let z := t 2
  let z1z1 := z * z
  let u2 := q.1 * z1z1
  let s2 := q.2 * z * z1z1
  let h := u2 - x
  let hh := h * h
  let i2 := hh + hh
  let i := i2 + i2
  let j := h * i
  let r := s2 - y
  let r := r + r
  let v := x * i
  let x3 := r * r - j - v - v
  let yj := y * j
  let y3 := (v - x3) * r - yj - yj
  let z3 := (z + h) * (z + h) - z1z1 - hh
  let l0 := r * q.1 - q.2 * z3
  let l0 := l0 + l0
  ⟨![x3, y3, z3], ![l0, r, z3]⟩

def affineField (t : Point) : Fp2Field × Fp2Field :=
  (t 0 / t 2 ^ 2, t 1 / t 2 ^ 3)

def doubleSlope (t : Point) : Fp2Field :=
  3 * (affineField t).1 * (affineField t).1 / (2 * (affineField t).2)

def addSlope (t : Point) (q : Fp2Field × Fp2Field) : Fp2Field :=
  (q.2 - (affineField t).2) / (q.1 - (affineField t).1)

def doubleScale (t : Point) : Fp2Field := 4 * t 1 * t 2 ^ 3

def addScale (t : Point) (q : Fp2Field × Fp2Field) : Fp2Field :=
  4 * t 2 * (q.1 * t 2 ^ 2 - t 0)

def chordField (t q : Fp2Field × Fp2Field) (m : Fp2Field) : Fp2Field × Fp2Field :=
  let x := m * m - t.1 - q.1
  (x, m * (t.1 - x) - t.2)

theorem double_z (t : Point) : (double t).point 2 = 2 * t 1 * t 2 := by
  simp only [double, Matrix.cons_val_two, Matrix.tail_cons, Matrix.head_cons]
  ring

theorem add_z (t : Point) (q : Fp2Field × Fp2Field) :
    (add t q).point 2 = 2 * t 2 * (q.1 * t 2 ^ 2 - t 0) := by
  simp only [add, Matrix.cons_val_two, Matrix.tail_cons, Matrix.head_cons]
  ring

theorem double_clear (t : Point) (h : (double t).point 2 ≠ 0) :
    t 1 ≠ 0 ∧ t 2 ≠ 0 := by
  rw [double_z] at h
  exact ⟨(mul_ne_zero_iff.mp (mul_ne_zero_iff.mp h).1).2, (mul_ne_zero_iff.mp h).2⟩

theorem add_clear (t : Point) (q : Fp2Field × Fp2Field) (h : (add t q).point 2 ≠ 0) :
    t 2 ≠ 0 ∧ q.1 * t 2 ^ 2 - t 0 ≠ 0 := by
  rw [add_z] at h
  exact ⟨(mul_ne_zero_iff.mp (mul_ne_zero_iff.mp h).1).2, (mul_ne_zero_iff.mp h).2⟩

theorem two_ne_zero : (2 : Fp2Field) ≠ 0 := by decide +kernel

theorem four_ne_zero : (4 : Fp2Field) ≠ 0 := by decide +kernel

theorem double_denominator (t : Point) (h : (double t).point 2 ≠ 0) :
    2 * (affineField t).2 ≠ 0 :=
  mul_ne_zero two_ne_zero (div_ne_zero (double_clear t h).1 (pow_ne_zero 3 (double_clear t h).2))

theorem add_denominator (t : Point) (q : Fp2Field × Fp2Field)
    (h : (add t q).point 2 ≠ 0) : q.1 - (affineField t).1 ≠ 0 := by
  obtain ⟨hz, hh⟩ := add_clear t q h
  change q.1 - t 0 / t 2 ^ 2 ≠ 0
  have he : q.1 - t 0 / t 2 ^ 2 = (q.1 * t 2 ^ 2 - t 0) / t 2 ^ 2 := by
    field_simp [hz]
  rw [he]
  exact div_ne_zero hh (pow_ne_zero 2 hz)

theorem doubleScale_ne_zero (t : Point) (h : (double t).point 2 ≠ 0) :
    doubleScale t ≠ 0 :=
  mul_ne_zero (mul_ne_zero four_ne_zero (double_clear t h).1)
    (pow_ne_zero 3 (double_clear t h).2)

theorem addScale_ne_zero (t : Point) (q : Fp2Field × Fp2Field)
    (h : (add t q).point 2 ≠ 0) : addScale t q ≠ 0 :=
  mul_ne_zero (mul_ne_zero four_ne_zero (add_clear t q h).1) (add_clear t q h).2

theorem double_coefficients (t : Point) (h : (double t).point 2 ≠ 0) :
    (double t).line 0 = doubleScale t *
        (doubleSlope t * (affineField t).1 - (affineField t).2) ∧
      (double t).line 1 * (-2) = -(doubleScale t * doubleSlope t) ∧
      (double t).line 2 * 2 = doubleScale t := by
  obtain ⟨hy, hz⟩ := double_clear t h
  simp only [double, doubleScale, doubleSlope, affineField, Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val_two, Matrix.tail_cons, Matrix.head_cons]
  constructor
  · field_simp [hy, hz, two_ne_zero]
    ring
  constructor
  · field_simp [hy, hz, two_ne_zero]
    ring
  · ring

theorem add_coefficients (t : Point) (q : Fp2Field × Fp2Field)
    (h : (add t q).point 2 ≠ 0) :
    (add t q).line 0 = addScale t q *
        (addSlope t q * (affineField t).1 - (affineField t).2) ∧
      (add t q).line 1 * (-2) = -(addScale t q * addSlope t q) ∧
      (add t q).line 2 * 2 = addScale t q := by
  obtain ⟨hz, hh⟩ := add_clear t q h
  have hd := add_denominator t q h
  simp only [affineField] at hd
  simp only [add, addScale, addSlope, affineField, Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val_two, Matrix.tail_cons, Matrix.head_cons]
  constructor
  · field_simp [hz, hh, hd]
    field_simp [hz, hh, mul_comm]
    ring
  constructor
  · field_simp [hz, hh, hd]
    field_simp [hz, hh, mul_comm]
    ring
  · ring

theorem double_point (t : Point) (h : (double t).point 2 ≠ 0) :
    affineField (double t).point =
      chordField (affineField t) (affineField t) (doubleSlope t) := by
  obtain ⟨hy, hz⟩ := double_clear t h
  apply Prod.ext <;>
    simp only [affineField, chordField, doubleSlope] <;>
    rw [double_z] <;>
    simp only [double, Matrix.cons_val_zero, Matrix.cons_val_one] <;>
    field_simp [hy, hz, two_ne_zero] <;> ring

theorem add_point (t : Point) (q : Fp2Field × Fp2Field)
    (h : (add t q).point 2 ≠ 0) :
    affineField (add t q).point = chordField (affineField t) q (addSlope t q) := by
  obtain ⟨hz, hh⟩ := add_clear t q h
  have hd := add_denominator t q h
  simp only [affineField] at hd
  apply Prod.ext <;>
    simp only [affineField, chordField, addSlope] <;>
    rw [add_z] <;>
    simp only [add, Matrix.cons_val_zero, Matrix.cons_val_one] <;>
    field_simp [hz, hh, hd, two_ne_zero] <;>
    field_simp [hz, hh, two_ne_zero, mul_comm] <;> ring

end

end LeanBlsSimd.PairingProduct.Step
