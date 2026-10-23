import LeanBlsSimd.Kzg.PortableFp
import LeanBlsSimd.Kzg.G1Arithmetic

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls
open silver_crypto_simd
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Kzg.PortableG1

def toRaw (p : portable.g1.G1) : blst.blst_p1 := ⟨⟨p.x⟩, ⟨p.y⟩, ⟨p.z⟩⟩
def read (p : portable.g1.G1) : G1 := g1ReadJacobian (toRaw p)
def Rep (p : portable.g1.G1) (P : G1) : Prop := G1Rep (toRaw p) P

structure Coords (p : portable.g1.G1) (P : G1) : Prop where
  x : PortableFpRep p.x P.x
  y : PortableFpRep p.y P.y
  z : PortableFpRep p.z P.z

theorem Coords.read_eq {p : portable.g1.G1} {P : G1} (h : Coords p P) : read p = P := by
  cases P
  simp only [read, toRaw, g1ReadJacobian, h.x.2, h.y.2, h.z.2]

theorem Coords.rep {p : portable.g1.G1} {P : G1} (h : Coords p P) : Rep p P := by
  exact ⟨⟨h.x.1, h.y.1, h.z.1⟩, congrArg G1.isInfinity h.read_eq,
    congrArg G1.toAffine h.read_eq⟩

theorem Rep.coords {p : portable.g1.G1} {P : G1} (h : Rep p P) : Coords p (read p) :=
  ⟨⟨h.1.1, rfl⟩, ⟨h.1.2.1, rfl⟩, ⟨h.1.2.2, rfl⟩⟩

theorem infinity_coords : Coords portable.g1.G1.INFINITY G1.zero := by
  simpa only [portable.g1.G1.INFINITY, G1.zero] using
    (Coords.mk portableFpRep_one portableFpRep_one portableFpRep_zero :
      Coords ⟨portable.constants.ONE, portable.constants.ONE, portable.fp.Fp.ZERO⟩ G1.zero)

theorem from_blst_refines (raw : blst.blst_p1) (P : G1) (hr : G1Rep raw P) :
    ∃ p, portable.g1.G1.from_blst raw = ok p ∧ Rep p P := by
  exact ⟨⟨raw.x.l, raw.y.l, raw.z.l⟩, rfl, hr⟩

theorem to_blst_eq (p : portable.g1.G1) : portable.g1.G1.to_blst p = ok (toRaw p) := rfl

theorem neg_coords [RuntimeFeatures] (hfp : PortableFpCorrect)
    {p : portable.g1.G1} {P : G1} (hp : Coords p P) :
    ∃ out, portable.g1.G1.neg p = ok out ∧ Coords out (G1.neg P) := by
  obtain ⟨y, hy, hyr⟩ := hfp.neg hp.y
  exact ⟨{p with y := y}, by simp [portable.g1.G1.neg, hy], ⟨hp.x, hyr, hp.z⟩⟩

structure TermValues where
  z1z1 : Fp
  z2z2 : Fp
  u1 : Fp
  s1 : Fp
  h : Fp
  r : Fp

structure TermsRep (t : portable.g1.Terms) (T : TermValues) : Prop where
  z1z1 : PortableFpRep t.z1z1 T.z1z1
  z2z2 : PortableFpRep t.z2z2 T.z2z2
  u1 : PortableFpRep t.u1 T.u1
  s1 : PortableFpRep t.s1 T.s1
  h : PortableFpRep t.h T.h
  r : PortableFpRep t.r T.r

def termsValues (P Q : G1) : TermValues :=
  let z1z1 := P.z * P.z
  let z2z2 := Q.z * Q.z
  let u1 := P.x * z2z2
  let f := P.y * Q.z
  let s1 := f * z2z2
  let f1 := Q.x * z1z1
  let h := f1 - u1
  let f2 := Q.y * P.z
  let f3 := f2 * z1z1
  let f4 := f3 - s1
  let r := f4 + f4
  ⟨z1z1, z2z2, u1, s1, h, r⟩

theorem termsValues_refines [RuntimeFeatures] (hfp : PortableFpCorrect)
    {p q : portable.g1.G1} {P Q : G1} (hp : Coords p P) (hq : Coords q Q) :
    ∃ out, portable.g1.Terms.new p q = ok out ∧ TermsRep out (termsValues P Q) := by
  obtain ⟨z1z1, e_z1z1, h_z1z1⟩ := hfp.square hp.z
  obtain ⟨z2z2, e_z2z2, h_z2z2⟩ := hfp.square hq.z
  obtain ⟨u1, e_u1, h_u1⟩ := hfp.mul hp.x h_z2z2
  obtain ⟨f, e_f, h_f⟩ := hfp.mul hp.y hq.z
  obtain ⟨s1, e_s1, h_s1⟩ := hfp.mul h_f h_z2z2
  obtain ⟨f1, e_f1, h_f1⟩ := hfp.mul hq.x h_z1z1
  obtain ⟨h, e_h, h_h⟩ := hfp.sub h_f1 h_u1
  obtain ⟨f2, e_f2, h_f2⟩ := hfp.mul hq.y hp.z
  obtain ⟨f3, e_f3, h_f3⟩ := hfp.mul h_f2 h_z1z1
  obtain ⟨f4, e_f4, h_f4⟩ := hfp.sub h_f3 h_s1
  obtain ⟨r, e_r, h_r⟩ := hfp.double h_f4
  refine ⟨⟨z1z1, z2z2, u1, s1, h, r⟩, ?_, ⟨h_z1z1, h_z2z2, h_u1, h_s1, h_h, h_r⟩⟩
  simp only [portable.g1.Terms.new, e_z1z1, e_z2z2, e_u1, e_f, e_s1, e_f1, e_h, e_f2, e_f3, e_f4, e_r, bind_tc_ok]

def doubleValues (P : G1) : G1 :=
  let a := P.x * P.x
  let b := P.y * P.y
  let c := b * b
  let f := P.x + b
  let f1 := f * f
  let f2 := f1 - a
  let f3 := f2 - c
  let d := f3 + f3
  let f4 := a + a
  let e := f4 + a
  let f5 := e * e
  let f6 := d + d
  let x3 := f5 - f6
  let f7 := d - x3
  let f8 := e * f7
  let f9 := c + c
  let f10 := f9 + f9
  let f11 := f10 + f10
  let y3 := f8 - f11
  let f12 := P.y * P.z
  let z3 := f12 + f12
  ⟨x3, y3, z3⟩

theorem doubleValues_refines [RuntimeFeatures] (hfp : PortableFpCorrect)
    {p : portable.g1.G1} {P : G1} (hp : Coords p P) :
    ∃ out, portable.g1.G1.double p = ok out ∧ Coords out (doubleValues P) := by
  obtain ⟨a, e_a, h_a⟩ := hfp.square hp.x
  obtain ⟨b, e_b, h_b⟩ := hfp.square hp.y
  obtain ⟨c, e_c, h_c⟩ := hfp.square h_b
  obtain ⟨f, e_f, h_f⟩ := hfp.add hp.x h_b
  obtain ⟨f1, e_f1, h_f1⟩ := hfp.square h_f
  obtain ⟨f2, e_f2, h_f2⟩ := hfp.sub h_f1 h_a
  obtain ⟨f3, e_f3, h_f3⟩ := hfp.sub h_f2 h_c
  obtain ⟨d, e_d, h_d⟩ := hfp.double h_f3
  obtain ⟨f4, e_f4, h_f4⟩ := hfp.double h_a
  obtain ⟨e, e_e, h_e⟩ := hfp.add h_f4 h_a
  obtain ⟨f5, e_f5, h_f5⟩ := hfp.square h_e
  obtain ⟨f6, e_f6, h_f6⟩ := hfp.double h_d
  obtain ⟨x3, e_x3, h_x3⟩ := hfp.sub h_f5 h_f6
  obtain ⟨f7, e_f7, h_f7⟩ := hfp.sub h_d h_x3
  obtain ⟨f8, e_f8, h_f8⟩ := hfp.mul h_e h_f7
  obtain ⟨f9, e_f9, h_f9⟩ := hfp.double h_c
  obtain ⟨f10, e_f10, h_f10⟩ := hfp.double h_f9
  obtain ⟨f11, e_f11, h_f11⟩ := hfp.double h_f10
  obtain ⟨y3, e_y3, h_y3⟩ := hfp.sub h_f8 h_f11
  obtain ⟨f12, e_f12, h_f12⟩ := hfp.mul hp.y hp.z
  obtain ⟨z3, e_z3, h_z3⟩ := hfp.double h_f12
  refine ⟨⟨x3, y3, z3⟩, ?_, ⟨h_x3, h_y3, h_z3⟩⟩
  simp only [portable.g1.G1.double, e_a, e_b, e_c, e_f, e_f1, e_f2, e_f3, e_d, e_f4, e_e, e_f5, e_f6, e_x3, e_f7, e_f8, e_f9, e_f10, e_f11, e_y3, e_f12, e_z3, bind_tc_ok]

def sumValues (T : TermValues) (P Q : G1) : G1 :=
  let f := T.h + T.h
  let i := f * f
  let j := T.h * i
  let v := T.u1 * i
  let f1 := T.r * T.r
  let f2 := f1 - j
  let f3 := v + v
  let x3 := f2 - f3
  let f4 := v - x3
  let f5 := T.r * f4
  let f6 := T.s1 * j
  let f7 := f6 + f6
  let y3 := f5 - f7
  let f8 := P.z + Q.z
  let f9 := f8 * f8
  let f10 := f9 - T.z1z1
  let f11 := f10 - T.z2z2
  let z3 := f11 * T.h
  ⟨x3, y3, z3⟩

theorem sumValues_refines [RuntimeFeatures] (hfp : PortableFpCorrect)
    {p q : portable.g1.G1} {P Q : G1} {t : portable.g1.Terms} {T : TermValues}
    (hp : Coords p P) (hq : Coords q Q) (ht : TermsRep t T) :
    ∃ out, portable.g1.Terms.sum t p q = ok out ∧ Coords out (sumValues T P Q) := by
  obtain ⟨f, e_f, h_f⟩ := hfp.double ht.h
  obtain ⟨i, e_i, h_i⟩ := hfp.square h_f
  obtain ⟨j, e_j, h_j⟩ := hfp.mul ht.h h_i
  obtain ⟨v, e_v, h_v⟩ := hfp.mul ht.u1 h_i
  obtain ⟨f1, e_f1, h_f1⟩ := hfp.square ht.r
  obtain ⟨f2, e_f2, h_f2⟩ := hfp.sub h_f1 h_j
  obtain ⟨f3, e_f3, h_f3⟩ := hfp.double h_v
  obtain ⟨x3, e_x3, h_x3⟩ := hfp.sub h_f2 h_f3
  obtain ⟨f4, e_f4, h_f4⟩ := hfp.sub h_v h_x3
  obtain ⟨f5, e_f5, h_f5⟩ := hfp.mul ht.r h_f4
  obtain ⟨f6, e_f6, h_f6⟩ := hfp.mul ht.s1 h_j
  obtain ⟨f7, e_f7, h_f7⟩ := hfp.double h_f6
  obtain ⟨y3, e_y3, h_y3⟩ := hfp.sub h_f5 h_f7
  obtain ⟨f8, e_f8, h_f8⟩ := hfp.add hp.z hq.z
  obtain ⟨f9, e_f9, h_f9⟩ := hfp.square h_f8
  obtain ⟨f10, e_f10, h_f10⟩ := hfp.sub h_f9 ht.z1z1
  obtain ⟨f11, e_f11, h_f11⟩ := hfp.sub h_f10 ht.z2z2
  obtain ⟨z3, e_z3, h_z3⟩ := hfp.mul h_f11 ht.h
  refine ⟨⟨x3, y3, z3⟩, ?_, ⟨h_x3, h_y3, h_z3⟩⟩
  simp only [portable.g1.Terms.sum, e_f, e_i, e_j, e_v, e_f1, e_f2, e_f3, e_x3, e_f4, e_f5, e_f6, e_f7, e_y3, e_f8, e_f9, e_f10, e_f11, e_z3, bind_tc_ok]

private def doublePoly (x y z : ZMod Fp.modulus) : ZMod Fp.modulus × ZMod Fp.modulus × ZMod Fp.modulus :=
  let a := x * x
  let b := y * y
  let c := b * b
  let f := x + b
  let f1 := f * f
  let f2 := f1 - a
  let f3 := f2 - c
  let d := f3 + f3
  let f4 := a + a
  let e := f4 + a
  let f5 := e * e
  let f6 := d + d
  let x3 := f5 - f6
  let f7 := d - x3
  let f8 := e * f7
  let f9 := c + c
  let f10 := f9 + f9
  let f11 := f10 + f10
  let y3 := f8 - f11
  let f12 := y * z
  let z3 := f12 + f12
  ⟨x3, y3, z3⟩

private def doubleSpecPoly (x y z : ZMod Fp.modulus) : ZMod Fp.modulus × ZMod Fp.modulus × ZMod Fp.modulus :=
  let a := x * x
  let b := y * y
  let c := b * b
  let d := 2 * ((x + b) * (x + b) - a - c)
  let e := 3 * a
  let x3 := e * e - 2 * d
  let y3 := e * (d - x3) - 8 * c
  let z3 := 2 * y * z
  ⟨x3, y3, z3⟩

private theorem doublePoly_eq (x y z : ZMod Fp.modulus) : doublePoly x y z = doubleSpecPoly x y z := by
  dsimp [doublePoly, doubleSpecPoly]
  apply Prod.ext
  · ring
  · apply Prod.ext <;> ring

theorem doubleValues_eq_double (P : G1) (hz : P.z.isZero ≠ true) :
    doubleValues P = G1.double P := by
  simp only [doubleValues, G1.double, if_neg hz, Fp.ofNat_eq_natCast]
  have h := doublePoly_eq P.x P.y P.z
  exact congrArg (fun t => (⟨t.1, t.2.1, t.2.2⟩ : G1)) h

private theorem isZero_iff {x : Fp} : x.isZero = true ↔ x = 0 := by
  simp only [Fp.isZero, beq_iff_eq]
  exact ⟨fun h => Fin.ext h, fun h => congrArg Fin.val h⟩

private theorem beq_iff {x y : Fp} : x.beq y = true ↔ x = y := by
  simp only [Fp.beq, beq_iff_eq]
  exact ⟨fun h => Fin.ext h, fun h => congrArg Fin.val h⟩

private theorem isZero_sub (x y : Fp) : (y - x).isZero = x.beq y := by
  apply Bool.eq_iff_iff.mpr
  rw [G1.isZero_iff, G1.beq_iff]
  exact (show ∀ x y : ZMod Fp.modulus, y - x = 0 ↔ x = y from
    fun x y => by rw [sub_eq_zero, eq_comm]) x y

private theorem isZero_double_sub (x y : Fp) :
    ((y - x) + (y - x)).isZero = x.beq y := by
  apply Bool.eq_iff_iff.mpr
  rw [G1.isZero_iff, G1.beq_iff]
  exact (show ∀ x y : ZMod Fp.modulus, y - x + (y - x) = 0 ↔ x = y from
    fun x y => by
      rw [← two_mul, mul_eq_zero]
      simp [show (2 : ZMod Fp.modulus) ≠ 0 by decide, sub_eq_zero, eq_comm]) x y

def addValues (P Q : G1) : G1 :=
  if P.z.isZero then Q else if Q.z.isZero then P else
    let t := termsValues P Q
    if t.h.isZero then
      if t.r.isZero then doubleValues P else G1.zero
    else sumValues t P Q

private def sumPoly (h r u s a b z w : ZMod Fp.modulus) : ZMod Fp.modulus × ZMod Fp.modulus × ZMod Fp.modulus :=
  let f := (h) + (h)
  let i := f * f
  let j := (h) * i
  let v := (u) * i
  let f1 := (r + r) * (r + r)
  let f2 := f1 - j
  let f3 := v + v
  let x3 := f2 - f3
  let f4 := v - x3
  let f5 := (r + r) * f4
  let f6 := (s) * j
  let f7 := f6 + f6
  let y3 := f5 - f7
  let f8 := (z) + (w)
  let f9 := f8 * f8
  let f10 := f9 - (a)
  let f11 := f10 - (b)
  let z3 := f11 * (h)
  ⟨x3, y3, z3⟩

private def sumSpecPoly (h r u s a b z w : ZMod Fp.modulus) : ZMod Fp.modulus × ZMod Fp.modulus × ZMod Fp.modulus :=
  let i := (2 * h) * (2 * h)
  let j := h * i
  let v := u * i
  let rr := 2 * r
  let x3 := rr * rr - j - 2 * v
  let y3 := rr * (v - x3) - 2 * s * j
  let z3 := ((z + w) * (z + w) - a - b) * h
  ⟨x3, y3, z3⟩

private theorem sumPoly_eq (h r u s a b z w : ZMod Fp.modulus) : sumPoly h r u s a b z w = sumSpecPoly h r u s a b z w := by
  dsimp [sumPoly, sumSpecPoly]
  apply Prod.ext
  · ring
  · apply Prod.ext <;> ring

theorem addValues_eq_add (P Q : G1) : addValues P Q = G1.add P Q := by
  unfold addValues
  split
  · rename_i hp
    simp only [G1.add, hp, if_true]
  · rename_i hp
    split
    · rename_i hq
      simp only [G1.add, if_neg hp, hq, if_true]
    · rename_i hq
      simp only [termsValues, isZero_sub, isZero_double_sub]
      unfold G1.add
      simp only [if_neg hp, if_neg hq]
      split
      · split
        · exact doubleValues_eq_double P hp
        · rfl
      · simp only [sumValues, Fp.ofNat_eq_natCast]
        have h := sumPoly_eq
          (Q.x * (P.z * P.z) - P.x * (Q.z * Q.z))
          (Q.y * P.z * (P.z * P.z) - P.y * Q.z * (Q.z * Q.z))
          (P.x * (Q.z * Q.z)) (P.y * Q.z * (Q.z * Q.z))
          (P.z * P.z) (Q.z * Q.z) P.z Q.z
        exact congrArg (fun t => (⟨t.1, t.2.1, t.2.2⟩ : G1)) h

theorem add_complete_coords [RuntimeFeatures] (hfp : PortableFpCorrect)
    {p q : portable.g1.G1} {P Q : G1} (hp : Coords p P) (hq : Coords q Q) :
    ∃ out, portable.g1.G1.add_complete p q = ok out ∧ Coords out (G1.add P Q) := by
  rw [← addValues_eq_add]
  unfold addValues
  have hpz := hfp.is_zero hp.z
  have hqz := hfp.is_zero hq.z
  split
  · rename_i hz
    exact ⟨q, by simp [portable.g1.G1.add_complete, portable.g1.G1.is_infinity, hpz, hz], hq⟩
  · rename_i hz
    split
    · rename_i hqzero
      exact ⟨p, by simp [portable.g1.G1.add_complete, portable.g1.G1.is_infinity, hpz, hqz, hz, hqzero], hp⟩
    · rename_i hqzero
      obtain ⟨t, ht, htr⟩ := termsValues_refines hfp hp hq
      have hth := hfp.is_zero htr.h
      have htrz := hfp.is_zero htr.r
      dsimp only
      split
      · rename_i hh
        split
        · rename_i hr
          obtain ⟨out, he, ho⟩ := doubleValues_refines hfp hp
          exact ⟨out, by simp [portable.g1.G1.add_complete, portable.g1.G1.is_infinity,
            hpz, hqz, hz, hqzero, ht, hth, htrz, hh, hr, he], ho⟩
        · rename_i hr
          exact ⟨portable.g1.G1.INFINITY,
            by simp [portable.g1.G1.add_complete, portable.g1.G1.is_infinity,
              hpz, hqz, hz, hqzero, ht, hth, htrz, hh, hr], infinity_coords⟩
      · rename_i hh
        obtain ⟨out, he, ho⟩ := sumValues_refines hfp hp hq htr
        exact ⟨out, by simp [portable.g1.G1.add_complete, portable.g1.G1.is_infinity,
          hpz, hqz, hz, hqzero, ht, hth, hh, he], ho⟩

theorem neg_refines [RuntimeFeatures] (hfp : PortableFpCorrect)
    (p : portable.g1.G1) (P : G1) (hp : Rep p P) (hP : G1Valid P) :
    ∃ out, portable.g1.G1.neg p = ok out ∧ Rep out (G1.neg P) := by
  obtain ⟨out, he, ho⟩ := neg_coords hfp hp.coords
  have hm := g1_neg_matches (g1Valid_of_rep hp hP) hP hp.2.1 hp.2.2
  exact ⟨out, he, ⟨ho.rep.1, ho.rep.2.1.trans hm.1, ho.rep.2.2.trans hm.2⟩⟩

theorem add_complete_refines [RuntimeFeatures] (hfp : PortableFpCorrect)
    (p q : portable.g1.G1) (P Q : G1) (hp : Rep p P) (hq : Rep q Q)
    (hP : G1Valid P) (hQ : G1Valid Q) :
    ∃ out, portable.g1.G1.add_complete p q = ok out ∧ Rep out (G1.add P Q) := by
  obtain ⟨out, he, ho⟩ := add_complete_coords hfp hp.coords hq.coords
  have hm := g1_add_matches (g1Valid_of_rep hp hP) (g1Valid_of_rep hq hQ) hP hQ
    hp.2.1 hp.2.2 hq.2.1 hq.2.2
  exact ⟨out, he, ⟨ho.rep.1, ho.rep.2.1.trans hm.1, ho.rep.2.2.trans hm.2⟩⟩

end LeanBlsSimd.Kzg.PortableG1
