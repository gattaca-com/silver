import LeanBlsSimd.Model.Fp2x8

/-!
# `g2x8.rs`

`crates/bls_simd/src/g2x8.rs`, transcribed one statement per Rust statement.
Points are Jacobian triples over `Fp2x8`, one per lane. `Membership` is the struct of `lib.rs`
that `scott_membership` returns. Rust's `!` on a mask is `~~~`.

`times_minus_z` loops over `(0..Z_BITS[0]).rev()` with a mutable point and mask; here the loop is
a fold over `(List.range Z_BITS[0]!).reverse` whose state is that pair.
-/

namespace LeanBlsSimd

/-- `Membership` of `lib.rs`. -/
structure Membership where
  members : Mmask8
  undecided : Mmask8

/-- `G2x8` of `g2x8.rs`. -/
structure G2x8 where
  x : Fp2x8
  y : Fp2x8
  z : Fp2x8

namespace G2x8

/-- dbl-2009-l. Undecided when y = 0 or z = 0. -/
def double (self : G2x8) : G2x8 × Mmask8 :=
  let a := self.x.square
  let b := self.y.square
  let c := b.square
  let d := (((self.x.add b).square.sub a).sub c).double
  let e := a.double.add a
  let f := e.square
  let x3 := f.sub d.double
  let y3 := (e.mul (d.sub x3)).sub c.double.double.double
  let z3 := (self.y.mul self.z).double
  let undecided := self.y.is_zero_mask ||| self.z.is_zero_mask
  ({ x := x3, y := y3, z := z3 }, undecided)

/-- madd-2007-bl with Z2 = 1. Undecided when H = 0, that is equal x coordinates, or z = 0. -/
def add_affine (self : G2x8) (qx qy : Fp2x8) : G2x8 × Mmask8 :=
  let z1z1 := self.z.square
  let u2 := qx.mul z1z1
  let s2 := (qy.mul self.z).mul z1z1
  let h := u2.sub self.x
  let hh := h.square
  let i := hh.double.double
  let j := h.mul i
  let r := (s2.sub self.y).double
  let v := self.x.mul i
  let x3 := (r.square.sub j).sub v.double
  let y3 := (r.mul (v.sub x3)).sub (self.y.mul j).double
  let z3 := ((self.z.add h).square.sub z1z1).sub hh
  let undecided := h.is_zero_mask ||| self.z.is_zero_mask
  ({ x := x3, y := y3, z := z3 }, undecided)

/-- `[-z] P = [|z|] P` for an affine P, by double-and-add over the six set bits of |z|. -/
def times_minus_z (px py : Fp2x8) : G2x8 × Mmask8 :=
  let undecided : Mmask8 := 0
  let r : G2x8 := { x := px, y := py, z := Fp2x8.one }
  (List.range Z_BITS[0]!).reverse.foldl (init := (r, undecided)) fun (r, undecided) bit =>
    let (d, u) := r.double
    let r := d
    let undecided := undecided ||| u
    if Z_BITS.contains bit then
      let (a, u) := r.add_affine px py
      (a, undecided ||| u)
    else (r, undecided)

/-- Scott's test: `psi(P) == [z] P`, which is `[-z] P` negated. -/
def scott_membership (px py : Fp2x8) : Membership :=
  let (mzp, chain_undecided) := times_minus_z px py
  let undecided := chain_undecided ||| mzp.z.is_zero_mask

  let psi_scale := Fp8.splat_limbs (.ofList PSI_X_MONT)
  let psi_x : Fp2x8 := { c0 := px.c1.mul psi_scale, c1 := px.c0.mul psi_scale }
  let psi_y := py.conjugate.mul (Fp2x8.splat #v[.ofList PSI_Y_MONT[0]!, .ofList PSI_Y_MONT[1]!])
  let zz := mzp.z.square
  let zzz := zz.mul mzp.z
  let x_matches := mzp.x.eq_mask (psi_x.mul zz)
  let y_matches := mzp.y.neg.eq_mask (psi_y.mul zzz)
  { members := x_matches &&& y_matches &&& ~~~undecided, undecided }

end G2x8

end LeanBlsSimd
