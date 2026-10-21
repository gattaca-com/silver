import LeanBlsSimd.Model.Fp2x8

/-!
# `g2x8.rs`

Model of `crates/crypto_simd/src/bls/g2x8.rs`, connected to the Aeneas output by `Refines/G2x8.lean`.
Points are Jacobian triples over `Fp2x8`, one per lane. `Membership` is the struct of `crates/crypto_simd/src/bls/mod.rs`
that `scott_membership` returns. Rust's `!` on a mask is `~~~`.

`times_minus_z` counts `bit` down from `Z_BITS[0]` in a `while` loop with a mutable point and
mask. After each decrement it doubles, and it adds where `bit` equals one of `Z_BITS[1]` to
`Z_BITS[5]`. Here the loop is a fold of `chainStep` over `(List.range Z_BITS[0]!).reverse`, the
values `bit` takes after its decrement, and its state is that pair. The five comparisons are
`Z_BITS.contains bit`: that also tests `Z_BITS[0]`, which `bit` stays below.
-/

namespace LeanBlsSimd

/-- `Membership` of `crates/crypto_simd/src/bls/mod.rs`. -/
structure Membership where
  members : Mmask8
  undecided : Mmask8

/-- `G2x8` of `g2x8.rs`. -/
structure G2x8 where
  x : Fp2x8
  y : Fp2x8
  z : Fp2x8

namespace G2x8

structure Offsets where
  two_p : Fp8
  four_p : Fp8
  eight_p : Fp8

namespace Offsets

def new : Offsets := ⟨Fp8.multiple_of_p 2, Fp8.multiple_of_p 4, Fp8.multiple_of_p 8⟩

def reduced_from_4p (self : Offsets) (v : Fp2x8) : Fp2x8 :=
  v.normalise.cond_sub self.two_p

def reduced_from_8p (self : Offsets) (v : Fp2x8) : Fp2x8 :=
  (v.normalise.cond_sub self.four_p).cond_sub self.two_p

end Offsets

/-- dbl-2009-l. Undecided when y = 0 or z = 0. -/
def double (self : G2x8) : G2x8 × Mmask8 :=
  let o := Offsets.new
  let a := self.x.square
  let b := self.y.square
  let e := ((a.add_raw a).add_raw a).normalise
  let f := e.square
  let c := b.square
  let xb := (self.x.add_raw b).normalise
  let xb_squared := xb.square
  let yz := self.y.mul self.z
  let d := o.reduced_from_8p ((xb_squared.sub_raw a o.two_p).sub_raw c o.two_p)
  let d := o.reduced_from_4p (d.add_raw d)
  let x3 := (f.sub_raw (d.add_raw d) o.four_p).normalise
  let dx := (d.sub_raw x3 o.eight_p).normalise
  let c8 := o.reduced_from_8p (((c.add_raw c).add_raw c).add_raw c)
  let y3 := o.reduced_from_8p ((e.mul dx).sub_raw (c8.add_raw c8) o.four_p)
  let z3 := o.reduced_from_4p (yz.add_raw yz)
  let undecided := self.y.is_zero_mask ||| self.z.is_zero_mask
  (⟨(x3.cond_sub o.four_p).cond_sub o.two_p, y3, z3⟩, undecided)

/-- madd-2007-bl with Z2 = 1. Undecided when H = 0, that is equal x coordinates, or z = 0. -/
def add_affine (self : G2x8) (qx qy : Fp2x8) : G2x8 × Mmask8 :=
  let o := Offsets.new
  let z1z1 := self.z.square
  let qy_z := qy.mul self.z
  let u2 := qx.mul z1z1
  let s2 := qy_z.mul z1z1
  let h := u2.sub self.x
  let hh := h.square
  let zh := (self.z.add_raw h).normalise
  let zh_squared := zh.square
  let i := (((hh.add_raw hh).add_raw hh).add_raw hh).normalise
  let j := h.mul i
  let v := self.x.mul i
  let r := s2.sub_raw self.y o.two_p
  let r := (r.add_raw r).normalise
  let rr := r.square
  let yj := self.y.mul j
  let x3 := o.reduced_from_8p ((rr.sub_raw j o.two_p).sub_raw (v.add_raw v) o.four_p)
  let vx := (v.sub_raw x3 o.two_p).normalise
  let y3 := o.reduced_from_8p ((r.mul vx).sub_raw (yj.add_raw yj) o.four_p)
  let z3 := o.reduced_from_8p ((zh_squared.sub_raw z1z1 o.two_p).sub_raw hh o.two_p)
  let undecided := h.is_zero_mask ||| self.z.is_zero_mask
  (⟨x3, y3, z3⟩, undecided)

/-- The body of `times_minus_z`'s loop. -/
def chainStep (px py : Fp2x8) : G2x8 × Mmask8 → ℕ → G2x8 × Mmask8 :=
  fun (r, undecided) bit =>
    let (d, u) := r.double
    let r := d
    let undecided := undecided ||| u
    if Z_BITS.contains bit then
      let (a, u) := r.add_affine px py
      (a, undecided ||| u)
    else (r, undecided)

/-- `[-z] P = [|z|] P` for an affine P, by double-and-add over the six set bits of |z|. -/
def times_minus_z (px py : Fp2x8) : G2x8 × Mmask8 :=
  let undecided : Mmask8 := 0
  let r : G2x8 := { x := px, y := py, z := Fp2x8.one }
  (List.range Z_BITS[0]!).reverse.foldl (chainStep px py) (r, undecided)

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
