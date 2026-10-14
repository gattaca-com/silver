import LeanBlsSimd.Model.G2x8

namespace LeanBlsSimd

def BETA_MONT : List ℕ := [
  0xa424657e25648, 0xc75706049e739, 0xb59085299e0e2, 0xd9cf17286a964,
  0x069ec7cb33aa8, 0x35e995b239c7e, 0x82faa0ff3c329, 0x0000000017601]

structure G1x8 where
  x : Fp8
  y : Fp8
  z : Fp8

namespace G1x8

def from_affine (x y : Fp8) : G1x8 := ⟨x, y, Fp8.one⟩

def double (self : G1x8) : G1x8 × Mmask8 :=
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
  (⟨x3, y3, z3⟩, undecided)

def add_affine (self : G1x8) (qx qy : Fp8) : G1x8 × Mmask8 :=
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
  (⟨x3, y3, z3⟩, undecided)

def add (self q : G1x8) : G1x8 × Mmask8 :=
  let z1z1 := self.z.square
  let z2z2 := q.z.square
  let u1 := self.x.mul z2z2
  let u2 := q.x.mul z1z1
  let s1 := (self.y.mul q.z).mul z2z2
  let s2 := (q.y.mul self.z).mul z1z1
  let h := u2.sub u1
  let i := h.double.square
  let j := h.mul i
  let r := (s2.sub s1).double
  let v := u1.mul i
  let x3 := (r.square.sub j).sub v.double
  let y3 := (r.mul (v.sub x3)).sub (s1.mul j).double
  let z3 := (((self.z.add q.z).square.sub z1z1).sub z2z2).mul h
  let undecided := h.is_zero_mask ||| self.z.is_zero_mask ||| q.z.is_zero_mask
  (⟨x3, y3, z3⟩, undecided)

def is_lower_z_bit (bit : ℕ) : Bool := (Z_BITS.drop 1).contains bit

def affineChainStep (px py : Fp8) : G1x8 × Mmask8 → ℕ → G1x8 × Mmask8 :=
  fun (r, undecided) bit =>
    let (d, u) := r.double
    let undecided := undecided ||| u
    if is_lower_z_bit bit then
      let (a, u) := d.add_affine px py
      (a, undecided ||| u)
    else (d, undecided)

def chainStep (q : G1x8) : G1x8 × Mmask8 → ℕ → G1x8 × Mmask8 :=
  fun (r, undecided) bit =>
    let (d, u) := r.double
    let undecided := undecided ||| u
    if is_lower_z_bit bit then
      let (a, u) := d.add q
      (a, undecided ||| u)
    else (d, undecided)

def times_z_affine (px py : Fp8) : G1x8 × Mmask8 :=
  (List.range Z_BITS[0]!).reverse.foldl (affineChainStep px py) (from_affine px py, 0)

def times_z (self : G1x8) : G1x8 × Mmask8 :=
  (List.range Z_BITS[0]!).reverse.foldl (chainStep self) (self, 0)

def scott_membership (px py : Fp8) : Membership :=
  let (zp, u1) := times_z_affine px py
  let (zzp, u2) := zp.times_z
  let undecided := u1 ||| u2 ||| zzp.z.is_zero_mask
  let beta := Fp8.splat_limbs (.ofList BETA_MONT)
  let sigma2_x := (px.mul beta).mul beta
  let zz := zzp.z.square
  let zzz := zz.mul zzp.z
  let x_matches := zzp.x.eq_mask (sigma2_x.mul zz)
  let y_matches := zzp.y.neg.eq_mask (py.mul zzz)
  ⟨x_matches &&& y_matches &&& ~~~undecided, undecided⟩

end G1x8
end LeanBlsSimd
