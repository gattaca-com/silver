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

structure Offsets where
  two_p : Fp8
  four_p : Fp8
  eight_p : Fp8

namespace Offsets

def new : Offsets := ⟨Fp8.multiple_of_p 2, Fp8.multiple_of_p 4, Fp8.multiple_of_p 8⟩

def reduced_from_4p (self : Offsets) (v : Fp8) : Fp8 :=
  v.normalise.cond_sub self.two_p

def reduced_from_8p (self : Offsets) (v : Fp8) : Fp8 :=
  (v.normalise.cond_sub self.four_p).cond_sub self.two_p

end Offsets

def double (self : G1x8) : G1x8 × Mmask8 :=
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

def add_affine (self : G1x8) (qx qy : Fp8) : G1x8 × Mmask8 :=
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

def add (self q : G1x8) : G1x8 × Mmask8 :=
  let o := Offsets.new
  let z1z1 := self.z.square
  let z2z2 := q.z.square
  let y1_z2 := self.y.mul q.z
  let y2_z1 := q.y.mul self.z
  let z_sum := (self.z.add_raw q.z).normalise
  let z_sum_squared := z_sum.square
  let u1 := self.x.mul z2z2
  let u2 := q.x.mul z1z1
  let s1 := y1_z2.mul z2z2
  let s2 := y2_z1.mul z1z1
  let h := u2.sub u1
  let i := (h.add_raw h).normalise.square
  let two_z1_z2 := ((z_sum_squared.sub_raw z1z1 o.two_p).sub_raw z2z2 o.two_p).normalise
  let z3 := two_z1_z2.mul h
  let j := h.mul i
  let v := u1.mul i
  let r := s2.sub_raw s1 o.two_p
  let r := (r.add_raw r).normalise
  let rr := r.square
  let s1_j := s1.mul j
  let x3 := o.reduced_from_8p ((rr.sub_raw j o.two_p).sub_raw (v.add_raw v) o.four_p)
  let vx := (v.sub_raw x3 o.two_p).normalise
  let y3 := o.reduced_from_8p ((r.mul vx).sub_raw (s1_j.add_raw s1_j) o.four_p)
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
