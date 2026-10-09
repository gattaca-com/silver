import LeanBlsSimd.Model.Fp8

/-!
# `fp2x8.rs`

`crates/bls_simd/src/fp2x8.rs`, transcribed one statement per Rust statement.
Fp2 = Fp[i]/(i² + 1); `c0` is the real part and `c1` the coefficient of i, in every lane.
A Rust tuple `(Self, __mmask8)` is a Lean pair, and the `|`, `&` of two masks are `|||`, `&&&`.
-/

namespace LeanBlsSimd

/-- `Fp2x8` of `fp2x8.rs`. -/
structure Fp2x8 where
  c0 : Fp8
  c1 : Fp8

namespace Fp2x8

def splat (limbs : Vector Limbs 2) : Fp2x8 :=
  { c0 := Fp8.splat_limbs limbs[0], c1 := Fp8.splat_limbs limbs[1] }

def one : Fp2x8 := { c0 := Fp8.one, c1 := Fp8.zero }

/-- Karatsuba: three Fp products. -/
def mul (self rhs : Fp2x8) : Fp2x8 :=
  let v0 := self.c0.mul rhs.c0
  let v1 := self.c1.mul rhs.c1
  let s := (self.c0.add self.c1).mul (rhs.c0.add rhs.c1)
  { c0 := v0.sub v1, c1 := (s.sub v0).sub v1 }

def square (self : Fp2x8) : Fp2x8 :=
  let c0 := (self.c0.add self.c1).mul (self.c0.sub self.c1)
  let c1 := (self.c0.mul self.c1).double
  { c0, c1 }

def add (self rhs : Fp2x8) : Fp2x8 := { c0 := self.c0.add rhs.c0, c1 := self.c1.add rhs.c1 }

def sub (self rhs : Fp2x8) : Fp2x8 := { c0 := self.c0.sub rhs.c0, c1 := self.c1.sub rhs.c1 }

def double (self : Fp2x8) : Fp2x8 := self.add self

def neg (self : Fp2x8) : Fp2x8 := { c0 := self.c0.neg, c1 := self.c1.neg }

def conjugate (self : Fp2x8) : Fp2x8 := { c0 := self.c0, c1 := self.c1.neg }

def mul_by_i (self : Fp2x8) : Fp2x8 := { c0 := self.c1.neg, c1 := self.c0 }

/-- Lanes of `k` take `b`, the rest `a`. -/
def select (k : Mmask8) (a b : Fp2x8) : Fp2x8 :=
  { c0 := Fp8.select k a.c0 b.c0, c1 := Fp8.select k a.c1 b.c1 }

def eq_mask (self rhs : Fp2x8) : Mmask8 := self.c0.eq_mask rhs.c0 &&& self.c1.eq_mask rhs.c1

def is_zero_mask (self : Fp2x8) : Mmask8 := self.c0.is_zero_mask &&& self.c1.is_zero_mask

/-- blst's `sqrt_fp2` with two alignments: the root, and the lanes that have one. -/
def sqrt (self : Fp2x8) : Fp2x8 × Mmask8 :=
  let n := (self.c0.square.add self.c1.square).sqrt_candidate
  let plus := self.c0.add n
  let t := (Fp8.select plus.is_zero_mask plus (self.c0.sub n)).half
  let r := t.pow_p_minus_3_over_4
  let candidate : Fp2x8 := { c0 := t.mul r, c1 := self.c1.half.mul r }
  let square := candidate.square
  let squares_to_self := square.eq_mask self
  let squares_to_neg := square.eq_mask self.neg
  let root := select squares_to_neg candidate candidate.mul_by_i
  (root, squares_to_self ||| squares_to_neg)

/-- c1 decides, and c0 only where c1 = 0. -/
def is_larger_root_mask (self : Fp2x8) : Mmask8 :=
  self.c1.is_larger_root_mask ||| (self.c0.is_larger_root_mask &&& self.c1.is_zero_mask)

end Fp2x8

end LeanBlsSimd
