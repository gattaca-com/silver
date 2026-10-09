import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Model.Fp2x8

open Aeneas Aeneas.Std Result
open silver_bls_simd

/-! The functions of `fp2x8.rs` that do not multiply. `ofFp2x8` converts each coordinate with
`ofFp8`. -/

namespace LeanBlsSimd

def ofFp2x8 (a : fp2x8.Fp2x8) : Fp2x8 := ⟨ofFp8 a.c0, ofFp8 a.c1⟩

def toFp2x8 (x : Fp2x8) : fp2x8.Fp2x8 := ⟨toFp8 x.c0, toFp8 x.c1⟩

@[simp] theorem c0_ofFp2x8 (a : fp2x8.Fp2x8) : (ofFp2x8 a).c0 = ofFp8 a.c0 := rfl
@[simp] theorem c1_ofFp2x8 (a : fp2x8.Fp2x8) : (ofFp2x8 a).c1 = ofFp8 a.c1 := rfl
@[simp] theorem c0_toFp2x8 (x : Fp2x8) : (toFp2x8 x).c0 = toFp8 x.c0 := rfl
@[simp] theorem c1_toFp2x8 (x : Fp2x8) : (toFp2x8 x).c1 = toFp8 x.c1 := rfl

@[simp] theorem ofFp2x8_toFp2x8 (x : Fp2x8) : ofFp2x8 (toFp2x8 x) = x := by
  simp [ofFp2x8, toFp2x8]

@[simp] theorem toFp2x8_ofFp2x8 (a : fp2x8.Fp2x8) : toFp2x8 (ofFp2x8 a) = a := by
  simp [ofFp2x8, toFp2x8]

namespace Fp2x8

theorem splat_refines (limbs : Array (Array U64 8#usize) 2#usize) :
    fp2x8.Fp2x8.splat limbs = ok (toFp2x8 (Fp2x8.splat (ofArray (ofArray ofU64) limbs))) := by
  simp [fp2x8.Fp2x8.splat, index_usize_eq limbs 0#usize (by decide),
    index_usize_eq limbs 1#usize (by decide), Fp8.splat_limbs_refines, Fp2x8.splat, toFp2x8]

theorem one_refines : fp2x8.Fp2x8.one = ok (toFp2x8 Fp2x8.one) := by
  simp [fp2x8.Fp2x8.one, Fp8.one_refines, Fp8.zero_refines, Fp2x8.one, toFp2x8]

theorem add_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.add self rhs = ok (toFp2x8 ((ofFp2x8 self).add (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.add, Fp8.add_refines, Fp2x8.add, toFp2x8]

theorem sub_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.sub self rhs = ok (toFp2x8 ((ofFp2x8 self).sub (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.sub, Fp8.sub_refines, Fp2x8.sub, toFp2x8]

theorem double_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.double self = ok (toFp2x8 (ofFp2x8 self).double) := by
  simp [fp2x8.Fp2x8.double, add_refines, Fp2x8.double]

theorem neg_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.neg self = ok (toFp2x8 (ofFp2x8 self).neg) := by
  simp [fp2x8.Fp2x8.neg, Fp8.neg_refines, Fp2x8.neg, toFp2x8]

theorem conjugate_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.conjugate self = ok (toFp2x8 (ofFp2x8 self).conjugate) := by
  simp [fp2x8.Fp2x8.conjugate, Fp8.neg_refines, Fp2x8.conjugate, toFp2x8]

theorem mul_by_i_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.mul_by_i self = ok (toFp2x8 (ofFp2x8 self).mul_by_i) := by
  simp [fp2x8.Fp2x8.mul_by_i, Fp8.neg_refines, Fp2x8.mul_by_i, toFp2x8]

theorem select_refines (k : U8) (a b : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.select k a b = ok (toFp2x8 (Fp2x8.select (ofU8 k) (ofFp2x8 a) (ofFp2x8 b))) := by
  simp [fp2x8.Fp2x8.select, Fp8.select_refines, Fp2x8.select, toFp2x8]

theorem eq_mask_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.eq_mask self rhs = ok (toU8 ((ofFp2x8 self).eq_mask (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.eq_mask, Fp8.eq_mask_refines, Fp2x8.eq_mask]

theorem is_zero_mask_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.is_zero_mask self = ok (toU8 (ofFp2x8 self).is_zero_mask) := by
  simp [fp2x8.Fp2x8.is_zero_mask, Fp8.is_zero_mask_refines, Fp2x8.is_zero_mask]

end Fp2x8

end LeanBlsSimd
