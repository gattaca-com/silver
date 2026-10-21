import LeanBlsSimd.Refines.Fp8
import LeanBlsSimd.Model.Fp2x8
import LeanBlsSimd.Proofs.MulComm

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

/-!
Exact refinement of the functions in `fp2x8.rs`. `ofFp2x8` converts each coordinate with
`ofFp8`. Multiplication uses exact limb-level commutativity to accept swapped operands.
The square-root proof names shared intermediate values to keep later mismatch goals small.
-/

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

@[simp] theorem ofFp2x8_mk (a b : fp8.Fp8) :
    ofFp2x8 { c0 := a, c1 := b } = { c0 := ofFp8 a, c1 := ofFp8 b } := rfl

namespace Fp2x8

theorem splat_refines (limbs : Array (Array U64 8#usize) 2#usize) :
    fp2x8.Fp2x8.splat limbs = ok (toFp2x8 (Fp2x8.splat (ofArray (ofArray ofU64) limbs))) := by
  simp [fp2x8.Fp2x8.splat, index_usize_eq limbs 0#usize (by decide),
    index_usize_eq limbs 1#usize (by decide), Fp8.splat_limbs_refines, Fp2x8.splat, toFp2x8]

theorem one_refines : fp2x8.Fp2x8.one = ok (toFp2x8 Fp2x8.one) := by
  simp [fp2x8.Fp2x8.one, Fp8.one_refines, Fp8.zero_refines, Fp2x8.one, toFp2x8]

theorem add_raw_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.add_raw self rhs = ok (toFp2x8 ((ofFp2x8 self).add_raw (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.add_raw, Fp8.add_raw_refines, Fp2x8.add_raw, toFp2x8]

theorem sub_raw_refines (self rhs : fp2x8.Fp2x8) (offset : fp8.Fp8) :
    fp2x8.Fp2x8.sub_raw self rhs offset =
      ok (toFp2x8 ((ofFp2x8 self).sub_raw (ofFp2x8 rhs) (ofFp8 offset))) := by
  simp [fp2x8.Fp2x8.sub_raw, Fp8.sub_raw_refines, Fp2x8.sub_raw, toFp2x8]

theorem normalise_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.normalise self = ok (toFp2x8 (ofFp2x8 self).normalise) := by
  simp [fp2x8.Fp2x8.normalise, Fp8.normalise_refines, Fp2x8.normalise, toFp2x8]

theorem cond_sub_refines (self : fp2x8.Fp2x8) (c : fp8.Fp8) :
    fp2x8.Fp2x8.cond_sub self c = ok (toFp2x8 ((ofFp2x8 self).cond_sub (ofFp8 c))) := by
  simp [fp2x8.Fp2x8.cond_sub, Fp8.cond_sub_refines, Fp2x8.cond_sub, toFp2x8]

theorem add_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.add self rhs = ok (toFp2x8 ((ofFp2x8 self).add (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.add, Fp8.add_refines, Fp2x8.add, toFp2x8]

theorem sub_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.sub self rhs = ok (toFp2x8 ((ofFp2x8 self).sub (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.sub, Fp8.sub_refines, Fp2x8.sub, toFp2x8]

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

attribute [local simp] Fp8.mul_comm in
theorem mul_refines (self rhs : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.mul self rhs = ok (toFp2x8 ((ofFp2x8 self).mul (ofFp2x8 rhs))) := by
  simp [fp2x8.Fp2x8.mul, Fp8.mul_refines, Fp8.add_raw_refines, Fp8.normalise_refines,
    Fp8.sub_refines, Fp2x8.mul, toFp2x8]

theorem square_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.square self = ok (toFp2x8 (ofFp2x8 self).square) := by
  simp [fp2x8.Fp2x8.square, Fp8.mul_refines, Fp8.add_raw_refines, Fp8.sub_raw_refines,
    Fp8.normalise_refines, Fp8.multiple_of_p_refines 8#u64 (by decide),
    Fp2x8.square, toFp2x8, ofU64]

theorem sqrt_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.sqrt self = ok (Prod.map toFp2x8 toU8 (ofFp2x8 self).sqrt) := by
  unfold fp2x8.Fp2x8.sqrt Fp2x8.sqrt
  simp only [Fp8.square_refines, Fp8.mul_refines, Fp8.square, Fp8.add_refines,
    Fp8.sqrt_candidate_refines, bind_tc_ok, ofFp8_toFp8, ofFp2x8]
  generalize (((ofFp8 self.c0).mul (ofFp8 self.c0)).add
    ((ofFp8 self.c1).mul (ofFp8 self.c1))).sqrt_candidate = n
  simp only [Fp8.is_zero_mask_refines, Fp8.sub_refines, Fp8.select_refines, Fp8.half_refines,
    bind_tc_ok, ofU8_toU8, ofFp8_toFp8]
  generalize (Fp8.select ((ofFp8 self.c0).add n).is_zero_mask ((ofFp8 self.c0).add n)
    ((ofFp8 self.c0).sub n)).half = t
  simp only [Fp8.pow_p_minus_3_over_4_refines, bind_tc_ok, ofFp8_toFp8]
  generalize t.pow_p_minus_3_over_4 = r
  generalize t.mul r = real
  generalize (ofFp8 self.c1).half.mul r = imag
  simp [square_refines, eq_mask_refines, neg_refines, mul_by_i_refines, select_refines,
    ofFp2x8, lift]

theorem is_larger_root_mask_refines (self : fp2x8.Fp2x8) :
    fp2x8.Fp2x8.is_larger_root_mask self = ok (toU8 (ofFp2x8 self).is_larger_root_mask) := by
  simp [fp2x8.Fp2x8.is_larger_root_mask, Fp8.is_larger_root_mask_refines,
    Fp8.is_zero_mask_refines, Fp2x8.is_larger_root_mask, lift]

end Fp2x8

end LeanBlsSimd
