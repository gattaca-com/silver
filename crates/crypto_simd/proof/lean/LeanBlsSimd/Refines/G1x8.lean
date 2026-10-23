import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Model.G1x8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd

def ofG1x8 (a : g1x8.G1x8) : G1x8 := ⟨ofFp8 a.x, ofFp8 a.y, ofFp8 a.z⟩

def toG1x8 (a : G1x8) : g1x8.G1x8 := ⟨toFp8 a.x, toFp8 a.y, toFp8 a.z⟩

@[simp] theorem x_ofG1x8 (a : g1x8.G1x8) : (ofG1x8 a).x = ofFp8 a.x := rfl
@[simp] theorem y_ofG1x8 (a : g1x8.G1x8) : (ofG1x8 a).y = ofFp8 a.y := rfl
@[simp] theorem z_ofG1x8 (a : g1x8.G1x8) : (ofG1x8 a).z = ofFp8 a.z := rfl

@[simp] theorem ofG1x8_mk (x y z : fp8.Fp8) :
    ofG1x8 { x, y, z } = { x := ofFp8 x, y := ofFp8 y, z := ofFp8 z } := rfl

@[simp] theorem ofG1x8_toG1x8 (x : G1x8) : ofG1x8 (toG1x8 x) = x := by
  simp [ofG1x8, toG1x8]

@[simp] theorem toG1x8_ofG1x8 (a : g1x8.G1x8) : toG1x8 (ofG1x8 a) = a := by
  simp [ofG1x8, toG1x8]

theorem BETA_MONT_refines : constants.BETA_MONT = toArray toU64 (Limbs.ofList BETA_MONT) := by
  rw [constants.BETA_MONT]; rfl

namespace G1x8

theorem from_affine_refines (x y : fp8.Fp8) :
    g1x8.G1x8.from_affine x y = ok (toG1x8 (from_affine (ofFp8 x) (ofFp8 y))) := by
  simp [g1x8.G1x8.from_affine, Fp8.one_refines, from_affine, toG1x8]

namespace Offsets

def ofOffsets (o : g1x8.Offsets) : Offsets :=
  ⟨ofFp8 o.two_p, ofFp8 o.four_p, ofFp8 o.eight_p⟩

def toOffsets (o : Offsets) : g1x8.Offsets :=
  ⟨toFp8 o.two_p, toFp8 o.four_p, toFp8 o.eight_p⟩

@[simp] theorem ofOffsets_toOffsets (o : Offsets) : ofOffsets (toOffsets o) = o := by
  simp [ofOffsets, toOffsets]

theorem new_refines : g1x8.Offsets.new = ok (toOffsets new) := by
  simp [g1x8.Offsets.new, Fp8.multiple_of_p_refines 2#u64 (by decide),
    Fp8.multiple_of_p_refines 4#u64 (by decide), Fp8.multiple_of_p_refines 8#u64 (by decide),
    new, toOffsets, show ofU64 2#u64 = 2 from rfl,
    show ofU64 4#u64 = 4 from rfl, show ofU64 8#u64 = 8 from rfl]

theorem reduced_from_4p_refines (o : g1x8.Offsets) (v : fp8.Fp8) :
    g1x8.Offsets.reduced_from_4p o v =
      ok (toFp8 ((ofOffsets o).reduced_from_4p (ofFp8 v))) := by
  simp [g1x8.Offsets.reduced_from_4p, Fp8.normalise_refines, Fp8.cond_sub_refines,
    reduced_from_4p, ofOffsets]

theorem reduced_from_8p_refines (o : g1x8.Offsets) (v : fp8.Fp8) :
    g1x8.Offsets.reduced_from_8p o v =
      ok (toFp8 ((ofOffsets o).reduced_from_8p (ofFp8 v))) := by
  simp [g1x8.Offsets.reduced_from_8p, Fp8.normalise_refines, Fp8.cond_sub_refines,
    reduced_from_8p, ofOffsets]

end Offsets

theorem double_refines (self : g1x8.G1x8) :
    g1x8.G1x8.double self = ok (Prod.map toG1x8 toU8 (ofG1x8 self).double) := by
  simp [g1x8.G1x8.double, Fp8.square_refines, Fp8.add_raw_refines, Fp8.sub_raw_refines,
    Fp8.normalise_refines, Fp8.cond_sub_refines, Fp8.mul_refines,
    Fp8.is_zero_mask_refines, Offsets.new_refines, Offsets.reduced_from_4p_refines,
    Offsets.reduced_from_8p_refines, Offsets.toOffsets, Offsets.ofOffsets,
    lift, G1x8.double, toG1x8]

theorem add_affine_refines (self : g1x8.G1x8) (qx qy : fp8.Fp8) :
    g1x8.G1x8.add_affine self qx qy =
      ok (Prod.map toG1x8 toU8 ((ofG1x8 self).add_affine (ofFp8 qx) (ofFp8 qy))) := by
  simp [g1x8.G1x8.add_affine, Fp8.square_refines, Fp8.add_raw_refines, Fp8.sub_raw_refines,
    Fp8.sub_refines, Fp8.normalise_refines, Fp8.mul_refines,
    Fp8.is_zero_mask_refines, Offsets.new_refines, Offsets.reduced_from_8p_refines,
    Offsets.toOffsets, Offsets.ofOffsets, lift, G1x8.add_affine, toG1x8]

theorem add_refines (self q : g1x8.G1x8) :
    g1x8.G1x8.add self q = ok (Prod.map toG1x8 toU8 ((ofG1x8 self).add (ofG1x8 q))) := by
  simp [g1x8.G1x8.add, Fp8.square_refines, Fp8.add_raw_refines, Fp8.sub_raw_refines,
    Fp8.sub_refines, Fp8.normalise_refines, Fp8.mul_refines,
    Fp8.is_zero_mask_refines, Offsets.new_refines, Offsets.reduced_from_8p_refines,
    Offsets.toOffsets, Offsets.ofOffsets, lift, G1x8.add, toG1x8]

theorem is_lower_z_bit_refines (bit : U32) :
    constants.is_lower_z_bit bit = ok (is_lower_z_bit bit.val) := by
  simp (disch := decide) only [constants.is_lower_z_bit, Z_BITS_index, bind_tc_ok,
    UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
  simp [is_lower_z_bit, Z_BITS]
  split_ifs <;> simp_all

theorem times_z_affine_loop_refines (px py : fp8.Fp8) (m : G1x8 × Mmask8) (c : U32) (n : ℕ)
    (hcn : c.val = n) :
    g1x8.G1x8.times_z_affine_loop px py (toU8 m.2) (toG1x8 m.1) c =
      ok (Prod.map toG1x8 toU8
        ((List.range n).reverse.foldl (affineChainStep (ofFp8 px) (ofFp8 py)) m)) := by
  unfold g1x8.G1x8.times_z_affine_loop
  refine loop_countdown _ (fun (m : G1x8 × Mmask8) c => (toU8 m.2, toG1x8 m.1, c))
    (affineChainStep (ofFp8 px) (ofFp8 py)) (Prod.map toG1x8 toU8) n ?_ ?_ c m hcn
  · intro m c hc
    simp [g1x8.G1x8.times_z_affine_loop.body, hc]
    rfl
  · intro ⟨r, u⟩ c c' hc _
    obtain ⟨⟨d, du⟩, hd⟩ : ∃ d, r.double = d := ⟨_, rfl⟩
    obtain ⟨⟨a, au⟩, ha⟩ : ∃ a, d.add_affine (ofFp8 px) (ofFp8 py) = a := ⟨_, rfl⟩
    simp only [g1x8.G1x8.times_z_affine_loop.body]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val - (1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [bind_tc_ok, double_refines, Function.uncurry_def, Prod.map_fst,
      Prod.map_snd, ofG1x8_toG1x8, lift, is_lower_z_bit_refines, toU8_or, add_affine_refines]
    simp only [affineChainStep, hd, ha]
    cases is_lower_z_bit c'.val <;> simp

theorem times_z_loop_refines (q : g1x8.G1x8) (m : G1x8 × Mmask8) (c : U32) (n : ℕ)
    (hcn : c.val = n) :
    g1x8.G1x8.times_z_loop q.x q.y q.z (toU8 m.2) (toG1x8 m.1) c =
      ok (Prod.map toG1x8 toU8
        ((List.range n).reverse.foldl (chainStep (ofG1x8 q)) m)) := by
  unfold g1x8.G1x8.times_z_loop
  refine loop_countdown _ (fun (m : G1x8 × Mmask8) c => (toU8 m.2, toG1x8 m.1, c))
    (chainStep (ofG1x8 q)) (Prod.map toG1x8 toU8) n ?_ ?_ c m hcn
  · intro m c hc
    simp [g1x8.G1x8.times_z_loop.body, hc]
    rfl
  · intro ⟨r, u⟩ c c' hc _
    obtain ⟨⟨d, du⟩, hd⟩ : ∃ d, r.double = d := ⟨_, rfl⟩
    obtain ⟨⟨a, au⟩, ha⟩ : ∃ a, d.add (ofG1x8 q) = a := ⟨_, rfl⟩
    simp only [g1x8.G1x8.times_z_loop.body]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val - (1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' := UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp only [bind_tc_ok, double_refines, Function.uncurry_def, Prod.map_fst,
      Prod.map_snd, ofG1x8_toG1x8, lift, is_lower_z_bit_refines, toU8_or, add_refines]
    simp only [chainStep, hd, ha]
    cases is_lower_z_bit c'.val <;> simp

theorem times_z_affine_refines (px py : fp8.Fp8) :
    g1x8.G1x8.times_z_affine px py =
      ok (Prod.map toG1x8 toU8 (times_z_affine (ofFp8 px) (ofFp8 py))) := by
  unfold g1x8.G1x8.times_z_affine
  simp only [from_affine_refines, bind_tc_ok, Z_BITS_index 0#usize (by decide)]
  exact times_z_affine_loop_refines px py (from_affine (ofFp8 px) (ofFp8 py), 0)
    _ Z_BITS[0]! (by simp)

theorem times_z_refines (self : g1x8.G1x8) :
    g1x8.G1x8.times_z self = ok (Prod.map toG1x8 toU8 (ofG1x8 self).times_z) := by
  unfold g1x8.G1x8.times_z
  simp only [bind_tc_ok, Z_BITS_index 0#usize (by decide)]
  have h := times_z_loop_refines self (ofG1x8 self, 0)
    (UScalar.ofNatCore Z_BITS[(0#usize).val]! (by decide)) Z_BITS[0]! (by simp)
  simpa only [toG1x8_ofG1x8] using h

theorem scott_membership_refines (px py : fp8.Fp8) :
    g1x8.G1x8.scott_membership px py =
      ok (toMembership (scott_membership (ofFp8 px) (ofFp8 py))) := by
  simp only [g1x8.G1x8.scott_membership, times_z_affine_refines, bind_tc_ok,
    Function.uncurry_def, scott_membership]
  generalize times_z_affine (ofFp8 px) (ofFp8 py) = T
  obtain ⟨zp, u1⟩ := T
  simp only [Prod.map_fst, Prod.map_snd, times_z_refines, ofG1x8_toG1x8, bind_tc_ok]
  generalize zp.times_z = T
  obtain ⟨zzp, u2⟩ := T
  simp [Fp8.is_zero_mask_refines, lift, BETA_MONT_refines, Fp8.splat_limbs_refines,
    Fp8.mul_refines, Fp8.square_refines, Fp8.eq_mask_refines, Fp8.neg_refines, toG1x8,
    toMembership]

end G1x8

end LeanBlsSimd
