import LeanBlsSimd.Refines.Fp2x8
import LeanBlsSimd.Model.G2x8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

/-!
# `g2x8.rs`

`ofG2x8` converts each coordinate with `ofFp2x8`, and `ofMembership` each mask with `ofU8`.

The Rust `times_minus_z` counts down from `Z_BITS[0]` and compares the decremented counter with
`Z_BITS[1]` to `Z_BITS[5]`. The model folds `chainStep` over `(List.range Z_BITS[0]!).reverse`.
`chainStep` tests `Z_BITS.contains`, which also lists `Z_BITS[0]`. The counter stays below
`Z_BITS[0]`, so both add at the same bits.
-/

namespace LeanBlsSimd

def ofG2x8 (a : g2x8.G2x8) : G2x8 := ⟨ofFp2x8 a.x, ofFp2x8 a.y, ofFp2x8 a.z⟩

def toG2x8 (x : G2x8) : g2x8.G2x8 := ⟨toFp2x8 x.x, toFp2x8 x.y, toFp2x8 x.z⟩

@[simp] theorem x_ofG2x8 (a : g2x8.G2x8) : (ofG2x8 a).x = ofFp2x8 a.x := rfl
@[simp] theorem y_ofG2x8 (a : g2x8.G2x8) : (ofG2x8 a).y = ofFp2x8 a.y := rfl
@[simp] theorem z_ofG2x8 (a : g2x8.G2x8) : (ofG2x8 a).z = ofFp2x8 a.z := rfl

@[simp] theorem ofG2x8_mk (x y z : fp2x8.Fp2x8) :
    ofG2x8 { x, y, z } = { x := ofFp2x8 x, y := ofFp2x8 y, z := ofFp2x8 z } := rfl

@[simp] theorem ofG2x8_toG2x8 (x : G2x8) : ofG2x8 (toG2x8 x) = x := by
  simp [ofG2x8, toG2x8]

@[simp] theorem toG2x8_ofG2x8 (a : g2x8.G2x8) : toG2x8 (ofG2x8 a) = a := by
  simp [ofG2x8, toG2x8]

def ofMembership (a : silver_crypto_simd.bls.Membership) : LeanBlsSimd.Membership :=
  ⟨ofU8 a.members, ofU8 a.undecided⟩

def toMembership (x : LeanBlsSimd.Membership) : silver_crypto_simd.bls.Membership :=
  ⟨toU8 x.members, toU8 x.undecided⟩

@[simp] theorem ofMembership_toMembership (x : LeanBlsSimd.Membership) :
    ofMembership (toMembership x) = x := rfl

@[simp] theorem toMembership_ofMembership (a : silver_crypto_simd.bls.Membership) :
    toMembership (ofMembership a) = a := rfl

@[simp] theorem toU8_not (a : UInt8) : ~~~ toU8 a = toU8 (~~~ a) := rfl

namespace G2x8

theorem double_refines (self : g2x8.G2x8) :
    g2x8.G2x8.double self = ok (Prod.map toG2x8 toU8 (ofG2x8 self).double) := by
  simp [g2x8.G2x8.double, Fp2x8.square_refines, Fp2x8.add_refines, Fp2x8.sub_refines,
    Fp2x8.double_refines, Fp2x8.mul_refines, Fp2x8.is_zero_mask_refines, lift, G2x8.double,
    toG2x8]

theorem add_affine_refines (self : g2x8.G2x8) (qx qy : fp2x8.Fp2x8) :
    g2x8.G2x8.add_affine self qx qy =
      ok (Prod.map toG2x8 toU8 ((ofG2x8 self).add_affine (ofFp2x8 qx) (ofFp2x8 qy))) := by
  simp [g2x8.G2x8.add_affine, Fp2x8.square_refines, Fp2x8.add_refines, Fp2x8.sub_refines,
    Fp2x8.double_refines, Fp2x8.mul_refines, Fp2x8.is_zero_mask_refines, lift, G2x8.add_affine,
    toG2x8]

theorem times_minus_z_loop_refines (px py : fp2x8.Fp2x8) (m : G2x8 × Mmask8) (c : U32) (n : ℕ)
    (hcn : c.val = n) (hn : n ≤ 63) :
    g2x8.G2x8.times_minus_z_loop px py (toU8 m.2) (toG2x8 m.1) c =
      ok (Prod.map toG2x8 toU8
        ((List.range n).reverse.foldl (chainStep (ofFp2x8 px) (ofFp2x8 py)) m)) := by
  unfold g2x8.G2x8.times_minus_z_loop
  refine loop_countdown _ (fun (m : G2x8 × Mmask8) c => (toU8 m.2, toG2x8 m.1, c))
    (chainStep (ofFp2x8 px) (ofFp2x8 py)) (Prod.map toG2x8 toU8) n ?_ ?_ c m hcn
  · intro m c hc
    simp [g2x8.G2x8.times_minus_z_loop.body, hc]
    rfl
  · intro ⟨r, u⟩ c c' hc hcn
    obtain ⟨⟨d, du⟩, hd⟩ : ∃ d, r.double = d := ⟨_, rfl⟩
    obtain ⟨⟨a, au⟩, ha⟩ : ∃ a, d.add_affine (ofFp2x8 px) (ofFp2x8 py) = a := ⟨_, rfl⟩
    simp only [g2x8.G2x8.times_minus_z_loop.body]
    rw [if_pos (by simp; omega), sub_ok _ _ (by simp; omega)]
    have e : (UScalar.ofNatCore (c.val - (1#u32).val) (by have := c.hBounds; omega) : U32) =
        c' :=
      UScalar.eq_of_val_eq (by simp; omega)
    rw [e]
    simp (disch := decide) only [bind_tc_ok, double_refines, Function.uncurry_def, Prod.map_fst,
      Prod.map_snd, ofG2x8_toG2x8, lift, Z_BITS_index, toU8_or, add_affine_refines,
      UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
    simp only [show Z_BITS[1]! = 62 from rfl, show Z_BITS[2]! = 60 from rfl,
      show Z_BITS[3]! = 57 from rfl, show Z_BITS[4]! = 48 from rfl, show Z_BITS[5]! = 16 from rfl]
    simp only [chainStep, hd, ha]
    by_cases h : c'.val = 62 ∨ c'.val = 60 ∨ c'.val = 57 ∨ c'.val = 48 ∨ c'.val = 16
    · have hz : Z_BITS.contains c'.val := by simp [Z_BITS]; omega
      rw [if_pos hz]
      rcases h with h | h | h | h | h <;> simp [h]
    · have hz : c'.val ∉ Z_BITS := by simp [Z_BITS]; omega
      simp only [not_or] at h
      simp [h, hz]

theorem times_minus_z_refines (px py : fp2x8.Fp2x8) :
    g2x8.G2x8.times_minus_z px py =
      ok (Prod.map toG2x8 toU8 (G2x8.times_minus_z (ofFp2x8 px) (ofFp2x8 py))) := by
  unfold g2x8.G2x8.times_minus_z
  simp only [Fp2x8.one_refines, bind_tc_ok, Z_BITS_index 0#usize (by decide)]
  have h := times_minus_z_loop_refines px py (⟨ofFp2x8 px, ofFp2x8 py, Fp2x8.one⟩, 0)
    (UScalar.ofNatCore Z_BITS[(0#usize).val]! (by decide)) Z_BITS[0]! (by simp) (by decide)
  simp only [toG2x8, toFp2x8_ofFp2x8] at h
  rw [show (0#u8) = toU8 0 from rfl, h, G2x8.times_minus_z]

theorem scott_membership_refines (px py : fp2x8.Fp2x8) :
    g2x8.G2x8.scott_membership px py =
      ok (toMembership (G2x8.scott_membership (ofFp2x8 px) (ofFp2x8 py))) := by
  simp only [g2x8.G2x8.scott_membership, times_minus_z_refines, bind_tc_ok, Function.uncurry_def,
    G2x8.scott_membership]
  generalize G2x8.times_minus_z (ofFp2x8 px) (ofFp2x8 py) = T
  obtain ⟨mzp, cu⟩ := T
  simp [Fp2x8.is_zero_mask_refines, lift, PSI_X_MONT_refines, Fp8.splat_limbs_refines,
    Fp8.mul_refines, Fp2x8.conjugate_refines, PSI_Y_MONT_refines, Fp2x8.splat_refines,
    Fp2x8.mul_refines, Fp2x8.square_refines, Fp2x8.eq_mask_refines, Fp2x8.neg_refines, toG2x8,
    toMembership]

end G2x8

end LeanBlsSimd
