import LeanBlsSimd.Pairing.LineScaling
import LeanBlsSimd.Pairing.FixedTableMeaning
import LeanBlsSimd.Spec.Line

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

def includeFp2 (a : Fp2) : Fp12 := ⟨Fp6.ofFp2 a, Fp6.zero⟩

theorem includeFp2_field (a : Fp2) :
    Fp12.toField (includeFp2 a) = fp2Embed (Fp2.toField a) := by
  rw [includeFp2, Fp12.toField_mk_zero, Fp6.toField_ofFp2]
  rfl

theorem pair_field (a b : Fp6) :
    Fp12.toField ⟨a, b⟩ = algebraMap Fp6Field Fp12Field (Fp6.toField a) +
      algebraMap Fp6Field Fp12Field (Fp6.toField b) * Fp12Field.w := by
  apply QuadraticAlgebra.ext <;> simp [Fp12Field.w]

theorem wInv2_field : Fp12.toField Embedded.wInv2 = (Fp12Field.w ^ 2)⁻¹ := by
  change Fp12.toField ⟨Fp6.v.inverse, Fp6.zero⟩ = _
  rw [Fp12.toField_mk_zero, Fp6.toField_inverse, Fp6.toField_v, map_inv₀, Fp12Field.w_sq]

theorem wInv3_field : Fp12.toField Embedded.wInv3 = (Fp12Field.w ^ 3)⁻¹ := by
  change Fp12.toField ⟨Fp6.zero, (Fp6.v * Fp6.v).inverse⟩ = _
  rw [pair_field, Fp6.toField_zero, map_zero, zero_add,
    Fp6.toField_inverse, map_mul, Fp6.toField_v, map_inv₀, map_mul, ← Fp12Field.w_sq]
  field_simp [w_ne_zero]

def untwist (t : Affine) : Embedded.Point :=
  ⟨includeFp2 t.1 * Embedded.wInv2, includeFp2 t.2 * Embedded.wInv3, false⟩

theorem untwist_x (t : Affine) :
    Fp12.toField (untwist t).x = fp2Embed (Fp2.toField t.1) * (Fp12Field.w ^ 2)⁻¹ := by
  simp only [untwist, map_mul, includeFp2_field, wInv2_field]

theorem untwist_y (t : Affine) :
    Fp12.toField (untwist t).y = fp2Embed (Fp2.toField t.2) * (Fp12Field.w ^ 3)⁻¹ := by
  simp only [untwist, map_mul, includeFp2_field, wInv3_field]

theorem line_field (a b c : Fp2) :
    Fp12.toField (Portable.Fp12.line a b c) =
      fp2Embed (Fp2.toField a) + fp2Embed (Fp2.toField b) * Fp12Field.w ^ 2 +
        fp2Embed (Fp2.toField c) * Fp12Field.w ^ 3 := by
  rw [show Fp12Field.w ^ 3 = Fp12Field.w ^ 2 * Fp12Field.w from pow_succ _ 2,
    Fp12Field.w_sq]
  rw [Portable.Fp12.line, pair_field]
  change algebraMap Fp6Field Fp12Field (Fp6Field.assemble
      (Fp2.toField a) (Fp2.toField b) 0) +
    algebraMap Fp6Field Fp12Field (Fp6Field.assemble 0 (Fp2.toField c) 0) * Fp12Field.w = _
  simp only [Fp6Field.assemble, map_add, map_mul, map_zero, zero_mul, add_zero, zero_add]
  change _ = algebraMap Fp6Field Fp12Field (Fp6Field.of (Fp2.toField a)) +
    algebraMap Fp6Field Fp12Field (Fp6Field.of (Fp2.toField b)) *
      algebraMap Fp6Field Fp12Field Fp6Field.v +
    algebraMap Fp6Field Fp12Field (Fp6Field.of (Fp2.toField c)) *
      (algebraMap Fp6Field Fp12Field Fp6Field.v * Fp12Field.w)
  ring

theorem tangent_field (x y : Fp2Field) :
    3 * (fp2Embed x * (Fp12Field.w ^ 2)⁻¹) * (fp2Embed x * (Fp12Field.w ^ 2)⁻¹) *
        (2 * (fp2Embed y * (Fp12Field.w ^ 3)⁻¹))⁻¹ =
      fp2Embed (3 * x * x * (2 * y)⁻¹) * Fp12Field.w⁻¹ := by
  simp only [map_mul, map_inv₀, map_ofNat, mul_inv_rev, inv_inv]
  field_simp [w_ne_zero]

theorem add_slope_field (x y u v : Fp2Field) :
    (fp2Embed v * (Fp12Field.w ^ 3)⁻¹ - fp2Embed y * (Fp12Field.w ^ 3)⁻¹) *
        (fp2Embed u * (Fp12Field.w ^ 2)⁻¹ - fp2Embed x * (Fp12Field.w ^ 2)⁻¹)⁻¹ =
      fp2Embed ((v - y) * (u - x)⁻¹) * Fp12Field.w⁻¹ := by
  rw [← sub_mul, ← sub_mul, mul_inv_rev, inv_inv]
  simp only [map_mul, map_sub, map_inv₀]
  field_simp [w_ne_zero]

theorem normalized_line_field (x y m xp yp : Fp2Field)
    (hc : m * x - y ≠ 0) :
    fp2Embed yp - fp2Embed y * (Fp12Field.w ^ 3)⁻¹ -
        (fp2Embed m * Fp12Field.w⁻¹) *
          (fp2Embed xp - fp2Embed x * (Fp12Field.w ^ 2)⁻¹) =
      lineScale (m * x - y) *
        (1 + fp2Embed (-m * (m * x - y)⁻¹ * xp) * Fp12Field.w ^ 2 +
          fp2Embed ((m * x - y)⁻¹ * yp) * Fp12Field.w ^ 3) := by
  have hc' : fp2Embed (m * x - y) ≠ 0 := (map_ne_zero fp2Embed).mpr hc
  rw [map_sub, map_mul] at hc'
  simp only [lineScale, map_mul, map_neg, map_sub, map_inv₀]
  field_simp [w_ne_zero, hc']
  ring

end

end LeanBlsSimd.Pairing
