import LeanBlsSimd.Pairing.Untwist

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

theorem includeFp2_nat (n : Nat) :
    Fp12.toField (includeFp2 (Fp2.ofFp (Fp.ofNat n))) = n := by
  rw [includeFp2_field]
  have hn : Fp2.toField (Fp2.ofFp (Fp.ofNat n)) = (n : Fp2Field) := by
    apply QuadraticAlgebra.ext <;> rfl
  rw [hn, map_natCast]

theorem tangent_slope (t : Affine) :
    Fp12.toField (Line.tangentSlope (untwist t).x (untwist t).y) =
      fp2Embed (3 * Fp2.toField t.1 * Fp2.toField t.1 * (2 * Fp2.toField t.2)⁻¹) *
        Fp12Field.w⁻¹ := by
  unfold Line.tangentSlope
  change Fp12.toField (includeFp2 (Fp2.ofFp (Fp.ofNat 3)) * (untwist t).x *
      (untwist t).x * (includeFp2 (Fp2.ofFp (Fp.ofNat 2)) * (untwist t).y).inverse) = _
  simp only [map_mul, Fp12.toField_inverse, includeFp2_nat, untwist_x, untwist_y]
  simpa only [map_mul, map_inv₀, map_ofNat, Nat.cast_ofNat] using
    tangent_field (Fp2.toField t.1) (Fp2.toField t.2)

theorem add_slope (t q : Affine) :
    Fp12.toField (Line.addSlope (untwist t).x (untwist t).y (untwist q).x (untwist q).y) =
      fp2Embed ((Fp2.toField q.2 - Fp2.toField t.2) *
        (Fp2.toField q.1 - Fp2.toField t.1)⁻¹) * Fp12Field.w⁻¹ := by
  simp only [Line.addSlope, map_mul, Fp12.toField_sub, Fp12.toField_inverse, untwist_x, untwist_y]
  simpa only [map_mul, map_inv₀] using
    add_slope_field (Fp2.toField t.1) (Fp2.toField t.2) (Fp2.toField q.1) (Fp2.toField q.2)

namespace FixedTable

def current (step : Fin 68) (pair : Fin 2) : Affine := point pair ⟨step.val, by omega⟩
def next (step : Fin 68) (pair : Fin 2) : Affine := point pair ⟨step.val + 1, by omega⟩

def normalizer (step : Fin 68) (pair : Fin 2) : Fp2Field :=
  Fp2.toField (slope pair step) * Fp2.toField (current step pair).1 -
    Fp2.toField (current step pair).2

def specSlope (step : Fin 68) (pair : Fin 2) : Fp12 :=
  let t := untwist (current step pair)
  let q := untwist (fixedPoint pair)
  if lineKind step then Line.addSlope t.x t.y q.x q.y else Line.tangentSlope t.x t.y

def normalizedLine (step : Fin 68) (pair : Fin 2) (xp yp : Fp2) : Fp12 :=
  Portable.Fp12.line Fp2.one (coefficient step pair 0 * xp) (coefficient step pair 1 * yp)

theorem normalizer_ne_zero (step : Fin 68) (pair : Fin 2) : normalizer step pair ≠ 0 := by
  have h := (step_correct step pair).2.2.2.2.2.1
  simpa only [normalizer, current, Fp2.toField_sub, map_mul] using h

theorem slope_field (step : Fin 68) (pair : Fin 2) :
    Fp12.toField (specSlope step pair) =
      fp2Embed (Fp2.toField (slope pair step)) * Fp12Field.w⁻¹ := by
  have hm := (step_correct step pair).2.1
  dsimp only [specSlope]
  split_ifs with hadd
  · rw [add_slope, hm]
    simp only [slopeNumerator, slopeDenominator, hadd, ↓reduceIte, Fp2.toField_sub]
    rfl
  · rw [tangent_slope, hm]
    have hthree : Fp2.toField (Fp2.ofFp (Fp.ofNat 3)) = (3 : Fp2Field) := by
      apply QuadraticAlgebra.ext <;> rfl
    simp only [slopeNumerator, slopeDenominator, hadd, Bool.false_eq_true, if_false, map_mul, map_add, hthree]
    rw [two_mul]
    rfl

theorem line_value (step : Fin 68) (pair : Fin 2) (xp yp : Fp2) :
    Fp12.toField (Line.evalAt (untwist (current step pair)).x
        (untwist (current step pair)).y (specSlope step pair) (includeFp2 xp) (includeFp2 yp)) =
      lineScale (normalizer step pair) * Fp12.toField (normalizedLine step pair xp yp) := by
  have hc := normalizer_ne_zero step pair
  have hl := (step_correct step pair).2.2.2.2.2.2
  simp only [Fp2.toField_sub, map_mul] at hl
  simp only [Line.evalAt, Fp12.toField_sub, map_mul, untwist_x, untwist_y,
    slope_field, includeFp2_field, normalizedLine, line_field, Fp2.toField_one, map_one]
  rw [hl.1, hl.2]
  simpa only [map_mul, map_neg, map_inv₀] using
    normalized_line_field (Fp2.toField (current step pair).1)
      (Fp2.toField (current step pair).2) (Fp2.toField (slope pair step))
      (Fp2.toField xp) (Fp2.toField yp) hc

theorem line_final_power (step : Fin 68) (pair : Fin 2) (xp yp : Fp2) :
    Fp12.toField (Line.evalAt (untwist (current step pair)).x
        (untwist (current step pair)).y (specSlope step pair) (includeFp2 xp) (includeFp2 yp)) ^
        finalExpExponent = Fp12.toField (normalizedLine step pair xp yp) ^ finalExpExponent := by
  rw [line_value, lineScale_remove _ (normalizer_ne_zero step pair)]

end FixedTable

end

end LeanBlsSimd.Pairing
