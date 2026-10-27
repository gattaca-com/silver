import LeanBlsSimd.PairingProduct.StepField

open EthLib.Cryptography Bls
open LeanBlsSimd.Pairing

namespace LeanBlsSimd.PairingProduct.Step

noncomputable section

def encodeAffine (t : Fp2Field × Fp2Field) : Pairing.Affine :=
  (Fp2.toField.symm t.1, Fp2.toField.symm t.2)

def affine (t : Point) : Pairing.Affine := encodeAffine (affineField t)

def evaluatedLine (o : Output) (xp yp : Fp2Field) : Fp12Field :=
  fp2Embed (o.line 0) + fp2Embed (o.line 1 * (-2 * xp)) * Fp12Field.w ^ 2 +
    fp2Embed (o.line 2 * (2 * yp)) * Fp12Field.w ^ 3

def scale (c : Fp2Field) : Fp12Field := fp2Embed c * Fp12Field.w ^ 3

theorem scale_final_power (c : Fp2Field) (hc : c ≠ 0) :
    scale c ^ finalExpExponent = 1 := by
  apply period_four_final_power
  rw [scale, mul_pow, fp2_period_four c hc, w_cube_period, one_mul]

theorem scale_remove (c : Fp2Field) (hc : c ≠ 0) (f : Fp12Field) :
    (f * scale c) ^ finalExpExponent = f ^ finalExpExponent := by
  rw [mul_pow, scale_final_power c hc, mul_one]

theorem encodeAffine_chord (t q : Fp2Field × Fp2Field) (m : Fp2Field) :
    encodeAffine (chordField t q m) =
      chord (encodeAffine t) (encodeAffine q) (Fp2.toField.symm m) := by
  apply Prod.ext <;> apply Fp2.toField.injective <;>
    simp only [encodeAffine, chordField, chord, Fp2.toField_sub, map_mul,
      RingEquiv.apply_symm_apply]

theorem double_slope_spec (t : Point) :
    Fp12.toField (Line.tangentSlope (untwist (affine t)).x (untwist (affine t)).y) =
      fp2Embed (doubleSlope t) * Fp12Field.w⁻¹ := by
  simpa [affine, encodeAffine, doubleSlope, div_eq_mul_inv] using tangent_slope (affine t)

theorem add_slope_spec (t : Point) (q : Fp2Field × Fp2Field) :
    Fp12.toField (Line.addSlope (untwist (affine t)).x (untwist (affine t)).y
        (untwist (encodeAffine q)).x (untwist (encodeAffine q)).y) =
      fp2Embed (addSlope t q) * Fp12Field.w⁻¹ := by
  simpa [affine, encodeAffine, addSlope, div_eq_mul_inv] using
    add_slope (affine t) (encodeAffine q)

theorem line_of_coefficients (o : Output) (t : Fp2Field × Fp2Field)
    (m c xp yp : Fp2Field) (s : Fp12)
    (hs : Fp12.toField s = fp2Embed m * Fp12Field.w⁻¹)
    (h0 : o.line 0 = c * (m * t.1 - t.2))
    (h1 : o.line 1 * (-2) = -(c * m)) (h2 : o.line 2 * 2 = c) :
    evaluatedLine o xp yp =
      Fp12.toField (Line.evalAt (untwist (encodeAffine t)).x
        (untwist (encodeAffine t)).y s
        (includeFp2 (Fp2.toField.symm xp)) (includeFp2 (Fp2.toField.symm yp))) * scale c := by
  have h1' : o.line 1 * (-2 * xp) = -(c * m) * xp := by rw [← mul_assoc, h1]
  have h2' : o.line 2 * (2 * yp) = c * yp := by rw [← mul_assoc, h2]
  simp only [evaluatedLine, h0, h1', h2', Line.evalAt, Fp12.toField_sub, map_mul,
    untwist_x, untwist_y, hs, includeFp2_field, encodeAffine, RingEquiv.apply_symm_apply,
    scale, map_sub, map_neg]
  field_simp [w_ne_zero]
  ring

theorem double_line (t : Point) (xp yp : Fp2Field) (h : (double t).point 2 ≠ 0) :
    evaluatedLine (double t) xp yp =
      Fp12.toField (Line.evalAt (untwist (affine t)).x (untwist (affine t)).y
        (Line.tangentSlope (untwist (affine t)).x (untwist (affine t)).y)
        (includeFp2 (Fp2.toField.symm xp)) (includeFp2 (Fp2.toField.symm yp))) *
          scale (doubleScale t) := by
  obtain ⟨h0, h1, h2⟩ := double_coefficients t h
  exact line_of_coefficients (double t) (affineField t) (doubleSlope t) (doubleScale t)
    xp yp _ (double_slope_spec t) h0 h1 h2

theorem add_line (t : Point) (q : Fp2Field × Fp2Field) (xp yp : Fp2Field)
    (h : (add t q).point 2 ≠ 0) :
    evaluatedLine (add t q) xp yp =
      Fp12.toField (Line.evalAt (untwist (affine t)).x (untwist (affine t)).y
        (Line.addSlope (untwist (affine t)).x (untwist (affine t)).y
          (untwist (encodeAffine q)).x (untwist (encodeAffine q)).y)
        (includeFp2 (Fp2.toField.symm xp)) (includeFp2 (Fp2.toField.symm yp))) *
          scale (addScale t q) := by
  obtain ⟨h0, h1, h2⟩ := add_coefficients t q h
  exact line_of_coefficients (add t q) (affineField t) (addSlope t q) (addScale t q)
    xp yp _ (add_slope_spec t q) h0 h1 h2

theorem double_next (t : Point) (h : (double t).point 2 ≠ 0) :
    untwist (affine (double t).point) =
      embeddedChord (untwist (affine t)) (untwist (affine t))
        (Line.tangentSlope (untwist (affine t)).x (untwist (affine t)).y) := by
  rw [chord_untwist _ _ (Fp2.toField.symm (doubleSlope t)) _
    (by simpa using double_slope_spec t)]
  exact congrArg untwist ((congrArg encodeAffine (double_point t h)).trans
    (encodeAffine_chord (affineField t) (affineField t) (doubleSlope t)))

theorem add_next (t : Point) (q : Fp2Field × Fp2Field) (h : (add t q).point 2 ≠ 0) :
    untwist (affine (add t q).point) =
      embeddedChord (untwist (affine t)) (untwist (encodeAffine q))
        (Line.addSlope (untwist (affine t)).x (untwist (affine t)).y
          (untwist (encodeAffine q)).x (untwist (encodeAffine q)).y) := by
  rw [chord_untwist _ _ (Fp2.toField.symm (addSlope t q)) _
    (by simpa using add_slope_spec t q)]
  exact congrArg untwist ((congrArg encodeAffine (add_point t q h)).trans
    (encodeAffine_chord (affineField t) q (addSlope t q)))

theorem double_line_final_power (t : Point) (xp yp : Fp2Field)
    (h : (double t).point 2 ≠ 0) :
    evaluatedLine (double t) xp yp ^ finalExpExponent =
      Fp12.toField (Line.evalAt (untwist (affine t)).x (untwist (affine t)).y
        (Line.tangentSlope (untwist (affine t)).x (untwist (affine t)).y)
        (includeFp2 (Fp2.toField.symm xp)) (includeFp2 (Fp2.toField.symm yp))) ^
          finalExpExponent := by
  rw [double_line t xp yp h, scale_remove _ (doubleScale_ne_zero t h)]

theorem add_line_final_power (t : Point) (q : Fp2Field × Fp2Field) (xp yp : Fp2Field)
    (h : (add t q).point 2 ≠ 0) :
    evaluatedLine (add t q) xp yp ^ finalExpExponent =
      Fp12.toField (Line.evalAt (untwist (affine t)).x (untwist (affine t)).y
        (Line.addSlope (untwist (affine t)).x (untwist (affine t)).y
          (untwist (encodeAffine q)).x (untwist (encodeAffine q)).y)
        (includeFp2 (Fp2.toField.symm xp)) (includeFp2 (Fp2.toField.symm yp))) ^
          finalExpExponent := by
  rw [add_line t q xp yp h, scale_remove _ (addScale_ne_zero t q h)]

end

end LeanBlsSimd.PairingProduct.Step
