import LeanBlsSimd.Pairing.FixedLine

open EthLib.Cryptography Bls

namespace LeanBlsSimd.Pairing

noncomputable section

def embeddedChord (t r : Embedded.Point) (m : Fp12) : Embedded.Point :=
  let x := m * m - t.x - r.x
  ⟨x, m * (t.x - x) - t.y, false⟩

theorem chord_untwist (t r : Affine) (m : Fp2) (s : Fp12)
    (hs : Fp12.toField s = fp2Embed (Fp2.toField m) * Fp12Field.w⁻¹) :
    embeddedChord (untwist t) (untwist r) s = untwist (chord t r m) := by
  change Embedded.Point.mk _ _ false = Embedded.Point.mk _ _ false
  congr 1
  · apply Fp12.toField.injective
    change Fp12.toField (s * s - (untwist t).x - (untwist r).x) =
      Fp12.toField (untwist (chord t r m)).x
    simp only [Fp12.toField_sub, map_mul, untwist_x, hs, chord, Fp2.toField_sub, map_sub]
    field_simp [w_ne_zero]
  · apply Fp12.toField.injective
    change Fp12.toField (s * ((untwist t).x - (s * s - (untwist t).x - (untwist r).x)) -
      (untwist t).y) = Fp12.toField (untwist (chord t r m)).y
    simp only [Fp12.toField_sub, map_mul, untwist_x, untwist_y, hs, chord, Fp2.toField_sub, map_sub]
    field_simp [w_ne_zero]

def evaluationPoint (xp yp : Fp2) : Embedded.Point := ⟨includeFp2 xp, includeFp2 yp, false⟩

def action (q p : Embedded.Point) (add : Bool) (state : Embedded.Point × Fp12) :
    Embedded.Point × Fp12 :=
  if add then millerAdd state.1 q p state.2 else millerDouble state.1 p state.2

theorem double_untwist (t : Affine) (p : Embedded.Point) (f : Fp12) :
    millerDouble (untwist t) p f =
      (embeddedChord (untwist t) (untwist t)
          (Line.tangentSlope (untwist t).x (untwist t).y),
        f * f * Line.evalAt (untwist t).x (untwist t).y
          (Line.tangentSlope (untwist t).x (untwist t).y) p.x p.y) := rfl

theorem add_untwist (t q : Affine) (p : Embedded.Point) (f : Fp12) :
    millerAdd (untwist t) (untwist q) p f =
      (embeddedChord (untwist t) (untwist q)
          (Line.addSlope (untwist t).x (untwist t).y (untwist q).x (untwist q).y),
        f * Line.evalAt (untwist t).x (untwist t).y
          (Line.addSlope (untwist t).x (untwist t).y (untwist q).x (untwist q).y) p.x p.y) := rfl

namespace FixedTable

def evaluatedLine (step : Fin 68) (pair : Fin 2) (xp yp : Fp2) : Fp12 :=
  Line.evalAt (untwist (current step pair)).x (untwist (current step pair)).y
    (specSlope step pair) (includeFp2 xp) (includeFp2 yp)

theorem point_step (step : Fin 68) (pair : Fin 2) :
    embeddedChord (untwist (current step pair))
      (untwist (if lineKind step then fixedPoint pair else current step pair)) (specSlope step pair) =
        untwist (next step pair) := by
  rw [chord_untwist _ _ (slope pair step) _ (slope_field step pair)]
  exact congrArg untwist (step_correct step pair).2.2.1.symm

theorem action_step (step : Fin 68) (pair : Fin 2) (xp yp : Fp2) (f : Fp12) :
    action (untwist (fixedPoint pair)) (evaluationPoint xp yp) (lineKind step)
      (untwist (current step pair), f) =
      (untwist (next step pair),
        (if lineKind step then f else f * f) * evaluatedLine step pair xp yp) := by
  have hp := point_step step pair
  unfold action
  split_ifs with h
  · simp only [h, if_true, specSlope] at hp
    rw [add_untwist]
    rw [hp]
    simp only [evaluatedLine, specSlope, h, if_true]
    rfl
  · simp only [h, Bool.false_eq_true, if_false, specSlope] at hp
    rw [double_untwist]
    rw [hp]
    simp only [evaluatedLine, specSlope, h, Bool.false_eq_true, if_false]
    rfl

end FixedTable

end

end LeanBlsSimd.Pairing
