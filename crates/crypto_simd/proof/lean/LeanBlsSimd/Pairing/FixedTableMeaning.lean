import LeanBlsSimd.Pairing.FixedTable

open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Pairing

private theorem radix_inverse : Fp.ofNat (2^416) * (Fp.ofNat (2^416)).inverse = Fp.one := by
  decide +kernel

theorem coefficient_of_montgomery (step : Fin 68) (pair i : Fin 2) (a : Fp2)
    (h : (encodedCoefficient step pair i).beq (montgomery a) = true) :
    coefficient step pair i = a := by
  have he := (Fp2.beq_iff _ _).mp h
  have h0 := congrArg QuadraticAlgebra.re he
  have h1 := congrArg QuadraticAlgebra.im he
  apply Fp2.toField.injective
  apply QuadraticAlgebra.ext
  · change Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step
        ⟨4 * pair.val + 2 * i.val, by omega⟩)) * (Fp.ofNat (2^416)).inverse = a.c0
    change Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step
        ⟨4 * pair.val + 2 * i.val, by omega⟩)) = a.c0 * Fp.ofNat (2^416) at h0
    rw [h0, mul_assoc, radix_inverse]
    exact mul_one (a.c0 : ZMod Fp.modulus)
  · change Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step
        ⟨4 * pair.val + 2 * i.val + 1, by omega⟩)) * (Fp.ofNat (2^416)).inverse = a.c1
    change Fp.ofNat (Kzg.pairingRawValue (Kzg.pairingRaw step
        ⟨4 * pair.val + 2 * i.val + 1, by omega⟩)) = a.c1 * Fp.ofNat (2^416) at h1
    rw [h1, mul_assoc, radix_inverse]
    exact mul_one (a.c1 : ZMod Fp.modulus)

namespace FixedTable

theorem point_initial (pair : Fin 2) : point pair 0 = fixedPoint pair := by
  apply Prod.ext
  · exact Fp2.toField.injective ((Fp2.beq_iff _ _).mp (initial pair).1)
  · exact Fp2.toField.injective ((Fp2.beq_iff _ _).mp (initial pair).2)

theorem entry_decodes (step : Fin 68) (pair i : Fin 2) :
    coefficient step pair i = if i = 0 then (lines pair step).1 else (lines pair step).2 := by
  have h := certificates step pair
  rcases h with ⟨_, _, _, _, _, _, _, _, _, h0, h1⟩
  fin_cases i
  · exact coefficient_of_montgomery step pair 0 _ h0
  · exact coefficient_of_montgomery step pair 1 _ h1

/-- The running point and slope certified for each of the 136 fixed lines. -/
theorem step_correct (step : Fin 68) (pair : Fin 2) :
    let t := point pair ⟨step.val, by omega⟩
    let next := point pair ⟨step.val + 1, by omega⟩
    let q := fixedPoint pair
    let d := slopeDenominator (lineKind step) q t
    let n := slopeNumerator (lineKind step) q t
    let m := slope pair step
    let c := m * t.1 - t.2
    Fp2.toField d ≠ 0 ∧
    Fp2.toField m = Fp2.toField n * (Fp2.toField d)⁻¹ ∧
    next = chord t (if lineKind step then q else t) m ∧
    onCurve t = true ∧ onCurve next = true ∧
    Fp2.toField c ≠ 0 ∧
    Fp2.toField (coefficient step pair 0) = -Fp2.toField m * (Fp2.toField c)⁻¹ ∧
    Fp2.toField (coefficient step pair 1) = (Fp2.toField c)⁻¹ := by
  dsimp only
  rcases certificates step pair with ⟨hd, hm, hx, hy, hb, ha, hc, hl1, hl2, _, _⟩
  have hd' : Fp2.toField (slopeDenominator (lineKind step) (fixedPoint pair)
      (point pair ⟨step.val, by omega⟩)) ≠ 0 := by
    intro h
    have hh := (Fp2.isZero_iff _).mpr h
    rw [hd] at hh
    contradiction
  have hc' : Fp2.toField (slope pair step * (point pair ⟨step.val, by omega⟩).1 -
      (point pair ⟨step.val, by omega⟩).2) ≠ 0 := by
    intro h
    have hh := (Fp2.isZero_iff _).mpr h
    rw [hc] at hh
    contradiction
  refine ⟨hd', ?_, ?_, hb, ha, hc', ?_, ?_⟩
  · have h := (Fp2.beq_iff _ _).mp hm
    rw [map_mul] at h
    calc
      _ = (Fp2.toField (slope pair step) * _) * _⁻¹ := by rw [mul_assoc, mul_inv_cancel₀ hd', mul_one]
      _ = _ := by rw [h]
  · apply Prod.ext
    · exact Fp2.toField.injective ((Fp2.beq_iff _ _).mp hx)
    · exact Fp2.toField.injective ((Fp2.beq_iff _ _).mp hy)
  · rw [entry_decodes]
    simp only [↓reduceIte]
    have h := (Fp2.beq_iff _ _).mp hl1
    rw [map_mul, Fp2.toField_neg] at h
    calc
      _ = (Fp2.toField (lines pair step).1 * _) * _⁻¹ := by rw [mul_assoc, mul_inv_cancel₀ hc', mul_one]
      _ = _ := by rw [h]
  · rw [entry_decodes]
    simp only [show (1 : Fin 2) ≠ 0 from by decide, ↓reduceIte]
    have h := (Fp2.beq_iff _ _).mp hl2
    rw [map_mul, Fp2.toField_one] at h
    exact eq_inv_of_mul_eq_one_left h

end FixedTable

end LeanBlsSimd.Pairing
