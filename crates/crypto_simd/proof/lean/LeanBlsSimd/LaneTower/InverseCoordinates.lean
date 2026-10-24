import LeanBlsSimd.LaneTower.Inverse

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls
open EthLib.Cryptography Bls

namespace LeanBlsSimd.LaneTower

theorem shuffle_invLeft {α : Type} (a b : V α) :
    shuffle invLeft a b = ![a 0, b 2, a 1, a 1, a 0, a 0, a 0, a 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invRight {α : Type} (a b : V α) :
    shuffle invRight a b = ![a 0, a 2, a 1, a 2, a 1, a 2, a 0, a 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invSub {α : Type} (a b : V α) :
    shuffle invSub a b = ![b 3, a 4, a 5, a 0, a 0, a 0, a 0, a 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invDet {α : Type} (a b : V α) :
    shuffle invDet a b = ![a 0, a 2, a 1, a 0, a 0, a 0, a 0, a 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invComponents {α : Type} (a b : V α) :
    shuffle invComponents a b = ![a 0, b 0, a 0, b 0, a 0, b 0, a 0, b 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invSwap {α : Type} (a b : V α) :
    shuffle invSwap a b = ![a 1, a 0, a 1, a 0, a 1, a 0, a 1, a 0] := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_invEmbed {α : Type} (a b : V α) :
    shuffle invEmbed a b = ![a 0, a 1, a 2, b 0, b 0, b 0, b 0, b 0] := by
  unfold invEmbed fp12.Z
  funext l
  fin_cases l <;> rfl

theorem shuffle_repeat0 {α : Type} (a : V α) :
    shuffle (Array.repeat 8#usize 0#i64) a a = fun _ => a 0 := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_repeat1 {α : Type} (a : V α) :
    shuffle (Array.repeat 8#usize 1#i64) a a = fun _ => a 1 := by
  funext l
  fin_cases l <;> rfl

theorem shuffle_repeat2 {α : Type} (a : V α) :
    shuffle (Array.repeat 8#usize 2#i64) a a = fun _ => a 2 := by
  funext l
  fin_cases l <;> rfl

theorem adjugate_coefficients (a : P F) :
    ![asFp2 (inverseAdjugate a) 0, asFp2 (inverseAdjugate a) 1, asFp2 (inverseAdjugate a) 2] =
      ![asFp2 a 0 * asFp2 a 0 - (asFp2 a 1 * asFp2 a 2) * Fp6Field.xi,
        (asFp2 a 2 * asFp2 a 2) * Fp6Field.xi - asFp2 a 0 * asFp2 a 1,
        asFp2 a 1 * asFp2 a 1 - asFp2 a 0 * asFp2 a 2] := by
  funext l
  fin_cases l <;> apply QuadraticAlgebra.ext
  all_goals
    simp only [inverseAdjugate, inverseProducts, shuffle2, shuffle_invLeft,
      shuffle_invRight, shuffle_invSub, asFp2, xi2, sub2, mul2, Matrix.cons_val]
    simp [Fp6Field.xi, show (1 : Fp2Field).re = 1 from rfl,
      show (1 : Fp2Field).im = 0 from rfl] <;> ring

theorem determinant_coefficient (a t : P F) :
    asFp2 (inverseDeterminant a t) 0 =
      asFp2 a 0 * asFp2 t 0 + (asFp2 a 2 * asFp2 t 1) * Fp6Field.xi +
        (asFp2 a 1 * asFp2 t 2) * Fp6Field.xi := by
  apply QuadraticAlgebra.ext
  all_goals
    simp only [inverseDeterminant, inverseDetProducts, shuffle2, shuffle_invDet,
      shuffle_repeat1, shuffle_repeat2, asFp2, add2, xi2, mul2, Matrix.cons_val]
    simp [Fp6Field.xi, show (1 : Fp2Field).re = 1 from rfl,
      show (1 : Fp2Field).im = 0 from rfl]
    ring

theorem determinant_inverse_coefficient (a : P F) (l : Fin 8) :
    asFp2 (determinantInverse a) l = (asFp2 a 0)⁻¹ := by
  have hn : QuadraticAlgebra.norm (asFp2 a 0) = a.1 0 * a.1 0 + a.2 0 * a.2 0 := by
    simp [QuadraticAlgebra.norm_def, asFp2]
  change asFp2 (determinantInverse a) l = (QuadraticAlgebra.norm (asFp2 a 0))⁻¹ • star (asFp2 a 0)
  rw [hn]
  apply QuadraticAlgebra.ext
  all_goals
    simp only [determinantInverse, repeatFirst, shuffle_repeat0, determinantNorm,
      determinantSquares, shuffle_invComponents, shuffle_invSwap, Matrix.cons_val, asFp2]
    simp
    ring

theorem value_field (a : P F) : Fp12.toField (value a) =
    (⟨Fp6Field.assemble (asFp2 a 0) (asFp2 a 1) (asFp2 a 2),
      Fp6Field.assemble (asFp2 a 3) (asFp2 a 4) (asFp2 a 5)⟩ : Fp12Field) := rfl

theorem inverse_embed_field (t d : P F) :
    Fp12.toField (value (inverseEmbed t d)) = algebraMap Fp6Field Fp12Field
      (Fp6Field.assemble (asFp2 t 0) (asFp2 t 1) (asFp2 t 2) *
        Fp6Field.of (asFp2 d 0)⁻¹) := by
  have h (l : Fin 3) : asFp2 (inverseEmbed t d) ⟨l.val, by omega⟩ =
      asFp2 t ⟨l.val, by omega⟩ * (asFp2 d 0)⁻¹ := by
    have he : asFp2 (inverseEmbed t d) ⟨l.val, by omega⟩ =
        asFp2 (mul2 t (determinantInverse d)) ⟨l.val, by omega⟩ := by
      fin_cases l <;> rfl
    rw [he, asFp2_mul2, determinant_inverse_coefficient]
  rw [value_field]
  apply QuadraticAlgebra.ext
  · change Fp6Field.assemble (asFp2 (inverseEmbed t d) 0)
      (asFp2 (inverseEmbed t d) 1) (asFp2 (inverseEmbed t d) 2) =
        Fp6Field.assemble (asFp2 t 0) (asFp2 t 1) (asFp2 t 2) * Fp6Field.of (asFp2 d 0)⁻¹
    have h0 : asFp2 (inverseEmbed t d) 0 = asFp2 t 0 * (asFp2 d 0)⁻¹ := h ⟨0, by decide⟩
    have h1 : asFp2 (inverseEmbed t d) 1 = asFp2 t 1 * (asFp2 d 0)⁻¹ := h ⟨1, by decide⟩
    have h2 : asFp2 (inverseEmbed t d) 2 = asFp2 t 2 * (asFp2 d 0)⁻¹ := h ⟨2, by decide⟩
    rw [h0, h1, h2]
    simp only [Fp6Field.assemble, map_mul, map_inv₀]
    ring
  · change Fp6Field.assemble (asFp2 (inverseEmbed t d) 3)
      (asFp2 (inverseEmbed t d) 4) (asFp2 (inverseEmbed t d) 5) = 0
    have hz (l : Fin 3) : asFp2 (inverseEmbed t d) ⟨l.val + 3, by omega⟩ = 0 := by
      fin_cases l <;> simp [inverseEmbed, asFp2, shuffle2, shuffle_invEmbed] <;> rfl
    have h3 : asFp2 (inverseEmbed t d) 3 = 0 := hz ⟨0, by decide⟩
    have h4 : asFp2 (inverseEmbed t d) 4 = 0 := hz ⟨1, by decide⟩
    have h5 : asFp2 (inverseEmbed t d) 5 = 0 := hz ⟨2, by decide⟩
    rw [h3, h4, h5]
    simp [Fp6Field.assemble]

theorem inverse_cofactor_field (a : P F) :
    Fp12.toField (value (inverseEmbed (inverseAdjugate a)
      (inverseDeterminant a (inverseAdjugate a)))) =
      algebraMap Fp6Field Fp12Field (Fp6.toField (value a).c0)⁻¹ := by
  rw [inverse_embed_field, determinant_coefficient]
  have h0 := congrFun (adjugate_coefficients a) 0
  have h1 := congrFun (adjugate_coefficients a) 1
  have h2 := congrFun (adjugate_coefficients a) 2
  simp only [Matrix.cons_val] at h0 h1 h2
  rw [h0, h1, h2]
  change algebraMap Fp6Field Fp12Field
      (Fp6Field.cofactor (asFp2 a 0) (asFp2 a 1) (asFp2 a 2) *
        Fp6Field.of (Fp6Field.determinant (asFp2 a 0) (asFp2 a 1) (asFp2 a 2))⁻¹) = _
  rw [← Fp6Field.inverse_formula]
  rfl

theorem field_inverse_via_conjugate (x : Fp12Field) :
    star x * algebraMap Fp6Field Fp12Field ((x * star x).re)⁻¹ = x⁻¹ := by
  have hn : (x * star x).re = QuadraticAlgebra.norm x := by
    simp [QuadraticAlgebra.norm_def]
    ring
  change star x * algebraMap Fp6Field Fp12Field ((x * star x).re)⁻¹ =
    (QuadraticAlgebra.norm x)⁻¹ • star x
  rw [hn, Algebra.smul_def, mul_comm]

theorem inverse_value (a : P F) : value (inverseValues a) = (value a).inverse := by
  apply Fp12.toField.injective
  rw [inverseValues, product_value, Fp12.toField_mul, conjugate_value,
    Fp12.toField_conjugate, inverse_cofactor_field, Fp12.toField_inverse]
  change star (Fp12.toField (value a)) * algebraMap Fp6Field Fp12Field
    ((Fp12.toField (value (inverseNormLanes a))).re)⁻¹ = _
  rw [inverseNormLanes, product_value, Fp12.toField_mul, conjugate_value, Fp12.toField_conjugate]
  exact field_inverse_via_conjugate _

theorem inverse_refines {x : fp2x8.Fp2x8} {a : Bls.Fp12} (hx : Rep x a) :
    ∃ out, fp12.Fp12.inverse x = ok out ∧ Rep out a.inverse := by
  obtain ⟨v, h0, h1, rfl⟩ := hx
  obtain ⟨out, hout, rout⟩ := inverse_raw_tower ⟨h0, h1⟩
  exact ⟨out, hout, inverseValues v,
    fun l => (rout.1 l).boundRep (by change 108 < 256; decide),
    fun l => (rout.2 l).boundRep (by change 108 < 256; decide), inverse_value v⟩

end LeanBlsSimd.LaneTower
