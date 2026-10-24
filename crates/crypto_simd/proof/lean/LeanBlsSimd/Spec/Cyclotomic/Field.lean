import LeanBlsSimd.Spec.Cyclotomic.FieldBridge

namespace LeanBlsSimd.Cyclotomic

open EthLib.Cryptography.Bls
open Bls Schedule

noncomputable section

@[simp] theorem fieldDecode_spec (x : Fp12) : fieldDecode (specCoeffs x) = Fp12.toField x := rfl

theorem fieldDecode_surjective : Function.Surjective fieldDecode := by
  intro x
  obtain ⟨a,rfl⟩ := Fp12.toField.surjective x
  exact ⟨specCoeffs a,rfl⟩

def powers (x : Coeffs K) : Fin 6 → K := ![x.c00,x.c10,x.c01,x.c11,x.c02,x.c12]

theorem decode_eq_sextic (x : Coeffs K) : decode xi x = sextic (powers x) := by
  simp only [decode, assemble, ca, cb, cc, embed_mk, sextic, powers, Fin.sum_univ_succ]
  norm_num [kembed, RingHom.comp_apply, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons]
  ring

def frobeniusCoeffs (x : Coeffs K) : Coeffs K :=
  ⟨star x.c00, star x.c01 * xi^(2*((p-1)/6)), star x.c02 * xi^(4*((p-1)/6)),
    star x.c10 * xi^((p-1)/6), star x.c11 * xi^(3*((p-1)/6)),
    star x.c12 * xi^(5*((p-1)/6))⟩

theorem powers_frobenius (x : Coeffs K) :
    powers (frobeniusCoeffs x) = fun i => star (powers x i)*xi^(i.val*((p-1)/6)) := by
  funext i
  fin_cases i <;> simp [powers, frobeniusCoeffs]

theorem field_frobenius (x : Coeffs K) :
    fieldDecode (frobeniusCoeffs x) = fieldDecode x ^ p := by
  apply toCubic.injective
  rw [map_pow, toCubic_fieldDecode, toCubic_fieldDecode,
    decode_eq_sextic, decode_eq_sextic, powers_frobenius, p_power_coefficients]

theorem fieldDecode_conjugate (x : Coeffs K) :
    fieldDecode (conjugate x) = star (fieldDecode x) := by
  apply QuadraticAlgebra.ext
  · simp [fieldDecode, conjugate]
  · simp only [fieldDecode, conjugate, Fp6Field.assemble, map_neg,
      QuadraticAlgebra.im_star]
    ring

theorem field_star (x : Fp12Field) : star x = x ^ (p^6) := by
  obtain ⟨a,rfl⟩ := fieldDecode_surjective x
  rw [← fieldDecode_conjugate, field_conjugate]

theorem spec_conjugate (x : Fp12) :
    Fp12.toField x.conjugate = Fp12.toField x ^ (p^6) := by
  rw [Fp12.toField_conjugate, field_star]

def fieldEasyPart (x : Fp12Field) : Fp12Field :=
  (star x * x⁻¹)^(p^2) * (star x * x⁻¹)

theorem field_easy_cyclotomic (x : Fp12Field) (hx : x ≠ 0) :
    fieldEasyPart x ^ (p^4-p^2+1) = 1 := by
  let g := Units.mk0 x hx
  have hperiod : g^(p^12-1) = 1 := by
    apply Units.ext
    change x^(p^12-1) = 1
    rw [← Fp12Field.card_eq]
    exact FiniteField.pow_card_sub_one_eq_one x hx
  have h := congrArg (fun u : Fp12Fieldˣ => (u : Fp12Field))
    (easyPart_cyclotomic g p (by decide +kernel) hperiod)
  simpa only [easyPart, Units.val_pow_eq_pow_val, Units.val_mul, Units.val_inv_eq_inv_val,
    Units.val_mk0, Units.val_one, fieldEasyPart, field_star] using h

theorem field_easy_zero : fieldEasyPart 0 = 0 := by
  simp [fieldEasyPart]

theorem field_easy_unitary (x : Fp12Field) (hx : x ≠ 0) :
    fieldEasyPart x ^ (p^6+1) = 1 := by
  rw [← phi_factor p (by decide +kernel), Nat.mul_comm, pow_mul,
    field_easy_cyclotomic x hx, one_pow]

theorem field_easy_inverse (x : Fp12Field) (hx : x ≠ 0) :
    star (fieldEasyPart x) = (fieldEasyPart x)⁻¹ := by
  have h := field_easy_unitary x hx
  rw [pow_succ] at h
  rw [field_star]
  exact eq_inv_of_mul_eq_one_left h

end
end LeanBlsSimd.Cyclotomic
