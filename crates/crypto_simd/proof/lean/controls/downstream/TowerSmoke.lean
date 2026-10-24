import LeanBlsSimd.Portable.Fp12.Frobenius
import LeanBlsSimd.Spec.Cyclotomic.Field
import LeanBlsSimd.Spec.FinalExponentiation

open EthLib.Cryptography.Bls LeanBlsSimd LeanBlsSimd.Cyclotomic

noncomputable section

example (a b : Fp12) : Fp12.toField (a * b) = Fp12.toField a * Fp12.toField b :=
  Fp12.toField.map_mul a b

example (a : Fp12) : Fp12.toField a.inverse = (Fp12.toField a)⁻¹ := Fp12.toField_inverse a

example (a : Fp12) : Fp12.toField a.conjugate = Fp12.toField a ^ (Fp.modulus^6) :=
  spec_conjugate a

example (a : Schedule.Coeffs Bls.K)
    (h : fieldDecode a ^ (Fp.modulus^4-Fp.modulus^2+1) = 1) :
    fieldDecode (Schedule.raw LeanBlsSimd.Fp6Field.xi a) = fieldDecode a ^ 2 := field_cyclotomic_square a h

example (a : Schedule.Coeffs Bls.K) :
    fieldDecode (frobeniusCoeffs a) = fieldDecode a ^ Fp.modulus := field_frobenius a

example (a : Fp12Field) (h : a ≠ 0) :
    fieldEasyPart a ^ (Fp.modulus^4-Fp.modulus^2+1) = 1 := field_easy_cyclotomic a h

example (a : Fp12) (h : a ≠ Fp12.zero) :
    finalExponentiationTarget a h ^ Fr.modulus = 1 := target_pow_r _

open Aeneas.Std Result silver_crypto_simd

example [RuntimeFeatures] (a b : Fp12) :
    portable.fp12.Fp12.mul (Portable.Fp12.encode a) (Portable.Fp12.encode b) =
      ok (Portable.Fp12.encode (a * b)) := Portable.Fp12.mul_encoded a b

example [RuntimeFeatures] (a : Fp12) :
    portable.fp12.Fp12.inverse (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode a.inverse) := Portable.Fp12.inverse_encoded a

example [RuntimeFeatures] (a : Fp12)
    (h : Fp12.toField a ^ (Fp.modulus ^ 4 - Fp.modulus ^ 2 + 1) = 1) :
    portable.fp12.Fp12.cyclotomic_square (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode a.square) := Portable.Fp12.cyclotomic_square_encoded a h

example [RuntimeFeatures] (a : Fp12) :
    portable.fp12.Fp12.frobenius (Portable.Fp12.encode a) =
      ok (Portable.Fp12.encode (Fp12.powNat a Fp.modulus)) := Portable.Fp12.frobenius_encoded a

example (j : Fin 6) :
    Fp2.toField ⟨Kzg.fpRead ⟨FrobeniusConstants.portableRow j 0⟩,
      Kzg.fpRead ⟨FrobeniusConstants.portableRow j 1⟩⟩ =
      Fp6Field.xi ^ (j.val * ((Fp.modulus - 1) / 6)) := FrobeniusConstants.portable_entry_decodes j
