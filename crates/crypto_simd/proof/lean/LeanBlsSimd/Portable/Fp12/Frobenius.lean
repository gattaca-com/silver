import LeanBlsSimd.Portable.Fp12.Cyclotomic
import LeanBlsSimd.Refines.FrobeniusConstants

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.FrobeniusConstants

open Portable
open LeanBlsSimd.Fp6Field (xi)

set_option maxRecDepth 4096
set_option maxHeartbeats 2000000
set_option exponentiation.threshold 4096

def coefficient (j : Fin 6) : Bls.Fp2 :=
  ⟨Bls.Fp.ofNat (words j).1, Bls.Fp.ofNat (words j).2⟩

theorem coefficient_field (j : Fin 6) :
    LeanBlsSimd.Fp2.toField (coefficient j) = xi ^ (j.val * ((Bls.Fp.modulus - 1) / 6)) := by
  rw [← words_spec]
  apply QuadraticAlgebra.ext <;> simp [coefficient, toFp2]
  all_goals rfl

/-- Uses the same canonical 2^384 encoder as the portable arithmetic refinements. -/
theorem portable_entry_encoded (j : Fin 6) :
    (⟨portableRow j 0, portableRow j 1⟩ : portable.fp2.Fp2) = Fp2.encode (coefficient j) := by
  unfold Fp2.encode coefficient
  apply congrArg₂ portable.fp2.Fp2.mk <;> fin_cases j <;> apply Subtype.ext <;> decide +kernel

theorem portable_entry_decodes (j : Fin 6) :
    LeanBlsSimd.Fp2.toField
      ⟨Kzg.fpRead ⟨portableRow j 0⟩, Kzg.fpRead ⟨portableRow j 1⟩⟩ =
      xi ^ (j.val * ((Bls.Fp.modulus - 1) / 6)) := by
  have h := Fp2.encode_rep (coefficient j)
  rw [← portable_entry_encoded j] at h
  rw [h.1.2, h.2.2]
  exact coefficient_field j

theorem portable_entry_field_encoded (j : Fin 6) :
    (⟨portableRow j 0, portableRow j 1⟩ : portable.fp2.Fp2) =
      Fp2.fieldEncode (xi ^ (j.val * ((Bls.Fp.modulus - 1) / 6))) := by
  rw [← coefficient_field, Fp2.fieldEncode_toField, portable_entry_encoded]

end LeanBlsSimd.FrobeniusConstants

namespace LeanBlsSimd.Portable.Fp12

open LeanBlsSimd.Fp6Field (xi)
open Cyclotomic Schedule FrobeniusConstants

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000

theorem coefficient_run [RuntimeFeatures] (a : portable.fp2.Fp2) (j : Fin 6) :
    portable.fp12.frobenius_coefficient a (Fp.Wide.rowIndex j) = (do
      let c ← portable.fp2.Fp2.conjugate a
      portable.fp2.Fp2.mul c ⟨portableRow j 0, portableRow j 1⟩) := by
  fin_cases j <;>
    simp (disch := decide) only [portable.fp12.frobenius_coefficient,
      Fp.Wide.rowIndex, index_usize_eq, bind_tc_ok]
  all_goals
    unfold portableRow portable.constants.FROBENIUS
    rfl

theorem coefficient_encoded [RuntimeFeatures] (a : Fp2Field) (j : Fin 6) :
    portable.fp12.frobenius_coefficient (Fp2.fieldEncode a) (Fp.Wide.rowIndex j) =
      ok (Fp2.fieldEncode (star a * xi ^ (j.val * ((Bls.Fp.modulus - 1) / 6)))) := by
  rw [coefficient_run, portable_entry_field_encoded, Fp2.conjugate_field, bind_tc_ok,
    Fp2.mul_field]

theorem frobenius_raw_encoded [RuntimeFeatures] (x : Coeffs Fp2Field) :
    portable.fp12.Fp12.frobenius (encode (ofCoeffs x)) =
      ok (encode (ofCoeffs (frobeniusCoeffs x))) := by
  have h0 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c00) 0#usize = _ :=
    coefficient_encoded x.c00 0
  have h2 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c01) 2#usize = _ :=
    coefficient_encoded x.c01 2
  have h4 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c02) 4#usize = _ :=
    coefficient_encoded x.c02 4
  have h1 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c10) 1#usize = _ :=
    coefficient_encoded x.c10 1
  have h3 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c11) 3#usize = _ :=
    coefficient_encoded x.c11 3
  have h5 : portable.fp12.frobenius_coefficient (Fp2.fieldEncode x.c12) 5#usize = _ :=
    coefficient_encoded x.c12 5
  change portable.fp12.Fp12.frobenius
    ⟨⟨Fp2.fieldEncode x.c00, Fp2.fieldEncode x.c01, Fp2.fieldEncode x.c02⟩,
      ⟨Fp2.fieldEncode x.c10, Fp2.fieldEncode x.c11, Fp2.fieldEncode x.c12⟩⟩ = _
  simp only [portable.fp12.Fp12.frobenius, h0, h2, h4, h1, h3, h5, bind_tc_ok]
  simp only [show (0 : Fin 6).val = 0 from rfl, show (1 : Fin 6).val = 1 from rfl,
    show (2 : Fin 6).val = 2 from rfl, show (3 : Fin 6).val = 3 from rfl,
    show (4 : Fin 6).val = 4 from rfl, show (5 : Fin 6).val = 5 from rfl,
    zero_mul, one_mul, pow_zero, mul_one]
  dsimp only [encode, Fp6.encode, ofCoeffs, Fp2.fieldEncode, frobeniusCoeffs]

theorem frobenius_encoded [RuntimeFeatures] (a : Bls.Fp12) :
    portable.fp12.Fp12.frobenius (encode a) =
      ok (encode (Bls.Fp12.powNat a Bls.Fp.modulus)) := by
  have h := frobenius_raw_encoded (specCoeffs a)
  rw [ofCoeffs_spec] at h
  have he : ofCoeffs (frobeniusCoeffs (specCoeffs a)) =
      Bls.Fp12.powNat a Bls.Fp.modulus := by
    apply LeanBlsSimd.Fp12.toField.injective
    rw [ofCoeffs_field, field_frobenius, fieldDecode_spec, LeanBlsSimd.Fp12.toField_powNat]
  rwa [he] at h

end LeanBlsSimd.Portable.Fp12
