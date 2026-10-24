import LeanBlsSimd.Portable.Fp12.Arithmetic
import LeanBlsSimd.Portable.Fp2.Field
import LeanBlsSimd.Spec.Cyclotomic.Field

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp12

open LeanBlsSimd.Fp6Field (xi)
open Cyclotomic Schedule

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000

def ofCoeffs (x : Coeffs Fp2Field) : Bls.Fp12 :=
  ⟨⟨LeanBlsSimd.Fp2.toField.symm x.c00, LeanBlsSimd.Fp2.toField.symm x.c01,
      LeanBlsSimd.Fp2.toField.symm x.c02⟩,
    ⟨LeanBlsSimd.Fp2.toField.symm x.c10, LeanBlsSimd.Fp2.toField.symm x.c11,
      LeanBlsSimd.Fp2.toField.symm x.c12⟩⟩

theorem ofCoeffs_spec (x : Bls.Fp12) : ofCoeffs (specCoeffs x) = x := rfl

theorem ofCoeffs_field (x : Coeffs Fp2Field) :
    LeanBlsSimd.Fp12.toField (ofCoeffs x) = fieldDecode x := rfl

theorem fp4_square_encoded [RuntimeFeatures] (a b : Fp2Field) :
    portable.fp12.fp4_square (Fp2.fieldEncode a) (Fp2.fieldEncode b) =
      ok (Fp2.fieldEncode (fp4Square xi a b).1, Fp2.fieldEncode (fp4Square xi a b).2) := by
  simp only [portable.fp12.fp4_square, Fp2.square_field, Fp2.add_field,
    Fp2.sub_field, Fp2.mul_by_xi_field, bind_tc_ok]
  rfl

theorem thrice_less_twice_encoded (a b : Fp2Field) :
    portable.fp12.thrice_less_twice (Fp2.fieldEncode a) (Fp2.fieldEncode b) =
      ok (Fp2.fieldEncode (less a b)) := by
  simp only [portable.fp12.thrice_less_twice, Fp2.sub_field, Fp2.double_field,
    Fp2.add_field, bind_tc_ok]
  rfl

theorem thrice_plus_twice_encoded (a b : Fp2Field) :
    portable.fp12.thrice_plus_twice (Fp2.fieldEncode a) (Fp2.fieldEncode b) =
      ok (Fp2.fieldEncode (plus a b)) := by
  simp only [portable.fp12.thrice_plus_twice, Fp2.add_field, Fp2.double_field, bind_tc_ok]
  rfl

theorem cyclotomic_raw_encoded [RuntimeFeatures] (x : Coeffs Fp2Field) :
    portable.fp12.Fp12.cyclotomic_square (encode (ofCoeffs x)) =
      ok (encode (ofCoeffs (raw xi x))) := by
  change portable.fp12.Fp12.cyclotomic_square
    ⟨⟨Fp2.fieldEncode x.c00, Fp2.fieldEncode x.c01, Fp2.fieldEncode x.c02⟩,
      ⟨Fp2.fieldEncode x.c10, Fp2.fieldEncode x.c11, Fp2.fieldEncode x.c12⟩⟩ = _
  simp only [portable.fp12.Fp12.cyclotomic_square, fp4_square_encoded, bind_tc_ok, Function.uncurry]
  simp only [thrice_less_twice_encoded, thrice_plus_twice_encoded,
    Fp2.mul_by_xi_field, bind_tc_ok]
  dsimp only [encode, Fp6.encode, ofCoeffs, Fp2.fieldEncode, raw]

theorem cyclotomic_square_encoded [RuntimeFeatures] (a : Bls.Fp12)
    (hphi : LeanBlsSimd.Fp12.toField a ^ (Bls.Fp.modulus ^ 4 - Bls.Fp.modulus ^ 2 + 1) = 1) :
    portable.fp12.Fp12.cyclotomic_square (encode a) = ok (encode a.square) := by
  have h := cyclotomic_raw_encoded (specCoeffs a)
  rw [ofCoeffs_spec] at h
  have he : ofCoeffs (raw xi (specCoeffs a)) = a.square := by
    apply LeanBlsSimd.Fp12.toField.injective
    rw [ofCoeffs_field, field_cyclotomic_square _ (by exact hphi), fieldDecode_spec,
      LeanBlsSimd.Fp12.toField_square]
  rwa [he] at h

end LeanBlsSimd.Portable.Fp12
