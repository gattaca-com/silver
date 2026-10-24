import LeanBlsSimd.Portable.Fp2.Arithmetic
import LeanBlsSimd.Spec.Fp6Noncube

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp2

open LeanBlsSimd.Fp2 (toField)
open LeanBlsSimd.Fp6Field (xi)

def fieldEncode (a : Fp2Field) : portable.fp2.Fp2 := encode (toField.symm a)

@[simp] theorem fieldEncode_toField (a : Bls.Fp2) : fieldEncode (toField a) = encode a := rfl

theorem add_field (a b : Fp2Field) :
    portable.fp2.Fp2.add (fieldEncode a) (fieldEncode b) = ok (fieldEncode (a + b)) := by
  simpa only [fieldEncode, map_add] using add_encoded (toField.symm a) (toField.symm b)

theorem sub_field (a b : Fp2Field) :
    portable.fp2.Fp2.sub (fieldEncode a) (fieldEncode b) = ok (fieldEncode (a - b)) := by
  have h : toField.symm (a - b) = toField.symm a - toField.symm b := by
    apply toField.injective
    simp only [RingEquiv.apply_symm_apply, LeanBlsSimd.Fp2.toField_sub]
  simp only [fieldEncode, h, sub_encoded]

theorem mul_field [RuntimeFeatures] (a b : Fp2Field) :
    portable.fp2.Fp2.mul (fieldEncode a) (fieldEncode b) = ok (fieldEncode (a * b)) := by
  simpa only [fieldEncode, map_mul] using mul_encoded (toField.symm a) (toField.symm b)

theorem square_field [RuntimeFeatures] (a : Fp2Field) :
    portable.fp2.Fp2.square (fieldEncode a) = ok (fieldEncode (a * a)) := by
  simpa only [fieldEncode, map_mul] using square_encoded (toField.symm a)

theorem double_field (a : Fp2Field) :
    portable.fp2.Fp2.double (fieldEncode a) = ok (fieldEncode (a + a)) := by
  simpa only [fieldEncode, map_add] using double_encoded (toField.symm a)

theorem mul_by_xi_field (a : Fp2Field) :
    portable.fp2.Fp2.mul_by_xi (fieldEncode a) = ok (fieldEncode (xi * a)) := by
  have h : toField.symm (xi * a) = (toField.symm a).mulByOnePlusI := by
    apply toField.injective
    simp only [RingEquiv.apply_symm_apply, LeanBlsSimd.Fp2.toField_mulByOnePlusI]
    exact mul_comm _ _
  simp only [fieldEncode, h, mul_by_xi_encoded]

theorem conjugate_field (a : Fp2Field) :
    portable.fp2.Fp2.conjugate (fieldEncode a) = ok (fieldEncode (star a)) := by
  have h : toField.symm (star a) = (toField.symm a).conjugate := by
    apply toField.injective
    simp only [RingEquiv.apply_symm_apply, LeanBlsSimd.Fp2.toField_conjugate]
  simp only [fieldEncode, h, conjugate_encoded]

end LeanBlsSimd.Portable.Fp2
