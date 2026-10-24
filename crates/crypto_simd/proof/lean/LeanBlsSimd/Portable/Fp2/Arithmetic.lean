import LeanBlsSimd.Portable.Fp2.Product
import LeanBlsSimd.Portable.Fp.Sign
import LeanBlsSimd.Portable.Fp.Inverse
import LeanBlsSimd.Portable.Fp.Equality

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp2

set_option maxRecDepth 4096

@[simp] theorem encode_c0 (a : Bls.Fp2) : (encode a).c0 = (Kzg.fpEncode a.c0).l := rfl
@[simp] theorem encode_c1 (a : Bls.Fp2) : (encode a).c1 = (Kzg.fpEncode a.c1).l := rfl

theorem zero_encoded : portable.fp2.Fp2.ZERO = encode Bls.Fp2.zero := by
  unfold portable.fp2.Fp2.ZERO
  exact congrArg₂ portable.fp2.Fp2.mk (Fp.rep_eq_encode Kzg.portableFpRep_zero)
    (Fp.rep_eq_encode Kzg.portableFpRep_zero)

theorem new_encoded (a b : Bls.Fp) :
    portable.fp2.Fp2.new (Kzg.fpEncode a).l (Kzg.fpEncode b).l = ok (encode ⟨a, b⟩) := rfl

theorem add_encoded (a b : Bls.Fp2) :
    portable.fp2.Fp2.add (encode a) (encode b) = ok (encode (a + b)) := by
  simp only [portable.fp2.Fp2.add, encode_c0, encode_c1, Fp.add_encoded, bind_tc_ok]
  rfl

theorem sub_encoded (a b : Bls.Fp2) :
    portable.fp2.Fp2.sub (encode a) (encode b) = ok (encode (a - b)) := by
  simp only [portable.fp2.Fp2.sub, encode_c0, encode_c1, Fp.sub_encoded, bind_tc_ok]
  rfl

theorem neg_encoded (a : Bls.Fp2) :
    portable.fp2.Fp2.neg (encode a) = ok (encode (-a)) := by
  simp only [portable.fp2.Fp2.neg, encode_c0, encode_c1, Fp.neg_encoded, bind_tc_ok]
  rfl

theorem double_encoded (a : Bls.Fp2) :
    portable.fp2.Fp2.double (encode a) = ok (encode (a + a)) := by
  simp only [portable.fp2.Fp2.double, portable.fp.Fp.double,
    encode_c0, encode_c1, Fp.add_encoded, bind_tc_ok]
  rfl

theorem conjugate_encoded (a : Bls.Fp2) :
    portable.fp2.Fp2.conjugate (encode a) = ok (encode a.conjugate) := by
  simp only [portable.fp2.Fp2.conjugate, encode_c1, Fp.neg_encoded, bind_tc_ok]
  rfl

theorem mul_by_xi_encoded (a : Bls.Fp2) :
    portable.fp2.Fp2.mul_by_xi (encode a) = ok (encode a.mulByOnePlusI) := by
  simp only [portable.fp2.Fp2.mul_by_xi, encode_c0, encode_c1,
    Fp.sub_encoded, Fp.add_encoded, bind_tc_ok]
  rfl

theorem mul_by_fp_encoded [RuntimeFeatures] (a : Bls.Fp2) (b : Bls.Fp) :
    portable.fp2.Fp2.mul_by_fp (encode a) (Kzg.fpEncode b).l =
      ok (encode (a * Bls.Fp2.ofFp b)) := by
  simp only [portable.fp2.Fp2.mul_by_fp, encode_c0, encode_c1,
    Fp.mul_encoded, bind_tc_ok]
  change ok (encode ⟨a.c0 * b, a.c1 * b⟩) = _
  congr 2
  apply LeanBlsSimd.Fp2.toField.injective
  simp only [map_mul, LeanBlsSimd.Fp2.toField_ofFp]
  apply QuadraticAlgebra.ext <;> simp <;> rfl

theorem square_encoded [RuntimeFeatures] (a : Bls.Fp2) :
    portable.fp2.Fp2.square (encode a) = ok (encode (a * a)) := by
  simp only [portable.fp2.Fp2.square, encode_c0, encode_c1,
    Fp.add_encoded, Fp.sub_encoded, Fp.mul_encoded, portable.fp.Fp.double, bind_tc_ok]
  change ok (encode ⟨(a.c0 + a.c1) * (a.c0 - a.c1), a.c0 * a.c1 + a.c0 * a.c1⟩) = _
  congr 2
  apply LeanBlsSimd.Fp2.toField.injective
  simp only [map_mul]
  apply QuadraticAlgebra.ext
  · change ((Bls.Fp.toZMod a.c0) + Bls.Fp.toZMod a.c1) *
        (Bls.Fp.toZMod a.c0 - Bls.Fp.toZMod a.c1) =
      Bls.Fp.toZMod a.c0 * Bls.Fp.toZMod a.c0 +
        (-1) * Bls.Fp.toZMod a.c1 * Bls.Fp.toZMod a.c1
    ring
  · change Bls.Fp.toZMod a.c0 * Bls.Fp.toZMod a.c1 +
        Bls.Fp.toZMod a.c0 * Bls.Fp.toZMod a.c1 =
      Bls.Fp.toZMod a.c0 * Bls.Fp.toZMod a.c1 +
        Bls.Fp.toZMod a.c1 * Bls.Fp.toZMod a.c0 +
        0 * Bls.Fp.toZMod a.c1 * Bls.Fp.toZMod a.c1
    ring

theorem inverse_encoded [RuntimeFeatures] (a : Bls.Fp2) :
    portable.fp2.Fp2.inverse (encode a) = ok (encode a.inverse) := by
  simp only [portable.fp2.Fp2.inverse, encode_c0, encode_c1,
    Fp.square_encoded, Fp.add_encoded, Fp.inverse_encoded, Fp.mul_encoded,
    Fp.neg_encoded, bind_tc_ok]
  change ok (encode ⟨a.c0 * (a.c0 * a.c0 + a.c1 * a.c1)⁻¹,
    (-a.c1) * (a.c0 * a.c0 + a.c1 * a.c1)⁻¹⟩) = _
  congr 2
  apply LeanBlsSimd.Fp2.toField.injective
  apply QuadraticAlgebra.ext <;>
    simp [Bls.Fp2.inverse, Bls.Fp.inverse_eq_inv, LeanBlsSimd.Fp2.toField]

theorem eq_encoded (a b : Bls.Fp2) :
    portable.fp2.Fp2.Insts.CoreCmpPartialEqFp2.eq (encode a) (encode b) =
      ok (a.beq b) := by
  simp only [portable.fp2.Fp2.Insts.CoreCmpPartialEqFp2.eq,
    encode_c0, encode_c1, Fp.eq_encoded, bind_tc_ok, decide_eq_true_eq]
  by_cases h : a.c0 = b.c0
  · simp only [h, if_true]
    congr 1
    apply Bool.eq_iff_iff.mpr
    simp only [Bls.Fp2.beq, Bool.and_eq_true, LeanBlsSimd.Fp.beq_iff,
      decide_eq_true_eq, h, true_and]
  · simp only [h, if_false]
    congr 1
    apply Bool.eq_iff_iff.mpr
    simp only [Bls.Fp2.beq, Bool.and_eq_true, LeanBlsSimd.Fp.beq_iff, h, false_and, Bool.false_eq_true]

theorem encode_injective : Function.Injective encode := by
  intro a b h
  have hc0 : a.c0 = b.c0 := (Fp.encoded_eq_iff a.c0 b.c0).mp
    (congrArg Subtype.val (congrArg portable.fp2.Fp2.c0 h))
  have hc1 : a.c1 = b.c1 := (Fp.encoded_eq_iff a.c1 b.c1).mp
    (congrArg Subtype.val (congrArg portable.fp2.Fp2.c1 h))
  cases a
  cases b
  simp_all

end LeanBlsSimd.Portable.Fp2
