import LeanBlsSimd.Portable.Fp6
import LeanBlsSimd.Spec.Fp12

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp12

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000

def encode (a : Bls.Fp12) : portable.fp12.Fp12 :=
  ⟨Fp6.encode a.c0, Fp6.encode a.c1⟩

def Rep (a : portable.fp12.Fp12) (x : Bls.Fp12) : Prop :=
  Fp6.Rep a.c0 x.c0 ∧ Fp6.Rep a.c1 x.c1

theorem encode_rep (x : Bls.Fp12) : Rep (encode x) x :=
  ⟨Fp6.encode_rep _, Fp6.encode_rep _⟩

theorem rep_eq_encode {a : portable.fp12.Fp12} {x : Bls.Fp12} (h : Rep a x) :
    a = encode x := by
  cases a
  exact congrArg₂ portable.fp12.Fp12.mk (Fp6.rep_eq_encode h.1) (Fp6.rep_eq_encode h.2)

@[simp] theorem encode_c0 (a : Bls.Fp12) : (encode a).c0 = Fp6.encode a.c0 := rfl
@[simp] theorem encode_c1 (a : Bls.Fp12) : (encode a).c1 = Fp6.encode a.c1 := rfl

theorem one_encoded : portable.fp12.Fp12.ONE = encode Bls.Fp12.one := by
  simp only [portable.fp12.Fp12.ONE, Fp6.zero_encoded, Fp2.zero_encoded]
  rw [Fp.rep_eq_encode Kzg.portableFpRep_one, Fp.rep_eq_encode Kzg.portableFpRep_zero]
  rfl

theorem mul_encoded [RuntimeFeatures] (a b : Bls.Fp12) :
    portable.fp12.Fp12.mul (encode a) (encode b) = ok (encode (a * b)) := by
  simp only [portable.fp12.Fp12.mul, encode_c0, encode_c1,
    Fp6.add_encoded, Fp6.sub_encoded, Fp6.mul_encoded, Fp6.mul_by_v_encoded, bind_tc_ok]
  rfl

theorem conjugate_encoded (a : Bls.Fp12) :
    portable.fp12.Fp12.conjugate (encode a) = ok (encode a.conjugate) := by
  simp only [portable.fp12.Fp12.conjugate, encode_c1, Fp6.neg_encoded, bind_tc_ok]
  rfl

theorem inverse_encoded [RuntimeFeatures] (a : Bls.Fp12) :
    portable.fp12.Fp12.inverse (encode a) = ok (encode a.inverse) := by
  simp only [portable.fp12.Fp12.inverse, encode_c0, encode_c1,
    Fp6.mul_encoded, Fp6.mul_by_v_encoded, Fp6.sub_encoded, Fp6.inverse_encoded,
    Fp6.neg_encoded, bind_tc_ok]
  rfl

private theorem square_formula (a b : Bls.Fp6) :
    (⟨(a + b) * (a + b.mulByV) - a * b - (a * b).mulByV,
      a * b + a * b⟩ : Bls.Fp12) = (⟨a, b⟩ : Bls.Fp12) * ⟨a, b⟩ := by
  apply LeanBlsSimd.Fp12.toField.injective
  simp only [map_mul, LeanBlsSimd.Fp12.toField_mk]
  apply QuadraticAlgebra.ext <;>
    simp [LeanBlsSimd.Fp6.toField_sub, LeanBlsSimd.Fp6.toField_mulByV] <;> ring

theorem square_encoded [RuntimeFeatures] (a : Bls.Fp12) :
    portable.fp12.Fp12.square (encode a) = ok (encode a.square) := by
  simp only [portable.fp12.Fp12.square, encode_c0, encode_c1,
    Fp6.mul_encoded, Fp6.add_encoded, Fp6.sub_encoded, Fp6.mul_by_v_encoded,
    Fp6.double_encoded, bind_tc_ok]
  change ok (encode ⟨(a.c0 + a.c1) * (a.c0 + a.c1.mulByV) - a.c0 * a.c1 -
    (a.c0 * a.c1).mulByV, a.c0 * a.c1 + a.c0 * a.c1⟩) = _
  rw [square_formula]
  rfl

def line (x y z : Bls.Fp2) : Bls.Fp12 :=
  ⟨Fp6.sparse x y, Fp6.sparse Bls.Fp2.zero z⟩

theorem mul_by_line_encoded [RuntimeFeatures] (a : Bls.Fp12) (x y z : Bls.Fp2) :
    portable.fp12.Fp12.mul_by_line (encode a) (Fp2.encode x) (Fp2.encode y) (Fp2.encode z) =
      ok (encode (a * line x y z)) := by
  have hs : Fp6.sparse x y + Fp6.sparse Bls.Fp2.zero z = Fp6.sparse x (y + z) := by
    apply LeanBlsSimd.Fp6.toField.injective
    rw [map_add]
    simp [Fp6.sparse, LeanBlsSimd.Fp6.toField, Fp6Field.assemble, map_add]
    ring
  have hm : (⟨a.c0 * Fp6.sparse x y + (a.c1 * Fp6.sparse Bls.Fp2.zero z).mulByV,
      (a.c0 + a.c1) * Fp6.sparse x (y + z) - a.c0 * Fp6.sparse x y -
        a.c1 * Fp6.sparse Bls.Fp2.zero z⟩ : Bls.Fp12) = a * line x y z := by
    rw [← hs]
    rfl
  have he (b c : Bls.Fp6) :
      (⟨Fp6.encode b, Fp6.encode c⟩ : portable.fp12.Fp12) = encode ⟨b, c⟩ := rfl
  simp only [portable.fp12.Fp12.mul_by_line, encode_c0, encode_c1,
    Fp6.mul_by_xy_encoded, Fp6.mul_by_y_encoded, Fp6.add_encoded,
    Fp2.add_encoded, Fp6.sub_encoded, Fp6.mul_by_v_encoded, bind_tc_ok, he, hm]

theorem eq_encoded (a b : Bls.Fp12) :
    portable.fp12.Fp12.Insts.CoreCmpPartialEqFp12.eq (encode a) (encode b) =
      ok (a.beq b) := by
  simp only [portable.fp12.Fp12.Insts.CoreCmpPartialEqFp12.eq,
    encode_c0, encode_c1, Fp6.eq_encoded, bind_tc_ok, Bls.Fp12.beq]
  cases a.c0.beq b.c0 <;> rfl

theorem is_one_encoded (a : Bls.Fp12) :
    portable.fp12.Fp12.is_one (encode a) = ok a.isOne := by
  rw [portable.fp12.Fp12.is_one, one_encoded, eq_encoded]
  congr 1

theorem mul_refines [RuntimeFeatures] {a b : portable.fp12.Fp12} {x y : Bls.Fp12}
    (ha : Rep a x) (hb : Rep b y) :
    ∃ out, portable.fp12.Fp12.mul a b = ok out ∧ Rep out (x * y) := by
  rw [rep_eq_encode ha, rep_eq_encode hb]
  exact ⟨encode (x * y), mul_encoded x y, encode_rep _⟩

theorem inverse_refines [RuntimeFeatures] {a : portable.fp12.Fp12} {x : Bls.Fp12}
    (ha : Rep a x) :
    ∃ out, portable.fp12.Fp12.inverse a = ok out ∧ Rep out x.inverse := by
  rw [rep_eq_encode ha]
  exact ⟨encode x.inverse, inverse_encoded x, encode_rep _⟩

theorem encode_injective : Function.Injective encode := by
  intro a b h
  have hc0 : a.c0 = b.c0 := Fp6.encode_injective (congrArg portable.fp12.Fp12.c0 h)
  have hc1 : a.c1 = b.c1 := Fp6.encode_injective (congrArg portable.fp12.Fp12.c1 h)
  cases a
  cases b
  simp_all

end LeanBlsSimd.Portable.Fp12
