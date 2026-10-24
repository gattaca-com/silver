import LeanBlsSimd.Portable.Fp2.Arithmetic
import LeanBlsSimd.Spec.Fp6Operations

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Fp6

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000

def encode (a : Bls.Fp6) : portable.fp6.Fp6 :=
  ⟨Fp2.encode a.c0, Fp2.encode a.c1, Fp2.encode a.c2⟩

def Rep (a : portable.fp6.Fp6) (x : Bls.Fp6) : Prop :=
  Fp2.Rep a.c0 x.c0 ∧ Fp2.Rep a.c1 x.c1 ∧ Fp2.Rep a.c2 x.c2

theorem encode_rep (x : Bls.Fp6) : Rep (encode x) x :=
  ⟨Fp2.encode_rep _, Fp2.encode_rep _, Fp2.encode_rep _⟩

theorem rep_eq_encode {a : portable.fp6.Fp6} {x : Bls.Fp6} (h : Rep a x) :
    a = encode x := by
  cases a
  simp only [encode, ← Fp2.rep_eq_encode h.1, ← Fp2.rep_eq_encode h.2.1,
    ← Fp2.rep_eq_encode h.2.2]

@[simp] theorem encode_c0 (a : Bls.Fp6) : (encode a).c0 = Fp2.encode a.c0 := rfl
@[simp] theorem encode_c1 (a : Bls.Fp6) : (encode a).c1 = Fp2.encode a.c1 := rfl
@[simp] theorem encode_c2 (a : Bls.Fp6) : (encode a).c2 = Fp2.encode a.c2 := rfl

theorem zero_encoded : portable.fp6.Fp6.ZERO = encode Bls.Fp6.zero := by
  simp only [portable.fp6.Fp6.ZERO, Fp2.zero_encoded]
  rfl

theorem add_encoded (a b : Bls.Fp6) :
    portable.fp6.Fp6.add (encode a) (encode b) = ok (encode (a + b)) := by
  simp only [portable.fp6.Fp6.add, encode_c0, encode_c1, encode_c2,
    Fp2.add_encoded, bind_tc_ok]
  rfl

theorem sub_encoded (a b : Bls.Fp6) :
    portable.fp6.Fp6.sub (encode a) (encode b) = ok (encode (a - b)) := by
  simp only [portable.fp6.Fp6.sub, encode_c0, encode_c1, encode_c2,
    Fp2.sub_encoded, bind_tc_ok]
  rfl

theorem neg_encoded (a : Bls.Fp6) :
    portable.fp6.Fp6.neg (encode a) = ok (encode (-a)) := by
  simp only [portable.fp6.Fp6.neg, encode_c0, encode_c1, encode_c2,
    Fp2.neg_encoded, bind_tc_ok]
  rfl

theorem double_encoded (a : Bls.Fp6) :
    portable.fp6.Fp6.double (encode a) = ok (encode (a + a)) := by
  simp only [portable.fp6.Fp6.double, encode_c0, encode_c1, encode_c2,
    Fp2.double_encoded, bind_tc_ok]
  rfl

theorem mul_by_v_encoded (a : Bls.Fp6) :
    portable.fp6.Fp6.mul_by_v (encode a) = ok (encode a.mulByV) := by
  simp only [portable.fp6.Fp6.mul_by_v, encode_c0, encode_c1, encode_c2,
    Fp2.mul_by_xi_encoded, bind_tc_ok]
  rfl

theorem mul_encoded [RuntimeFeatures] (a b : Bls.Fp6) :
    portable.fp6.Fp6.mul (encode a) (encode b) = ok (encode (a * b)) := by
  simp only [portable.fp6.Fp6.mul, encode_c0, encode_c1, encode_c2,
    Fp2.mul_encoded, Fp2.add_encoded, Fp2.sub_encoded, Fp2.mul_by_xi_encoded, bind_tc_ok]
  rfl

private theorem mul_by_xi_add (a b : Bls.Fp2) :
    (a + b).mulByOnePlusI = a.mulByOnePlusI + b.mulByOnePlusI := by
  apply LeanBlsSimd.Fp2.toField.injective
  simp only [LeanBlsSimd.Fp2.toField_mulByOnePlusI, map_add]
  ring

theorem inverse_encoded [RuntimeFeatures] (a : Bls.Fp6) :
    portable.fp6.Fp6.inverse (encode a) = ok (encode a.inverse) := by
  simp only [portable.fp6.Fp6.inverse, encode_c0, encode_c1, encode_c2,
    Fp2.square_encoded, Fp2.mul_encoded, Fp2.add_encoded, Fp2.sub_encoded,
    Fp2.mul_by_xi_encoded, Fp2.inverse_encoded, bind_tc_ok]
  simp only [mul_by_xi_add]
  have hadd (x y z : Bls.Fp2) : x + (y + z) = x + y + z := by
    apply LeanBlsSimd.Fp2.toField.injective
    simp only [map_add, add_assoc]
  simp only [hadd]
  rfl

def sparse (x y : Bls.Fp2) : Bls.Fp6 := ⟨x, y, Bls.Fp2.zero⟩

theorem mul_by_y_encoded [RuntimeFeatures] (a : Bls.Fp6) (y : Bls.Fp2) :
    portable.fp6.Fp6.mul_by_y (encode a) (Fp2.encode y) =
      ok (encode (a * sparse Bls.Fp2.zero y)) := by
  simp only [portable.fp6.Fp6.mul_by_y, encode_c0, encode_c1, encode_c2,
    Fp2.mul_encoded, Fp2.mul_by_xi_encoded, bind_tc_ok]
  change ok (encode ⟨(a.c2 * y).mulByOnePlusI, a.c0 * y, a.c1 * y⟩) = _
  congr 2
  congr 1 <;>
    apply LeanBlsSimd.Fp2.toField.injective <;>
    simp only [sparse, map_mul, map_add, LeanBlsSimd.Fp2.toField_sub,
      LeanBlsSimd.Fp2.toField_mulByOnePlusI, LeanBlsSimd.Fp2.toField_zero,
      mul_zero, zero_mul, add_zero, zero_add, sub_zero] <;> ring

theorem mul_by_xy_encoded [RuntimeFeatures] (a : Bls.Fp6) (x y : Bls.Fp2) :
    portable.fp6.Fp6.mul_by_xy (encode a) (Fp2.encode x) (Fp2.encode y) =
      ok (encode (a * sparse x y)) := by
  simp only [portable.fp6.Fp6.mul_by_xy, encode_c0, encode_c1, encode_c2,
    Fp2.mul_encoded, Fp2.mul_by_xi_encoded, Fp2.add_encoded, Fp2.sub_encoded, bind_tc_ok]
  change ok (encode ⟨(a.c2 * y).mulByOnePlusI + a.c0 * x,
    (a.c0 + a.c1) * (x + y) - a.c0 * x - a.c1 * y,
    a.c2 * x + a.c1 * y⟩) = _
  congr 2
  congr 1 <;>
    apply LeanBlsSimd.Fp2.toField.injective <;>
    simp only [sparse, map_mul, map_add, LeanBlsSimd.Fp2.toField_sub,
      LeanBlsSimd.Fp2.toField_mulByOnePlusI, LeanBlsSimd.Fp2.toField_zero,
      mul_zero, zero_mul, add_zero, sub_zero] <;> ring

theorem eq_encoded (a b : Bls.Fp6) :
    portable.fp6.Fp6.Insts.CoreCmpPartialEqFp6.eq (encode a) (encode b) =
      ok (a.beq b) := by
  simp only [portable.fp6.Fp6.Insts.CoreCmpPartialEqFp6.eq,
    encode_c0, encode_c1, encode_c2, Fp2.eq_encoded, bind_tc_ok, Bls.Fp6.beq]
  cases a.c0.beq b.c0 <;> cases a.c1.beq b.c1 <;> rfl

theorem encode_injective : Function.Injective encode := by
  intro a b h
  have hc0 : a.c0 = b.c0 := Fp2.encode_injective (congrArg portable.fp6.Fp6.c0 h)
  have hc1 : a.c1 = b.c1 := Fp2.encode_injective (congrArg portable.fp6.Fp6.c1 h)
  have hc2 : a.c2 = b.c2 := Fp2.encode_injective (congrArg portable.fp6.Fp6.c2 h)
  cases a
  cases b
  simp_all

end LeanBlsSimd.Portable.Fp6
