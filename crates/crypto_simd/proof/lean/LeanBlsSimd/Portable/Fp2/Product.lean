import LeanBlsSimd.Portable.Fp.WideProduct
import LeanBlsSimd.Portable.Fp.WideReduction
import LeanBlsSimd.Spec.Fp2Tower

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls
open scoped EthLib.Cryptography.Bls.Fp

namespace LeanBlsSimd.Portable.Fp2

open Word64

set_option maxRecDepth 4096
set_option maxHeartbeats 1000000
set_option exponentiation.threshold 4096

def encode (x : Bls.Fp2) : portable.fp2.Fp2 :=
  ⟨(Kzg.fpEncode x.c0).l, (Kzg.fpEncode x.c1).l⟩

def Rep (a : portable.fp2.Fp2) (x : Bls.Fp2) : Prop :=
  Fp.Rep a.c0 x.c0 ∧ Fp.Rep a.c1 x.c1

theorem encode_rep (x : Bls.Fp2) : Rep (encode x) x :=
  ⟨Kzg.portableFpRep_encode _, Kzg.portableFpRep_encode _⟩

theorem rep_eq_encode {a : portable.fp2.Fp2} {x : Bls.Fp2} (h : Rep a x) :
    a = encode x := by
  cases a
  exact congrArg₂ portable.fp2.Fp2.mk (Fp.rep_eq_encode h.1) (Fp.rep_eq_encode h.2)

private theorem reduce_encoded (a : portable.fp.Wide) (x : ZMod Bls.Fp.modulus)
    (ha : value a < (Bls.Fp.modulus : ℤ) * (radix : ℤ) ^ 6)
    (hx : (value a : ZMod Bls.Fp.modulus) = x * (2 ^ 384 : ZMod Bls.Fp.modulus) ^ 2) :
    portable.fp.Wide.reduce a = ok (Kzg.fpEncode x).l := by
  obtain ⟨out, hr, hb, k, hv⟩ := Fp.Wide.reduce_refines a ha
  have hf := congrArg (fun n : ℤ => (n : ZMod Bls.Fp.modulus)) hv
  have hp : (radix : ZMod Bls.Fp.modulus) ^ 6 = (2 ^ 384 : ZMod Bls.Fp.modulus) := by
    norm_num [radix]
  simp only [Int.cast_mul, Int.cast_add, Int.cast_pow, Int.cast_natCast,
    ZMod.natCast_self, mul_zero, add_zero, hp, hx] at hf
  have heq : out = (Kzg.fpEncode x).l := by
    apply Fp.eq_encode_of_field out x hb
    apply mul_right_cancel₀ (by decide +kernel : (2 ^ 384 : ZMod Bls.Fp.modulus) ≠ 0)
    rw [hf, Fp.encode_field]
    change x * (2 ^ 384 : ZMod Bls.Fp.modulus) ^ 2 = (x * 2 ^ 384) * 2 ^ 384
    ring
  rwa [heq] at hr

private theorem product_bound (a b : ℤ)
    (ha : 0 ≤ a ∧ a < Bls.Fp.modulus) (hb : 0 ≤ b ∧ b < Bls.Fp.modulus) :
    a * b < (Bls.Fp.modulus : ℤ) * (radix : ℤ) ^ 6 := by
  have hp : (0 : ℤ) < Bls.Fp.modulus := by decide
  have h := lt_of_le_of_lt (mul_le_mul_of_nonneg_right ha.2.le hb.1)
    (mul_lt_mul_of_pos_left hb.2 hp)
  have hc : (Bls.Fp.modulus : ℤ) * Bls.Fp.modulus <
      (Bls.Fp.modulus : ℤ) * (radix : ℤ) ^ 6 := by norm_num [Bls.Fp.modulus, radix]
  exact h.trans hc

theorem product_encoded (a b : Bls.Fp2) :
    portable.fp2.Fp2.product (encode a) (encode b) = ok (encode (a * b)) := by
  let a0 := (Kzg.fpEncode a.c0).l
  let a1 := (Kzg.fpEncode a.c1).l
  let b0 := (Kzg.fpEncode b.c0).l
  let b1 := (Kzg.fpEncode b.c1).l
  have ha0 : 0 ≤ value a0 ∧ value a0 < Bls.Fp.modulus :=
    ⟨(value_bounds a0).1, Fp.encode_bound _⟩
  have ha1 : 0 ≤ value a1 ∧ value a1 < Bls.Fp.modulus :=
    ⟨(value_bounds a1).1, Fp.encode_bound _⟩
  have hb0 : 0 ≤ value b0 ∧ value b0 < Bls.Fp.modulus :=
    ⟨(value_bounds b0).1, Fp.encode_bound _⟩
  have hb1 : 0 ≤ value b1 ∧ value b1 < Bls.Fp.modulus :=
    ⟨(value_bounds b1).1, Fp.encode_bound _⟩
  obtain ⟨t0, ht0, hv0⟩ := Fp.Wide.product_refines a0 b0
  obtain ⟨t1, ht1, hv1⟩ := Fp.Wide.product_refines a1 b1
  obtain ⟨asum, hasum, hvasum⟩ := Fp.Wide.unreduced_add_refines a0 a1 ha0.2 ha1.2
  obtain ⟨bsum, hbsum, hvbsum⟩ := Fp.Wide.unreduced_add_refines b0 b1 hb0.2 hb1.2
  obtain ⟨t2, ht2, hv2⟩ := Fp.Wide.product_refines asum bsum
  rw [hvasum, hvbsum] at hv2
  obtain ⟨real, hreal, hvreal⟩ := Fp.Wide.minus_mod_refines t0 t1
    (by rw [hv0]; exact product_bound _ _ ha0 hb0)
    (by rw [hv1]; exact product_bound _ _ ha1 hb1)
  have hc := Fp.Wide.cross_term_bounds _ _ _ _ ha0 ha1 hb0 hb1
  have hn1 := (value_bounds t1).1
  obtain ⟨cross, hcross, hvcross⟩ := Fp.Wide.minus_refines t2 t0 (by
    rw [hv1] at hn1
    rw [hv0, hv2]
    nlinarith [hc.1])
  obtain ⟨imag, himag, hvimag⟩ := Fp.Wide.minus_refines cross t1 (by
    rw [hvcross, hv2, hv0, hv1]
    linarith [hc.1])
  have hrbound : value real < (Bls.Fp.modulus : ℤ) * (radix : ℤ) ^ 6 := by
    rw [hvreal]
    exact Int.emod_lt_of_pos _ (by norm_num [Bls.Fp.modulus, radix])
  have hibound : value imag < (Bls.Fp.modulus : ℤ) * (radix : ℤ) ^ 6 := by
    rw [hvimag, hvcross, hv2, hv0, hv1]
    exact hc.2.2
  have hrf : (value real : ZMod Bls.Fp.modulus) =
      Bls.Fp.toZMod (a.c0 * b.c0 - a.c1 * b.c1) * (2 ^ 384) ^ 2 := by
    rw [hvreal, Int.emod_def, hv0, hv1]
    simp only [Int.cast_sub, Int.cast_mul, Int.cast_natCast, ZMod.natCast_self,
      zero_mul, sub_zero, a0, a1, b0, b1, Fp.encode_field]
    change _ = ((Bls.Fp.toZMod a.c0) * (Bls.Fp.toZMod b.c0) -
      (Bls.Fp.toZMod a.c1) * (Bls.Fp.toZMod b.c1)) * (2 ^ 384) ^ 2
    ring
  have hif : (value imag : ZMod Bls.Fp.modulus) =
      Bls.Fp.toZMod (a.c0 * b.c1 + a.c1 * b.c0) * (2 ^ 384) ^ 2 := by
    rw [hvimag, hvcross, hv2, hv0, hv1]
    simp only [Int.cast_sub, Int.cast_mul, Int.cast_add, a0, a1, b0, b1, Fp.encode_field]
    change _ = ((Bls.Fp.toZMod a.c0) * (Bls.Fp.toZMod b.c1) +
      (Bls.Fp.toZMod a.c1) * (Bls.Fp.toZMod b.c0)) * (2 ^ 384) ^ 2
    ring
  have hr := reduce_encoded real _ hrbound hrf
  have hi := reduce_encoded imag _ hibound hif
  change (do
    let t0 ← portable.fp.Wide.product a0 b0
    let t1 ← portable.fp.Wide.product a1 b1
    let asum ← portable.fp.Fp.unreduced_add a0 a1
    let bsum ← portable.fp.Fp.unreduced_add b0 b1
    let t2 ← portable.fp.Wide.product asum bsum
    let real ← portable.fp.Wide.minus_mod t0 t1
    let r ← portable.fp.Wide.reduce real
    let cross ← portable.fp.Wide.minus t2 t0
    let imag ← portable.fp.Wide.minus cross t1
    let i ← portable.fp.Wide.reduce imag
    ok (⟨r, i⟩ : portable.fp2.Fp2)) = _
  simp only [ht0, ht1, hasum, hbsum, ht2, hreal, hr, hcross, himag, hi, bind_tc_ok]
  rfl

theorem mul_encoded [RuntimeFeatures] (a b : Bls.Fp2) :
    portable.fp2.Fp2.mul (encode a) (encode b) = ok (encode (a * b)) := by
  simp only [portable.fp2.Fp2.mul, bmi2_available, bind_tc_ok]
  split <;> exact product_encoded a b

end LeanBlsSimd.Portable.Fp2
