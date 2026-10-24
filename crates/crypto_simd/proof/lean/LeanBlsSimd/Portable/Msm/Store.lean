import LeanBlsSimd.Portable.Fp.PairArithmetic
import LeanBlsSimd.Msm8.Queue

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Store

open QueueRefines

def Holds (s : portable.msm.store.PointStore) (i : ℕ)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus) : Prop :=
  s.points.val[i]? = some (Fp.pairEncode x y)

theorem holds_bound {s : portable.msm.store.PointStore} {i : ℕ}
    {x y : ZMod EthLib.Cryptography.Bls.Fp.modulus} (h : Holds s i x y) :
    i < s.points.val.length := by
  exact (List.getElem?_eq_some_iff.mp h).choose

theorem holds_row {s : portable.msm.store.PointStore} {i : ℕ}
    {x y : ZMod EthLib.Cryptography.Bls.Fp.modulus} (h : Holds s i x y) :
    s.points.val[i]'(holds_bound h) = Fp.pairEncode x y := by
  simpa only [Holds, List.getElem?_eq_getElem (holds_bound h), Option.some.injEq] using h

theorem negative_mask : portable.msm.store.NEGATED = ok 2147483648#u32 := by
  unfold portable.msm.store.NEGATED
  rfl

theorem negative_iff (r : U32) : (r &&& 2147483648#u32 != 0#u32) = decide (2^31 ≤ r.val) := by
  have hb := r.hBounds
  change r.val < 2^32 at hb
  have hv : (r &&& 2147483648#u32).val = (r.val.testBit 31).toNat * 2^31 := by
    rw [UScalar.val_and]
    change r.val &&& 2^31 = _
    exact Nat.and_two_pow _ _
  have hz : (r &&& 2147483648#u32 = 0#u32) ↔ (r &&& 2147483648#u32).val = 0 := by
    constructor
    · intro h; rw [h]; rfl
    · intro h; exact UScalar.eq_of_val_eq h
  have ht : r.val.testBit 31 = decide (2^31 ≤ r.val) := by
    rw [Nat.testBit_eq_decide_div_mod_eq, decide_eq_decide]
    omega
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq, bne_iff_ne, ne_eq, hz, hv, ht]
  by_cases h : 2^31 ≤ r.val
  · simp
  · simp

theorem x_refines (s : portable.msm.store.PointStore) (r : U32)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (h : Holds s (r.val % 2^31) x y) :
    s.x r = ok (Kzg.fpEncode x).l := by
  have hi : (UScalar.cast .Usize (clearSign r)).val < s.points.val.length := by
    simpa only [cast_Usize_val, clearSign_value] using holds_bound h
  have hr : s.points.val[(UScalar.cast .Usize (clearSign r)).val] = Fp.pairEncode x y := by
    simpa only [cast_Usize_val, clearSign_value] using holds_row h
  simp only [portable.msm.store.PointStore.x, negative_mask, bind_tc_ok, lift,
    show (~~~2147483648#u32 : U32) = 2147483647#u32 from rfl]
  simp only [clearSign] at hi hr
  rw [BucketsRefines.vec_index _ _ hi, hr]
  exact Fp.pair_index_zero x y

theorem signed_refines (s : portable.msm.store.PointStore) (r : U32)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus)
    (h : Holds s (r.val % 2^31) x y) :
    s.signed r = ok ((Kzg.fpEncode x).l,
      (Kzg.fpEncode (if 2^31 ≤ r.val then -y else y)).l) := by
  have hi : (UScalar.cast .Usize (clearSign r)).val < s.points.val.length := by
    simpa only [cast_Usize_val, clearSign_value] using holds_bound h
  have hr : s.points.val[(UScalar.cast .Usize (clearSign r)).val] = Fp.pairEncode x y := by
    simpa only [cast_Usize_val, clearSign_value] using holds_row h
  simp only [portable.msm.store.PointStore.signed, negative_mask, bind_tc_ok, lift,
    show (~~~2147483648#u32 : U32) = 2147483647#u32 from rfl]
  simp only [clearSign] at hi hr
  rw [BucketsRefines.vec_index _ _ hi, hr]
  simp only [Fp.pair_index_zero, Fp.pair_index_one, bind_tc_ok, negative_iff, decide_eq_true_eq]
  split
  · simp only [Fp.neg_encoded, bind_tc_ok]
    rfl
  · rfl

def write (s : portable.msm.store.PointStore) (i : ℕ)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus) : portable.msm.store.PointStore :=
  { s with points := ⟨s.points.val.set i (Fp.pairEncode x y), by simpa using s.points.property⟩ }

theorem set_refines (s : portable.msm.store.PointStore) (i : U32)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus) (hi : i.val < s.points.val.length) :
    s.set i (Kzg.fpEncode x).l (Kzg.fpEncode y).l = ok (write s i.val x y) := by
  have hic : (UScalar.cast .Usize i).val < s.points.val.length := by simpa using hi
  simp only [portable.msm.store.PointStore.set, lift, bind_tc_ok,
    BucketsRefines.vec_index_mut _ _ hic, bind_tc_ok]
  simp only [write, alloc.vec.Vec.set, cast_Usize_val, Fp.pairEncode, Function.uncurry_def]

theorem write_holds (s : portable.msm.store.PointStore) (i : ℕ)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus) (hi : i < s.points.val.length) :
    Holds (write s i x y) i x y := by
  exact List.getElem?_set_self hi

theorem write_other (s : portable.msm.store.PointStore) (i j : ℕ)
    (x y : ZMod EthLib.Cryptography.Bls.Fp.modulus) (hij : i ≠ j) :
    (write s i x y).points.val[j]? = s.points.val[j]? := by
  exact List.getElem?_set_ne hij

end LeanBlsSimd.Portable.Msm.Store
