import LeanBlsSimd.Refines.LoopEquiv
import LeanBlsSimd.Msm8.FillReady

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Buckets
set_option maxRecDepth 4096

abbrev Scalar := Array U64 4#usize

def toLane (s : portable.msm.buckets.Buckets) : bls.msm8.buckets.Buckets :=
  ⟨s.window_bits, s.windows, s.refs, s.starts, s.lens⟩

def fromLane (s : bls.msm8.buckets.Buckets) : portable.msm.buckets.Buckets :=
  ⟨s.window_bits, s.windows, s.refs, s.starts, s.lens⟩

@[simp] theorem toLane_fromLane (s : bls.msm8.buckets.Buckets) : toLane (fromLane s) = s := rfl
@[simp] theorem fromLane_toLane (s : portable.msm.buckets.Buckets) : fromLane (toLane s) = s := rfl

def stateEquiv :
    bls.msm8.buckets.Buckets × bls.signed_digits.SignedDigits × Usize ≃
      portable.msm.buckets.Buckets × bls.signed_digits.SignedDigits × Usize where
  toFun s := (fromLane s.1, s.2)
  invFun s := (toLane s.1, s.2)
  left_inv _ := rfl
  right_inv _ := rfl

theorem list_eq (s : bls.msm8.buckets.Buckets) (w m : Usize) :
    (fromLane s).list w m = s.list w m := rfl

theorem count_eq (s : portable.msm.buckets.Buckets) (w m : Usize) :
    s.count w m = (do let out ← (toLane s).count w m; ok (fromLane out)) := by
  simp only [portable.msm.buckets.Buckets.count, bls.msm8.buckets.Buckets.count, toLane, portable.msm.buckets.Buckets.list, bls.msm8.buckets.Buckets.list]
  split <;> simp only [fromLane, bind_assoc_eq, bind_tc_ok, Function.uncurry_def]

theorem place_eq (s : portable.msm.buckets.Buckets) (w m : Usize) (r : U32) :
    s.place w m r = (do let out ← (toLane s).place w m r; ok (fromLane out)) := by
  simp only [portable.msm.buckets.Buckets.place, bls.msm8.buckets.Buckets.place, toLane, portable.msm.buckets.Buckets.list, bls.msm8.buckets.Buckets.list]
  split <;> simp only [fromLane, bind_assoc_eq, bind_tc_ok, Function.uncurry_def]

theorem count_windows_eq (s : bls.msm8.buckets.Buckets)
    (d : bls.signed_digits.SignedDigits) (w : Usize) :
    (fromLane s).fill_loop0_loop0 d w = s.fill_loop0_loop0 d w := by
  apply loop_equiv _ _ stateEquiv _ (s,d,w)
  rintro ⟨s,d,w⟩
  simp only [stateEquiv, Equiv.coe_fn_mk, portable.msm.buckets.Buckets.fill_loop0_loop0.body,
    bls.msm8.buckets.Buckets.fill_loop0_loop0.body, fromLane]
  split <;> simp only [count_eq, bind_assoc_eq, bind_tc_ok, Function.uncurry_def, mapLoopState_bind, mapLoopState_cont, mapLoopState_done,
    fromLane, toLane]

theorem count_scalars_body_eq (scalars : Slice Scalar) (width w n : Usize)
    (refs starts lens : alloc.vec.Vec U32) (i : Usize) :
    portable.msm.buckets.Buckets.fill_loop0.body scalars width w n refs starts lens i =
      bls.msm8.buckets.Buckets.fill_loop0.body scalars width w n refs starts lens i := by
  simp only [portable.msm.buckets.Buckets.fill_loop0.body, bls.msm8.buckets.Buckets.fill_loop0.body]
  simp only [show (⟨w,n,refs,starts,lens⟩ : portable.msm.buckets.Buckets) =
    fromLane ⟨w,n,refs,starts,lens⟩ from rfl, count_windows_eq]

theorem count_scalars_eq (w n : Usize) (refs starts lens : alloc.vec.Vec U32)
    (scalars : Slice Scalar) (width i : Usize) :
    portable.msm.buckets.Buckets.fill_loop0 w n refs starts lens scalars width i =
      bls.msm8.buckets.Buckets.fill_loop0 w n refs starts lens scalars width i := by
  simp only [portable.msm.buckets.Buckets.fill_loop0, bls.msm8.buckets.Buckets.fill_loop0,
    count_scalars_body_eq]

theorem prefix_eq (starts lens : alloc.vec.Vec U32) (lists : Usize) (total : U32) (i : Usize) :
    portable.msm.buckets.Buckets.fill_loop1 starts lens lists total i =
      bls.msm8.buckets.Buckets.fill_loop1 starts lens lists total i := rfl

theorem negativeMask_eq : portable.msm.store.NEGATED = bls.msm8.pairs.NEGATED := by
  unfold portable.msm.store.NEGATED bls.msm8.pairs.NEGATED
  rfl

theorem place_cont_eq {β : Type} (s : bls.msm8.buckets.Buckets)
    (d : bls.signed_digits.SignedDigits) (w m : Usize) (r : U32) :
    (do let next ← (fromLane s).place w m r
        let w' ← w + 1#usize
        ok (cont (next,d,w'))) =
      mapLoopState (β := β) stateEquiv
        (do let next ← s.place w m r
            let w' ← w + 1#usize
            ok (cont (next,d,w'))) := by
  simp only [place_eq, toLane_fromLane, bind_assoc_eq, bind_tc_ok,
    mapLoopState_bind, mapLoopState_cont, stateEquiv, Equiv.coe_fn_mk]

theorem signedReference_bind {β : Type} (i : Usize) (negative : Bool) (k : U32 → Result β) :
    (do let bit ← lift (UScalar.cast_fromBool .U32 negative)
        let mask ← bls.msm8.pairs.NEGATED
        let sign ← bit * mask
        let index ← lift (UScalar.cast .U32 i)
        let reference ← lift (index ||| sign)
        k reference) = k (BucketsRefines.signedReference i negative) := by
  have h := congrArg (fun r : Result U32 => r >>= k)
    (BucketsRefines.signedReference_refines i negative)
  simpa only [bind_assoc_eq, bind_tc_ok] using h

theorem place_windows_body_eq (s : bls.msm8.buckets.Buckets) (i : Usize)
    (d : bls.signed_digits.SignedDigits) (w : Usize) :
    portable.msm.buckets.Buckets.fill_loop2_loop0.body i (fromLane s) d w =
      mapLoopState stateEquiv (bls.msm8.buckets.Buckets.fill_loop2_loop0.body i s d w) := by
  simp only [portable.msm.buckets.Buckets.fill_loop2_loop0.body,
    bls.msm8.buckets.Buckets.fill_loop2_loop0.body, Function.uncurry_def,
    negativeMask_eq, signedReference_bind]
  change (if w < s.windows then _ else _) = _
  split
  · rw [mapLoopState_bind]
    congr 1
    funext p
    exact place_cont_eq s p.2 w p.1.1 (BucketsRefines.signedReference i p.1.2)
  · simp only [mapLoopState_done]
    rfl

theorem place_windows_eq (s : bls.msm8.buckets.Buckets) (i : Usize)
    (d : bls.signed_digits.SignedDigits) (w : Usize) :
    (fromLane s).fill_loop2_loop0 i d w = s.fill_loop2_loop0 i d w := by
  exact loop_equiv _ _ stateEquiv
    (fun t => place_windows_body_eq t.1 i t.2.1 t.2.2) (s,d,w)

theorem place_scalars_body_eq (scalars : Slice Scalar) (width w n : Usize)
    (refs starts lens : alloc.vec.Vec U32) (i : Usize) :
    portable.msm.buckets.Buckets.fill_loop2.body scalars width w n refs starts lens i =
      bls.msm8.buckets.Buckets.fill_loop2.body scalars width w n refs starts lens i := by
  simp only [portable.msm.buckets.Buckets.fill_loop2.body, bls.msm8.buckets.Buckets.fill_loop2.body]
  simp only [show (⟨w,n,refs,starts,lens⟩ : portable.msm.buckets.Buckets) =
    fromLane ⟨w,n,refs,starts,lens⟩ from rfl, place_windows_eq]

theorem place_scalars_eq (w n : Usize) (refs starts lens : alloc.vec.Vec U32)
    (scalars : Slice Scalar) (width i : Usize) :
    portable.msm.buckets.Buckets.fill_loop2 w n refs starts lens scalars width i =
      bls.msm8.buckets.Buckets.fill_loop2 w n refs starts lens scalars width i := by
  simp only [portable.msm.buckets.Buckets.fill_loop2, bls.msm8.buckets.Buckets.fill_loop2,
    place_scalars_body_eq]

/-- Both generated schedules use the same signed digits, counters and prefix-packed references. -/
theorem fill_eq (s : portable.msm.buckets.Buckets) (scalars : Slice Scalar) (bits : Usize) :
    s.fill scalars bits = (do let out ← (toLane s).fill scalars bits; ok (fromLane out)) := by
  simp only [portable.msm.buckets.Buckets.fill, bls.msm8.buckets.Buckets.fill,
    portable.msm.buckets.window_bits, portable.msm.buckets.NARROWEST_WINDOW_BITS,
    bls.msm8.buckets.NARROWEST_WINDOW_BITS, toLane, count_scalars_eq, prefix_eq,
    place_scalars_eq, bind_assoc_eq, bind_tc_ok, Function.uncurry_def, fromLane]

end LeanBlsSimd.Portable.Msm.Buckets
