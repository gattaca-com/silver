import LeanBlsSimd.Portable.Msm.PushLoop
import LeanBlsSimd.Portable.Msm.StoreLifecycle

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Store
local instance : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine EthLib.Cryptography.Bls.G1.zero⟩

/-- The reset and two signed point pushes in the generated nonempty chunk. -/
def prepareStore [RuntimeFeatures] (store : portable.msm.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows : Usize) :
    Result portable.msm.store.PointStore := do
  let n := Slice.len points
  let count ← 2#usize*n
  let extra ← windows*n
  let capacity ← count+extra
  let reset ← store.reset capacity
  let pushed ← reset.push_blst points first false
  pushed.push_blst points second true

theorem prepare_store_correct [RuntimeFeatures] (store : portable.msm.store.PointStore)
    (points : Slice blst.blst_p1_affine) (first second : Slice Bool) (windows : Usize)
    (hf : first.val.length = points.val.length) (hs : second.val.length = points.val.length)
    (hp : ∀ j < points.val.length, Kzg.G1AffineValid points.val[j]!)
    (hfinite : ∀ j < points.val.length, (Kzg.g1ReadAffine points.val[j]!).isInfinity ≠ true)
    (hbound : 2*points.val.length+windows.val*points.val.length < 2^32) :
    ∃ out, prepareStore store points first second windows = ok out ∧
      out.len.val = 2*points.val.length ∧
      out.points.val.length = max store.points.val.length
        (2*points.val.length+windows.val*points.val.length) ∧
      2*points.val.length+windows.val*points.val.length ≤ out.points.val.length ∧
      (∀ j < points.val.length, PointRep out j
        (Msm8.transformedPoint points.val[j]! false first.val[j]!)) ∧
      (∀ j < points.val.length, PointRep out (points.val.length+j)
        (Msm8.transformedPoint points.val[j]! true second.val[j]!)) := by
  have hmax := two_pow_32_le_usize
  have hc : 2*points.val.length+windows.val*points.val.length < 2^UScalarTy.Usize.numBits := by omega
  let capacity : Usize := UScalar.ofNatCore _ hc
  have hcapacity : capacity.val = 2*points.val.length+windows.val*points.val.length := rfl
  obtain ⟨reset,hreset,hpoints,hzero⟩ := reset_refines store capacity
  have hrlen : reset.points.val.length = max store.points.val.length capacity.val := by
    rw [hpoints,List.length_append,List.length_replicate]
    omega
  have hrzero : reset.len.val = 0 := by rw [hzero]; rfl
  obtain ⟨pushed,hpush,hlen,hsize,hfirst,_⟩ := push_blst_refines reset points first false hf
    (by omega) hp hfinite
  have hpushed : pushed.len.val = points.val.length := by omega
  obtain ⟨out,hout,hlen2,hsize2,hsecond,hframe⟩ := push_blst_refines pushed points second true hs
    (by omega) hp hfinite
  refine ⟨out,?_,by omega,by omega,by omega,?_,?_⟩
  · have h2 : (2#usize).val*(Slice.len points).val < 2^UScalarTy.Usize.numBits := by
      change 2*points.val.length < _
      omega
    have hw : windows.val*(Slice.len points).val < 2^UScalarTy.Usize.numBits := by
      change windows.val*points.val.length < _
      omega
    let count : Usize := UScalar.ofNatCore _ h2
    let extra : Usize := UScalar.ofNatCore _ hw
    have hmul2 : 2#usize*Slice.len points = ok count := mul_ok _ _ h2
    have hmulw : windows*Slice.len points = ok extra := mul_ok _ _ hw
    have hsum : count+extra = ok capacity := by
      rw [add_ok count extra hc]
      rfl
    simp only [prepareStore,hmul2,hmulw,hsum,bind_tc_ok,hreset,hpush,hout]
  · intro j hj
    have hr := (hfirst j hj).frame (hframe (reset.len.val+j) (by omega))
    simpa only [hrzero,Nat.zero_add] using hr
  · intro j hj
    simpa only [hpushed] using hsecond j hj

end LeanBlsSimd.Portable.Msm.Store
