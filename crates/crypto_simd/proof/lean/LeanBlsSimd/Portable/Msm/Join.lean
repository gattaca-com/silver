import LeanBlsSimd.Portable.Msm.Group
import LeanBlsSimd.Msm8.Flatten
import LeanBlsSimd.Portable.Msm.Queue

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Sums
open QueueRefines BucketsRefines BatchedRefines

theorem join_loop [RuntimeFeatures] (refs : alloc.vec.Vec U32) (store : portable.msm.store.PointStore)
    (start len cursor : Usize) (running : portable.g1.G1) (P : G1Spec.E.Point)
    (entries : ℕ → U32) (values : ℕ → G1Spec.E.Point)
    (hc : cursor.val ≤ len.val) (hspan : start.val+len.val ≤ refs.val.length)
    (hr : Group.PointRep running P)
    (he : ∀ j < len.val, refs.val[start.val+j]? = some (entries j))
    (hp : ∀ j < len.val, Store.PointRep store (pointIndex (entries j)) (values (pointIndex (entries j)))) :
    ∃ out, portable.msm.buckets.Buckets.window_sum_loop0_loop0 refs store running start len cursor = ok out ∧
      Group.PointRep out (P+∑ j ∈ Finset.Ico cursor.val len.val, signedReferenceValue values (entries j)) := by
  induction hrem : len.val-cursor.val generalizing running P cursor with
  | zero =>
    have hz : cursor.val = len.val := by omega
    refine ⟨running,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.window_sum_loop0_loop0,loop.eq_1]
      simp only [portable.msm.buckets.Buckets.window_sum_loop0_loop0.body,UScalar.lt_equiv,
        hz,Nat.lt_irrefl,if_false]
    · simpa only [hz,Finset.Ico_self,Finset.sum_empty,add_zero] using hr
  | succ remaining ih =>
    have hlt : cursor.val < len.val := by omega
    have hab : start.val+cursor.val < 2^UScalarTy.Usize.numBits := by
      have := QueueRefines.vec_length_bound refs
      omega
    have hnext : cursor.val+1 < 2^UScalarTy.Usize.numBits := by have := len.hBounds; omega
    let address : Usize := UScalar.ofNatCore _ hab
    let next : Usize := UScalar.ofNatCore _ hnext
    have hn : next.val = cursor.val+1 := rfl
    obtain ⟨joined,hjoin,hjoined⟩ := Group.add_reference store values (entries cursor.val) running P hr (hp cursor.val hlt)
    have hi : address.val < refs.val.length := by change start.val+cursor.val < _; omega
    have hindex : refs.val[address.val] = entries cursor.val := by
      have h : refs.val[address.val]? = some (entries cursor.val) := he cursor.val hlt
      simpa only [List.getElem?_eq_getElem hi,Option.some.injEq] using h
    have hbody : portable.msm.buckets.Buckets.window_sum_loop0_loop0.body refs store start len running cursor =
        ok (cont (joined,next)) := by
      simp only [portable.msm.buckets.Buckets.window_sum_loop0_loop0.body,UScalar.lt_equiv,hlt,if_true]
      rw [add_ok start cursor hab]
      simp only [bind_tc_ok]
      rw [vec_index refs address hi,hindex]
      simp only [bind_tc_ok]
      have h := congrArg (fun r : Result portable.g1.G1 => r >>= fun p => do
        let c ← cursor+1#usize
        ok (cont (β := portable.g1.G1) (p,c))) hjoin
      simpa only [bind_assoc_eq,bind_tc_ok,add_ok cursor (1#usize) hnext] using h
    obtain ⟨out,hloop,hrep⟩ := ih next joined _ (by omega) hjoined (by omega)
    refine ⟨out,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.window_sum_loop0_loop0,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [Finset.sum_eq_sum_Ico_succ_bot hlt]
      simpa only [hn,add_assoc] using hrep

/-- Load one packed bucket and accumulate it with complete mixed additions. -/
def joinBucket [RuntimeFeatures] (state : portable.msm.buckets.Buckets) (store : portable.msm.store.PointStore)
    (index : Usize) (running : portable.g1.G1) : Result portable.g1.G1 := do
  let rawStart ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.starts index
  let start ← lift (UScalar.cast .Usize rawStart)
  let rawLen ← alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.lens index
  let len ← lift (UScalar.cast .Usize rawLen)
  portable.msm.buckets.Buckets.window_sum_loop0_loop0 state.refs store running start len 0#usize

theorem join_packed [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state n base capacity contents)
    (index : Usize) (hi : index.val < n) (running : portable.g1.G1) (P : G1Spec.E.Point)
    (hr : Group.PointRep running P)
    (hp : ∀ r ∈ contents index.val, Store.PointRep store (pointIndex r) (values (pointIndex r))) :
    ∃ out, joinBucket state store index running = ok out ∧
      Group.PointRep out (P+((contents index.val).map (signedReferenceValue values)).sum) := by
  have his : index.val < state.starts.val.length := by
    rw [show state.starts.val.length = n from hpacked.starts_length]; exact hi
  have hil : index.val < state.lens.val.length := by
    rw [show state.lens.val.length = n from hpacked.counts.length]; exact hi
  let start := UScalar.cast .Usize state.starts.val[index.val]
  let len := UScalar.cast .Usize state.lens.val[index.val]
  have hs : start.val = base index.val := by
    simpa only [start,cast_Usize_val,Buckets.toLane,getElem!_pos state.starts.val index.val his]
      using hpacked.starts_values index.val hi
  have hl : len.val = (contents index.val).length := by
    simpa only [len,cast_Usize_val,Buckets.toLane,getElem!_pos state.lens.val index.val hil]
      using hpacked.counts.values index.val hi
  have hspan : start.val+len.val ≤ state.refs.val.length := by
    rw [hs,hl]
    exact le_trans (Nat.add_le_add_left (hpacked.capacity_bound index.val hi) _) (hpacked.regions index.val hi)
  obtain ⟨out,hcall,hrep⟩ := join_loop state.refs store start len 0#usize running P
    (fun j => (contents index.val)[j]!) values (by simp) hspan hr (by
      intro j hj
      have hbound : start.val+j < state.refs.val.length := by omega
      rw [List.getElem?_eq_getElem hbound]
      congr 1
      have he := hpacked.entries index.val hi j (by omega)
      simpa only [Buckets.toLane,←hs,getElem!_pos state.refs.val (start.val+j) hbound] using he) (by
      intro j hj
      exact hp _ (by simpa only [getElem!_pos (contents index.val) j (by omega)] using
        List.getElem_mem (l := contents index.val) (n := j) (by omega)))
  refine ⟨out,?_,?_⟩
  · simp only [joinBucket,vec_index state.starts index his,vec_index state.lens index hil,
      bind_tc_ok,lift]
    exact hcall
  · simpa only [show (0#usize).val = 0 from rfl,Nat.Ico_zero_eq_range,hl,
      WindowSums.sum_list_indices] using hrep

end LeanBlsSimd.Portable.Msm.Sums
