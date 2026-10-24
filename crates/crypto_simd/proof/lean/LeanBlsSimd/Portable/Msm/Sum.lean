import LeanBlsSimd.Portable.Msm.Window
import LeanBlsSimd.Msm8.ReferenceSums

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Sums
open QueueRefines BucketsRefines BatchedRefines

theorem double_loop [RuntimeFeatures] (bits cursor : Usize) (total : portable.g1.G1)
    (P : G1Spec.E.Point) (hc : cursor.val ≤ bits.val) (hp : Group.PointRep total P) :
    ∃ out, portable.msm.buckets.Buckets.sum_loop0_loop0 bits total cursor = ok out ∧
      Group.PointRep out (2^(bits.val-cursor.val) • P) := by
  induction hrem : bits.val-cursor.val generalizing cursor total P with
  | zero =>
    refine ⟨total,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.sum_loop0_loop0,loop.eq_1]
      simp only [portable.msm.buckets.Buckets.sum_loop0_loop0.body,UScalar.lt_equiv,
        show ¬cursor.val < bits.val by omega,if_false]
    · simpa only [pow_zero,one_nsmul] using hp
  | succ remaining ih =>
    have hlt : cursor.val < bits.val := by omega
    have hnext : cursor.val+1 < 2^UScalarTy.Usize.numBits := by have := bits.hBounds; omega
    let next : Usize := UScalar.ofNatCore _ hnext
    have hn : next.val = cursor.val+1 := rfl
    obtain ⟨doubled,hd,hdp⟩ := Group.double total P hp
    obtain ⟨out,hloop,hrep⟩ := ih next doubled (P+P) (by omega) hdp (by omega)
    refine ⟨out,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.sum_loop0_loop0,loop.eq_1]
      simpa only [portable.msm.buckets.Buckets.sum_loop0_loop0.body,UScalar.lt_equiv,hlt,if_true,
        hd,bind_tc_ok,add_ok cursor (1#usize) hnext] using hloop
    · simpa only [pow_succ,mul_nsmul,two_nsmul,nsmul_add] using hrep

noncomputable def windowValue (width window : ℕ) (contents : BucketLists)
    (values : ℕ → G1Spec.E.Point) : G1Spec.E.Point :=
  ∑ b ∈ Finset.range (2^(width-1)), (b+1) • bucketValue width window (b+1) contents values

theorem sum_loop [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state (state.windows.val*2^(state.window_bits.val-1)) base capacity contents)
    (hlo : 1 ≤ state.window_bits.val) (hhi : state.window_bits.val ≤ 8)
    (htotal : state.windows.val*2^(state.window_bits.val-1) < 2^32)
    (hp : ∀ i < state.windows.val*2^(state.window_bits.val-1), ∀ r ∈ contents i,
      Store.PointRep store (pointIndex r) (values (pointIndex r)))
    (window : Usize) (hw : window.val < state.windows.val)
    (total : portable.g1.G1) (P : G1Spec.E.Point) (hrep : Group.PointRep total P) :
    ∃ out, portable.msm.buckets.Buckets.sum_loop0 state.window_bits state.windows
      state.refs state.starts state.lens store window total = ok out ∧
      Group.PointRep out (2^(window.val*state.window_bits.val) • P+
        ∑ w ∈ Finset.range window.val, 2^(w*state.window_bits.val) •
          windowValue state.window_bits.val w contents values) := by
  induction hcount : window.val generalizing window total P with
  | zero =>
    refine ⟨total,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.sum_loop0,loop.eq_1]
      simp only [portable.msm.buckets.Buckets.sum_loop0.body,UScalar.lt_equiv,hcount,
        show (0#usize).val = 0 from rfl,Nat.lt_irrefl,if_false]
    · simpa only [Nat.zero_mul,pow_zero,one_nsmul,Finset.sum_range_zero,add_zero] using hrep
  | succ w ih =>
    have hpos : 1 ≤ window.val := by omega
    let next : Usize := UScalar.ofNatCore (window.val-1) (by have := window.hBounds; omega)
    have hn : next.val = w := by change window.val-1=w; omega
    obtain ⟨doubled,hd,hdp⟩ := double_loop state.window_bits 0#usize total P (by simp) hrep
    have hdp' : Group.PointRep doubled (2^state.window_bits.val • P) := by simpa using hdp
    obtain ⟨part,hpart,hpartrep⟩ := window_correct state store base capacity contents values hpacked hlo hhi htotal hp next (by omega)
    obtain ⟨joined,hadd,hjoined⟩ := Group.add_complete doubled part _ _ hdp' hpartrep
    obtain ⟨out,hloop,hout⟩ := ih next (by omega) joined _ hjoined hn
    have hbody : portable.msm.buckets.Buckets.sum_loop0.body state.window_bits state.windows
        state.refs state.starts state.lens store window total = ok (cont (next,joined)) := by
      simp only [portable.msm.buckets.Buckets.sum_loop0.body,UScalar.lt_equiv,
        show (0#usize).val < window.val by change 0 < window.val; omega,if_true,
        sub_ok window (1#usize) hpos,bind_tc_ok,hd]
      change (do let g ← state.window_sum store next
                 let total ← doubled.add_complete g
                 ok (cont (next,total))) = _
      simp only [hpart,hadd,bind_tc_ok]
    refine ⟨out,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.sum_loop0,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [Finset.sum_range_succ,WindowSums.horner_step]
      simpa only [hn,windowValue] using hout

theorem sum_correct [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state (state.windows.val*2^(state.window_bits.val-1)) base capacity contents)
    (hlo : 1 ≤ state.window_bits.val) (hhi : state.window_bits.val ≤ 8)
    (htotal : state.windows.val*2^(state.window_bits.val-1) < 2^32)
    (hwin : 1 ≤ state.windows.val)
    (hp : ∀ i < state.windows.val*2^(state.window_bits.val-1), ∀ r ∈ contents i,
      Store.PointRep store (pointIndex r) (values (pointIndex r))) :
    ∃ out, state.sum store = ok out ∧
      Group.PointRep out (∑ w ∈ Finset.range state.windows.val, 2^(w*state.window_bits.val) •
        windowValue state.window_bits.val w contents values) := by
  let top : Usize := UScalar.ofNatCore (state.windows.val-1) (by have := state.windows.hBounds; omega)
  have ht : top.val = state.windows.val-1 := rfl
  have htop : top.val < state.windows.val := by omega
  obtain ⟨first,hfirst,hrep⟩ := window_correct state store base capacity contents values hpacked hlo hhi htotal hp top htop
  obtain ⟨out,hloop,hout⟩ := sum_loop state store base capacity contents values hpacked hlo hhi htotal hp top htop first _ hrep
  refine ⟨out,?_,?_⟩
  · rw [portable.msm.buckets.Buckets.sum,sub_ok state.windows (1#usize) hwin]
    change (do let first ← state.window_sum store top
               portable.msm.buckets.Buckets.sum_loop0 state.window_bits state.windows
                 state.refs state.starts state.lens store top first) = _
    simp only [hfirst,bind_tc_ok,hloop]
  · have hw : state.windows.val = top.val+1 := by omega
    rw [hw,Finset.sum_range_succ,add_comm]
    exact hout

theorem packed_sum_contribution [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state (state.windows.val*2^(state.window_bits.val-1)) base capacity contents)
    (hshape : WindowSums.BucketShape (Buckets.toLane state)) (hwin : 1 ≤ state.windows.val)
    (hp : ∀ i < state.windows.val*2^(state.window_bits.val-1), ∀ r ∈ contents i,
      Store.PointRep store (pointIndex r) (values (pointIndex r))) :
    ∃ out, state.sum store = ok out ∧
      Group.PointRep out (bucketContributions state.window_bits.val state.windows.val values
        (bucketSlice (Buckets.toLane state))) := by
  obtain ⟨out,hcall,hrep⟩ := sum_correct state store base capacity contents values hpacked
    hshape.width_lower hshape.width_upper hshape.total_bound hwin hp
  have he : bucketContributions state.window_bits.val state.windows.val values
      (bucketSlice (Buckets.toLane state)) =
      bucketContributions state.window_bits.val state.windows.val values contents := by
    apply bucketContributions_congr
    intro i hi
    rw [packed_recovers (Buckets.toLane state) _ base capacity contents hpacked i hi]
  refine ⟨out,hcall,?_⟩
  rw [he]
  simpa only [bucketContributions,windowValue,bucketValue,signedReferenceValue_eq_referencePoint] using hrep

end LeanBlsSimd.Portable.Msm.Sums
