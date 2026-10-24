import LeanBlsSimd.Portable.Msm.Join

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Sums
open QueueRefines BucketsRefines BatchedRefines

noncomputable def bucketValue (width window bucket : ℕ) (contents : BucketLists)
    (values : ℕ → G1Spec.E.Point) : G1Spec.E.Point :=
  ((contents (listIndex width window bucket)).map (signedReferenceValue values)).sum

theorem window_loop [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state (state.windows.val*2^(state.window_bits.val-1)) base capacity contents)
    (hlo : 1 ≤ state.window_bits.val) (hhi : state.window_bits.val ≤ 8)
    (htotal : state.windows.val*2^(state.window_bits.val-1) < 2^32)
    (hp : ∀ i < state.windows.val*2^(state.window_bits.val-1), ∀ r ∈ contents i,
      Store.PointRep store (pointIndex r) (values (pointIndex r)))
    (window bucket : Usize) (hw : window.val < state.windows.val)
    (hb : bucket.val ≤ 2^(state.window_bits.val-1))
    (running sum : portable.g1.G1) (R S : G1Spec.E.Point)
    (hr : Group.PointRep running R) (hs : Group.PointRep sum S) :
    ∃ out, portable.msm.buckets.Buckets.window_sum_loop0 state.window_bits state.windows
      state.refs state.starts state.lens store window running sum bucket = ok out ∧
      Group.PointRep out (S+bucket.val • R+∑ b ∈ Finset.range bucket.val,
        (b+1) • bucketValue state.window_bits.val window.val (b+1) contents values) := by
  induction hcount : bucket.val generalizing bucket running sum R S with
  | zero =>
    refine ⟨sum,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.window_sum_loop0,loop.eq_1]
      simp only [portable.msm.buckets.Buckets.window_sum_loop0.body,UScalar.lt_equiv,
        hcount,show (0#usize).val = 0 from rfl,Nat.lt_irrefl,if_false]
    · simpa only [hcount,Finset.sum_range_zero,zero_nsmul,add_zero] using hs
  | succ b ih =>
    have hpos : 1 ≤ bucket.val := by omega
    have hbound : (window.val+1)*2^(state.window_bits.val-1) < 2^32 :=
      lt_of_le_of_lt (Nat.mul_le_mul_right _ (by omega)) htotal
    obtain ⟨index,hindex,hiv⟩ := BucketsRefines.list_refines (Buckets.toLane state) window bucket hlo hhi hpos hb hbound
    have hlist : state.list window bucket = ok index := hindex
    have hi : index.val < state.windows.val*2^(state.window_bits.val-1) := by
      rw [hiv]
      exact WindowSums.listIndex_lt _ _ _ _ hw hpos hb
    obtain ⟨joined,hjoin,hjoined⟩ := join_packed state store _ base capacity contents values
      hpacked index hi running R hr (hp index.val hi)
    have hjoined' : Group.PointRep joined
        (R+bucketValue state.window_bits.val window.val (b+1) contents values) := by
      simpa only [bucketValue,hiv,hcount] using hjoined
    obtain ⟨total,hadd,htotalrep⟩ := Group.add_complete sum joined _ _ hs hjoined'
    let next : Usize := UScalar.ofNatCore (bucket.val-1) (by have := bucket.hBounds; omega)
    have hn : next.val = b := by change bucket.val-1=b; omega
    have hbody : portable.msm.buckets.Buckets.window_sum_loop0.body state.window_bits state.windows
        state.refs state.starts state.lens store window running sum bucket = ok (cont (joined,total,next)) := by
      simp only [portable.msm.buckets.Buckets.window_sum_loop0.body,UScalar.lt_equiv,
        show (0#usize).val < bucket.val by change 0 < bucket.val; omega,if_true,hlist,bind_tc_ok]
      have h := congrArg (fun value : Result portable.g1.G1 => value >>= fun running1 => do
        let sum1 ← sum.add_complete running1
        let next ← bucket-1#usize
        ok (cont (β := portable.g1.G1) (running1,sum1,next))) hjoin
      simpa only [joinBucket,bind_assoc_eq,bind_tc_ok,hadd,sub_ok bucket (1#usize) hpos] using h
    obtain ⟨out,hloop,hrep⟩ := ih next (by omega) joined total _ _ hjoined' htotalrep hn
    refine ⟨out,?_,?_⟩
    · rw [portable.msm.buckets.Buckets.window_sum_loop0,loop.eq_1]
      simpa only [hbody] using hloop
    · rw [Finset.sum_range_succ,WindowSums.weighted_step]
      simpa only [hn] using hrep

theorem window_correct [RuntimeFeatures] (state : portable.msm.buckets.Buckets)
    (store : portable.msm.store.PointStore) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (values : ℕ → G1Spec.E.Point)
    (hpacked : Queue.Packed state (state.windows.val*2^(state.window_bits.val-1)) base capacity contents)
    (hlo : 1 ≤ state.window_bits.val) (hhi : state.window_bits.val ≤ 8)
    (htotal : state.windows.val*2^(state.window_bits.val-1) < 2^32)
    (hp : ∀ i < state.windows.val*2^(state.window_bits.val-1), ∀ r ∈ contents i,
      Store.PointRep store (pointIndex r) (values (pointIndex r)))
    (window : Usize) (hw : window.val < state.windows.val) :
    ∃ out, state.window_sum store window = ok out ∧
      Group.PointRep out (∑ b ∈ Finset.range (2^(state.window_bits.val-1)),
        (b+1) • bucketValue state.window_bits.val window.val (b+1) contents values) := by
  obtain ⟨maximum,hm,hcall⟩ := WindowSums.bucketCount_refines state.window_bits hlo hhi
  obtain ⟨out,hloop,hrep⟩ := window_loop state store base capacity contents values hpacked hlo hhi htotal hp
    window maximum hw (le_of_eq hm) _ _ _ _ Group.infinity_rep Group.infinity_rep
  refine ⟨out,?_,?_⟩
  · unfold portable.msm.buckets.Buckets.window_sum
    have h := congrArg (fun value : Result Usize => value >>= fun bucket =>
      portable.msm.buckets.Buckets.window_sum_loop0 state.window_bits state.windows state.refs state.starts
        state.lens store window portable.g1.G1.INFINITY portable.g1.G1.INFINITY bucket) hcall
    simpa only [bind_assoc_eq,bind_tc_ok,hloop] using h
  · simpa only [hm,nsmul_zero,zero_add] using hrep

end LeanBlsSimd.Portable.Msm.Sums
