import LeanBlsSimd.Portable.Msm.RoundLayout

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Rounds
open portable.msm QueueRefines BucketsRefines BatchedRefines
open PairRoundsRefines (original_refs_independent)

theorem run_pending [RuntimeFeatures] (ctx : Context) (state : RoundState)
    (hpending : Pending ctx state) (he : state.2.2.a.val.isEmpty = false) :
    ∃ flag adds ps, state.2.2.run state.1 = ok (flag,adds,ps) ∧
      if flag then Completed ctx (ps,state.2.1,adds)
      else Frame ctx (ps,state.2.1,adds) ∧ adds.a.val.isEmpty = false := by
  obtain ⟨source,contents,values,hc,hq⟩ := hpending
  let jobs := (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1
  have hreserve := hc.layout.reserve ctx.limits
  have hinfo := reduceChunks_job_info ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
    hc.layout.lower hc.layout.live hreserve
  have hind : jobs.Pairwise JobIndependent :=
    reduceChunks_independent ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
      hc.layout.lower hc.layout.live hreserve hc.layout.independent
  have hout : ∀ job ∈ jobs, job.output.val < 2^31 := by
    intro job hj
    have hh := (hinfo job hj).2.2.2.1
    have hb := reduceChunks_budget ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
    omega
  have hbound : ∀ job ∈ jobs, job.output.val < state.1.points.val.length := by
    intro job hj
    have ho := (hinfo job hj).2.2.2.1
    have hn := hq.next
    have hu := hq.layout.upper
    have hl := hq.layout.points_length
    have ha := ctx.limits.allocate
    omega
  have hinputs : ∀ job ∈ jobs,
      Store.PointRep state.1 (pointIndex job.first) (values (pointIndex job.first)) ∧
      Store.PointRep state.1 (pointIndex job.second) (values (pointIndex job.second)) := by
    intro job hj
    have hi := hinfo job hj
    constructor
    · simpa only [Store.PointRep,Store.Holds,hq.points] using hc.refs job.first hi.1
    · simpa only [Store.PointRep,Store.Holds,hq.points] using hc.refs job.second hi.2.1
  obtain ⟨flag,adds,ps,hrun,hfirsts,_,_,hlen,hsize,hframe,hresult⟩ :=
    Batch.run_jobs_correct state.2.2 state.1 jobs values hq.firsts hq.seconds hq.outputs
      hind hinputs hbound
  refine ⟨flag,adds,ps,hrun,?_⟩
  cases flag with
  | false =>
    change ps = state.1 at hresult
    simp only [Bool.false_eq_true,if_false]
    constructor
    · have hf := hq.frame hc.frame
      refine ⟨?_,hf.bits,hf.windows,?_⟩
      · simpa only [hresult] using hf.originals
      · simpa only [hresult] using hf.points_length
    · simpa only [hfirsts] using he
  | true =>
    simp only [if_true]
    have hupdated := Batch.jobs_points_updated jobs values hind state.1 ps hresult hframe
    refine ⟨replaceContents contents 0 (reduceChunks ctx.originals.val source.1.len.val
      (bucketChunks ctx.total contents)).1,updatedValues jobs values,?_⟩
    apply complete_after ctx source state contents values (updatedValues jobs values) hc hq
      ps adds hlen hsize hupdated.1
    · intro r hr
      apply hupdated.2
      simpa only [Store.PointRep,Store.Holds,hq.points] using hc.refs r hr
    · intro job hj
      rw [signedReferenceValue_eq_sign,if_neg (by have := hout job hj; omega),
        Nat.mod_eq_of_lt (hout job hj)]
      exact updatedValues_job jobs values hind job hj
    · intro r hr
      have hodd := reduceChunks_odd_frame ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
        hc.layout.lower hc.layout.live hreserve hc.layout.independent
      have hne : ∀ job ∈ jobs, pointIndex r ≠ job.output.val := by
        intro job hj
        exact (hodd job hj r hr).symm
      simp only [signedReferenceValue,updatedValues_frame jobs values (pointIndex r) hne]
    · intro p hp
      apply hframe p (ctx.originalValues p) ((hq.frame hc.frame).originals p hp)
      intro job hj
      have hh := (hinfo job hj).2.2.1
      omega

theorem pair_rounds_concrete [RuntimeFeatures] (ctx : Context) (state : portable.msm.Msm)
    (h : Completed ctx (state.store, state.buckets, state.adds)) :
    ∃ flag result, state.pair_rounds ctx.originals = ok (flag, result) ∧
      (if flag then Success ctx (result.store, result.buckets, result.adds)
       else Frame ctx (result.store, result.buckets, result.adds)) ∧
      result.finite_points = state.finite_points ∧ result.finite_scalars = state.finite_scalars ∧
      result.halves = state.halves ∧ result.first_signs = state.first_signs ∧
      result.second_signs = state.second_signs :=
  pair_rounds_correct ctx.originals (Pending ctx) (Completed ctx) (Success ctx) (Frame ctx)
    (pending_empty ctx) (run_pending ctx) (queue_completed ctx) state h

theorem initial_completed (ctx : Context) (state : RoundState) (contents : BucketLists)
    (hp : Packed state.2.1 ctx.total ctx.base ctx.capacity contents)
    (hlen : state.1.len.val = ctx.originals.val)
    (hpoints : state.1.points.val.length = ctx.slots)
    (hactive : chunksActive (bucketChunks ctx.total contents) ≤ ctx.maximum)
    (hlive : ∀ r ∈ (bucketChunks ctx.total contents).flatten, pointIndex r < ctx.originals.val)
    (hframe : Frame ctx state)
    (hsums : ∀ i < ctx.total, ((contents i).map (signedReferenceValue ctx.originalValues)).sum = ctx.target i) :
    Completed ctx state := by
  refine ⟨contents, ctx.originalValues, ?_, ?_, hsums, hframe⟩
  · refine ⟨hp, ?_, ?_, hpoints, hactive, ?_, original_refs_independent _ _ hlive, Or.inl hlen⟩
    · omega
    · omega
    · simpa only [hlen] using hlive
  · intro r hr
    exact hframe.originals (pointIndex r) (hlive r hr)

theorem pair_rounds_initial [RuntimeFeatures] (ctx : Context) (state : portable.msm.Msm)
    (contents : BucketLists)
    (hp : Packed state.buckets ctx.total ctx.base ctx.capacity contents)
    (hlen : state.store.len.val = ctx.originals.val)
    (hpoints : state.store.points.val.length = ctx.slots)
    (hactive : chunksActive (bucketChunks ctx.total contents) ≤ ctx.maximum)
    (hlive : ∀ r ∈ (bucketChunks ctx.total contents).flatten, pointIndex r < ctx.originals.val)
    (hframe : Frame ctx (state.store, state.buckets, state.adds))
    (hsums : ∀ i < ctx.total, ((contents i).map (signedReferenceValue ctx.originalValues)).sum = ctx.target i) :
    ∃ flag result, state.pair_rounds ctx.originals = ok (flag, result) ∧
      (if flag then Success ctx (result.store, result.buckets, result.adds)
       else Frame ctx (result.store, result.buckets, result.adds)) ∧
      result.finite_points = state.finite_points ∧ result.finite_scalars = state.finite_scalars ∧
      result.halves = state.halves ∧ result.first_signs = state.first_signs ∧
      result.second_signs = state.second_signs :=
  pair_rounds_concrete ctx state (initial_completed ctx (state.store, state.buckets, state.adds)
    contents hp hlen hpoints hactive hlive hframe hsums)

theorem Success.buckets {ctx : Context} {state : RoundState} (h : Success ctx state) :
    ∃ values : ℕ → G1Spec.E.Point,
      (∀ i < ctx.total, ∀ r ∈ bucketSlice state.2.1 i,
        Store.PointRep state.1 (pointIndex r) (values (pointIndex r))) ∧
      (∀ i < ctx.total, ((bucketSlice state.2.1 i).map (signedReferenceValue values)).sum = ctx.target i) ∧
      (∀ i < ctx.total, (bucketSlice state.2.1 i).length ≤ 1) ∧ Frame ctx state := by
  obtain ⟨⟨contents, values, hc⟩, hs⟩ := h
  refine ⟨values, ?_, ?_, hs, hc.frame⟩
  · intro i hi r hr
    rw [packed_recovers state.2.1 ctx.total ctx.base ctx.capacity contents hc.layout.packed i hi] at hr
    apply hc.refs r
    exact List.mem_flatten.mpr ⟨contents i, List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩, hr⟩
  · intro i hi
    rw [packed_recovers state.2.1 ctx.total ctx.base ctx.capacity contents hc.layout.packed i hi]
    exact hc.sums i hi

end LeanBlsSimd.Portable.Msm.Rounds
