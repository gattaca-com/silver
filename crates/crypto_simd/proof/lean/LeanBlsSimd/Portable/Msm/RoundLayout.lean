import LeanBlsSimd.Portable.Msm.Queue
import LeanBlsSimd.Portable.Msm.BatchJobs
import LeanBlsSimd.Msm8.PairRounds

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Rounds
open portable.msm QueueRefines BucketsRefines BatchedRefines
open PairRoundsRefines (bucketChunks_replace reduceChunks_singletons chunksActive_member
  reduceChunks_members original_refs_independent)

abbrev Packed := Queue.Packed
abbrev Counts (state : buckets.Buckets) (n : ℕ) (contents : BucketLists) :=
  BucketsRefines.Counts (Buckets.toLane state) n contents
abbrev bucketSlice (state : buckets.Buckets) (i : ℕ) :=
  BucketsRefines.bucketSlice (Buckets.toLane state) i

theorem packed_recovers (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents) (i : ℕ) (hi : i < n) :
    bucketSlice state i = contents i := BucketsRefines.packed_recovers _ _ _ _ _ h i hi

theorem counts_active (state : buckets.Buckets) (n : ℕ) (contents : BucketLists)
    (h : Counts state n contents) :
    activeCount state.lens.val = chunksActive (bucketChunks n contents) :=
  PairRoundsRefines.counts_active (Buckets.toLane state) n contents h

abbrev RoundState := store.PointStore × buckets.Buckets × pairs.BatchedAdds

def roundMeasure (state : RoundState) : ℕ :=
  activeCount state.2.1.lens.val + state.2.2.a.val.length

theorem adds_is_empty (adds : pairs.BatchedAdds) :
    adds.is_empty = ok adds.a.val.isEmpty := rfl

theorem pair_rounds_loop_correct [RuntimeFeatures] (originals : Usize)
    (Ready Completed Success Rejected : RoundState → Prop)
    (hempty : ∀ state, Ready state → state.2.2.a.val.isEmpty = true → Success state)
    (hrun : ∀ state, Ready state → state.2.2.a.val.isEmpty = false →
      ∃ flag adds ps, state.2.2.run state.1 = ok (flag, adds, ps) ∧
        if flag then Completed (ps, state.2.1, adds)
        else Rejected (ps, state.2.1, adds) ∧ adds.a.val.isEmpty = false)
    (hqueue : ∀ state, Completed state →
      ∃ b adds ps, state.2.1.queue_round state.2.2 state.1 originals = ok (b, adds, ps) ∧
        Ready (ps, b, adds) ∧ roundMeasure (ps, b, adds) = activeCount state.2.1.lens.val)
    (state : RoundState) (hready : Ready state) :
    ∃ result, Msm.pair_rounds_loop state.1 state.2.1 state.2.2 originals = ok result ∧
      (result.2.2.a.val.isEmpty = true ∧ Success result ∨
       result.2.2.a.val.isEmpty = false ∧ Rejected result) := by
  generalize hm : roundMeasure state = measure
  induction measure using Nat.strong_induction_on generalizing state with
  | h measure ih =>
    rcases state with ⟨ps, b, adds⟩
    by_cases he : adds.a.val.isEmpty = true
    · refine ⟨(ps, b, adds), ?_, Or.inl ⟨he, hempty _ hready he⟩⟩
      rw [Msm.pair_rounds_loop, loop.eq_1]
      simp only [Msm.pair_rounds_loop.body, adds_is_empty, he, bind_tc_ok, if_true]
    · have he' : adds.a.val.isEmpty = false := Bool.eq_false_iff.mpr he
      obtain ⟨flag, adds', ps', hrunEq, hrunPost⟩ := hrun (ps, b, adds) hready he'
      cases flag with
      | false =>
        obtain ⟨hreject, hnonempty⟩ := hrunPost
        refine ⟨(ps', b, adds'), ?_, Or.inr ⟨hnonempty, hreject⟩⟩
        rw [Msm.pair_rounds_loop, loop.eq_1]
        simp only [Msm.pair_rounds_loop.body, adds_is_empty, he', bind_tc_ok,
          Bool.false_eq_true, if_false, hrunEq]
        rfl
      | true =>
        obtain ⟨b', adds'', ps'', hqueueEq, hready', hmeasure⟩ := hqueue (ps', b, adds') hrunPost
        have hpos : 0 < adds.a.val.length := by
          have hn : adds.a.val ≠ [] := List.isEmpty_eq_false_iff.mp he'
          exact List.length_pos_iff.mpr hn
        have hlt : roundMeasure (ps'', b', adds'') < measure := by
          simp only [roundMeasure] at hm
          dsimp only at hmeasure
          omega
        obtain ⟨result, hloop, hpost⟩ := ih (roundMeasure (ps'', b', adds'')) hlt
          (ps'', b', adds'') hready' rfl
        refine ⟨result, ?_, hpost⟩
        have hbody : Msm.pair_rounds_loop.body originals ps b adds = ok (cont (ps'', b', adds'')) := by
          simp only [Msm.pair_rounds_loop.body, adds_is_empty, he', bind_tc_ok,
            Bool.false_eq_true, if_false, hrunEq]
          change (do
            let (bucket, batch, points) ← b.queue_round adds' ps' originals
            ok (cont (points, bucket, batch))) = _
          rw [hqueueEq]
          rfl
        rw [Msm.pair_rounds_loop, loop.eq_1]
        simpa only [hbody] using hloop

theorem pair_rounds_correct [RuntimeFeatures] (originals : Usize)
    (Ready Completed Success Rejected : RoundState → Prop)
    (hempty : ∀ state, Ready state → state.2.2.a.val.isEmpty = true → Success state)
    (hrun : ∀ state, Ready state → state.2.2.a.val.isEmpty = false →
      ∃ flag adds ps, state.2.2.run state.1 = ok (flag, adds, ps) ∧
        if flag then Completed (ps, state.2.1, adds)
        else Rejected (ps, state.2.1, adds) ∧ adds.a.val.isEmpty = false)
    (hqueue : ∀ state, Completed state →
      ∃ b adds ps, state.2.1.queue_round state.2.2 state.1 originals = ok (b, adds, ps) ∧
        Ready (ps, b, adds) ∧ roundMeasure (ps, b, adds) = activeCount state.2.1.lens.val)
    (state : Msm) (hcompleted : Completed (state.store, state.buckets, state.adds)) :
    ∃ flag result, state.pair_rounds originals = ok (flag, result) ∧
      (if flag then Success (result.store, result.buckets, result.adds)
       else Rejected (result.store, result.buckets, result.adds)) ∧
      result.finite_points = state.finite_points ∧ result.finite_scalars = state.finite_scalars ∧
      result.halves = state.halves ∧ result.first_signs = state.first_signs ∧
      result.second_signs = state.second_signs := by
  obtain ⟨b, adds, ps, hqueueEq, hready, _⟩ :=
    hqueue (state.store, state.buckets, state.adds) hcompleted
  obtain ⟨result, hloop, hpost⟩ := pair_rounds_loop_correct originals Ready Completed Success Rejected
    hempty hrun hqueue (ps, b, adds) hready
  refine ⟨result.2.2.a.val.isEmpty,
    {state with store := result.1, buckets := result.2.1, adds := result.2.2}, ?_, ?_,
    rfl, rfl, rfl, rfl, rfl⟩
  · simp only [Msm.pair_rounds, hqueueEq, bind_tc_ok]
    change (do
      let (ps1, b1, ba1) ← Msm.pair_rounds_loop ps b adds originals
      let flag ← ba1.is_empty
      ok (flag, {state with store := ps1, buckets := b1, adds := ba1})) = _
    rw [hloop]
    rcases result with ⟨ps1, b1, ba1⟩
    rfl
  · rcases hpost with ⟨he, hp⟩ | ⟨he, hp⟩
    · simp only [he, if_true]; exact hp
    · simp only [he, Bool.false_eq_true, if_false]; exact hp


theorem packed_reduction_measure (originals next n : ℕ) (contents : BucketLists)
    (before after : buckets.Buckets) (base capacity : ℕ → ℕ) (ps : store.PointStore)
    (adds : pairs.BatchedAdds) (hb : Counts before n contents)
    (ha : Packed after n base capacity (replaceContents contents 0
      (reduceChunks originals next (bucketChunks n contents)).1))
    (hadds : adds.a.val = (reduceChunks originals next (bucketChunks n contents)).2.1.map Job.first) :
    roundMeasure (ps, after, adds) = activeCount before.lens.val := by
  have hl : (reduceChunks originals next (bucketChunks n contents)).1.length = n :=
    (reduceChunks_lengths originals next (bucketChunks n contents)).1.trans (bucketChunks_length n contents)
  rw [roundMeasure, counts_active after n _ ha.counts,
    bucketChunks_replace contents n _ hl, hadds, List.length_map, counts_active before n contents hb]
  exact reduceChunks_active originals next (bucketChunks n contents)


theorem packed_empty_singletons (originals next n : ℕ) (contents : BucketLists)
    (after : buckets.Buckets) (base capacity : ℕ → ℕ) (adds : pairs.BatchedAdds)
    (ha : Packed after n base capacity (replaceContents contents 0
      (reduceChunks originals next (bucketChunks n contents)).1))
    (hadds : adds.a.val = (reduceChunks originals next (bucketChunks n contents)).2.1.map Job.first)
    (hempty : adds.a.val.isEmpty = true) :
    ∀ i < n, (bucketSlice after i).length ≤ 1 := by
  have hz : (reduceChunks originals next (bucketChunks n contents)).2.1.length = 0 := by
    have hn := List.isEmpty_iff.mp hempty
    have hh := congrArg List.length hadds
    simp only [hn, List.length_nil, List.length_map] at hh
    exact hh.symm
  have hs := reduceChunks_singletons originals next (bucketChunks n contents) hz
  intro i hi
  rw [packed_recovers after n base capacity _ ha i hi]
  have hl : i < (reduceChunks originals next (bucketChunks n contents)).1.length := by
    rw [(reduceChunks_lengths originals next (bucketChunks n contents)).1, bucketChunks_length]
    exact hi
  rw [show replaceContents contents 0 (reduceChunks originals next (bucketChunks n contents)).1 i =
    (reduceChunks originals next (bucketChunks n contents)).1[i]! from
      by simpa only [Nat.zero_add] using replaceContents_inside contents 0 _ i hl]
  exact hs _ (by rw [getElem!_pos _ i hl]; exact List.getElem_mem hl)


structure Limits (originals n maximum slots : ℕ) (base capacity : ℕ → ℕ) : Prop where
  size : maximum + 1 < 2 ^ 32
  allocate : originals + maximum / 2 ≤ slots
  indices : originals + maximum < 2 ^ 31
  disjoint : DisjointRegions n base capacity

structure Layout (originals n maximum slots : ℕ) (base capacity : ℕ → ℕ)
    (state : RoundState) (contents : BucketLists) : Prop where
  packed : Packed state.2.1 n base capacity contents
  lower : originals ≤ state.1.len.val
  upper : state.1.len.val ≤ originals + maximum / 2
  points_length : state.1.points.val.length = slots
  active : chunksActive (bucketChunks n contents) ≤ maximum
  live : ∀ r ∈ (bucketChunks n contents).flatten, pointIndex r < state.1.len.val
  independent : (bucketChunks n contents).flatten.Pairwise (RefIndependent originals)
  reusable : state.1.len.val = originals ∨ ∀ xs ∈ bucketChunks n contents, ReuseReady originals xs


theorem Layout.reserve {originals n maximum slots : ℕ} {base capacity : ℕ → ℕ}
    {state : RoundState} {contents : BucketLists}
    (lim : Limits originals n maximum slots base capacity)
    (h : Layout originals n maximum slots base capacity state contents) :
    state.1.len.val + chunksBudget (bucketChunks n contents) < 2 ^ 31 := by
  have hb := chunksBudget_le_half (bucketChunks n contents)
  have ha := h.active
  have hu := h.upper
  have hi := lim.indices
  omega

theorem Layout.allocation {originals n maximum slots : ℕ} {base capacity : ℕ → ℕ}
    {state : RoundState} {contents : BucketLists}
    (h : Layout originals n maximum slots base capacity state contents) :
    (reduceChunks originals state.1.len.val (bucketChunks n contents)).2.2 ≤ originals + maximum / 2 := by
  rcases h.reusable with he | hr
  · have hb := reduceChunks_allocation_bound originals state.1.len.val (bucketChunks n contents)
    have ha := h.active
    omega
  · rw [reduceChunks_no_allocation originals state.1.len.val (bucketChunks n contents) hr]
    exact h.upper

theorem layout_reduced {originals n maximum slots : ℕ} {base capacity : ℕ → ℕ}
    {before after : RoundState} {contents : BucketLists}
    (lim : Limits originals n maximum slots base capacity)
    (h : Layout originals n maximum slots base capacity before contents)
    (hp : Packed after.2.1 n base capacity (replaceContents contents 0
      (reduceChunks originals before.1.len.val (bucketChunks n contents)).1))
    (hlen : after.1.len.val = (reduceChunks originals before.1.len.val (bucketChunks n contents)).2.2)
    (hpoints : after.1.points = before.1.points) :
    Layout originals n maximum slots base capacity after (replaceContents contents 0
      (reduceChunks originals before.1.len.val (bucketChunks n contents)).1) := by
  have hchunks : bucketChunks n (replaceContents contents 0
      (reduceChunks originals before.1.len.val (bucketChunks n contents)).1) =
      (reduceChunks originals before.1.len.val (bucketChunks n contents)).1 :=
    bucketChunks_replace contents n _ ((reduceChunks_lengths originals before.1.len.val _).1.trans (bucketChunks_length n contents))
  have hreserve := h.reserve lim
  have hbudget := reduceChunks_budget originals before.1.len.val (bucketChunks n contents)
  refine ⟨hp, ?_, ?_, ?_, ?_, ?_, ?_, Or.inr ?_⟩
  · rw [hlen]; exact le_trans h.lower hbudget.1
  · rw [hlen]; exact h.allocation
  · rw [hpoints]; exact h.points_length
  · rw [hchunks]
    have hc := reduceChunks_active originals before.1.len.val (bucketChunks n contents)
    have ha := h.active
    omega
  · rw [hchunks, hlen]
    intro r hr
    exact (reduceChunks_ref_info originals before.1.len.val (bucketChunks n contents)
      h.lower h.live hreserve r hr).1
  · rw [hchunks]
    exact reduceChunks_refs_independent originals before.1.len.val (bucketChunks n contents)
      h.lower h.live hreserve h.independent
  · rw [hchunks]
    exact reduceChunks_reuseReady originals before.1.len.val (bucketChunks n contents)
      h.lower h.live hreserve

theorem queue_layout (originals : Usize) (n maximum slots : ℕ) (base capacity : ℕ → ℕ)
    (lim : Limits originals.val n maximum slots base capacity)
    (before : RoundState) (contents : BucketLists)
    (h : Layout originals.val n maximum slots base capacity before contents) :
    ∃ after : RoundState,
      before.2.1.queue_round before.2.2 before.1 originals = ok (after.2.1, after.2.2, after.1) ∧
      Layout originals.val n maximum slots base capacity after (replaceContents contents 0
        (reduceChunks originals.val before.1.len.val (bucketChunks n contents)).1) ∧
      after.2.2.a.val = (reduceChunks originals.val before.1.len.val (bucketChunks n contents)).2.1.map Job.first ∧
      after.2.2.b.val = (reduceChunks originals.val before.1.len.val (bucketChunks n contents)).2.1.map Job.second ∧
      after.2.2.out.val = (reduceChunks originals.val before.1.len.val (bucketChunks n contents)).2.1.map Job.output ∧
      after.1.len.val = (reduceChunks originals.val before.1.len.val (bucketChunks n contents)).2.2 ∧
      after.1.points = before.1.points ∧
      after.2.1.window_bits = before.2.1.window_bits ∧ after.2.1.windows = before.2.1.windows ∧
      roundMeasure after = activeCount before.2.1.lens.val := by
  have hreserve := h.reserve lim
  have hbound := h.allocation
  have hsize : ∀ i < n, (contents i).length + 1 < 2 ^ 32 := by
    intro i hi
    have hc := chunksActive_member (bucketChunks n contents) (contents i)
      (List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩)
    have ha := h.active
    have hs := lim.size
    omega
  have hb : chunksBudget (bucketChunks n contents) ≤ Usize.max := by
    have h32 := two_pow_32_le_usize
    simp only [Usize.max_def, Usize.numBits_def]
    change _ ≤ 2 ^ UScalarTy.Usize.numBits - 1
    omega
  obtain ⟨b, adds, ps, heq, hp, ha, hb', ho, hlen, hw, hn, _, hr, _, _⟩ :=
    Queue.queue_round_packed_capacity before.2.1 n base capacity contents h.packed lim.disjoint
      before.2.2 before.1 originals hsize hb
      (by intro _; rw [h.points_length]; exact le_trans hbound lim.allocate)
      (by have hi := lim.indices; omega)
  have hnew := layout_reduced (after := (ps, b, adds)) lim h hp hlen hr
  refine ⟨(ps, b, adds), heq, hnew, ha, hb', ho, hlen, hr, hw, hn, ?_⟩
  exact packed_reduction_measure originals.val before.1.len.val n contents before.2.1 b
    base capacity ps adds h.packed.counts hp ha


structure Context where
  originals : Usize
  total : ℕ
  maximum : ℕ
  slots : ℕ
  base : ℕ → ℕ
  capacity : ℕ → ℕ
  limits : Limits originals.val total maximum slots base capacity
  window_bits : Usize
  windows : Usize
  target : ℕ → G1Spec.E.Point
  originalValues : ℕ → G1Spec.E.Point

structure Frame (ctx : Context) (state : RoundState) : Prop where
  originals : ∀ p < ctx.originals.val, Store.PointRep state.1 p (ctx.originalValues p)
  bits : state.2.1.window_bits = ctx.window_bits
  windows : state.2.1.windows = ctx.windows
  points_length : state.1.points.val.length = ctx.slots

structure CompleteAt (ctx : Context) (state : RoundState) (contents : BucketLists)
    (values : ℕ → G1Spec.E.Point) : Prop where
  layout : Layout ctx.originals.val ctx.total ctx.maximum ctx.slots ctx.base ctx.capacity state contents
  refs : ∀ r ∈ (bucketChunks ctx.total contents).flatten,
    Store.PointRep state.1 (pointIndex r) (values (pointIndex r))
  sums : ∀ i < ctx.total, ((contents i).map (signedReferenceValue values)).sum = ctx.target i
  frame : Frame ctx state

def Completed (ctx : Context) (state : RoundState) : Prop :=
  ∃ contents values, CompleteAt ctx state contents values

structure QueueLink (ctx : Context) (source : RoundState) (contents : BucketLists)
    (state : RoundState) : Prop where
  layout : Layout ctx.originals.val ctx.total ctx.maximum ctx.slots ctx.base ctx.capacity state
    (replaceContents contents 0 (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).1)
  firsts : state.2.2.a.val = (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1.map Job.first
  seconds : state.2.2.b.val = (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1.map Job.second
  outputs : state.2.2.out.val = (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1.map Job.output
  next : state.1.len.val = (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.2
  points : state.1.points = source.1.points
  bits : state.2.1.window_bits = source.2.1.window_bits
  windows : state.2.1.windows = source.2.1.windows

def Pending (ctx : Context) (state : RoundState) : Prop :=
  ∃ source contents values, CompleteAt ctx source contents values ∧ QueueLink ctx source contents state

def Success (ctx : Context) (state : RoundState) : Prop :=
  Completed ctx state ∧ ∀ i < ctx.total, (bucketSlice state.2.1 i).length ≤ 1

theorem queue_completed (ctx : Context) (state : RoundState) (h : Completed ctx state) :
    ∃ b adds ps, state.2.1.queue_round state.2.2 state.1 ctx.originals = ok (b, adds, ps) ∧
      Pending ctx (ps, b, adds) ∧ roundMeasure (ps, b, adds) = activeCount state.2.1.lens.val := by
  obtain ⟨contents, values, hc⟩ := h
  obtain ⟨after, heq, hl, ha, hb, ho, hn, hr, hw, hwin, hm⟩ :=
    queue_layout ctx.originals ctx.total ctx.maximum ctx.slots ctx.base ctx.capacity ctx.limits state contents hc.layout
  exact ⟨after.2.1, after.2.2, after.1, heq,
    ⟨state, contents, values, hc, hl, ha, hb, ho, hn, hr, hw, hwin⟩, hm⟩


theorem QueueLink.frame {ctx : Context} {source state : RoundState} {contents : BucketLists}
    (h : QueueLink ctx source contents state) (hf : Frame ctx source) : Frame ctx state := by
  refine ⟨?_, h.bits.trans hf.bits, h.windows.trans hf.windows, h.layout.points_length⟩
  intro p hp
  simpa only [Store.PointRep,Store.Holds, h.points] using hf.originals p hp

theorem complete_after (ctx : Context) (source state : RoundState) (contents : BucketLists)
    (values afterValues : ℕ → G1Spec.E.Point) (hc : CompleteAt ctx source contents values)
    (hq : QueueLink ctx source contents state) (ps : store.PointStore) (adds : pairs.BatchedAdds)
    (hlen : ps.len = state.1.len) (hpoints : ps.points.val.length = state.1.points.val.length)
    (houtputs : ∀ job ∈ (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1,
      Store.PointRep ps job.output.val (afterValues job.output.val))
    (hcarry : ∀ r ∈ (bucketChunks ctx.total contents).flatten,
      Store.PointRep ps (pointIndex r) (afterValues (pointIndex r)))
    (hpairs : PairValues (signedReferenceValue values) (signedReferenceValue afterValues)
      (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1)
    (hodd : ∀ r ∈ oddRefs (bucketChunks ctx.total contents),
      signedReferenceValue afterValues r = signedReferenceValue values r)
    (horiginals : ∀ p < ctx.originals.val, Store.PointRep ps p (ctx.originalValues p)) :
    CompleteAt ctx (ps, state.2.1, adds) (replaceContents contents 0
      (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).1) afterValues := by
  have hl := hq.layout
  have hreserve := hc.layout.reserve ctx.limits
  have hi := reduceChunks_job_info ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
    hc.layout.lower hc.layout.live hreserve
  have hbud := reduceChunks_budget ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)
  have hchunks := bucketChunks_replace contents ctx.total
    (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).1
    ((reduceChunks_lengths ctx.originals.val source.1.len.val _).1.trans (bucketChunks_length ctx.total contents))
  refine ⟨?_, ?_, ?_, ⟨horiginals, hq.bits.trans hc.frame.bits, hq.windows.trans hc.frame.windows, ?_⟩⟩
  · refine ⟨hl.packed, ?_, ?_, ?_, hl.active, ?_, hl.independent, ?_⟩
    · simpa only [hlen] using hl.lower
    · simpa only [hlen] using hl.upper
    · exact hpoints.trans hl.points_length
    · simpa only [hlen] using hl.live
    · simpa only [hlen] using hl.reusable
  · rw [hchunks]
    intro r hr
    rcases reduceChunks_members ctx.originals.val source.1.len.val (bucketChunks ctx.total contents) r hr with
      ⟨job, hj, rfl⟩ | hr
    · have hjb : job.output.val < 2 ^ 31 := by have := (hi job hj).2.2.2.1; omega
      rw [pointIndex_output job hjb]
      exact houtputs job hj
    · exact hcarry r (oddRefs_mem _ r hr)
  · intro i hindex
    have hs := packed_round_sums (signedReferenceValue values) (signedReferenceValue afterValues)
      ctx.originals.val source.1.len.val ctx.total contents (Buckets.toLane state.2.1) ctx.base ctx.capacity hl.packed hpairs
      (by
        intro j hj r hr
        apply hodd r
        exact List.mem_flatten.mpr ⟨unpaired (contents j),
          List.mem_map.mpr ⟨contents j, List.mem_map.mpr ⟨j, List.mem_range.mpr hj, rfl⟩, rfl⟩, hr⟩)
      i hindex
    rw [BucketsRefines.packed_recovers (Buckets.toLane state.2.1) ctx.total ctx.base ctx.capacity _ hl.packed i hindex] at hs
    exact hs.trans (hc.sums i hindex)
  · exact hpoints.trans hl.points_length

theorem pending_empty (ctx : Context) (state : RoundState) (h : Pending ctx state)
    (he : state.2.2.a.val.isEmpty = true) : Success ctx state := by
  obtain ⟨source, contents, values, hc, hq⟩ := h
  have hjobs : (reduceChunks ctx.originals.val source.1.len.val (bucketChunks ctx.total contents)).2.1 = [] := by
    have hh := congrArg List.length hq.firsts
    rw [List.isEmpty_iff.mp he, List.length_nil, List.length_map] at hh
    exact List.length_eq_zero_iff.mp hh.symm
  have hf := hq.frame hc.frame
  have hcomplete := complete_after ctx source state contents values values hc hq state.1 state.2.2 rfl rfl
    (by intro job hj; rw [hjobs] at hj; cases hj)
    (by intro r hr; simpa only [Store.PointRep,Store.Holds, hq.points] using hc.refs r hr)
    (by intro job hj; rw [hjobs] at hj; cases hj)
    (by intro _ _; rfl) hf.originals
  refine ⟨⟨_, values, hcomplete⟩, ?_⟩
  exact packed_empty_singletons ctx.originals.val source.1.len.val ctx.total contents state.2.1
    ctx.base ctx.capacity state.2.2 hq.layout.packed hq.firsts he


end LeanBlsSimd.Portable.Msm.Rounds
