import LeanBlsSimd.Portable.Msm.StoreLifecycle
import LeanBlsSimd.Portable.Msm.Buckets
import LeanBlsSimd.Msm8.Queue

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Queue
open portable.msm alloc.vec BucketsRefines QueueRefines

abbrev Packed (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) : Prop :=
  BucketsRefines.Packed (Buckets.toLane state) n base capacity contents

theorem adds_clear (adds : pairs.BatchedAdds) :
    adds.clear = ok { adds with a := Vec.new U32, b := Vec.new U32, out := Vec.new U32 } := rfl

theorem adds_push (adds : pairs.BatchedAdds) (first second output : U32)
    (ha : adds.a.val.length < Usize.max) (hb : adds.b.val.length < Usize.max)
    (ho : adds.out.val.length < Usize.max) :
    ∃ result, adds.push first second output = ok result ∧
      result.a.val = adds.a.val ++ [first] ∧
      result.b.val = adds.b.val ++ [second] ∧
      result.out.val = adds.out.val ++ [output] ∧
      result.dx = adds.dx ∧ result.prefix = adds.prefix := by
  obtain ⟨a, hpa, hva⟩ := WP.spec_imp_exists (Vec.push_spec adds.a first ha)
  obtain ⟨b, hpb, hvb⟩ := WP.spec_imp_exists (Vec.push_spec adds.b second hb)
  obtain ⟨o, hpo, hvo⟩ := WP.spec_imp_exists (Vec.push_spec adds.out output ho)
  refine ⟨{ adds with a := a, b := b, out := o }, ?_, hva, hvb, hvo, rfl, rfl⟩
  simp [pairs.BatchedAdds.push, hpa, hpb, hpo]

def stateOf (refs : Vec U32) (adds : pairs.BatchedAdds) (s : store.PointStore) : QueueState :=
  ⟨refs.val, adds.a.val, adds.b.val, adds.out.val, s.len.val⟩

theorem queue_step_refines_conditional
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hactive : cursor.val + 1 < len.val)
    (hspan : start.val + len.val ≤ refs.val.length)
    (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length < Usize.max) (hb : adds.b.val.length < Usize.max)
    (ho : adds.out.val.length < Usize.max)
    (halloc : pointIndex refs.val[start.val + cursor.val]! < originals.val →
      s.len.val < s.points.val.length ∧ s.len.val < 2 ^ 32) :
    ∃ refs' adds' s' cursor',
      buckets.Buckets.queue_pairs_loop.body originals start len refs adds s cursor =
        ok (cont (refs', adds', s', cursor')) ∧
      stateOf refs' adds' s' = enqueue originals.val start.val cursor.val (stateOf refs adds s) ∧
      cursor'.val = cursor.val + 2 ∧ s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  have hmax := two_pow_32_le_usize
  have hinc : cursor.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by change cursor.val + 1 < _; omega
  have hfirst : start.val + cursor.val < 2 ^ UScalarTy.Usize.numBits := by omega
  have hsecond : start.val + cursor.val + 1 < 2 ^ UScalarTy.Usize.numBits := by omega
  have hwrite : start.val + cursor.val / 2 < 2 ^ UScalarTy.Usize.numBits := by omega
  have hnext : cursor.val + (2#usize).val < 2 ^ UScalarTy.Usize.numBits := by change cursor.val + 2 < _; omega
  let ix : Usize := UScalar.ofNatCore (start.val + cursor.val) hfirst
  let iy : Usize := UScalar.ofNatCore (start.val + cursor.val + 1) hsecond
  let dest : Usize := UScalar.ofNatCore (start.val + cursor.val / 2) hwrite
  let next : Usize := UScalar.ofNatCore (cursor.val + 2) hnext
  have hix : ix.val < refs.val.length := by simp only [ix, UScalar.ofNatCore_val_eq]; omega
  have hiy : iy.val < refs.val.length := by simp only [iy, UScalar.ofNatCore_val_eq]; omega
  have hdest : dest.val < refs.val.length := by simp only [dest, UScalar.ofNatCore_val_eq]; omega
  let first := refs.val[ix.val]
  let second := refs.val[iy.val]
  let output := (slot originals.val s.len.val first).1
  obtain ⟨s', hslot, hlen, hpoints⟩ := Store.sum_slot_refines first s originals (by
      intro ha
      apply halloc
      simpa only [pointIndex, first, ix, UScalar.ofNatCore_val_eq,
        getElem!_pos refs.val (start.val + cursor.val) (by omega)] using ha)
  obtain ⟨adds', hpush, hfa, hfb, hfo, hdx, hprefix⟩ := adds_push adds first second output ha hb ho
  refine ⟨refs.set dest output, adds', s', next, ?_, ?_, rfl, hpoints, hdx, hprefix⟩
  · simp only [buckets.Buckets.queue_pairs_loop.body]
    rw [add_ok _ _ hinc]
    simp only [bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hactive, if_true]
    rw [add_ok _ _ hfirst]
    change (do
      let first ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs ix
      let (out, store1) ← buckets.sum_slot first s originals
      let i2 ← ix + 1#usize
      let second ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs i2
      let adds1 ← adds.push first second out
      let i4 ← cursor / 2#usize
      let i5 ← start + i4
      let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs i5
      let at2 ← cursor + 2#usize
      ok (cont (back out, adds1, store1, at2))) = _
    rw [vec_index refs ix hix]
    simp only [bind_tc_ok]
    rw [hslot]
    simp only [bind_tc_ok]
    rw [add_ok ix (1#usize) hsecond]
    change (do
      let second ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs iy
      let adds1 ← adds.push first second output
      let i4 ← cursor / 2#usize
      let i5 ← start + i4
      let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs i5
      let at2 ← cursor + 2#usize
      ok (cont (back output, adds1, s', at2))) = _
    rw [vec_index refs iy hiy]
    simp only [bind_tc_ok]
    rw [hpush]
    simp only [bind_tc_ok]
    rw [div_ok cursor (2#usize) (by decide)]
    simp only [bind_tc_ok]
    rw [add_ok _ _ hwrite]
    change (do
      let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs dest
      let at2 ← cursor + 2#usize
      ok (cont (back output, adds', s', at2))) = _
    rw [vec_index_mut refs dest hdest]
    simp only [bind_tc_ok]
    rw [add_ok _ _ hnext]
    rfl
  · have hf : first = refs.val[start.val + cursor.val]! := by
      simp only [first, ix, UScalar.ofNatCore_val_eq]
      exact (getElem!_pos refs.val _ (by omega)).symm
    have hs : second = refs.val[start.val + cursor.val + 1]! := by
      simp only [second, iy, UScalar.ofNatCore_val_eq]
      exact (getElem!_pos refs.val _ (by omega)).symm
    simp only [stateOf, enqueue, Vec.set, dest, UScalar.ofNatCore_val_eq,
      hfa, hfb, hfo, hlen, output, hf, hs]

theorem queue_loop_refines_capacity (n : ℕ)
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hlo : cursor.val + 2 * n ≤ len.val) (hhi : len.val ≤ cursor.val + 2 * n + 1)
    (hlen : len.val + 1 < 2 ^ 32)
    (hspan : start.val + len.val ≤ refs.val.length) (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + n ≤ Usize.max) (hb : adds.b.val.length + n ≤ Usize.max)
    (ho : adds.out.val.length + n ≤ Usize.max)
    (hcap : s.len.val < (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next →
      (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next ≤ s.points.val.length)
    (h32 : (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next ≤ 2 ^ 32) :
    ∃ refs' adds' s',
      buckets.Buckets.queue_pairs_loop refs adds s originals start len cursor = ok (refs', adds', s') ∧
      stateOf refs' adds' s' = queueSteps originals.val start.val n cursor.val (stateOf refs adds s) ∧
      s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  induction n generalizing cursor refs adds s with
  | zero =>
    refine ⟨refs, adds, s, ?_, rfl, rfl, rfl, rfl⟩
    have hsum : cursor.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
      have := two_pow_32_le_usize
      change cursor.val + 1 < _
      omega
    rw [buckets.Buckets.queue_pairs_loop, loop.eq_1]
    simp only [buckets.Buckets.queue_pairs_loop.body]
    rw [add_ok _ _ hsum]
    simp only [bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq]
    rw [if_neg (by omega)]
  | succ n ih =>
    have hmon := (queueSteps_lengths originals.val start.val n (cursor.val + 2)
      (enqueue originals.val start.val cursor.val (stateOf refs adds s))).2.2.2.2.1
    have halloc : pointIndex refs.val[start.val + cursor.val]! < originals.val →
        s.len.val < s.points.val.length ∧ s.len.val < 2 ^ 32 := by
      intro hfirst
      have hn : (enqueue originals.val start.val cursor.val (stateOf refs adds s)).next = s.len.val + 1 := by
        simp only [enqueue, stateOf, slot, show (clearSign refs.val[start.val + cursor.val]!).val < originals.val from hfirst,
          if_true]
      rw [hn] at hmon
      change s.len.val < (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next → _ at hcap
      have hh := hcap (by omega)
      change (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next ≤ s.points.val.length at hh
      change (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next ≤ 2 ^ 32 at h32
      exact ⟨by omega, by omega⟩
    obtain ⟨refs', adds', s', cursor', hstep, hstate, hcursor, hpoints, hdx, hprefix⟩ :=
      queue_step_refines_conditional originals start len cursor refs adds s (by omega) hspan hrefs
        (by omega) (by omega) (by omega) halloc
    have hfields := enqueue_lengths originals.val start.val cursor.val (stateOf refs adds s)
    rw [← hstate] at hfields
    change refs'.val.length = refs.val.length ∧ adds'.a.val.length = adds.a.val.length + 1 ∧
      adds'.b.val.length = adds.b.val.length + 1 ∧ adds'.out.val.length = adds.out.val.length + 1 ∧
      s.len.val ≤ s'.len.val ∧ s'.len.val ≤ s.len.val + 1 at hfields
    obtain ⟨hr, hfa, hfb, hfo, hnext, _⟩ := hfields
    have hsame : queueSteps originals.val start.val n cursor'.val (stateOf refs' adds' s') =
        queueSteps originals.val start.val (n + 1) cursor.val (stateOf refs adds s) := by
      simp only [queueSteps, hcursor, hstate]
    obtain ⟨refs'', adds'', s'', hloop, hmodel, hpoints', hdx', hprefix'⟩ :=
      ih cursor' refs' adds' s' (by omega) (by omega) (by omega) (by omega)
        (by omega) (by omega) (by omega)
        (by intro hh; rw [hsame, hpoints]; apply hcap; rw [hsame] at hh; omega)
        (by rwa [hsame])
    refine ⟨refs'', adds'', s'', ?_, hmodel.trans hsame, hpoints'.trans hpoints, hdx'.trans hdx, hprefix'.trans hprefix⟩
    rw [buckets.Buckets.queue_pairs_loop, loop.eq_1]
    simpa only [hstep] using hloop

def finishBucketCode (state : buckets.Buckets) (list start len : Usize)
    (refs : Vec U32) (adds : pairs.BatchedAdds) (s : store.PointStore) :
    Result (buckets.Buckets × pairs.BatchedAdds × store.PointStore) := do
  let rem ← len % 2#usize
  let refs' ← if rem = 1#usize then do
    let endAt ← start + len
    let source ← endAt - 1#usize
    let value ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs source
    let half ← len / 2#usize
    let dest ← start + half
    let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs dest
    ok (back value)
  else ok refs
  let half ← len / 2#usize
  let newLen ← half + rem
  let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) state.lens list
  let cast ← lift (UScalar.cast .U32 newLen)
  ok ({ state with refs := refs', lens := back cast }, adds, s)

theorem queue_pairs_split (state : buckets.Buckets) (list : Usize)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize) :
    state.queue_pairs list adds s originals = (do
      let i ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.starts list
      let start ← lift (UScalar.cast .Usize i)
      let j ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) state.lens list
      let len ← lift (UScalar.cast .Usize j)
      let (refs, adds', s') ← buckets.Buckets.queue_pairs_loop state.refs adds s originals start len 0#usize
      finishBucketCode state list start len refs adds' s') := rfl

theorem finishBucket_refines (state : buckets.Buckets) (list start len : Usize)
    (refs : Vec U32) (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hlist : list.val < state.lens.val.length)
    (hspan : start.val + len.val ≤ refs.val.length) (hrefs : refs.val.length < 2 ^ 32) :
    ∃ refs' newLen, finishBucketCode state list start len refs adds s =
        ok ({ state with refs := refs', lens := state.lens.set list newLen }, adds, s) ∧
      refs'.val = oddCopy start.val len.val refs.val ∧
      newLen.val = len.val / 2 + len.val % 2 := by
  obtain ⟨refs', hc, hv⟩ := oddCopy_refines start len refs hspan hrefs
  have hnew : len.val / 2 + len.val % 2 < 2 ^ 32 := by omega
  have hsum : len.val / 2 + len.val % 2 < 2 ^ UScalarTy.Usize.numBits :=
    lt_of_lt_of_le hnew two_pow_32_le_usize
  let newLen : U32 := UScalar.ofNatCore (len.val / 2 + len.val % 2) hnew
  refine ⟨refs', newLen, ?_, hv, rfl⟩
  simp only [oddCopyCode] at hc
  rw [rem_ok len (2#usize) (by decide)] at hc
  simp only [bind_tc_ok] at hc
  simp only [finishBucketCode]
  rw [rem_ok len (2#usize) (by decide)]
  simp only [bind_tc_ok]
  rw [hc]
  simp only [bind_tc_ok]
  rw [div_ok len (2#usize) (by decide)]
  simp only [bind_tc_ok]
  simp only [show (2#usize).val = 2 from rfl]
  rw [add_ok (UScalar.ofNatCore (len.val / 2) (by have := len.hBounds; omega) : Usize)
    (UScalar.ofNatCore (len.val % 2) (by have := len.hBounds; omega) : Usize) hsum]
  simp only [bind_tc_ok]
  rw [vec_index_mut state.lens list hlist]
  simp only [bind_tc_ok, lift]
  have hcast : UScalar.cast .U32 (UScalar.ofNatCore (len.val / 2 + len.val % 2) hsum : Usize) = newLen := by
    apply UScalar.eq_of_val_eq
    simp only [UScalar.cast_val_eq, UScalar.ofNatCore_val_eq, newLen]
    exact Nat.mod_eq_of_lt hnew
  simpa only [UScalar.ofNatCore_val_eq] using congrArg
    (fun value => ok ({ state with refs := refs', lens := state.lens.set list value }, adds, s)) hcast

theorem queue_pairs_refines_capacity (state : buckets.Buckets) (list : Usize)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hstart : list.val < state.starts.val.length) (hlist : list.val < state.lens.val.length)
    (hlen : state.lens.val[list.val].val + 1 < 2 ^ 32)
    (hspan : state.starts.val[list.val].val + state.lens.val[list.val].val ≤ state.refs.val.length)
    (hrefs : state.refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (hb : adds.b.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (ho : adds.out.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (hcap : s.len.val < (queueBucket originals.val state.starts.val[list.val].val
        state.lens.val[list.val].val (stateOf state.refs adds s)).next →
      (queueBucket originals.val state.starts.val[list.val].val
        state.lens.val[list.val].val (stateOf state.refs adds s)).next ≤ s.points.val.length)
    (h32 : (queueBucket originals.val state.starts.val[list.val].val
      state.lens.val[list.val].val (stateOf state.refs adds s)).next ≤ 2 ^ 32) :
    ∃ result adds' s' newLen,
      state.queue_pairs list adds s originals = ok (result, adds', s') ∧
      stateOf result.refs adds' s' = queueBucket originals.val state.starts.val[list.val].val
        state.lens.val[list.val].val (stateOf state.refs adds s) ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧ result.lens = state.lens.set list newLen ∧
      newLen.val = state.lens.val[list.val].val / 2 + state.lens.val[list.val].val % 2 ∧
      s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let start : Usize := UScalar.cast .Usize state.starts.val[list.val]
  let len : Usize := UScalar.cast .Usize state.lens.val[list.val]
  have hs : start.val = state.starts.val[list.val].val := cast_Usize_val _
  have hl : len.val = state.lens.val[list.val].val := cast_Usize_val _
  obtain ⟨refs', adds', s', hloop, hmodel, hpoints, hdx, hprefix⟩ :=
    queue_loop_refines_capacity (len.val / 2) originals start len 0#usize state.refs adds s
      (by simp only [UScalar.ofNatCore_val_eq]; omega) (by simp only [UScalar.ofNatCore_val_eq]; omega)
      (by omega) (by omega) hrefs (by omega) (by omega) (by omega)
      (by simpa only [queueBucket, hs, hl, show (0#usize).val = 0 from rfl] using hcap)
      (by simpa only [queueBucket, hs, hl, show (0#usize).val = 0 from rfl] using h32)
  change stateOf refs' adds' s' = queueSteps originals.val start.val (len.val / 2) 0 (stateOf state.refs adds s) at hmodel
  have hlength := (queueSteps_lengths originals.val start.val (len.val / 2) 0 (stateOf state.refs adds s)).1
  rw [← hmodel] at hlength
  change refs'.val.length = state.refs.val.length at hlength
  obtain ⟨refs'', newLen, hfinish, href, hnew⟩ :=
    finishBucket_refines state list start len refs' adds' s' hlist (by omega) (by omega)
  refine ⟨{ state with refs := refs'', lens := state.lens.set list newLen }, adds', s', newLen,
    ?_, ?_, rfl, rfl, rfl, rfl, by simpa only [hl] using hnew, hpoints, hdx, hprefix⟩
  · rw [queue_pairs_split, vec_index state.starts list hstart]
    simp only [bind_tc_ok, lift]
    rw [vec_index state.lens list hlist]
    simp only [bind_tc_ok]
    change (do
      let (refs, adds', s') ← buckets.Buckets.queue_pairs_loop state.refs adds s originals start len 0#usize
      finishBucketCode state list start len refs adds' s') = _
    rw [hloop]
    exact hfinish
  · have he := congrArg (fun q : QueueState => { q with refs := oddCopy start.val len.val q.refs }) hmodel
    simpa only [stateOf, queueBucket, href, hs, hl] using he

theorem packed_replace (state result : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents)
    (hd : DisjointRegions n base capacity) (index : Usize) (hi : index.val < n)
    (values : List U32) (newLen : U32)
    (hsize : values.length ≤ capacity index.val) (hnew : newLen.val = values.length)
    (hrefs : result.refs.val = writeAt state.refs.val (base index.val) values)
    (hstarts : result.starts = state.starts) (hlens : result.lens = state.lens.set index newLen) :
    Packed result n base capacity (Function.update contents index.val values) := by
  exact QueueRefines.packed_replace (Buckets.toLane state) (Buckets.toLane result)
    n base capacity contents h hd index hi values newLen hsize hnew hrefs hstarts hlens

theorem queue_pairs_packed_capacity (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents)
    (hd : DisjointRegions n base capacity) (index : Usize) (hi : index.val < n)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hlen : (contents index.val).length + 1 < 2 ^ 32)
    (ha : adds.a.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hb : adds.b.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (ho : adds.out.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hcap : s.len.val < (reduce originals.val s.len.val (contents index.val)).2.2 →
      (reduce originals.val s.len.val (contents index.val)).2.2 ≤ s.points.val.length)
    (h32 : (reduce originals.val s.len.val (contents index.val)).2.2 ≤ 2 ^ 32) :
    ∃ result adds' s',
      state.queue_pairs index adds s originals = ok (result, adds', s') ∧
      Packed result n base capacity (Function.update contents index.val
        (reduce originals.val s.len.val (contents index.val)).1) ∧
      adds'.a.val = adds.a.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.first) ∧
      adds'.b.val = adds.b.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.second) ∧
      adds'.out.val = adds.out.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.output) ∧
      s'.len.val = (reduce originals.val s.len.val (contents index.val)).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧ s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  have hil : index.val < state.lens.val.length := by rw [show state.lens.val.length = n from h.counts.length]; exact hi
  have his : index.val < state.starts.val.length := by rw [show state.starts.val.length = n from h.starts_length]; exact hi
  have hlenv : state.lens.val[index.val].val = (contents index.val).length := by
    simpa only [Buckets.toLane, getElem!_pos state.lens.val index.val hil] using h.counts.values index.val hi
  have hstartv : state.starts.val[index.val].val = base index.val := by
    simpa only [Buckets.toLane, getElem!_pos state.starts.val index.val his] using h.starts_values index.val hi
  have hplan := queueBucket_plan originals.val (base index.val) (stateOf state.refs adds s)
    (contents index.val) (h.entries index.val hi)
  have hnextq := congrArg QueueState.next hplan
  change (queueBucket originals.val (base index.val) (contents index.val).length
    (stateOf state.refs adds s)).next = (reduce originals.val s.len.val (contents index.val)).2.2 at hnextq
  obtain ⟨result, adds', s', newLen, hcall, hq, hw, hn, hs, hl, hnew, hr, hdx, hp⟩ :=
    queue_pairs_refines_capacity state index adds s originals his hil (by rwa [hlenv])
      (by rw [hlenv, hstartv]; exact le_trans (Nat.add_le_add_left (h.capacity_bound index.val hi) _) (h.regions index.val hi))
      h.refs_bound (by rwa [hlenv]) (by rwa [hlenv]) (by rwa [hlenv])
      (by simpa only [hlenv, hstartv, hnextq] using hcap)
      (by simpa only [hlenv, hstartv, hnextq] using h32)
  rw [hlenv, hstartv] at hq
  have he := hq.trans hplan
  have href := congrArg QueueState.refs he
  have ha' := congrArg QueueState.firsts he
  have hb' := congrArg QueueState.seconds he
  have ho' := congrArg QueueState.outputs he
  have hnext := congrArg QueueState.next he
  dsimp only [stateOf] at href ha' hb' ho' hnext
  have hc := (reduce_counts originals.val s.len.val (contents index.val)).1
  refine ⟨result, adds', s', hcall, ?_, ha', hb', ho', hnext, hw, hn, hs, hr, hdx, hp⟩
  apply packed_replace state result n base capacity contents h hd index hi _ newLen
    (by have := h.capacity_bound index.val hi; omega) (by rw [hnew, hlenv]; exact hc.symm) href hs hl

def roundFields (state : buckets.Buckets) (adds : pairs.BatchedAdds) (s : store.PointStore) :=
  (state.window_bits, state.windows, state.refs, state.starts, state.lens, adds, s)

theorem queue_round_loop_packed_capacity (chunks : List (List U32))
    (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ) (contents : BucketLists)
    (h : Packed state n base capacity contents) (hd : DisjointRegions n base capacity)
    (index : Usize) (hn : index.val + chunks.length = n)
    (hchunks : ∀ j < chunks.length, contents (index.val + j) = chunks[j]!)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hsize : ∀ xs ∈ chunks, xs.length + 1 < 2 ^ 32)
    (ha : adds.a.val.length + chunksBudget chunks ≤ Usize.max)
    (hb : adds.b.val.length + chunksBudget chunks ≤ Usize.max)
    (ho : adds.out.val.length + chunksBudget chunks ≤ Usize.max)
    (hcap : s.len.val < (reduceChunks originals.val s.len.val chunks).2.2 →
      (reduceChunks originals.val s.len.val chunks).2.2 ≤ s.points.val.length)
    (h32 : (reduceChunks originals.val s.len.val chunks).2.2 ≤ 2 ^ 32) :
    ∃ result adds' s', state.queue_round_loop adds s originals index = ok (roundFields result adds' s') ∧
      Packed result n base capacity
        (replaceContents contents index.val (reduceChunks originals.val s.len.val chunks).1) ∧
      adds'.a.val = adds.a.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.first) ∧
      adds'.b.val = adds.b.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.second) ∧
      adds'.out.val = adds.out.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val chunks).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  induction chunks generalizing state contents index adds s with
  | nil =>
    refine ⟨state, adds, s, ?_, h, by simp [reduceChunks], by simp [reduceChunks],
      by simp [reduceChunks], rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
    have hdone : ¬ index < Vec.len state.lens := by
      change ¬index.val < state.lens.val.length
      rw [show state.lens.val.length = n from h.counts.length]
      simp only [List.length_nil, Nat.add_zero] at hn
      omega
    rw [buckets.Buckets.queue_round_loop, loop.eq_1]
    simp only [buckets.Buckets.queue_round_loop.body, hdone, if_false, roundFields]
  | cons xs rest ih =>
    have hi : index.val < n := by simp only [List.length_cons] at hn; omega
    have hcur : contents index.val = xs := by simpa using hchunks 0 (by simp)
    have hheadBound := reduce_budget originals.val s.len.val xs
    have htailBound := reduceChunks_budget originals.val (reduce originals.val s.len.val xs).2.2 rest
    change s.len.val < (reduceChunks originals.val (reduce originals.val s.len.val xs).2.2 rest).2.2 →
      (reduceChunks originals.val (reduce originals.val s.len.val xs).2.2 rest).2.2 ≤ s.points.val.length at hcap
    change (reduceChunks originals.val (reduce originals.val s.len.val xs).2.2 rest).2.2 ≤ 2 ^ 32 at h32
    have hbudget : chunksBudget (xs :: rest) = xs.length / 2 + chunksBudget rest := by simp [chunksBudget]
    obtain ⟨state', adds', s', hcall, hpacked, hfirsts, hseconds, houtputs, hlen, hw, hwins, hstarts, hpoints, hdx, hp⟩ :=
      queue_pairs_packed_capacity state n base capacity contents h hd index hi adds s originals
        (by rw [hcur]; exact hsize xs (by simp))
        (by rw [hcur]; omega) (by rw [hcur]; omega) (by rw [hcur]; omega)
        (by rw [hcur]; intro hh; have := hcap (by omega); omega)
        (by rw [hcur]; omega)
    simp only [hcur] at hpacked hfirsts hseconds houtputs hlen
    let updated := Function.update contents index.val (reduce originals.val s.len.val xs).1
    have hnextBound : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hb := vec_length_bound state.lens
      rw [show state.lens.val.length = n from h.counts.length] at hb
      omega
    let next : Usize := UScalar.ofNatCore (index.val + 1) hnextBound
    have hnval : next.val = index.val + 1 := rfl
    have hchunks' : ∀ j < rest.length, updated (next.val + j) = rest[j]! := by
      intro j hj
      simp only [updated, hnval, Function.update_of_ne (show index.val + 1 + j ≠ index.val by omega)]
      have hh := hchunks (j + 1) (by simp only [List.length_cons]; omega)
      simpa only [List.getElem!_cons_succ, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using hh
    have hcount := (reduce_counts originals.val s.len.val xs).2
    have hla : adds'.a.val.length = adds.a.val.length + xs.length / 2 := by
      rw [hfirsts, List.length_append, List.length_map, hcount]
    have hlb : adds'.b.val.length = adds.b.val.length + xs.length / 2 := by
      rw [hseconds, List.length_append, List.length_map, hcount]
    have hlo : adds'.out.val.length = adds.out.val.length + xs.length / 2 := by
      rw [houtputs, List.length_append, List.length_map, hcount]
    have hnext := (reduce_budget originals.val s.len.val xs).2
    obtain ⟨result, adds'', s'', hloop, hpacked', hfirsts', hseconds', houtputs', hlen', hw', hwins', hstarts', hpoints', hdx', hp'⟩ :=
      ih state' updated hpacked next (by simp only [List.length_cons] at hn; omega) hchunks'
        adds' s' (by intro ys hy; exact hsize ys (by simp [hy]))
        (by omega) (by omega) (by omega)
        (by intro hh; rw [hlen] at hh ⊢; rw [hpoints]; exact hcap (by omega))
        (by simpa only [hlen] using h32)
    refine ⟨result, adds'', s'', ?_, ?_, ?_, ?_, ?_, ?_, hw'.trans hw, hwins'.trans hwins,
      hstarts'.trans hstarts, hpoints'.trans hpoints, hdx'.trans hdx, hp'.trans hp⟩
    · have hactive : index < Vec.len state.lens := by
        change index.val < state.lens.val.length
        rw [show state.lens.val.length = n from h.counts.length]; exact hi
      rw [buckets.Buckets.queue_round_loop, loop.eq_1]
      simp only [buckets.Buckets.queue_round_loop.body, hactive, if_true, hcall, bind_tc_ok]
      rw [add_ok index (1#usize) hnextBound]
      exact hloop
    · simpa only [reduceChunks, replaceContents, updated, hnval, hlen] using hpacked'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hfirsts] using hfirsts'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hseconds] using hseconds'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, houtputs] using houtputs'
    · simpa only [reduceChunks, hlen] using hlen'

theorem queue_round_packed_capacity (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents) (hd : DisjointRegions n base capacity)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hsize : ∀ i < n, (contents i).length + 1 < 2 ^ 32)
    (hbudget : chunksBudget (bucketChunks n contents) ≤ Usize.max)
    (hcap : s.len.val < (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 →
      (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ≤ s.points.val.length)
    (h32 : (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ≤ 2 ^ 32) :
    ∃ result adds' s', state.queue_round adds s originals = ok (result, adds', s') ∧
      Packed result n base capacity (replaceContents contents 0
        (reduceChunks originals.val s.len.val (bucketChunks n contents)).1) ∧
      adds'.a.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.first) ∧
      adds'.b.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.second) ∧
      adds'.out.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.points = s.points ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let fresh : pairs.BatchedAdds := { adds with a := Vec.new U32, b := Vec.new U32, out := Vec.new U32 }
  have hchunkSize : ∀ xs ∈ bucketChunks n contents, xs.length + 1 < 2 ^ 32 := by
    intro xs hx
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hx
    exact hsize i (by simpa using hi)
  obtain ⟨result, adds', s', hloop, hp, ha, hb, ho, hlen, hw, hn, hs, hr, hdx, hprefix⟩ :=
    queue_round_loop_packed_capacity (bucketChunks n contents) state n base capacity contents h hd 0#usize
      (by change 0 + (bucketChunks n contents).length = n; rw [bucketChunks_length]; omega)
      (by intro j hj; change contents (0 + j) = _; simpa only [Nat.zero_add] using
        (bucketChunks_at n contents j (by simpa only [bucketChunks_length] using hj)).symm)
      fresh s originals hchunkSize (by simpa [fresh, Vec.new] using hbudget)
      (by simpa [fresh, Vec.new] using hbudget) (by simpa [fresh, Vec.new] using hbudget) hcap h32
  refine ⟨result, adds', s', ?_, hp, ?_, ?_, ?_, hlen, hw, hn, hs, hr, hdx, hprefix⟩
  · simp only [buckets.Buckets.queue_round, adds_clear, bind_tc_ok]
    change (do
      let (i, j, refs, starts, lens, adds', s') ← state.queue_round_loop fresh s originals 0#usize
      ok (({window_bits := i, windows := j, refs := refs, starts := starts, lens := lens} : buckets.Buckets), adds', s')) = _
    rw [hloop]
    rfl
  · simpa only [fresh, Vec.new, List.nil_append] using ha
  · simpa only [fresh, Vec.new, List.nil_append] using hb
  · simpa only [fresh, Vec.new, List.nil_append] using ho

end LeanBlsSimd.Portable.Msm.Queue
