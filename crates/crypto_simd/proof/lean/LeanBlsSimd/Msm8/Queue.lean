import LeanBlsSimd.Msm8.Buckets

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

structure Job where
  first : U32
  second : U32
  output : U32

def clearSign (reference : U32) : U32 := reference &&& 2147483647#u32

def slot (originals next : ℕ) (reference : U32) : U32 × ℕ :=
  if (clearSign reference).val < originals
  then (⟨BitVec.ofNat 32 next⟩, next + 1)
  else (clearSign reference, next)

def reduce (originals next : ℕ) : List U32 → List U32 × List Job × ℕ
  | [] => ([], [], next)
  | [a] => ([a], [], next)
  | a :: b :: rest =>
    let (out, next') := slot originals next a
    let (refs, jobs, finish) := reduce originals next' rest
    (out :: refs, { first := a, second := b, output := out } :: jobs, finish)

theorem reduce_counts (originals next : ℕ) (refs : List U32) :
    (reduce originals next refs).1.length = refs.length / 2 + refs.length % 2 ∧
    (reduce originals next refs).2.1.length = refs.length / 2 := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simp [reduce]
  | cons_cons a b rest ih =>
    rcases hs : slot originals next a with ⟨out, n⟩
    obtain ⟨hr, hj⟩ := ih n
    simp only [reduce, hs, List.length_cons]
    change (reduce originals n rest).1.length + 1 = _ ∧
      (reduce originals n rest).2.1.length + 1 = _
    constructor <;> omega

theorem reduce_budget (originals next : ℕ) (refs : List U32) :
    next ≤ (reduce originals next refs).2.2 ∧
    (reduce originals next refs).2.2 ≤ next + refs.length / 2 := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simp [reduce]
  | cons_cons a b rest ih =>
    obtain ⟨hl, hu⟩ := ih (slot originals next a).2
    have hs : next ≤ (slot originals next a).2 ∧ (slot originals next a).2 ≤ next + 1 := by
      simp only [slot]; split <;> simp
    change next ≤ (reduce originals (slot originals next a).2 rest).2.2 ∧
      (reduce originals (slot originals next a).2 rest).2.2 ≤ next + (rest.length + 1 + 1) / 2
    constructor <;> omega

def unpaired : List U32 → List U32
  | [] => []
  | [a] => [a]
  | _ :: _ :: rest => unpaired rest

def PairValues {G : Type} [AddMonoid G] (before after : U32 → G) (jobs : List Job) : Prop :=
  ∀ job ∈ jobs, after job.output = before job.first + before job.second

theorem reduce_sum {G : Type} [AddMonoid G]
    (before after : U32 → G) (originals next : ℕ) (refs : List U32)
    (hpairs : PairValues before after (reduce originals next refs).2.1)
    (hpreserve : ∀ r ∈ unpaired refs, after r = before r) :
    ((reduce originals next refs).1.map after).sum = (refs.map before).sum := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simpa [reduce] using hpreserve a (by simp [unpaired])
  | cons_cons a b rest ih =>
    have hpair := hpairs {first := a, second := b, output := (slot originals next a).1}
      (by simp [reduce])
    have htail : PairValues before after (reduce originals (slot originals next a).2 rest).2.1 := by
      intro job hj; apply hpairs job; simp [reduce, hj]
    have hrest := ih (slot originals next a).2 htail (by simpa only [unpaired] using hpreserve)
    simp only [reduce, List.map_cons, List.sum_cons, hpair, hrest, add_assoc]

theorem reduce_measure (originals next pending : ℕ) (refs : List U32) (hp : 0 < pending) :
    (reduce originals next refs).1.length + (reduce originals next refs).2.1.length <
      refs.length + pending := by
  obtain ⟨hr, hj⟩ := reduce_counts originals next refs
  omega

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem vec_length_bound {α : Type} (v : Vec α) :
    v.val.length < 2 ^ UScalarTy.Usize.numBits := by
  have h := v.property
  simp only [Usize.max_def, Usize.numBits_def] at h
  have := two_pow_32_le_usize
  change v.val.length ≤ 2 ^ UScalarTy.Usize.numBits - 1 at h
  omega

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
theorem pointStore_capacity_refines (s : store.PointStore) :
    store.PointStore.capacity s = ok
      (UScalar.ofNatCore (s.rows.val.length / 2)
        (lt_of_le_of_lt (Nat.div_le_self _ _) (vec_length_bound s.rows))) := by
  unfold store.PointStore.capacity
  rw [div_ok _ _ (by decide)]
  rfl

theorem pointStore_allocate_refines (s : store.PointStore)
    (hcap : s.len.val < s.rows.val.length / 2)
    (h32 : s.len.val < 2 ^ 32) :
    ∃ n : Usize, n.val = s.len.val + 1 ∧
      store.PointStore.allocate s =
        ok (UScalar.ofNatCore s.len.val h32, { s with len := n }) := by
  have hs := vec_length_bound s.rows
  have hsum : s.len.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    change s.len.val + 1 < _
    have := Nat.div_le_self s.rows.val.length 2
    omega
  let n : Usize := UScalar.ofNatCore (s.len.val + 1) hsum
  refine ⟨n, by simp [n], ?_⟩
  have hsub : n - 1#usize = ok s.len := by
    rw [sub_ok _ _ (by simp [n])]
    congr 1
  have hcast : UScalar.cast .U32 s.len = (UScalar.ofNatCore s.len.val h32 : U32) := by
    apply UScalar.eq_of_val_eq
    simp only [UScalar.cast_val_eq, UScalar.ofNatCore_val_eq]
    exact Nat.mod_eq_of_lt h32
  simp only [store.PointStore.allocate, pointStore_capacity_refines,
    bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hcap, massert]
  rw [add_ok _ _ hsum]
  change (do let i ← n - 1#usize; let j ← lift (UScalar.cast .U32 i); ok (j, { s with len := n })) = _
  rw [hsub]
  simp [hcast, lift]



theorem clearSign_value (reference : U32) :
    (clearSign reference).val = reference.val % 2 ^ 31 := by
  change reference.val &&& (2 ^ 31 - 1) = _
  exact Nat.and_two_pow_sub_one_eq_mod reference.val 31

theorem sum_slot_reuse (reference : U32) (s : store.PointStore) (originals : Usize)
    (h : originals.val ≤ (clearSign reference).val) :
    buckets.sum_slot reference s originals = ok (clearSign reference, s) := by
  have hn : pairs.NEGATED = ok 2147483648#u32 := by unfold pairs.NEGATED; rfl
  have hm : (~~~ (2147483648#u32) : U32) = 2147483647#u32 := by decide
  simp only [buckets.sum_slot, hn, bind_tc_ok, lift, hm]
  simp only [UScalar.lt_equiv, cast_Usize_val]
  change (if (clearSign reference).val < originals.val then s.allocate else ok (clearSign reference, s)) = _
  rw [if_neg (by omega)]

theorem sum_slot_allocate (reference : U32) (s : store.PointStore) (originals : Usize)
    (h : (clearSign reference).val < originals.val)
    (hcap : s.len.val < s.rows.val.length / 2) (h32 : s.len.val < 2 ^ 32) :
    ∃ n : Usize, n.val = s.len.val + 1 ∧
      buckets.sum_slot reference s originals =
        ok (UScalar.ofNatCore s.len.val h32, { s with len := n }) := by
  obtain ⟨n, hn, he⟩ := pointStore_allocate_refines s hcap h32
  refine ⟨n, hn, ?_⟩
  have hneg : pairs.NEGATED = ok 2147483648#u32 := by unfold pairs.NEGATED; rfl
  have hm : (~~~ (2147483648#u32) : U32) = 2147483647#u32 := by decide
  simp only [buckets.sum_slot, hneg, bind_tc_ok, lift, hm]
  simp only [UScalar.lt_equiv, cast_Usize_val]
  change (if (clearSign reference).val < originals.val then s.allocate else ok (clearSign reference, s)) = _
  rw [if_pos h]
  exact he

theorem sum_slot_refines (reference : U32) (s : store.PointStore) (originals : Usize)
    (halloc : (clearSign reference).val < originals.val →
      s.len.val < s.rows.val.length / 2 ∧ s.len.val < 2 ^ 32) :
    ∃ result, buckets.sum_slot reference s originals =
        ok ((slot originals.val s.len.val reference).1, result) ∧
      result.len.val = (slot originals.val s.len.val reference).2 ∧ result.rows = s.rows := by
  by_cases h : (clearSign reference).val < originals.val
  · obtain ⟨hcap, h32⟩ := halloc h
    obtain ⟨n, hn, he⟩ := sum_slot_allocate reference s originals h hcap h32
    refine ⟨{ s with len := n }, ?_, ?_, rfl⟩
    · have hc : (UScalar.ofNatCore s.len.val h32 : U32) = ⟨BitVec.ofNat 32 s.len.val⟩ := by
        apply UScalar.eq_of_val_eq
        simp only [UScalar.val]
        exact (Nat.mod_eq_of_lt h32).symm
      simpa only [slot, h, if_true, hc] using he
    · simpa only [slot, h, if_true] using hn
  · refine ⟨s, ?_, ?_, rfl⟩
    · simpa only [slot, h, if_false] using sum_slot_reuse reference s originals (by omega)
    · simp only [slot, h, if_false]

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

structure QueueState where
  refs : List U32
  firsts : List U32
  seconds : List U32
  outputs : List U32
  next : ℕ

def stateOf (refs : Vec U32) (adds : pairs.BatchedAdds) (s : store.PointStore) : QueueState :=
  ⟨refs.val, adds.a.val, adds.b.val, adds.out.val, s.len.val⟩

def enqueue (originals start cursor : ℕ) (q : QueueState) : QueueState :=
  let first := q.refs[start + cursor]!
  let second := q.refs[start + cursor + 1]!
  let (output, next) := slot originals q.next first
  ⟨q.refs.set (start + cursor / 2) output, q.firsts ++ [first],
    q.seconds ++ [second], q.outputs ++ [output], next⟩

def queueSteps (originals start : ℕ) : ℕ → ℕ → QueueState → QueueState
  | 0, _, q => q
  | n + 1, cursor, q => queueSteps originals start n (cursor + 2) (enqueue originals start cursor q)

theorem enqueue_lengths (originals start cursor : ℕ) (q : QueueState) :
    (enqueue originals start cursor q).refs.length = q.refs.length ∧
    (enqueue originals start cursor q).firsts.length = q.firsts.length + 1 ∧
    (enqueue originals start cursor q).seconds.length = q.seconds.length + 1 ∧
    (enqueue originals start cursor q).outputs.length = q.outputs.length + 1 ∧
    q.next ≤ (enqueue originals start cursor q).next ∧
    (enqueue originals start cursor q).next ≤ q.next + 1 := by
  simp only [enqueue, slot]
  split <;> simp

theorem queue_step_refines
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hactive : cursor.val + 1 < len.val)
    (hspan : start.val + len.val ≤ refs.val.length)
    (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length < Usize.max) (hb : adds.b.val.length < Usize.max)
    (ho : adds.out.val.length < Usize.max)
    (hcap : s.len.val < s.rows.val.length / 2) (h32 : s.len.val < 2 ^ 32) :
    ∃ refs' adds' s' cursor',
      buckets.Buckets.queue_pairs_loop.body originals start len refs adds s cursor =
        ok (cont (refs', adds', s', cursor')) ∧
      stateOf refs' adds' s' = enqueue originals.val start.val cursor.val (stateOf refs adds s) ∧
      cursor'.val = cursor.val + 2 ∧ s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
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
  obtain ⟨s', hslot, hlen, hrows⟩ := sum_slot_refines first s originals (by intro _; exact ⟨hcap, h32⟩)
  obtain ⟨adds', hpush, hfa, hfb, hfo, hdx, hprefix⟩ := adds_push adds first second output ha hb ho
  refine ⟨refs.set dest output, adds', s', next, ?_, ?_, rfl, hrows, hdx, hprefix⟩
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem queueSteps_lengths (originals start n cursor : ℕ) (q : QueueState) :
    (queueSteps originals start n cursor q).refs.length = q.refs.length ∧
    (queueSteps originals start n cursor q).firsts.length = q.firsts.length + n ∧
    (queueSteps originals start n cursor q).seconds.length = q.seconds.length + n ∧
    (queueSteps originals start n cursor q).outputs.length = q.outputs.length + n ∧
    q.next ≤ (queueSteps originals start n cursor q).next ∧
    (queueSteps originals start n cursor q).next ≤ q.next + n := by
  induction n generalizing cursor q with
  | zero => simp [queueSteps]
  | succ n ih =>
    obtain ⟨hr, ha, hb, ho, hn, hu⟩ := enqueue_lengths originals start cursor q
    obtain ⟨hrr, haa, hbb, hoo, hnn, huu⟩ := ih (cursor + 2) (enqueue originals start cursor q)
    simp only [queueSteps]
    exact ⟨by omega, by omega, by omega, by omega, by omega, by omega⟩

theorem queue_loop_refines (n : ℕ)
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hlo : cursor.val + 2 * n ≤ len.val)
    (hhi : len.val ≤ cursor.val + 2 * n + 1)
    (hlen : len.val + 1 < 2 ^ 32)
    (hspan : start.val + len.val ≤ refs.val.length)
    (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + n ≤ Usize.max)
    (hb : adds.b.val.length + n ≤ Usize.max)
    (ho : adds.out.val.length + n ≤ Usize.max)
    (hcap : s.len.val + n ≤ s.rows.val.length / 2)
    (h32 : s.len.val + n < 2 ^ 32) :
    ∃ refs' adds' s',
      buckets.Buckets.queue_pairs_loop refs adds s originals start len cursor = ok (refs', adds', s') ∧
      stateOf refs' adds' s' = queueSteps originals.val start.val n cursor.val (stateOf refs adds s) ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
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
    obtain ⟨refs', adds', s', cursor', hstep, hstate, hcursor, hrows, hdx, hprefix⟩ :=
      queue_step_refines originals start len cursor refs adds s (by omega) hspan hrefs
        (by omega) (by omega) (by omega) (by omega) (by omega)
    have hfields := enqueue_lengths originals.val start.val cursor.val (stateOf refs adds s)
    rw [← hstate] at hfields
    change refs'.val.length = refs.val.length ∧
      adds'.a.val.length = adds.a.val.length + 1 ∧
      adds'.b.val.length = adds.b.val.length + 1 ∧
      adds'.out.val.length = adds.out.val.length + 1 ∧
      s.len.val ≤ s'.len.val ∧ s'.len.val ≤ s.len.val + 1 at hfields
    obtain ⟨hr, hfa, hfb, hfo, _, hnext⟩ := hfields
    obtain ⟨refs'', adds'', s'', hloop, hmodel, hrows', hdx', hprefix'⟩ :=
      ih cursor' refs' adds' s' (by omega) (by omega) (by omega) (by omega)
        (by omega) (by omega) (by omega) (by rw [hrows]; omega) (by omega)
    refine ⟨refs'', adds'', s'', ?_, ?_, hrows'.trans hrows, hdx'.trans hdx, hprefix'.trans hprefix⟩
    · rw [buckets.Buckets.queue_pairs_loop, loop.eq_1]
      simpa only [hstep] using hloop
    · simpa only [queueSteps, hcursor, hstate] using hmodel

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def writeAt (xs : List U32) (offset : ℕ) : List U32 → List U32
  | [] => xs
  | a :: rest => writeAt (xs.set offset a) (offset + 1) rest

theorem writeAt_length (xs values : List U32) (offset : ℕ) :
    (writeAt xs offset values).length = xs.length := by
  induction values generalizing xs offset with
  | nil => rfl
  | cons a rest ih => simpa [writeAt] using ih (xs.set offset a) (offset + 1)

theorem writeAt_outside (xs values : List U32) (offset index : ℕ)
    (h : index < offset ∨ offset + values.length ≤ index) :
    (writeAt xs offset values)[index]! = xs[index]! := by
  induction values generalizing xs offset with
  | nil => rfl
  | cons a rest ih =>
    rw [writeAt, ih (xs.set offset a) (offset + 1) (by simp only [List.length_cons] at h; omega)]
    exact List.getElem!_set_ne xs offset index a (by simp only [List.length_cons] at h; omega)

theorem queueSteps_plan (originals start cursor : ℕ) (q : QueueState) (xs : List U32)
    (hin : ∀ i < xs.length, q.refs[start + cursor + i]! = xs[i]!) :
    queueSteps originals start (xs.length / 2) cursor q =
      { refs := writeAt q.refs (start + cursor / 2)
          ((reduce originals q.next xs).1.take (xs.length / 2))
        firsts := q.firsts ++ ((reduce originals q.next xs).2.1.map Job.first)
        seconds := q.seconds ++ ((reduce originals q.next xs).2.1.map Job.second)
        outputs := q.outputs ++ ((reduce originals q.next xs).2.1.map Job.output)
        next := (reduce originals q.next xs).2.2 } := by
  induction xs using List.twoStepInduction generalizing cursor q with
  | nil => simp [reduce, queueSteps, writeAt]
  | singleton a => simp [reduce, queueSteps, writeAt]
  | cons_cons a b rest ih =>
    have hf : q.refs[start + cursor]! = a := by simpa using hin 0 (by simp)
    have hs : q.refs[start + cursor + 1]! = b := by simpa using hin 1 (by simp)
    have htail : ∀ i < rest.length,
        (enqueue originals start cursor q).refs[start + (cursor + 2) + i]! = rest[i]! := by
      intro i hi
      change (q.refs.set (start + cursor / 2) _)[start + (cursor + 2) + i]! = _
      rw [List.getElem!_set_ne q.refs (start + cursor / 2) (start + (cursor + 2) + i)
        _ (by omega)]
      have hh := hin (i + 2) (by simp; omega)
      simpa [Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using hh
    have hn : (a :: b :: rest).length / 2 = rest.length / 2 + 1 := by simp; omega
    have hc : (cursor + 2) / 2 = cursor / 2 + 1 := by omega
    rw [hn, queueSteps, ih (cursor + 2) (enqueue originals start cursor q) htail]
    rcases he : slot originals q.next a with ⟨out, next⟩
    have hs' : q.refs[start + (cursor + 1)]! = b := by simpa only [Nat.add_assoc] using hs
    simp only [enqueue, hf, hs', he, reduce, hc, List.take_succ_cons, writeAt,
      List.map_cons, List.append_assoc, List.singleton_append, Nat.add_assoc]

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

def oddCopy (start len : ℕ) (refs : List U32) : List U32 :=
  if len % 2 = 1 then refs.set (start + len / 2) refs[start + len - 1]! else refs

def oddCopyCode (start len : Usize) (refs : Vec U32) : Result (Vec U32) := do
  let rem ← len % 2#usize
  if rem = 1#usize then do
    let i3 ← start + len
    let i4 ← i3 - 1#usize
    let i5 ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs i4
    let i6 ← len / 2#usize
    let i7 ← start + i6
    let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs i7
    ok (back i5)
  else ok refs

theorem oddCopy_refines (start len : Usize) (refs : Vec U32)
    (hspan : start.val + len.val ≤ refs.val.length) (hrefs : refs.val.length < 2 ^ 32) :
    ∃ result, oddCopyCode start len refs = ok result ∧
      result.val = oddCopy start.val len.val refs.val := by
  have hmax := two_pow_32_le_usize
  have hsum : start.val + len.val < 2 ^ UScalarTy.Usize.numBits := by omega
  have hdiv : start.val + len.val / 2 < 2 ^ UScalarTy.Usize.numBits := by omega
  unfold oddCopyCode
  rw [rem_ok len (2#usize) (by decide)]
  simp only [bind_tc_ok, UScalar.eq_equiv, UScalar.ofNatCore_val_eq]
  change (∃ result, (if len.val % 2 = 1 then _ else ok refs) = ok result ∧ result.val = _)
  by_cases hodd : len.val % 2 = 1
  · let source : Usize := UScalar.ofNatCore (start.val + len.val - 1) (by omega)
    let dest : Usize := UScalar.ofNatCore (start.val + len.val / 2) hdiv
    have hsource : source.val < refs.val.length := by simp only [source, UScalar.ofNatCore_val_eq]; omega
    have hdest : dest.val < refs.val.length := by simp only [dest, UScalar.ofNatCore_val_eq]; omega
    refine ⟨refs.set dest refs.val[source.val], ?_, ?_⟩
    · rw [if_pos hodd, add_ok _ _ hsum]
      simp only [bind_tc_ok]
      rw [sub_ok _ _ (by change 1 ≤ start.val + len.val; omega)]
      change (do
        let value ← Vec.index (core.slice.index.SliceIndexUsizeSlice U32) refs source
        let half ← len / 2#usize
        let dest ← start + half
        let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs dest
        ok (back value)) = _
      rw [vec_index refs source hsource]
      simp only [bind_tc_ok]
      rw [div_ok _ _ (by decide)]
      simp only [bind_tc_ok]
      rw [add_ok _ _ hdiv]
      change (do
        let (_, back) ← Vec.index_mut (core.slice.index.SliceIndexUsizeSlice U32) refs dest
        ok (back refs.val[source.val])) = _
      rw [vec_index_mut refs dest hdest]
      rfl
    · simp only [oddCopy, hodd, if_true, Vec.set, dest, source, UScalar.ofNatCore_val_eq]
      rw [getElem!_pos refs.val (start.val + len.val - 1) (by omega)]
  · exact ⟨refs, by rw [if_neg hodd], by simp only [oddCopy, hodd, if_false]⟩

def queueBucket (originals start len : ℕ) (q : QueueState) : QueueState :=
  let done := queueSteps originals start (len / 2) 0 q
  { done with refs := oddCopy start len done.refs }

theorem queueBucket_lengths (originals start len : ℕ) (q : QueueState) :
    (queueBucket originals start len q).refs.length = q.refs.length ∧
    (queueBucket originals start len q).firsts.length = q.firsts.length + len / 2 ∧
    (queueBucket originals start len q).seconds.length = q.seconds.length + len / 2 ∧
    (queueBucket originals start len q).outputs.length = q.outputs.length + len / 2 ∧
    q.next ≤ (queueBucket originals start len q).next ∧
    (queueBucket originals start len q).next ≤ q.next + len / 2 := by
  have hh := queueSteps_lengths originals start (len / 2) 0 q
  simp only [queueBucket, oddCopy]
  split <;> simpa only [List.length_set] using hh

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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

theorem queue_pairs_refines (state : buckets.Buckets) (list : Usize)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hstart : list.val < state.starts.val.length) (hlist : list.val < state.lens.val.length)
    (hlen : state.lens.val[list.val].val + 1 < 2 ^ 32)
    (hspan : state.starts.val[list.val].val + state.lens.val[list.val].val ≤ state.refs.val.length)
    (hrefs : state.refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (hb : adds.b.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (ho : adds.out.val.length + state.lens.val[list.val].val / 2 ≤ Usize.max)
    (hcap : s.len.val + state.lens.val[list.val].val / 2 ≤ s.rows.val.length / 2)
    (h32 : s.len.val + state.lens.val[list.val].val / 2 < 2 ^ 32) :
    ∃ result adds' s' newLen,
      state.queue_pairs list adds s originals = ok (result, adds', s') ∧
      stateOf result.refs adds' s' = queueBucket originals.val state.starts.val[list.val].val
        state.lens.val[list.val].val (stateOf state.refs adds s) ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧ result.lens = state.lens.set list newLen ∧
      newLen.val = state.lens.val[list.val].val / 2 + state.lens.val[list.val].val % 2 ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let start : Usize := UScalar.cast .Usize state.starts.val[list.val]
  let len : Usize := UScalar.cast .Usize state.lens.val[list.val]
  have hs : start.val = state.starts.val[list.val].val := cast_Usize_val _
  have hl : len.val = state.lens.val[list.val].val := cast_Usize_val _
  obtain ⟨refs', adds', s', hloop, hmodel, hrows, hdx, hprefix⟩ :=
    queue_loop_refines (len.val / 2) originals start len 0#usize state.refs adds s
      (by simp only [UScalar.ofNatCore_val_eq]; omega) (by simp only [UScalar.ofNatCore_val_eq]; omega)
      (by omega) (by omega) hrefs (by omega) (by omega) (by omega) (by omega) (by omega)
  change stateOf refs' adds' s' = queueSteps originals.val start.val (len.val / 2) 0 (stateOf state.refs adds s) at hmodel
  have hlength := (queueSteps_lengths originals.val start.val (len.val / 2) 0 (stateOf state.refs adds s)).1
  rw [← hmodel] at hlength
  change refs'.val.length = state.refs.val.length at hlength
  obtain ⟨refs'', newLen, hfinish, href, hnew⟩ :=
    finishBucket_refines state list start len refs' adds' s' hlist (by omega) (by omega)
  refine ⟨{ state with refs := refs'', lens := state.lens.set list newLen }, adds', s', newLen,
    ?_, ?_, rfl, rfl, rfl, rfl, by simpa only [hl] using hnew, hrows, hdx, hprefix⟩
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem reduce_unpaired (originals next : ℕ) (xs : List U32) :
    (reduce originals next xs).1.drop (xs.length / 2) = unpaired xs := by
  induction xs using List.twoStepInduction generalizing next with
  | nil => simp [reduce, unpaired]
  | singleton a => simp [reduce, unpaired]
  | cons_cons a b rest ih =>
    have hn : (a :: b :: rest).length / 2 = rest.length / 2 + 1 := by simp; omega
    rcases hs : slot originals next a with ⟨out, next'⟩
    simpa only [reduce, hs, hn, List.drop_succ_cons, unpaired] using ih next'

theorem unpaired_last (xs : List U32) :
    unpaired xs = if xs.length % 2 = 1 then [xs[xs.length - 1]!] else [] := by
  induction xs using List.twoStepInduction with
  | nil => simp [unpaired]
  | singleton a => simp [unpaired]
  | cons_cons a b rest ih =>
    have hm : (a :: b :: rest).length % 2 = rest.length % 2 := by simp; omega
    simp only [unpaired, hm, ih]
    split
    · have hpos : 1 ≤ rest.length := by omega
      have hi : (a :: b :: rest).length - 1 = rest.length - 1 + 2 := by simp; omega
      rw [hi]
      simp only [Nat.add_succ, Nat.add_zero, List.getElem!_cons_succ]
    · rfl

theorem writeAt_append (xs left right : List U32) (offset : ℕ) :
    writeAt xs offset (left ++ right) =
      writeAt (writeAt xs offset left) (offset + left.length) right := by
  induction left generalizing xs offset with
  | nil => simp [writeAt]
  | cons a rest ih =>
    simpa [writeAt, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using
      (ih (xs.set offset a) (offset + 1))

theorem queueBucket_plan (originals start : ℕ) (q : QueueState) (xs : List U32)
    (hin : ∀ i < xs.length, q.refs[start + i]! = xs[i]!) :
    queueBucket originals start xs.length q =
      { refs := writeAt q.refs start (reduce originals q.next xs).1
        firsts := q.firsts ++ ((reduce originals q.next xs).2.1.map Job.first)
        seconds := q.seconds ++ ((reduce originals q.next xs).2.1.map Job.second)
        outputs := q.outputs ++ ((reduce originals q.next xs).2.1.map Job.output)
        next := (reduce originals q.next xs).2.2 } := by
  have hplan := queueSteps_plan originals start 0 q xs (by simpa using hin)
  simp only [queueBucket, hplan, Nat.zero_div, Nat.add_zero]
  congr 1
  let reduced := (reduce originals q.next xs).1
  have hcount := (reduce_counts originals q.next xs).1
  have htake : (reduced.take (xs.length / 2)).length = xs.length / 2 := by
    simp only [List.length_take, reduced]
    omega
  have hsplit : reduced = reduced.take (xs.length / 2) ++ unpaired xs := by
    rw [← reduce_unpaired originals q.next xs]
    exact (List.take_append_drop _ reduced).symm
  have hwrite : writeAt q.refs start reduced =
      writeAt (writeAt q.refs start (reduced.take (xs.length / 2)))
        (start + xs.length / 2) (unpaired xs) := by
    conv_lhs => rw [hsplit]
    rw [writeAt_append, htake]
  change oddCopy start xs.length (writeAt q.refs start (reduced.take (xs.length / 2))) = _
  rw [hwrite, unpaired_last]
  by_cases hodd : xs.length % 2 = 1
  · have hidx : xs.length - 1 < xs.length := by omega
    have hsource : start + xs.length / 2 ≤ start + xs.length - 1 := by omega
    simp only [oddCopy, hodd, if_true, writeAt]
    rw [writeAt_outside q.refs (reduced.take (xs.length / 2)) start
      (start + xs.length - 1) (Or.inr (by rw [htake]; omega))]
    rw [show start + xs.length - 1 = start + (xs.length - 1) by omega, hin _ hidx]
  · simp only [oddCopy, hodd, if_false, writeAt]

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def ceilWord (v : U32) : U32 := ⟨BitVec.ofNat 32 (v.val / 2 + v.val % 2)⟩

theorem ceilWord_val (v : U32) : (ceilWord v).val = v.val / 2 + v.val % 2 := by
  change (v.val / 2 + v.val % 2) % 2 ^ 32 = _
  apply Nat.mod_eq_of_lt
  have := v.hBounds
  change v.val < 2 ^ 32 at this
  omega

def pairBudget (lengths : List U32) : ℕ := (lengths.map (fun v => v.val / 2)).sum

def queueRound (originals : ℕ) (starts : List U32) : ℕ → List U32 → QueueState → QueueState
  | _, [], q => q
  | index, len :: rest, q =>
    queueRound originals starts (index + 1) rest
      (queueBucket originals starts[index]!.val len.val q)

def roundFields (state : buckets.Buckets) (adds : pairs.BatchedAdds) (s : store.PointStore) :=
  (state.window_bits, state.windows, state.refs, state.starts, state.lens, adds, s)

theorem drop_set_succ (xs : List U32) (index : ℕ) (value : U32) :
    (xs.set index value).drop (index + 1) = xs.drop (index + 1) := by
  induction xs generalizing index with
  | nil => simp
  | cons x xs ih =>
    cases index with
    | zero => rfl
    | succ index => simpa using ih index

theorem queue_round_loop_refines (remaining : List U32)
    (state : buckets.Buckets) (adds : pairs.BatchedAdds) (s : store.PointStore)
    (originals index : Usize)
    (hindex : index.val ≤ state.lens.val.length)
    (hremaining : state.lens.val.drop index.val = remaining)
    (hstarts : state.lens.val.length ≤ state.starts.val.length)
    (hshape : ∀ i, index.val ≤ i → i < state.lens.val.length →
      state.lens.val[i]!.val + 1 < 2 ^ 32 ∧
      state.starts.val[i]!.val + state.lens.val[i]!.val ≤ state.refs.val.length)
    (hrefs : state.refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + pairBudget remaining ≤ Usize.max)
    (hb : adds.b.val.length + pairBudget remaining ≤ Usize.max)
    (ho : adds.out.val.length + pairBudget remaining ≤ Usize.max)
    (hcap : s.len.val + pairBudget remaining ≤ s.rows.val.length / 2)
    (h32 : s.len.val + pairBudget remaining < 2 ^ 32) :
    ∃ result adds' s',
      state.queue_round_loop adds s originals index = ok (roundFields result adds' s') ∧
      stateOf result.refs adds' s' =
        queueRound originals.val state.starts.val index.val remaining (stateOf state.refs adds s) ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧
      result.lens.val = writeAt state.lens.val index.val (remaining.map ceilWord) ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  induction remaining generalizing state adds s index with
  | nil =>
    have hdone : ¬ index < Vec.len state.lens := by
      change ¬ index.val < state.lens.val.length
      have hl := congrArg List.length hremaining
      simp only [List.length_drop, List.length_nil] at hl
      omega
    refine ⟨state, adds, s, ?_, rfl, rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
    rw [buckets.Buckets.queue_round_loop, loop.eq_1]
    simp only [buckets.Buckets.queue_round_loop.body, hdone, if_false, roundFields]
  | cons len rest ih =>
    have hsize := congrArg List.length hremaining
    simp only [List.length_drop, List.length_cons] at hsize
    have hlist : index.val < state.lens.val.length := by omega
    have hstart : index.val < state.starts.val.length := by omega
    have hcurrent : state.lens.val[index.val]! = len := by
      have hh := congrArg (fun xs : List U32 => xs[0]!) hremaining
      simpa only [List.getElem!_drop, Nat.add_zero, List.getElem!_cons_zero] using hh
    have hcurrent' : state.lens.val[index.val] = len := by
      simpa only [getElem!_pos state.lens.val index.val hlist] using hcurrent
    have hbound := hshape index.val (by omega) hlist
    simp only [getElem!_pos state.lens.val index.val hlist,
      getElem!_pos state.starts.val index.val hstart, hcurrent'] at hbound
    have hbudget : pairBudget (len :: rest) = len.val / 2 + pairBudget rest := by simp [pairBudget]
    obtain ⟨state', adds', s', newLen, hpair, hq, hw, hn, hs, hl, hnew, hr, hdx, hp⟩ :=
      queue_pairs_refines state index adds s originals hstart hlist
        (by simpa only [hcurrent'] using hbound.1)
        (by simpa only [hcurrent'] using hbound.2) hrefs
        (by rw [hcurrent']; omega) (by rw [hcurrent']; omega) (by rw [hcurrent']; omega)
        (by rw [hcurrent']; omega) (by rw [hcurrent']; omega)
    have hnewEq : newLen = ceilWord len := by
      apply UScalar.eq_of_val_eq
      rw [hnew, hcurrent', ceilWord_val]
    have hl' : state'.lens.val = state.lens.val.set index.val (ceilWord len) := by
      rw [hl, hnewEq]; rfl
    have hlength : state'.lens.val.length = state.lens.val.length := by rw [hl', List.length_set]
    have hq' : stateOf state'.refs adds' s' =
        queueBucket originals.val state.starts.val[index.val]!.val len.val (stateOf state.refs adds s) := by
      simpa only [hcurrent', getElem!_pos state.starts.val index.val hstart] using hq
    have hf := queueBucket_lengths originals.val state.starts.val[index.val]!.val len.val (stateOf state.refs adds s)
    rw [← hq'] at hf
    change state'.refs.val.length = state.refs.val.length ∧
      adds'.a.val.length = adds.a.val.length + len.val / 2 ∧
      adds'.b.val.length = adds.b.val.length + len.val / 2 ∧
      adds'.out.val.length = adds.out.val.length + len.val / 2 ∧
      s.len.val ≤ s'.len.val ∧ s'.len.val ≤ s.len.val + len.val / 2 at hf
    obtain ⟨hrefLength, hla, hlb, hlo, _, hnext⟩ := hf
    have hnextBound : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := vec_length_bound state.lens
      omega
    let next : Usize := UScalar.ofNatCore (index.val + 1) hnextBound
    have hnval : next.val = index.val + 1 := rfl
    have hrem : state'.lens.val.drop next.val = rest := by
      rw [hl', hnval, drop_set_succ]
      have ht := congrArg (List.drop 1) hremaining
      simpa only [List.drop_drop, Nat.add_comm 1 index.val, List.drop_succ_cons, List.drop_zero] using ht
    have hshape' : ∀ i, next.val ≤ i → i < state'.lens.val.length →
        state'.lens.val[i]!.val + 1 < 2 ^ 32 ∧
        state'.starts.val[i]!.val + state'.lens.val[i]!.val ≤ state'.refs.val.length := by
      intro i hni hil
      rw [hl', List.getElem!_set_ne _ _ _ _ (by omega), hs, hrefLength]
      apply hshape i (by omega) (by omega)
    obtain ⟨result, adds'', s'', hloop, hmodel, hw', hn', hs', hlens, hr', hdx', hp'⟩ :=
      ih state' adds' s' next (by omega) hrem (by rw [hs]; omega) hshape' (by omega)
        (by omega) (by omega) (by omega) (by rw [hr]; omega) (by omega)
    refine ⟨result, adds'', s'', ?_, ?_, hw'.trans hw, hn'.trans hn, hs'.trans hs,
      ?_, hr'.trans hr, hdx'.trans hdx, hp'.trans hp⟩
    · rw [buckets.Buckets.queue_round_loop, loop.eq_1]
      have hactive : index < Vec.len state.lens := by simp only [UScalar.lt_equiv, Vec.len_val]; exact hlist
      simp only [buckets.Buckets.queue_round_loop.body, hactive, if_true, hpair, bind_tc_ok]
      rw [add_ok index (1#usize) hnextBound]
      exact hloop
    · simpa only [queueRound, hs, hnval, hq'] using hmodel
    · simpa only [hl', hnval, List.map_cons, writeAt] using hlens

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def cleared (q : QueueState) : QueueState :=
  { q with firsts := [], seconds := [], outputs := [] }

theorem queue_round_refines (state : buckets.Buckets) (adds : pairs.BatchedAdds)
    (s : store.PointStore) (originals : Usize)
    (hstarts : state.lens.val.length ≤ state.starts.val.length)
    (hshape : ∀ i < state.lens.val.length,
      state.lens.val[i]!.val + 1 < 2 ^ 32 ∧
      state.starts.val[i]!.val + state.lens.val[i]!.val ≤ state.refs.val.length)
    (hrefs : state.refs.val.length < 2 ^ 32)
    (hbudget : pairBudget state.lens.val ≤ Usize.max)
    (hcap : s.len.val + pairBudget state.lens.val ≤ s.rows.val.length / 2)
    (h32 : s.len.val + pairBudget state.lens.val < 2 ^ 32) :
    ∃ result adds' s', state.queue_round adds s originals = ok (result, adds', s') ∧
      stateOf result.refs adds' s' =
        queueRound originals.val state.starts.val 0 state.lens.val (cleared (stateOf state.refs adds s)) ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧
      result.lens.val = writeAt state.lens.val 0 (state.lens.val.map ceilWord) ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let fresh : pairs.BatchedAdds :=
    { adds with a := Vec.new U32, b := Vec.new U32, out := Vec.new U32 }
  obtain ⟨result, adds', s', hloop, hmodel, hw, hn, hs, hl, hr, hdx, hp⟩ :=
    queue_round_loop_refines state.lens.val state fresh s originals 0#usize
      (by change 0 ≤ _; omega) (by rfl) hstarts (by intro i _ hi; exact hshape i hi)
      hrefs (by simpa [fresh, Vec.new] using hbudget) (by simpa [fresh, Vec.new] using hbudget)
      (by simpa [fresh, Vec.new] using hbudget) hcap h32
  refine ⟨result, adds', s', ?_, hmodel, hw, hn, hs, hl, hr, hdx, hp⟩
  simp only [buckets.Buckets.queue_round, adds_clear, bind_tc_ok]
  change (do
    let (i, j, refs, starts, lens, adds', s') ← state.queue_round_loop fresh s originals 0#usize
    ok (({window_bits := i, windows := j, refs := refs, starts := starts, lens := lens} : buckets.Buckets),
      adds', s')) = _
  rw [hloop]
  rfl

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem writeAt_inside (xs values : List U32) (offset index : ℕ)
    (hspan : offset + values.length ≤ xs.length) (hi : index < values.length) :
    (writeAt xs offset values)[offset + index]! = values[index]! := by
  induction values generalizing xs offset index with
  | nil => simp at hi
  | cons a rest ih =>
    cases index with
    | zero =>
      simp only [writeAt, Nat.add_zero, List.getElem!_cons_zero]
      rw [writeAt_outside (xs.set offset a) rest (offset + 1) offset (Or.inl (by omega))]
      apply List.getElem!_set
      simp only [List.length_cons] at hspan
      omega
    | succ index =>
      have hh := ih (xs.set offset a) (offset + 1) index
        (by simp only [List.length_set, List.length_cons] at *; omega) (by simp at hi; omega)
      simpa only [writeAt, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm, List.getElem!_cons_succ] using hh

theorem writeAt_slice (xs values : List U32) (offset : ℕ)
    (hspan : offset + values.length ≤ xs.length) :
    ((writeAt xs offset values).drop offset).take values.length = values := by
  apply List.ext_getElem
  · simp only [List.length_take, List.length_drop, writeAt_length]
    omega
  · intro i hi hj
    rw [← getElem!_pos _ i hi, ← getElem!_pos values i hj]
    rw [List.getElem!_take_of_lt _ _ _ hj, List.getElem!_drop]
    exact writeAt_inside xs values offset i hspan hj

theorem writeAt_all (xs values : List U32) (h : values.length = xs.length) :
    writeAt xs 0 values = values := by
  have hh := writeAt_slice xs values 0 (by omega)
  have hl : (writeAt xs 0 values).length ≤ values.length := by rw [writeAt_length]; omega
  simpa only [List.drop_zero, List.take_of_length_le hl] using hh

theorem queueBucket_slice (originals start : ℕ) (q : QueueState) (xs : List U32)
    (hin : ∀ i < xs.length, q.refs[start + i]! = xs[i]!)
    (hspan : start + xs.length ≤ q.refs.length) :
    ((queueBucket originals start xs.length q).refs.drop start).take
      (xs.length / 2 + xs.length % 2) = (reduce originals q.next xs).1 := by
  rw [queueBucket_plan originals start q xs hin]
  have hc := (reduce_counts originals q.next xs).1
  rw [← hc]
  apply writeAt_slice
  omega

theorem queueBucket_frame (originals start : ℕ) (q : QueueState) (xs : List U32)
    (hin : ∀ i < xs.length, q.refs[start + i]! = xs[i]!)
    (index : ℕ) (houtside : index < start ∨ start + xs.length ≤ index) :
    (queueBucket originals start xs.length q).refs[index]! = q.refs[index]! := by
  rw [queueBucket_plan originals start q xs hin]
  apply writeAt_outside
  have hc := (reduce_counts originals q.next xs).1
  omega

theorem queueBucket_sum {G : Type} [AddMonoid G]
    (before after : U32 → G) (originals start : ℕ) (q : QueueState) (xs : List U32)
    (hin : ∀ i < xs.length, q.refs[start + i]! = xs[i]!)
    (hspan : start + xs.length ≤ q.refs.length)
    (hpairs : PairValues before after (reduce originals q.next xs).2.1)
    (hodd : ∀ r ∈ unpaired xs, after r = before r) :
    ((((queueBucket originals start xs.length q).refs.drop start).take
      (xs.length / 2 + xs.length % 2)).map after).sum = (xs.map before).sum := by
  rw [queueBucket_slice originals start q xs hin hspan]
  exact reduce_sum before after originals q.next xs hpairs hodd

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def pointIndex (reference : U32) : ℕ := (clearSign reference).val

def RefIndependent (originals : ℕ) (a b : U32) : Prop :=
  originals ≤ pointIndex a → originals ≤ pointIndex b → pointIndex a ≠ pointIndex b

def JobIndependent (a b : Job) : Prop :=
  a.output.val ≠ b.output.val ∧
  a.output.val ≠ pointIndex b.first ∧ a.output.val ≠ pointIndex b.second ∧
  b.output.val ≠ pointIndex a.first ∧ b.output.val ≠ pointIndex a.second

theorem slot_info (originals next : ℕ) (reference : U32)
    (ho : originals ≤ next) (hr : pointIndex reference < next) (hn : next < 2 ^ 31) :
    originals ≤ (slot originals next reference).1.val ∧
    (slot originals next reference).1.val < (slot originals next reference).2 ∧
    next ≤ (slot originals next reference).2 ∧ (slot originals next reference).2 ≤ next + 1 ∧
    ((slot originals next reference).1.val = pointIndex reference ∧ originals ≤ pointIndex reference ∨
      (slot originals next reference).1.val = next) := by
  unfold slot
  split
  · have hv : (⟨BitVec.ofNat 32 next⟩ : U32).val = next := by
      change next % 2 ^ 32 = next
      apply Nat.mod_eq_of_lt
      omega
    simp only [hv]
    exact ⟨ho, by omega, by omega, by omega, Or.inr trivial⟩
  · change originals ≤ pointIndex reference ∧ pointIndex reference < next ∧ next ≤ next ∧
      next ≤ next + 1 ∧ (pointIndex reference = pointIndex reference ∧ originals ≤ pointIndex reference ∨
        pointIndex reference = next)
    exact ⟨by unfold pointIndex; omega, hr, by omega, by omega, Or.inl ⟨rfl, by unfold pointIndex; omega⟩⟩

theorem reduce_job_info (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31) :
    ∀ job ∈ (reduce originals next refs).2.1,
      job.first ∈ refs ∧ job.second ∈ refs ∧ originals ≤ job.output.val ∧
      job.output.val < (reduce originals next refs).2.2 ∧
      (job.output.val = pointIndex job.first ∧ originals ≤ pointIndex job.first ∨ next ≤ job.output.val) := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simp [reduce]
  | cons_cons a b rest ih =>
    rcases hs : slot originals next a with ⟨out, next'⟩
    have hinfo := slot_info originals next a ho (hb a (by simp)) (by simp only [List.length_cons] at hn; omega)
    rw [hs] at hinfo
    dsimp only at hinfo
    obtain ⟨hlo, hout, hnext, hup, hkind⟩ := hinfo
    have ht := ih next' (by omega) (by intro r hr; have := hb r (by simp [hr]); omega)
      (by simp only [List.length_cons] at hn; omega)
    have hfinish := (reduce_budget originals next' rest).1
    intro job hj
    simp only [reduce, hs, List.mem_cons] at hj
    rcases hj with rfl | hj
    · have hk : out.val = pointIndex a ∧ originals ≤ pointIndex a ∨ next ≤ out.val :=
        hkind.elim Or.inl (fun h => Or.inr (by omega))
      exact ⟨by simp, by simp, hlo, by simpa only [reduce, hs] using lt_of_lt_of_le hout hfinish, hk⟩
    · obtain ⟨ha, hb, hlo, hhi, hk⟩ := ht job hj
      exact ⟨by simp [ha], by simp [hb], hlo, by simpa only [reduce, hs] using hhi,
        hk.elim Or.inl (fun h => Or.inr (by omega))⟩

theorem RefIndependent.left_ne {originals : ℕ} {a b : U32}
    (h : RefIndependent originals a b) (ha : originals ≤ pointIndex a) :
    pointIndex a ≠ pointIndex b := by
  intro he
  exact h ha (by omega) he

theorem RefIndependent.right_ne {originals : ℕ} {a b : U32}
    (h : RefIndependent originals a b) (hb : originals ≤ pointIndex b) :
    pointIndex b ≠ pointIndex a := by
  intro he
  exact h (by omega) hb he.symm

theorem reduce_independent (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31)
    (hi : refs.Pairwise (RefIndependent originals)) :
    ((reduce originals next refs).2.1).Pairwise JobIndependent := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simp [reduce]
  | cons_cons a b rest ih =>
    rcases hs : slot originals next a with ⟨out, next'⟩
    have hinfo := slot_info originals next a ho (hb a (by simp)) (by simp only [List.length_cons] at hn; omega)
    rw [hs] at hinfo
    dsimp only at hinfo
    obtain ⟨hlo, hout, hnext, hup, hkind⟩ := hinfo
    obtain ⟨ha, hrest⟩ := List.pairwise_cons.mp hi
    obtain ⟨hb', hrest⟩ := List.pairwise_cons.mp hrest
    have hbound : ∀ r ∈ rest, pointIndex r < next' := by
      intro r hr; have := hb r (by simp [hr]); omega
    have hreserve : next' + rest.length / 2 < 2 ^ 31 := by simp only [List.length_cons] at hn; omega
    have htail := ih next' (by omega) hbound hreserve hrest
    have hjobs := reduce_job_info originals next' rest (by omega) hbound hreserve
    simp only [reduce, hs]
    apply List.pairwise_cons.mpr
    refine ⟨?_, htail⟩
    intro job hj
    obtain ⟨hfirst, hsecond, hjlo, _, hjkind⟩ := hjobs job hj
    have hfa := ha job.first (by simp [hfirst])
    have hsa := ha job.second (by simp [hsecond])
    have hfb := hb' job.first hfirst
    have h1 := hb job.first (by simp [hfirst])
    have h2 := hb job.second (by simp [hsecond])
    have h3 := hb a (by simp)
    have h4 := hb b (by simp)
    change out.val ≠ job.output.val ∧ out.val ≠ pointIndex job.first ∧
      out.val ≠ pointIndex job.second ∧ job.output.val ≠ pointIndex a ∧ job.output.val ≠ pointIndex b
    have hleft1 : out.val ≠ pointIndex job.first := by
      rcases hkind with ⟨he, hn⟩ | he
      · rw [he]; exact hfa.left_ne hn
      · omega
    have hleft2 : out.val ≠ pointIndex job.second := by
      rcases hkind with ⟨he, hn⟩ | he
      · rw [he]; exact hsa.left_ne hn
      · omega
    rcases hjkind with ⟨he, hn⟩ | he
    · rw [he]
      exact ⟨hleft1, hleft1, hleft2, hfa.right_ne hn, hfb.right_ne hn⟩
    · exact ⟨by omega, hleft1, hleft2, by omega, by omega⟩

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

theorem packed_replace (state result : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents)
    (hd : DisjointRegions n base capacity) (index : Usize) (hi : index.val < n)
    (values : List U32) (newLen : U32)
    (hsize : values.length ≤ capacity index.val) (hnew : newLen.val = values.length)
    (hrefs : result.refs.val = writeAt state.refs.val (base index.val) values)
    (hstarts : result.starts = state.starts) (hlens : result.lens = state.lens.set index newLen) :
    Packed result n base capacity (Function.update contents index.val values) := by
  have hlength : result.refs.val.length = state.refs.val.length := by rw [hrefs, writeAt_length]
  refine ⟨⟨?_, ?_⟩, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hlens]; simpa only [Vec.set, List.length_set] using h.counts.length
  · intro i hil
    rw [hlens]
    change (state.lens.val.set index.val newLen)[i]!.val = _
    by_cases he : i = index.val
    · subst i
      rw [List.getElem!_set _ _ _ (by rw [h.counts.length]; exact hi), Function.update_self]
      exact hnew
    · rw [List.getElem!_set_ne _ _ _ _ (by omega), Function.update_of_ne he]
      exact h.counts.values i hil
  · rw [hstarts]; exact h.starts_length
  · rw [hstarts]; exact h.starts_values
  · rw [hlength]; exact h.refs_bound
  · intro i hil; rw [hlength]; exact h.regions i hil
  · intro i hil
    by_cases he : i = index.val
    · subst i; rw [Function.update_self]; exact hsize
    · rw [Function.update_of_ne he]; exact h.capacity_bound i hil
  · intro i hil j hj
    by_cases he : i = index.val
    · subst i
      simp only [Function.update_self] at hj ⊢
      rw [hrefs]
      exact writeAt_inside state.refs.val values (base index.val) j
        (le_trans (Nat.add_le_add_left hsize _) (h.regions index.val hi)) hj
    · simp only [Function.update_of_ne he] at hj ⊢
      rw [hrefs, writeAt_outside]
      · exact h.entries i hil j hj
      · by_cases hlt : base i + j < base index.val
        · exact Or.inl hlt
        · right
          by_contra hb
          have hnot := hd index.val hi i hil (Ne.symm he) (base i + j - base index.val)
            (by omega) j (lt_of_lt_of_le hj (h.capacity_bound i hil))
          omega

theorem queue_pairs_packed (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents)
    (hd : DisjointRegions n base capacity) (index : Usize) (hi : index.val < n)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hlen : (contents index.val).length + 1 < 2 ^ 32)
    (ha : adds.a.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hb : adds.b.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (ho : adds.out.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hcap : s.len.val + (contents index.val).length / 2 ≤ s.rows.val.length / 2)
    (h32 : s.len.val + (contents index.val).length / 2 < 2 ^ 32) :
    ∃ result adds' s',
      state.queue_pairs index adds s originals = ok (result, adds', s') ∧
      Packed result n base capacity (Function.update contents index.val
        (reduce originals.val s.len.val (contents index.val)).1) ∧
      adds'.a.val = adds.a.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.first) ∧
      adds'.b.val = adds.b.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.second) ∧
      adds'.out.val = adds.out.val ++ ((reduce originals.val s.len.val (contents index.val)).2.1.map Job.output) ∧
      s'.len.val = (reduce originals.val s.len.val (contents index.val)).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧ s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  have hil : index.val < state.lens.val.length := by rw [h.counts.length]; exact hi
  have his : index.val < state.starts.val.length := by rw [h.starts_length]; exact hi
  have hlenv : state.lens.val[index.val].val = (contents index.val).length := by
    simpa only [getElem!_pos state.lens.val index.val hil] using h.counts.values index.val hi
  have hstartv : state.starts.val[index.val].val = base index.val := by
    simpa only [getElem!_pos state.starts.val index.val his] using h.starts_values index.val hi
  obtain ⟨result, adds', s', newLen, hcall, hq, hw, hn, hs, hl, hnew, hr, hdx, hp⟩ :=
    queue_pairs_refines state index adds s originals his hil (by rwa [hlenv])
      (by rw [hlenv, hstartv]; exact le_trans (Nat.add_le_add_left (h.capacity_bound index.val hi) _) (h.regions index.val hi))
      h.refs_bound (by rwa [hlenv]) (by rwa [hlenv]) (by rwa [hlenv]) (by rwa [hlenv]) (by rwa [hlenv])
  rw [hlenv, hstartv] at hq
  have hplan := queueBucket_plan originals.val (base index.val) (stateOf state.refs adds s)
    (contents index.val) (h.entries index.val hi)
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def activeCount (lengths : List U32) : ℕ := (lengths.map UScalar.val).sum

theorem activeCount_ceil (lengths : List U32) :
    activeCount (lengths.map ceilWord) + pairBudget lengths = activeCount lengths := by
  induction lengths with
  | nil => simp [activeCount, pairBudget]
  | cons v rest ih =>
    simp only [List.map_cons, activeCount, pairBudget, List.sum_cons, ceilWord_val] at *
    omega

theorem queueRound_counts (originals : ℕ) (starts lengths : List U32) (index : ℕ) (q : QueueState) :
    (queueRound originals starts index lengths q).refs.length = q.refs.length ∧
    (queueRound originals starts index lengths q).firsts.length = q.firsts.length + pairBudget lengths ∧
    (queueRound originals starts index lengths q).seconds.length = q.seconds.length + pairBudget lengths ∧
    (queueRound originals starts index lengths q).outputs.length = q.outputs.length + pairBudget lengths ∧
    q.next ≤ (queueRound originals starts index lengths q).next ∧
    (queueRound originals starts index lengths q).next ≤ q.next + pairBudget lengths := by
  induction lengths generalizing index q with
  | nil => simp [queueRound, pairBudget]
  | cons len rest ih =>
    have ht := ih (index + 1) (queueBucket originals starts[index]!.val len.val q)
    have hb := queueBucket_lengths originals starts[index]!.val len.val q
    simp only [queueRound, pairBudget, List.map_cons, List.sum_cons]
    dsimp only [pairBudget] at ht
    exact ⟨by omega, by omega, by omega, by omega, by omega, by omega⟩

theorem queueRound_measure (originals : ℕ) (starts lengths : List U32) (q : QueueState) :
    activeCount (lengths.map ceilWord) +
      (queueRound originals starts 0 lengths (cleared q)).firsts.length = activeCount lengths := by
  have hc := (queueRound_counts originals starts lengths 0 (cleared q)).2.1
  change _ = 0 + pairBudget lengths at hc
  rw [hc, Nat.zero_add]
  exact activeCount_ceil lengths

theorem queueRound_strict_measure (originals : ℕ) (starts lengths : List U32) (q : QueueState)
    (hpending : 0 < q.firsts.length) :
    activeCount (lengths.map ceilWord) +
      (queueRound originals starts 0 lengths (cleared q)).firsts.length <
        activeCount lengths + q.firsts.length := by
  rw [queueRound_measure]
  omega

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def chunksBudget (chunks : List (List U32)) : ℕ := (chunks.map (fun xs => xs.length / 2)).sum

def reduceChunks (originals next : ℕ) : List (List U32) → List (List U32) × List Job × ℕ
  | [] => ([], [], next)
  | xs :: rest =>
    let (ys, jobs, next') := reduce originals next xs
    let (outputs, more, finish) := reduceChunks originals next' rest
    (ys :: outputs, jobs ++ more, finish)

theorem reduceChunks_budget (originals next : ℕ) (chunks : List (List U32)) :
    next ≤ (reduceChunks originals next chunks).2.2 ∧
    (reduceChunks originals next chunks).2.2 ≤ next + chunksBudget chunks := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks, chunksBudget]
  | cons xs rest ih =>
    have hb := reduce_budget originals next xs
    have ht := ih (reduce originals next xs).2.2
    change next ≤ (reduceChunks originals (reduce originals next xs).2.2 rest).2.2 ∧
      (reduceChunks originals (reduce originals next xs).2.2 rest).2.2 ≤ next + chunksBudget (xs :: rest)
    simp only [chunksBudget, List.map_cons, List.sum_cons]
    dsimp only [chunksBudget] at ht
    exact ⟨by omega, by omega⟩

theorem reduceChunks_job_info (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31) :
    ∀ job ∈ (reduceChunks originals next chunks).2.1,
      job.first ∈ chunks.flatten ∧ job.second ∈ chunks.flatten ∧ originals ≤ job.output.val ∧
      job.output.val < (reduceChunks originals next chunks).2.2 ∧
      (job.output.val = pointIndex job.first ∧ originals ≤ pointIndex job.first ∨ next ≤ job.output.val) := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbhead := reduce_job_info originals next xs ho
      (by intro r hr; apply hb r; simp [hr]) (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega)
    have hbud := reduce_budget originals next xs
    have ht := ih (reduce originals next xs).2.2 (by omega)
      (by intro r hr; have := hb r (by simp [hr]); omega)
      (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega)
    have hfinish := (reduceChunks_budget originals (reduce originals next xs).2.2 rest).1
    intro job hj
    change job ∈ (reduce originals next xs).2.1 ++ (reduceChunks originals (reduce originals next xs).2.2 rest).2.1 at hj
    rw [List.mem_append] at hj
    rcases hj with hj | hj
    · obtain ⟨ha, hb, hlo, hhi, hk⟩ := hbhead job hj
      refine ⟨by simp [ha], by simp [hb], hlo, ?_, hk⟩
      change job.output.val < (reduceChunks originals (reduce originals next xs).2.2 rest).2.2
      omega
    · obtain ⟨ha, hb, hlo, hhi, hk⟩ := ht job hj
      refine ⟨by simp [ha], by simp [hb], hlo, hhi, ?_⟩
      exact hk.elim Or.inl (fun h => Or.inr (by omega))

theorem reduceChunks_independent (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31)
    (hi : chunks.flatten.Pairwise (RefIndependent originals)) :
    ((reduceChunks originals next chunks).2.1).Pairwise JobIndependent := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbud := reduce_budget originals next xs
    have hbound : ∀ r ∈ xs, pointIndex r < next := by intro r hr; apply hb r; simp [hr]
    have hbound' : ∀ r ∈ rest.flatten, pointIndex r < (reduce originals next xs).2.2 := by
      intro r hr; have := hb r (by simp [hr]); omega
    have hreserve : next + xs.length / 2 < 2 ^ 31 := by
      simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega
    have hreserve' : (reduce originals next xs).2.2 + chunksBudget rest < 2 ^ 31 := by
      simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega
    simp only [List.flatten_cons, List.pairwise_append] at hi
    obtain ⟨hleft, hright, hcross⟩ := hi
    have hhead := reduce_independent originals next xs ho hbound hreserve hleft
    have htail := ih (reduce originals next xs).2.2 (by omega) hbound' hreserve' hright
    have hheadInfo := reduce_job_info originals next xs ho hbound hreserve
    have htailInfo := reduceChunks_job_info originals (reduce originals next xs).2.2 rest
      (by omega) hbound' hreserve'
    change ((reduce originals next xs).2.1 ++ (reduceChunks originals (reduce originals next xs).2.2 rest).2.1).Pairwise _
    apply List.pairwise_append.mpr
    refine ⟨hhead, htail, ?_⟩
    intro p hp q hq
    obtain ⟨hpa, hpb, _, hpbound, hpkind⟩ := hheadInfo p hp
    obtain ⟨hqa, hqb, _, _, hqkind⟩ := htailInfo q hq
    have h1 := hcross p.first hpa q.first hqa
    have h2 := hcross p.first hpa q.second hqb
    have h3 := hcross p.second hpb q.first hqa
    have hpaBound := hbound p.first hpa
    have hpbBound := hbound p.second hpb
    have hqaBound := hb q.first (by simp [hqa])
    have hqbBound := hb q.second (by simp [hqb])
    have hleft1 : p.output.val ≠ pointIndex q.first := by
      rcases hpkind with ⟨he, hn⟩ | he
      · rw [he]; exact h1.left_ne hn
      · omega
    have hleft2 : p.output.val ≠ pointIndex q.second := by
      rcases hpkind with ⟨he, hn⟩ | he
      · rw [he]; exact h2.left_ne hn
      · omega
    unfold JobIndependent
    rcases hqkind with ⟨he, hn⟩ | he
    · rw [he]
      exact ⟨hleft1, hleft1, hleft2, h1.right_ne hn, h3.right_ne hn⟩
    · exact ⟨by omega, hleft1, hleft2, by omega, by omega⟩

theorem reduceChunks_sums {G : Type} [AddMonoid G]
    (before after : U32 → G) (originals next : ℕ) (chunks : List (List U32))
    (hpairs : PairValues before after (reduceChunks originals next chunks).2.1)
    (hodd : ∀ xs ∈ chunks, ∀ r ∈ unpaired xs, after r = before r) :
    ((reduceChunks originals next chunks).1.map (fun xs => (xs.map after).sum)) =
      chunks.map (fun xs => (xs.map before).sum) := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hhead : PairValues before after (reduce originals next xs).2.1 := by
      intro job hj; apply hpairs job
      change job ∈ (reduce originals next xs).2.1 ++ _
      exact List.mem_append_left _ hj
    have htail : PairValues before after (reduceChunks originals (reduce originals next xs).2.2 rest).2.1 := by
      intro job hj; apply hpairs job
      change job ∈ _ ++ (reduceChunks originals (reduce originals next xs).2.2 rest).2.1
      exact List.mem_append_right _ hj
    have ht := ih (reduce originals next xs).2.2 htail (by intro ys hy r hr; apply hodd ys (by simp [hy]) r hr)
    have hh := reduce_sum before after originals next xs hhead (hodd xs (by simp))
    change (List.map after (reduce originals next xs).1).sum :: _ = _ :: _
    rw [hh, ht]

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

def replaceContents (contents : BucketLists) (index : ℕ) : List (List U32) → BucketLists
  | [] => contents
  | xs :: rest => replaceContents (Function.update contents index xs) (index + 1) rest

theorem queue_round_loop_packed (chunks : List (List U32))
    (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ) (contents : BucketLists)
    (h : Packed state n base capacity contents) (hd : DisjointRegions n base capacity)
    (index : Usize) (hn : index.val + chunks.length = n)
    (hchunks : ∀ j < chunks.length, contents (index.val + j) = chunks[j]!)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hsize : ∀ xs ∈ chunks, xs.length + 1 < 2 ^ 32)
    (ha : adds.a.val.length + chunksBudget chunks ≤ Usize.max)
    (hb : adds.b.val.length + chunksBudget chunks ≤ Usize.max)
    (ho : adds.out.val.length + chunksBudget chunks ≤ Usize.max)
    (hcap : s.len.val + chunksBudget chunks ≤ s.rows.val.length / 2)
    (h32 : s.len.val + chunksBudget chunks < 2 ^ 32) :
    ∃ result adds' s', state.queue_round_loop adds s originals index = ok (roundFields result adds' s') ∧
      Packed result n base capacity
        (replaceContents contents index.val (reduceChunks originals.val s.len.val chunks).1) ∧
      adds'.a.val = adds.a.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.first) ∧
      adds'.b.val = adds.b.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.second) ∧
      adds'.out.val = adds.out.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val chunks).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  induction chunks generalizing state contents index adds s with
  | nil =>
    refine ⟨state, adds, s, ?_, h, by simp [reduceChunks], by simp [reduceChunks],
      by simp [reduceChunks], rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
    have hdone : ¬ index < Vec.len state.lens := by
      change ¬index.val < state.lens.val.length
      rw [h.counts.length]
      simp only [List.length_nil, Nat.add_zero] at hn
      omega
    rw [buckets.Buckets.queue_round_loop, loop.eq_1]
    simp only [buckets.Buckets.queue_round_loop.body, hdone, if_false, roundFields]
  | cons xs rest ih =>
    have hi : index.val < n := by simp only [List.length_cons] at hn; omega
    have hcur : contents index.val = xs := by simpa using hchunks 0 (by simp)
    have hbudget : chunksBudget (xs :: rest) = xs.length / 2 + chunksBudget rest := by simp [chunksBudget]
    obtain ⟨state', adds', s', hcall, hpacked, hfirsts, hseconds, houtputs, hlen, hw, hwins, hstarts, hrows, hdx, hp⟩ :=
      queue_pairs_packed state n base capacity contents h hd index hi adds s originals
        (by rw [hcur]; exact hsize xs (by simp))
        (by rw [hcur]; omega) (by rw [hcur]; omega) (by rw [hcur]; omega)
        (by rw [hcur]; omega) (by rw [hcur]; omega)
    simp only [hcur] at hpacked hfirsts hseconds houtputs hlen
    let updated := Function.update contents index.val (reduce originals.val s.len.val xs).1
    have hnextBound : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hb := vec_length_bound state.lens
      rw [h.counts.length] at hb
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
    obtain ⟨result, adds'', s'', hloop, hpacked', hfirsts', hseconds', houtputs', hlen', hw', hwins', hstarts', hrows', hdx', hp'⟩ :=
      ih state' updated hpacked next (by simp only [List.length_cons] at hn; omega) hchunks'
        adds' s' (by intro ys hy; exact hsize ys (by simp [hy]))
        (by omega) (by omega) (by omega) (by rw [hrows]; omega) (by omega)
    refine ⟨result, adds'', s'', ?_, ?_, ?_, ?_, ?_, ?_, hw'.trans hw, hwins'.trans hwins,
      hstarts'.trans hstarts, hrows'.trans hrows, hdx'.trans hdx, hp'.trans hp⟩
    · have hactive : index < Vec.len state.lens := by
        change index.val < state.lens.val.length
        rw [h.counts.length]; exact hi
      rw [buckets.Buckets.queue_round_loop, loop.eq_1]
      simp only [buckets.Buckets.queue_round_loop.body, hactive, if_true, hcall, bind_tc_ok]
      rw [add_ok index (1#usize) hnextBound]
      exact hloop
    · simpa only [reduceChunks, replaceContents, updated, hnval, hlen] using hpacked'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hfirsts] using hfirsts'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hseconds] using hseconds'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, houtputs] using houtputs'
    · simpa only [reduceChunks, hlen] using hlen'

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

def bucketChunks (n : ℕ) (contents : BucketLists) : List (List U32) :=
  (List.range n).map contents

theorem bucketChunks_length (n : ℕ) (contents : BucketLists) :
    (bucketChunks n contents).length = n := by simp [bucketChunks]

theorem bucketChunks_at (n : ℕ) (contents : BucketLists) (i : ℕ) (hi : i < n) :
    (bucketChunks n contents)[i]! = contents i := by
  simp only [bucketChunks]
  rw [List.getElem!_map_eq _ _ _ (by simpa using hi)]
  simp [hi]

theorem reduceChunks_lengths (originals next : ℕ) (chunks : List (List U32)) :
    (reduceChunks originals next chunks).1.length = chunks.length ∧
    (reduceChunks originals next chunks).2.1.length = chunksBudget chunks := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks, chunksBudget]
  | cons xs rest ih =>
    rcases hr : reduce originals next xs with ⟨ys, jobs, finish⟩
    have ht := ih finish
    have hh := (reduce_counts originals next xs).2
    rw [hr] at hh
    dsimp only at hh
    simp only [reduceChunks, hr, List.length_cons, List.length_append]
    constructor
    · exact congrArg (fun k => k + 1) ht.1
    · rw [hh, ht.2]
      rfl

theorem replaceContents_outside (contents : BucketLists) (start : ℕ) (chunks : List (List U32))
    (index : ℕ) (hi : index < start ∨ start + chunks.length ≤ index) :
    replaceContents contents start chunks index = contents index := by
  induction chunks generalizing contents start with
  | nil => rfl
  | cons xs rest ih =>
    rw [replaceContents, ih (Function.update contents start xs) (start + 1) (by simp only [List.length_cons] at hi; omega)]
    rw [Function.update_of_ne (by simp only [List.length_cons] at hi; omega)]

theorem replaceContents_inside (contents : BucketLists) (start : ℕ) (chunks : List (List U32))
    (index : ℕ) (hi : index < chunks.length) :
    replaceContents contents start chunks (start + index) = chunks[index]! := by
  induction chunks generalizing contents start index with
  | nil => simp at hi
  | cons xs rest ih =>
    cases index with
    | zero =>
      simp only [Nat.add_zero, List.getElem!_cons_zero, replaceContents]
      rw [replaceContents_outside _ (start + 1) rest start (Or.inl (by omega)), Function.update_self]
    | succ index =>
      have hh := ih (Function.update contents start xs) (start + 1) index (by simp at hi; omega)
      simpa only [replaceContents, List.getElem!_cons_succ, Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using hh

theorem queue_round_packed (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents) (hd : DisjointRegions n base capacity)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hsize : ∀ i < n, (contents i).length + 1 < 2 ^ 32)
    (hbudget : chunksBudget (bucketChunks n contents) ≤ Usize.max)
    (hcap : s.len.val + chunksBudget (bucketChunks n contents) ≤ s.rows.val.length / 2)
    (h32 : s.len.val + chunksBudget (bucketChunks n contents) < 2 ^ 32) :
    ∃ result adds' s', state.queue_round adds s originals = ok (result, adds', s') ∧
      Packed result n base capacity (replaceContents contents 0
        (reduceChunks originals.val s.len.val (bucketChunks n contents)).1) ∧
      adds'.a.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.first) ∧
      adds'.b.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.second) ∧
      adds'.out.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let fresh : pairs.BatchedAdds := { adds with a := Vec.new U32, b := Vec.new U32, out := Vec.new U32 }
  have hchunkSize : ∀ xs ∈ bucketChunks n contents, xs.length + 1 < 2 ^ 32 := by
    intro xs hx
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hx
    exact hsize i (by simpa using hi)
  obtain ⟨result, adds', s', hloop, hp, ha, hb, ho, hlen, hw, hn, hs, hr, hdx, hprefix⟩ :=
    queue_round_loop_packed (bucketChunks n contents) state n base capacity contents h hd 0#usize
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

theorem packed_round_sums {G : Type} [AddMonoid G]
    (before after : U32 → G) (originals next n : ℕ) (contents : BucketLists)
    (result : buckets.Buckets) (base capacity : ℕ → ℕ)
    (hpacked : Packed result n base capacity (replaceContents contents 0
      (reduceChunks originals next (bucketChunks n contents)).1))
    (hpairs : PairValues before after (reduceChunks originals next (bucketChunks n contents)).2.1)
    (hodd : ∀ i < n, ∀ r ∈ unpaired (contents i), after r = before r) :
    ∀ i < n, ((bucketSlice result i).map after).sum = ((contents i).map before).sum := by
  letI : Inhabited G := ⟨0⟩
  have hlength : (reduceChunks originals next (bucketChunks n contents)).1.length = n :=
    (reduceChunks_lengths originals next (bucketChunks n contents)).1.trans (bucketChunks_length n contents)
  have hsum := reduceChunks_sums before after originals next (bucketChunks n contents) hpairs (by
    intro xs hx r hr
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hx
    exact hodd i (by simpa using hi) r hr)
  intro i hi
  rw [packed_recovers result n base capacity _ hpacked i hi]
  rw [show replaceContents contents 0 (reduceChunks originals next (bucketChunks n contents)).1 i =
      (reduceChunks originals next (bucketChunks n contents)).1[i]! from
    by simpa only [Nat.zero_add] using
      replaceContents_inside contents 0 (reduceChunks originals next (bucketChunks n contents)).1 i (by rw [hlength]; exact hi)]
  have hh := congrArg (fun sums : List G => sums[i]!) hsum
  dsimp only at hh
  rw [List.getElem!_map_eq (reduceChunks originals next (bucketChunks n contents)).1 i
    (fun xs => (xs.map after).sum) (by rw [hlength]; exact hi),
    List.getElem!_map_eq (bucketChunks n contents) i (fun xs => (xs.map before).sum)
      (by rw [bucketChunks_length]; exact hi), bucketChunks_at n contents i hi] at hh
  exact hh

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem reduce_outputs (originals next : ℕ) (refs : List U32) :
    (reduce originals next refs).1 =
      (reduce originals next refs).2.1.map Job.output ++ unpaired refs := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce, unpaired]
  | singleton a => simp [reduce, unpaired]
  | cons_cons a b rest ih =>
    rcases hs : slot originals next a with ⟨out, next'⟩
    simpa only [reduce, hs, List.map_cons, List.cons_append, unpaired] using
      congrArg (List.cons out) (ih next')

theorem unpaired_length (refs : List U32) : (unpaired refs).length ≤ 1 := by
  rw [unpaired_last]
  split <;> simp

theorem unpaired_mem (refs : List U32) (r : U32) (hr : r ∈ unpaired refs) : r ∈ refs := by
  induction refs using List.twoStepInduction with
  | nil => simp [unpaired] at hr
  | singleton a => simpa [unpaired] using hr
  | cons_cons a b rest ih =>
    exact List.mem_cons_of_mem a (List.mem_cons_of_mem b (ih hr))

theorem pointIndex_eq (reference : U32) (h : reference.val < 2 ^ 31) :
    pointIndex reference = reference.val := by
  unfold pointIndex
  rw [clearSign_value, Nat.mod_eq_of_lt h]

def ReuseReady (originals : ℕ) (refs : List U32) : Prop :=
  ∀ i, i + 1 < refs.length → originals ≤ pointIndex refs[i]!

theorem reduce_reuseReady (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31) :
    ReuseReady originals (reduce originals next refs).1 := by
  have hjobs := reduce_job_info originals next refs ho hb hn
  have hbudget := (reduce_budget originals next refs).2
  have htail := unpaired_length refs
  unfold ReuseReady
  rw [reduce_outputs]
  intro i hi
  have hlen : i < ((reduce originals next refs).2.1.map Job.output).length := by
    simp only [List.length_append] at hi
    omega
  rw [List.getElem!_append_left _ _ i hlen]
  have hm : ((reduce originals next refs).2.1.map Job.output)[i]! ∈
      (reduce originals next refs).2.1.map Job.output := by
    rw [getElem!_pos ((reduce originals next refs).2.1.map Job.output) i hlen]
    exact List.getElem_mem _
  obtain ⟨job, hj, he⟩ := List.mem_map.mp hm
  obtain ⟨_, _, hlo, hhi, _⟩ := hjobs job hj
  rw [← he, pointIndex_eq job.output (by omega)]
  exact hlo

theorem reduce_no_allocation (originals next : ℕ) (refs : List U32)
    (h : ReuseReady originals refs) : (reduce originals next refs).2.2 = next := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => rfl
  | singleton a => rfl
  | cons_cons a b rest ih =>
    have ha : originals ≤ pointIndex a := by simpa using h 0 (by simp)
    have hs : slot originals next a = (clearSign a, next) := by
      unfold slot
      rw [if_neg (by change ¬ pointIndex a < originals; omega)]
    have ht : ReuseReady originals rest := by
      intro i hi
      have hh := h (i + 2) (by simp only [List.length_cons]; omega)
      simpa [Nat.add_assoc, Nat.add_left_comm, Nat.add_comm] using hh
    simpa only [reduce, hs] using ih next ht

theorem reduce_ref_info (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31) :
    ∀ r ∈ (reduce originals next refs).1,
      pointIndex r < (reduce originals next refs).2.2 ∧
      ((∃ source ∈ refs, pointIndex r = pointIndex source) ∨ next ≤ pointIndex r) := by
  have hjobs := reduce_job_info originals next refs ho hb hn
  have hbudget := reduce_budget originals next refs
  intro r hr
  rw [reduce_outputs, List.mem_append] at hr
  rcases hr with hr | hr
  · obtain ⟨job, hj, rfl⟩ := List.mem_map.mp hr
    obtain ⟨ha, _, _, hhi, hk⟩ := hjobs job hj
    rw [pointIndex_eq job.output (by omega)]
    refine ⟨hhi, ?_⟩
    exact hk.elim (fun hh => Or.inl ⟨job.first, ha, hh.1⟩) Or.inr
  · have hm := unpaired_mem refs r hr
    have hh := hb r hm
    exact ⟨by omega, Or.inl ⟨r, hm, rfl⟩⟩

theorem reduceChunks_reuseReady (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31) :
    ∀ xs ∈ (reduceChunks originals next chunks).1, ReuseReady originals xs := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbud := reduce_budget originals next xs
    have ht := ih (reduce originals next xs).2.2 (by omega)
      (by intro r hr; have := hb r (by simp [hr]); omega)
      (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega)
    intro ys hy
    change ys ∈ (reduce originals next xs).1 :: (reduceChunks originals (reduce originals next xs).2.2 rest).1 at hy
    rcases List.mem_cons.mp hy with rfl | hy
    · exact reduce_reuseReady originals next xs ho (by intro r hr; apply hb r; simp [hr])
        (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega)
    · exact ht ys hy

theorem reduceChunks_no_allocation (originals next : ℕ) (chunks : List (List U32))
    (h : ∀ xs ∈ chunks, ReuseReady originals xs) :
    (reduceChunks originals next chunks).2.2 = next := by
  induction chunks generalizing next with
  | nil => rfl
  | cons xs rest ih =>
    have hh := reduce_no_allocation originals next xs (h xs (by simp))
    have ht := ih next (by intro ys hy; exact h ys (by simp [hy]))
    simpa only [reduceChunks, hh] using ht

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

theorem queue_step_refines_conditional
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hactive : cursor.val + 1 < len.val)
    (hspan : start.val + len.val ≤ refs.val.length)
    (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length < Usize.max) (hb : adds.b.val.length < Usize.max)
    (ho : adds.out.val.length < Usize.max)
    (halloc : pointIndex refs.val[start.val + cursor.val]! < originals.val →
      s.len.val < s.rows.val.length / 2 ∧ s.len.val < 2 ^ 32) :
    ∃ refs' adds' s' cursor',
      buckets.Buckets.queue_pairs_loop.body originals start len refs adds s cursor =
        ok (cont (refs', adds', s', cursor')) ∧
      stateOf refs' adds' s' = enqueue originals.val start.val cursor.val (stateOf refs adds s) ∧
      cursor'.val = cursor.val + 2 ∧ s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
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
  obtain ⟨s', hslot, hlen, hrows⟩ := sum_slot_refines first s originals (by
      intro ha
      apply halloc
      simpa only [pointIndex, first, ix, UScalar.ofNatCore_val_eq,
        getElem!_pos refs.val (start.val + cursor.val) (by omega)] using ha)
  obtain ⟨adds', hpush, hfa, hfb, hfo, hdx, hprefix⟩ := adds_push adds first second output ha hb ho
  refine ⟨refs.set dest output, adds', s', next, ?_, ?_, rfl, hrows, hdx, hprefix⟩
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem queue_loop_refines_capacity (n : ℕ)
    (originals start len cursor : Usize) (refs : Vec U32)
    (adds : pairs.BatchedAdds) (s : store.PointStore)
    (hlo : cursor.val + 2 * n ≤ len.val) (hhi : len.val ≤ cursor.val + 2 * n + 1)
    (hlen : len.val + 1 < 2 ^ 32)
    (hspan : start.val + len.val ≤ refs.val.length) (hrefs : refs.val.length < 2 ^ 32)
    (ha : adds.a.val.length + n ≤ Usize.max) (hb : adds.b.val.length + n ≤ Usize.max)
    (ho : adds.out.val.length + n ≤ Usize.max)
    (hcap : s.len.val < (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next →
      (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next ≤ s.rows.val.length / 2)
    (h32 : (queueSteps originals.val start.val n cursor.val (stateOf refs adds s)).next ≤ 2 ^ 32) :
    ∃ refs' adds' s',
      buckets.Buckets.queue_pairs_loop refs adds s originals start len cursor = ok (refs', adds', s') ∧
      stateOf refs' adds' s' = queueSteps originals.val start.val n cursor.val (stateOf refs adds s) ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
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
        s.len.val < s.rows.val.length / 2 ∧ s.len.val < 2 ^ 32 := by
      intro hfirst
      have hn : (enqueue originals.val start.val cursor.val (stateOf refs adds s)).next = s.len.val + 1 := by
        simp only [enqueue, stateOf, slot, show (clearSign refs.val[start.val + cursor.val]!).val < originals.val from hfirst,
          if_true]
      rw [hn] at hmon
      change s.len.val < (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next → _ at hcap
      have hh := hcap (by omega)
      change (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next ≤ s.rows.val.length / 2 at hh
      change (queueSteps originals.val start.val n (cursor.val + 2)
        (enqueue originals.val start.val cursor.val (stateOf refs adds s))).next ≤ 2 ^ 32 at h32
      exact ⟨by omega, by omega⟩
    obtain ⟨refs', adds', s', cursor', hstep, hstate, hcursor, hrows, hdx, hprefix⟩ :=
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
    obtain ⟨refs'', adds'', s'', hloop, hmodel, hrows', hdx', hprefix'⟩ :=
      ih cursor' refs' adds' s' (by omega) (by omega) (by omega) (by omega)
        (by omega) (by omega) (by omega)
        (by intro hh; rw [hsame, hrows]; apply hcap; rw [hsame] at hh; omega)
        (by rwa [hsame])
    refine ⟨refs'', adds'', s'', ?_, hmodel.trans hsame, hrows'.trans hrows, hdx'.trans hdx, hprefix'.trans hprefix⟩
    rw [buckets.Buckets.queue_pairs_loop, loop.eq_1]
    simpa only [hstep] using hloop

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def pairedInput : List U32 → List U32
  | [] => []
  | [_] => []
  | a :: b :: rest => a :: b :: pairedInput rest

theorem pairedInput_append (refs : List U32) : pairedInput refs ++ unpaired refs = refs := by
  induction refs using List.twoStepInduction with
  | nil => rfl
  | singleton a => rfl
  | cons_cons a b rest ih =>
    simpa only [pairedInput, unpaired, List.cons_append] using
      (congrArg (List.cons a ∘ List.cons b) ih)

theorem reduce_job_sources (originals next : ℕ) (refs : List U32) :
    ∀ job ∈ (reduce originals next refs).2.1, job.first ∈ pairedInput refs ∧ job.second ∈ pairedInput refs := by
  induction refs using List.twoStepInduction generalizing next with
  | nil => simp [reduce]
  | singleton a => simp [reduce]
  | cons_cons a b rest ih =>
    rcases hs : slot originals next a with ⟨out, next'⟩
    intro job hj
    simp only [reduce, hs, List.mem_cons] at hj
    rcases hj with rfl | hj
    · simp [pairedInput]
    · obtain ⟨ha, hb⟩ := ih next' job hj
      exact ⟨by simp [pairedInput, ha], by simp [pairedInput, hb]⟩

theorem reduce_refs_independent (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31)
    (hi : refs.Pairwise (RefIndependent originals)) :
    (reduce originals next refs).1.Pairwise (RefIndependent originals) := by
  have hjobs := reduce_independent originals next refs ho hb hn hi
  have hinfo := reduce_job_info originals next refs ho hb hn
  have hbudget := (reduce_budget originals next refs).2
  rw [← pairedInput_append refs, List.pairwise_append] at hi
  obtain ⟨_, hodd, hcross⟩ := hi
  rw [reduce_outputs, List.pairwise_append]
  refine ⟨?_, hodd, ?_⟩
  · apply List.pairwise_map.mpr
    apply List.Pairwise.imp_of_mem _ hjobs
    intro p q hp hq hpq
    have hpbound := (hinfo p hp).2.2.2.1
    have hqbound := (hinfo q hq).2.2.2.1
    unfold RefIndependent
    rw [pointIndex_eq p.output (by omega), pointIndex_eq q.output (by omega)]
    exact fun _ _ => hpq.1
  · intro output hout odd hodd
    obtain ⟨job, hj, rfl⟩ := List.mem_map.mp hout
    obtain ⟨_, _, _, hjbound, hkind⟩ := hinfo job hj
    have hsource := (reduce_job_sources originals next refs job hj).1
    have hsep := hcross job.first hsource odd hodd
    have hoddBound := hb odd (unpaired_mem refs odd hodd)
    unfold RefIndependent
    rw [pointIndex_eq job.output (by omega)]
    intro _ _
    rcases hkind with ⟨he, hnonorig⟩ | he
    · rw [he]; exact hsep.left_ne hnonorig
    · omega

theorem reduceChunks_ref_info (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31) :
    ∀ r ∈ (reduceChunks originals next chunks).1.flatten,
      pointIndex r < (reduceChunks originals next chunks).2.2 ∧
      ((∃ source ∈ chunks.flatten, pointIndex r = pointIndex source) ∨ next ≤ pointIndex r) := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbud := reduce_budget originals next xs
    have hh := reduce_ref_info originals next xs ho (by intro r hr; apply hb r; simp [hr])
      (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega)
    have ht := ih (reduce originals next xs).2.2 (by omega)
      (by intro r hr; have := hb r (by simp [hr]); omega)
      (by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega)
    have hfinish := (reduceChunks_budget originals (reduce originals next xs).2.2 rest).1
    intro r hr
    change r ∈ (reduce originals next xs).1 ++ (reduceChunks originals (reduce originals next xs).2.2 rest).1.flatten at hr
    rcases List.mem_append.mp hr with hr | hr
    · obtain ⟨hbound, hk⟩ := hh r hr
      refine ⟨?_, ?_⟩
      · change pointIndex r < (reduceChunks originals (reduce originals next xs).2.2 rest).2.2; omega
      · rcases hk with ⟨source, hs, he⟩ | he
        · exact Or.inl ⟨source, by simp [hs], he⟩
        · exact Or.inr he
    · obtain ⟨hbound, hk⟩ := ht r hr
      refine ⟨hbound, ?_⟩
      rcases hk with ⟨source, hs, he⟩ | he
      · exact Or.inl ⟨source, by simp [hs], he⟩
      · exact Or.inr (by omega)

theorem reduceChunks_refs_independent (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31)
    (hi : chunks.flatten.Pairwise (RefIndependent originals)) :
    (reduceChunks originals next chunks).1.flatten.Pairwise (RefIndependent originals) := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbud := reduce_budget originals next xs
    have hbound : ∀ r ∈ xs, pointIndex r < next := by intro r hr; apply hb r; simp [hr]
    have hbound' : ∀ r ∈ rest.flatten, pointIndex r < (reduce originals next xs).2.2 := by
      intro r hr; have := hb r (by simp [hr]); omega
    have hreserve : next + xs.length / 2 < 2 ^ 31 := by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega
    have hreserve' : (reduce originals next xs).2.2 + chunksBudget rest < 2 ^ 31 := by
      simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega
    simp only [List.flatten_cons, List.pairwise_append] at hi
    obtain ⟨hleft, hright, hcross⟩ := hi
    have hhead := reduce_refs_independent originals next xs ho hbound hreserve hleft
    have htail := ih (reduce originals next xs).2.2 (by omega) hbound' hreserve' hright
    have hheadInfo := reduce_ref_info originals next xs ho hbound hreserve
    have htailInfo := reduceChunks_ref_info originals (reduce originals next xs).2.2 rest
      (by omega) hbound' hreserve'
    change ((reduce originals next xs).1 ++ (reduceChunks originals (reduce originals next xs).2.2 rest).1.flatten).Pairwise _
    apply List.pairwise_append.mpr
    refine ⟨hhead, htail, ?_⟩
    intro p hp q hq
    obtain ⟨hpbound, hpkind⟩ := hheadInfo p hp
    obtain ⟨_, hqkind⟩ := htailInfo q hq
    intro hpn hqn
    rcases hqkind with ⟨sourceQ, hqmem, heq⟩ | hqfresh
    · have hqold := hb sourceQ (by simp [hqmem])
      rcases hpkind with ⟨sourceP, hpmem, hep⟩ | hpfresh
      · rw [hep, heq]
        exact hcross sourceP hpmem sourceQ hqmem (by omega) (by omega)
      · omega
    · omega

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

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
        state.lens.val[list.val].val (stateOf state.refs adds s)).next ≤ s.rows.val.length / 2)
    (h32 : (queueBucket originals.val state.starts.val[list.val].val
      state.lens.val[list.val].val (stateOf state.refs adds s)).next ≤ 2 ^ 32) :
    ∃ result adds' s' newLen,
      state.queue_pairs list adds s originals = ok (result, adds', s') ∧
      stateOf result.refs adds' s' = queueBucket originals.val state.starts.val[list.val].val
        state.lens.val[list.val].val (stateOf state.refs adds s) ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧
      result.starts = state.starts ∧ result.lens = state.lens.set list newLen ∧
      newLen.val = state.lens.val[list.val].val / 2 + state.lens.val[list.val].val % 2 ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  let start : Usize := UScalar.cast .Usize state.starts.val[list.val]
  let len : Usize := UScalar.cast .Usize state.lens.val[list.val]
  have hs : start.val = state.starts.val[list.val].val := cast_Usize_val _
  have hl : len.val = state.lens.val[list.val].val := cast_Usize_val _
  obtain ⟨refs', adds', s', hloop, hmodel, hrows, hdx, hprefix⟩ :=
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
    ?_, ?_, rfl, rfl, rfl, rfl, by simpa only [hl] using hnew, hrows, hdx, hprefix⟩
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

theorem queue_pairs_packed_capacity (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents)
    (hd : DisjointRegions n base capacity) (index : Usize) (hi : index.val < n)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hlen : (contents index.val).length + 1 < 2 ^ 32)
    (ha : adds.a.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hb : adds.b.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (ho : adds.out.val.length + (contents index.val).length / 2 ≤ Usize.max)
    (hcap : s.len.val < (reduce originals.val s.len.val (contents index.val)).2.2 →
      (reduce originals.val s.len.val (contents index.val)).2.2 ≤ s.rows.val.length / 2)
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
      result.starts = state.starts ∧ s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  have hil : index.val < state.lens.val.length := by rw [h.counts.length]; exact hi
  have his : index.val < state.starts.val.length := by rw [h.starts_length]; exact hi
  have hlenv : state.lens.val[index.val].val = (contents index.val).length := by
    simpa only [getElem!_pos state.lens.val index.val hil] using h.counts.values index.val hi
  have hstartv : state.starts.val[index.val].val = base index.val := by
    simpa only [getElem!_pos state.starts.val index.val his] using h.starts_values index.val hi
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

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

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
      (reduceChunks originals.val s.len.val chunks).2.2 ≤ s.rows.val.length / 2)
    (h32 : (reduceChunks originals.val s.len.val chunks).2.2 ≤ 2 ^ 32) :
    ∃ result adds' s', state.queue_round_loop adds s originals index = ok (roundFields result adds' s') ∧
      Packed result n base capacity
        (replaceContents contents index.val (reduceChunks originals.val s.len.val chunks).1) ∧
      adds'.a.val = adds.a.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.first) ∧
      adds'.b.val = adds.b.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.second) ∧
      adds'.out.val = adds.out.val ++ ((reduceChunks originals.val s.len.val chunks).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val chunks).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
  induction chunks generalizing state contents index adds s with
  | nil =>
    refine ⟨state, adds, s, ?_, h, by simp [reduceChunks], by simp [reduceChunks],
      by simp [reduceChunks], rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩
    have hdone : ¬ index < Vec.len state.lens := by
      change ¬index.val < state.lens.val.length
      rw [h.counts.length]
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
      (reduceChunks originals.val (reduce originals.val s.len.val xs).2.2 rest).2.2 ≤ s.rows.val.length / 2 at hcap
    change (reduceChunks originals.val (reduce originals.val s.len.val xs).2.2 rest).2.2 ≤ 2 ^ 32 at h32
    have hbudget : chunksBudget (xs :: rest) = xs.length / 2 + chunksBudget rest := by simp [chunksBudget]
    obtain ⟨state', adds', s', hcall, hpacked, hfirsts, hseconds, houtputs, hlen, hw, hwins, hstarts, hrows, hdx, hp⟩ :=
      queue_pairs_packed_capacity state n base capacity contents h hd index hi adds s originals
        (by rw [hcur]; exact hsize xs (by simp))
        (by rw [hcur]; omega) (by rw [hcur]; omega) (by rw [hcur]; omega)
        (by rw [hcur]; intro hh; have := hcap (by omega); omega)
        (by rw [hcur]; omega)
    simp only [hcur] at hpacked hfirsts hseconds houtputs hlen
    let updated := Function.update contents index.val (reduce originals.val s.len.val xs).1
    have hnextBound : index.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hb := vec_length_bound state.lens
      rw [h.counts.length] at hb
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
    obtain ⟨result, adds'', s'', hloop, hpacked', hfirsts', hseconds', houtputs', hlen', hw', hwins', hstarts', hrows', hdx', hp'⟩ :=
      ih state' updated hpacked next (by simp only [List.length_cons] at hn; omega) hchunks'
        adds' s' (by intro ys hy; exact hsize ys (by simp [hy]))
        (by omega) (by omega) (by omega)
        (by intro hh; rw [hlen] at hh ⊢; rw [hrows]; exact hcap (by omega))
        (by simpa only [hlen] using h32)
    refine ⟨result, adds'', s'', ?_, ?_, ?_, ?_, ?_, ?_, hw'.trans hw, hwins'.trans hwins,
      hstarts'.trans hstarts, hrows'.trans hrows, hdx'.trans hdx, hp'.trans hp⟩
    · have hactive : index < Vec.len state.lens := by
        change index.val < state.lens.val.length
        rw [h.counts.length]; exact hi
      rw [buckets.Buckets.queue_round_loop, loop.eq_1]
      simp only [buckets.Buckets.queue_round_loop.body, hactive, if_true, hcall, bind_tc_ok]
      rw [add_ok index (1#usize) hnextBound]
      exact hloop
    · simpa only [reduceChunks, replaceContents, updated, hnval, hlen] using hpacked'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hfirsts] using hfirsts'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, hseconds] using hseconds'
    · simpa only [reduceChunks, List.map_append, List.append_assoc, hlen, houtputs] using houtputs'
    · simpa only [reduceChunks, hlen] using hlen'

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec BucketsRefines

theorem queue_round_packed_capacity (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed state n base capacity contents) (hd : DisjointRegions n base capacity)
    (adds : pairs.BatchedAdds) (s : store.PointStore) (originals : Usize)
    (hsize : ∀ i < n, (contents i).length + 1 < 2 ^ 32)
    (hbudget : chunksBudget (bucketChunks n contents) ≤ Usize.max)
    (hcap : s.len.val < (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 →
      (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ≤ s.rows.val.length / 2)
    (h32 : (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ≤ 2 ^ 32) :
    ∃ result adds' s', state.queue_round adds s originals = ok (result, adds', s') ∧
      Packed result n base capacity (replaceContents contents 0
        (reduceChunks originals.val s.len.val (bucketChunks n contents)).1) ∧
      adds'.a.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.first) ∧
      adds'.b.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.second) ∧
      adds'.out.val = ((reduceChunks originals.val s.len.val (bucketChunks n contents)).2.1.map Job.output) ∧
      s'.len.val = (reduceChunks originals.val s.len.val (bucketChunks n contents)).2.2 ∧
      result.window_bits = state.window_bits ∧ result.windows = state.windows ∧ result.starts = state.starts ∧
      s'.rows = s.rows ∧ adds'.dx = adds.dx ∧ adds'.prefix = adds.prefix := by
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


end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def oddRefs (chunks : List (List U32)) : List U32 := (chunks.map unpaired).flatten

theorem oddRefs_mem (chunks : List (List U32)) (r : U32) (hr : r ∈ oddRefs chunks) : r ∈ chunks.flatten := by
  obtain ⟨xs, hx, hr⟩ := List.mem_flatten.mp hr
  obtain ⟨ys, hy, rfl⟩ := List.mem_map.mp hx
  exact List.mem_flatten.mpr ⟨ys, hy, unpaired_mem ys r hr⟩

theorem reduce_odd_frame (originals next : ℕ) (refs : List U32)
    (ho : originals ≤ next) (hb : ∀ r ∈ refs, pointIndex r < next)
    (hn : next + refs.length / 2 < 2 ^ 31) (hi : refs.Pairwise (RefIndependent originals)) :
    ∀ job ∈ (reduce originals next refs).2.1, ∀ r ∈ unpaired refs,
      job.output.val ≠ pointIndex r := by
  rw [← pairedInput_append refs, List.pairwise_append] at hi
  intro job hj r hr
  have hsource := (reduce_job_sources originals next refs job hj).1
  have hsep := hi.2.2 job.first hsource r hr
  have hbound := hb r (unpaired_mem refs r hr)
  have hk := (reduce_job_info originals next refs ho hb hn job hj).2.2.2.2
  rcases hk with ⟨he, hnonorig⟩ | he
  · rw [he]; exact hsep.left_ne hnonorig
  · omega

theorem reduceChunks_odd_frame (originals next : ℕ) (chunks : List (List U32))
    (ho : originals ≤ next) (hb : ∀ r ∈ chunks.flatten, pointIndex r < next)
    (hn : next + chunksBudget chunks < 2 ^ 31)
    (hi : chunks.flatten.Pairwise (RefIndependent originals)) :
    ∀ job ∈ (reduceChunks originals next chunks).2.1, ∀ r ∈ oddRefs chunks,
      job.output.val ≠ pointIndex r := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks]
  | cons xs rest ih =>
    have hbud := reduce_budget originals next xs
    have hbound : ∀ r ∈ xs, pointIndex r < next := by intro r hr; apply hb r; simp [hr]
    have hbound' : ∀ r ∈ rest.flatten, pointIndex r < (reduce originals next xs).2.2 := by
      intro r hr; have := hb r (by simp [hr]); omega
    have hreserve : next + xs.length / 2 < 2 ^ 31 := by simp only [chunksBudget, List.map_cons, List.sum_cons] at hn; omega
    have hreserve' : (reduce originals next xs).2.2 + chunksBudget rest < 2 ^ 31 := by
      simp only [chunksBudget, List.map_cons, List.sum_cons] at hn ⊢; omega
    simp only [List.flatten_cons, List.pairwise_append] at hi
    obtain ⟨hleft, hright, hcross⟩ := hi
    have hhead := reduce_odd_frame originals next xs ho hbound hreserve hleft
    have htail := ih (reduce originals next xs).2.2 (by omega) hbound' hreserve' hright
    have hheadInfo := reduce_job_info originals next xs ho hbound hreserve
    have htailInfo := reduceChunks_job_info originals (reduce originals next xs).2.2 rest
      (by omega) hbound' hreserve'
    intro job hj r hr
    change job ∈ (reduce originals next xs).2.1 ++ (reduceChunks originals (reduce originals next xs).2.2 rest).2.1 at hj
    change r ∈ unpaired xs ++ oddRefs rest at hr
    rcases List.mem_append.mp hj with hj | hj <;> rcases List.mem_append.mp hr with hr | hr
    · exact hhead job hj r hr
    · obtain ⟨hsource, _, _, _, hkind⟩ := hheadInfo job hj
      have hrmem := oddRefs_mem rest r hr
      have hsep := hcross job.first hsource r hrmem
      have hrbound := hb r (by simp [hrmem])
      rcases hkind with ⟨he, hnonorig⟩ | he
      · rw [he]; exact hsep.left_ne hnonorig
      · omega
    · obtain ⟨hsource, _, _, _, hkind⟩ := htailInfo job hj
      have hrmem := unpaired_mem xs r hr
      have hsep := hcross r hrmem job.first hsource
      have hrbound := hbound r hrmem
      rcases hkind with ⟨he, hnonorig⟩ | he
      · rw [he]; exact hsep.right_ne hnonorig
      · omega
    · exact htail job hj r hr

end LeanBlsSimd.QueueRefines

namespace LeanBlsSimd.QueueRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def chunksActive (chunks : List (List U32)) : ℕ := (chunks.map List.length).sum

theorem chunksBudget_le_half (chunks : List (List U32)) :
    chunksBudget chunks ≤ chunksActive chunks / 2 := by
  induction chunks with
  | nil => simp [chunksBudget, chunksActive]
  | cons xs rest ih =>
    simp only [chunksBudget, chunksActive, List.map_cons, List.sum_cons] at *
    omega

theorem reduceChunks_active (originals next : ℕ) (chunks : List (List U32)) :
    chunksActive (reduceChunks originals next chunks).1 +
      (reduceChunks originals next chunks).2.1.length = chunksActive chunks := by
  induction chunks generalizing next with
  | nil => simp [reduceChunks, chunksActive]
  | cons xs rest ih =>
    rcases hr : reduce originals next xs with ⟨ys, jobs, finish⟩
    have ht := ih finish
    have hh := reduce_counts originals next xs
    rw [hr] at hh
    dsimp only at hh
    simp only [reduceChunks, hr, chunksActive, List.map_cons, List.sum_cons, List.length_append]
    change ys.length + chunksActive (reduceChunks originals finish rest).1 +
      (jobs.length + (reduceChunks originals finish rest).2.1.length) = xs.length + chunksActive rest
    omega

theorem reduceChunks_strict_measure (originals next pending : ℕ) (chunks : List (List U32))
    (hpending : 0 < pending) :
    chunksActive (reduceChunks originals next chunks).1 +
      (reduceChunks originals next chunks).2.1.length < chunksActive chunks + pending := by
  rw [reduceChunks_active]
  omega

theorem reduceChunks_allocation_bound (originals next : ℕ) (chunks : List (List U32)) :
    (reduceChunks originals next chunks).2.2 ≤ next + chunksActive chunks / 2 := by
  have h := (reduceChunks_budget originals next chunks).2
  have hb := chunksBudget_le_half chunks
  omega

end LeanBlsSimd.QueueRefines
