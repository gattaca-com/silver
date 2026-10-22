import LeanBlsSimd.Msm8.SignedDigits

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def listIndex (width window magnitude : ℕ) : ℕ :=
  window * 2 ^ (width - 1) + magnitude - 1

theorem vec_index {α : Type} (v : Vec α) (i : Usize) (hi : i.val < v.val.length) :
    Vec.index (core.slice.index.SliceIndexUsizeSlice α) v i = ok v.val[i.val] := by
  simp [Vec.index_slice_index, Vec.index_usize, List.getElem?_eq_getElem hi]

theorem vec_index_mut {α : Type} (v : Vec α) (i : Usize) (hi : i.val < v.val.length) :
    Vec.index_mut (core.slice.index.SliceIndexUsizeSlice α) v i =
      ok (v.val[i.val], v.set i) := by
  rw [Vec.index_mut_slice_index]
  simp [Vec.index_mut_usize, Vec.index_usize, List.getElem?_eq_getElem hi]

theorem list_refines (self : buckets.Buckets) (window magnitude : Usize)
    (hwl : 1 ≤ self.window_bits.val) (hwh : self.window_bits.val ≤ 8)
    (hm : 1 ≤ magnitude.val) (hmag : magnitude.val ≤ 2 ^ (self.window_bits.val - 1))
    (hbound : (window.val + 1) * 2 ^ (self.window_bits.val - 1) < 2 ^ 32) :
    ∃ i, self.list window magnitude = ok i ∧
      i.val = listIndex self.window_bits.val window.val magnitude.val := by
  have hb : window.val * 2 ^ (self.window_bits.val - 1) + magnitude.val < 2 ^ 32 := by
    rw [Nat.add_mul, Nat.one_mul] at hbound
    omega
  let sh : Usize := UScalar.ofNatCore (self.window_bits.val - 1) (by
    have := self.window_bits.hBounds
    exact lt_of_le_of_lt (Nat.sub_le _ _) this)
  let shifted : Usize := ⟨window.bv.shiftLeft sh.val⟩
  have hsv : shifted.val = window.val * 2 ^ (self.window_bits.val - 1) := by
    change (window.bv.shiftLeft sh.val).toNat = _
    rw [show (window.bv.shiftLeft sh.val).toNat = window.bv.toNat <<< sh.val %
      2 ^ UScalarTy.Usize.numBits from BitVec.toNat_shiftLeft]
    change (window.val <<< (self.window_bits.val - 1)) % 2 ^ UScalarTy.Usize.numBits = _
    rw [Nat.shiftLeft_eq, Nat.mod_eq_of_lt (lt_of_lt_of_le (by omega) two_pow_32_le_usize)]
  have hsum : shifted.val + magnitude.val < 2 ^ 32 := by rw [hsv]; exact hb
  have hsub : 1 ≤ shifted.val + magnitude.val := by omega
  refine ⟨UScalar.ofNatCore (shifted.val + magnitude.val - 1)
    (lt_of_le_of_lt (Nat.sub_le _ _) (lt_of_lt_of_le hsum two_pow_32_le_usize)), ?_, ?_⟩
  · simp only [buckets.Buckets.list]
    rw [sub_ok self.window_bits 1#usize hwl]
    simp only [bind_tc_ok]
    change (do
      let i1 ← window <<< sh
      let i2 ← i1 + magnitude
      i2 - 1#usize) = _
    rw [shiftLeft_ok window sh (by
      have hu : 32 ≤ UScalarTy.Usize.numBits := by
        rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
      change self.window_bits.val - 1 < _
      omega)]
    simp only [bind_tc_ok]
    change (do
      let i2 ← shifted + magnitude
      i2 - 1#usize) = _
    rw [usize_add_ok shifted magnitude hsum]
    simp only [bind_tc_ok]
    exact sub_ok (UScalar.ofNatCore (shifted.val + magnitude.val)
      (lt_of_lt_of_le hsum two_pow_32_le_usize) : Usize) 1#usize hsub
  · change shifted.val + magnitude.val - 1 = _
    rw [hsv]
    rfl

theorem count_zero (self : buckets.Buckets) (window : Usize) :
    self.count window 0#usize = ok self := by
  simp [buckets.Buckets.count]

theorem count_at (self : buckets.Buckets) (window magnitude i : Usize)
    (hm : magnitude ≠ 0#usize) (hi : self.list window magnitude = ok i)
    (hil : i.val < self.lens.val.length)
    (hc : self.lens.val[i.val].val + 1 < 2 ^ 32) :
    self.count window magnitude = ok {self with lens := self.lens.set i (UScalar.ofNatCore (self.lens.val[i.val].val + 1) hc)} := by
  simp only [buckets.Buckets.count]
  rw [if_pos (by simpa only [bne_iff_ne, ne_eq] using hm)]
  simp only [hi, bind_tc_ok]
  rw [vec_index_mut self.lens i hil]
  simp only [bind_tc_ok, Function.uncurry_def]
  rw [add_ok _ 1#u32 hc]
  rfl

theorem place_zero (self : buckets.Buckets) (window : Usize) (reference : U32) :
    self.place window 0#usize reference = ok self := by
  simp [buckets.Buckets.place]

theorem place_at (self : buckets.Buckets) (window magnitude i : Usize) (reference : U32)
    (hm : magnitude ≠ 0#usize) (hi : self.list window magnitude = ok i)
    (his : i.val < self.starts.val.length) (hil : i.val < self.lens.val.length)
    (hsum : self.starts.val[i.val].val + self.lens.val[i.val].val < 2 ^ 32)
    (href : self.starts.val[i.val].val + self.lens.val[i.val].val < self.refs.val.length)
    (hc : self.lens.val[i.val].val + 1 < 2 ^ 32) :
    self.place window magnitude reference = ok {self with
      refs := self.refs.set (UScalar.cast .Usize
        (UScalar.ofNatCore (self.starts.val[i.val].val + self.lens.val[i.val].val) hsum : U32)) reference,
      lens := self.lens.set i (UScalar.ofNatCore (self.lens.val[i.val].val + 1) hc)} := by
  simp only [buckets.Buckets.place]
  rw [if_pos (by simpa only [bne_iff_ne, ne_eq] using hm)]
  simp only [hi, bind_tc_ok]
  rw [vec_index self.starts i his]
  simp only [bind_tc_ok]
  rw [vec_index self.lens i hil]
  simp only [bind_tc_ok]
  rw [add_ok _ _ hsum]
  simp only [bind_tc_ok, lift]
  rw [vec_index_mut self.refs _ (by simpa only [cast_Usize_val, UScalar.ofNatCore_val_eq] using href)]
  simp only [bind_tc_ok]
  rw [vec_index_mut self.lens i hil]
  simp only [bind_tc_ok, Function.uncurry_def]
  rw [add_ok _ 1#u32 hc]
  rfl

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

abbrev BucketLists := ℕ → List U32

def appendReference (contents : BucketLists) (i : ℕ) (reference : U32) : BucketLists :=
  Function.update contents i (contents i ++ [reference])

structure Counts (state : buckets.Buckets) (n : ℕ) (contents : BucketLists) : Prop where
  length : state.lens.val.length = n
  values : ∀ i < n, state.lens.val[i]!.val = (contents i).length

structure Packed (state : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) : Prop where
  counts : Counts state n contents
  starts_length : state.starts.val.length = n
  starts_values : ∀ i < n, state.starts.val[i]!.val = base i
  refs_bound : state.refs.val.length < 2 ^ 32
  regions : ∀ i < n, base i + capacity i ≤ state.refs.val.length
  capacity_bound : ∀ i < n, (contents i).length ≤ capacity i
  entries : ∀ i < n, ∀ j < (contents i).length,
    state.refs.val[base i + j]! = (contents i)[j]!

def DisjointRegions (n : ℕ) (base capacity : ℕ → ℕ) : Prop :=
  ∀ i < n, ∀ k < n, i ≠ k → ∀ j < capacity i, ∀ l < capacity k,
    base i + j ≠ base k + l

theorem counts_update (self : buckets.Buckets) (n : ℕ) (contents : BucketLists)
    (h : Counts self n contents) (i : Usize) (hi : i.val < n) (reference count : U32)
    (hc : count.val = (contents i.val).length + 1) :
    Counts {self with lens := self.lens.set i count} n (appendReference contents i.val reference) := by
  refine ⟨by simpa [Vec.set] using h.length, ?_⟩
  intro k hk
  by_cases he : k = i.val
  · subst k
    simp only [Vec.set, appendReference, Function.update_self, List.length_append, List.length_singleton]
    rw [List.getElem!_set _ _ _ (by rw [h.length]; exact hi)]
    exact hc
  · simp only [Vec.set, appendReference, Function.update_of_ne he]
    rw [List.getElem!_set_ne self.lens.val i.val k count (by omega)]
    exact h.values k hk

theorem count_preserves (self : buckets.Buckets) (n : ℕ) (contents : BucketLists)
    (h : Counts self n contents) (window magnitude i : Usize) (reference : U32)
    (hm : magnitude ≠ 0#usize) (hlist : self.list window magnitude = ok i)
    (hi : i.val < n) (hbound : (contents i.val).length + 1 < 2 ^ 32) :
    ∃ next, self.count window magnitude = ok next ∧
      Counts next n (appendReference contents i.val reference) ∧
      next.window_bits = self.window_bits ∧ next.windows = self.windows ∧
      next.refs = self.refs ∧ next.starts = self.starts := by
  have hil : i.val < self.lens.val.length := by rw [h.length]; exact hi
  have hv : self.lens.val[i.val].val = (contents i.val).length := by
    simpa only [getElem!_pos self.lens.val i.val hil] using h.values i.val hi
  have hc : self.lens.val[i.val].val + 1 < 2 ^ 32 := by rw [hv]; exact hbound
  refine ⟨_, count_at self window magnitude i hm hlist hil hc, ?_, rfl, rfl, rfl, rfl⟩
  apply counts_update self n contents h i hi reference _
  exact congrArg (· + 1) hv

theorem packed_update (self : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed self n base capacity contents)
    (hd : DisjointRegions n base capacity) (i address : Usize) (reference count : U32)
    (hi : i.val < n) (hroom : (contents i.val).length < capacity i.val)
    (ha : address.val = base i.val + (contents i.val).length)
    (hc : count.val = (contents i.val).length + 1) :
    Packed {self with refs := self.refs.set address reference, lens := self.lens.set i count}
      n base capacity (appendReference contents i.val reference) := by
  have ha_bound : address.val < self.refs.val.length := by
    have := h.regions i.val hi
    omega
  have hc' := counts_update self n contents h.counts i hi reference count hc
  refine ⟨⟨hc'.length, hc'.values⟩,
    h.starts_length, h.starts_values, ?_, ?_, ?_, ?_⟩
  · simpa [Vec.set] using h.refs_bound
  · simpa [Vec.set] using h.regions
  · intro k hk
    by_cases he : k = i.val
    · subst k
      simp only [appendReference, Function.update_self, List.length_append, List.length_singleton]
      omega
    · simp only [appendReference, Function.update_of_ne he]
      exact h.capacity_bound k hk
  · intro k hk j hj
    change (self.refs.val.set address.val reference)[base k + j]! = _
    by_cases he : k = i.val
    · subst k
      simp only [appendReference, Function.update_self] at hj ⊢
      have hj' : j ≤ (contents i.val).length := by
        simp only [List.length_append, List.length_singleton] at hj
        omega
      by_cases heq : j = (contents i.val).length
      · subst j
        rw [← ha, List.getElem!_set _ _ _ ha_bound]
        simp only [List.getElem!_append_right _ _ _ (by omega), Nat.sub_self,
          List.getElem!_cons_zero]
      · have hjlt : j < (contents i.val).length := by omega
        rw [List.getElem!_set_ne _ _ _ _ (by omega)]
        rw [List.getElem!_append_left _ _ _ hjlt]
        exact h.entries i.val hi j hjlt
    · simp only [appendReference, Function.update_of_ne he] at hj ⊢
      have hslot : address.val ≠ base k + j := by
        rw [ha]
        exact hd i.val hi k hk (Ne.symm he) _ hroom _
          (lt_of_lt_of_le hj (h.capacity_bound k hk))
      rw [List.getElem!_set_ne self.refs.val address.val (base k + j) reference (by omega)]
      exact h.entries k hk j hj

theorem place_preserves (self : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed self n base capacity contents)
    (hd : DisjointRegions n base capacity) (window magnitude i : Usize) (reference : U32)
    (hm : magnitude ≠ 0#usize) (hlist : self.list window magnitude = ok i)
    (hi : i.val < n) (hroom : (contents i.val).length < capacity i.val) :
    ∃ next, self.place window magnitude reference = ok next ∧
      Packed next n base capacity (appendReference contents i.val reference) ∧
      next.window_bits = self.window_bits ∧ next.windows = self.windows ∧ next.starts = self.starts := by
  have hil : i.val < self.lens.val.length := by rw [h.counts.length]; exact hi
  have his : i.val < self.starts.val.length := by rw [h.starts_length]; exact hi
  have hv : self.lens.val[i.val].val = (contents i.val).length := by
    simpa only [getElem!_pos self.lens.val i.val hil] using h.counts.values i.val hi
  have hs : self.starts.val[i.val].val = base i.val := by
    simpa only [getElem!_pos self.starts.val i.val his] using h.starts_values i.val hi
  have href : self.starts.val[i.val].val + self.lens.val[i.val].val < self.refs.val.length := by
    rw [hv, hs]
    have := h.regions i.val hi
    omega
  have hsum : self.starts.val[i.val].val + self.lens.val[i.val].val < 2 ^ 32 :=
    lt_trans href h.refs_bound
  have hc : self.lens.val[i.val].val + 1 < 2 ^ 32 := by
    have := h.regions i.val hi
    have := h.refs_bound
    rw [hv]
    omega
  refine ⟨_, place_at self window magnitude i reference hm hlist his hil hsum href hc,
    ?_, rfl, rfl, rfl⟩
  apply packed_update self n base capacity contents h hd i _ reference _ hi hroom
  · simp only [cast_Usize_val, UScalar.ofNatCore_val_eq, hs, hv]
  · exact congrArg (· + 1) hv

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def prefixSum (capacity : ℕ → ℕ) : ℕ → ℕ
  | 0 => 0
  | n + 1 => prefixSum capacity n + capacity n

theorem prefix_mono (capacity : ℕ → ℕ) {i n : ℕ} (hi : i ≤ n) :
    prefixSum capacity i ≤ prefixSum capacity n := by
  induction n with
  | zero =>
    have : i = 0 := by omega
    subst i
    exact le_rfl
  | succ n ih =>
    by_cases he : i = n + 1
    · subst i; exact le_rfl
    · have := ih (by omega)
      simp only [prefixSum]
      omega

theorem prefix_disjoint (capacity : ℕ → ℕ) (n : ℕ) :
    DisjointRegions n (prefixSum capacity) capacity := by
  intro i _ k _ hne j hj l hl
  rcases lt_or_gt_of_ne hne with hlt | hgt
  · have h := prefix_mono capacity (show i + 1 ≤ k by omega)
    simp only [prefixSum] at h
    omega
  · have h := prefix_mono capacity (show k + 1 ≤ i by omega)
    simp only [prefixSum] at h
    omega

structure PrefixState (starts lens : Vec U32) (total : U32) (i n : ℕ)
    (capacity : ℕ → ℕ) : Prop where
  starts_length : starts.val.length = i
  lens_length : lens.val.length = n
  starts_values : ∀ j < i, starts.val[j]!.val = prefixSum capacity j
  lens_values : ∀ j < n, lens.val[j]!.val = if j < i then 0 else capacity j
  total_value : total.val = prefixSum capacity i

theorem prefix_step (starts lens : Vec U32) (total : U32) (i lists : Usize)
    (capacity : ℕ → ℕ) (h : PrefixState starts lens total i.val lists.val capacity)
    (hi : i.val < lists.val) (hn : lists.val < 2 ^ 32)
    (ht : prefixSum capacity lists.val < 2 ^ 32) :
    ∃ starts' lens' total' i',
      buckets.Buckets.fill_loop1.body lists starts lens total i = ok (cont (starts', lens', total', i')) ∧
      i'.val = i.val + 1 ∧ PrefixState starts' lens' total' i'.val lists.val capacity := by
  have hmax : starts.val.length < Usize.max := by
    simp only [Usize.max, Usize.numBits]
    have := two_pow_32_le_usize
    have := h.starts_length
    omega
  obtain ⟨starts', hpush, hstarts⟩ := WP.spec_imp_exists (Vec.push_spec starts total hmax)
  have hil : i.val < lens.val.length := by rw [h.lens_length]; exact hi
  have hv : lens.val[i.val].val = capacity i.val := by
    simpa only [getElem!_pos lens.val i.val hil, Nat.lt_irrefl, if_false] using h.lens_values i.val hi
  have hs : total.val + lens.val[i.val].val = prefixSum capacity (i.val + 1) := by
    rw [h.total_value, hv, prefixSum]
  have hsum : total.val + lens.val[i.val].val < 2 ^ 32 := by
    rw [hs]
    exact lt_of_le_of_lt (prefix_mono capacity (by omega)) ht
  let total' : U32 := UScalar.ofNatCore (total.val + lens.val[i.val].val) hsum
  let i' : Usize := UScalar.ofNatCore (i.val + 1)
    (lt_of_lt_of_le (by omega : i.val + 1 < 2 ^ 32) two_pow_32_le_usize)
  have hi' : i'.val = i.val + 1 := rfl
  refine ⟨starts', lens.set i 0#u32, total', i', ?_, hi', ?_⟩
  · simp only [buckets.Buckets.fill_loop1.body, show i < lists from hi, if_true,
      hpush, bind_tc_ok]
    rw [vec_index lens i hil]
    simp only [bind_tc_ok]
    rw [add_ok total lens.val[i.val] hsum]
    simp only [bind_tc_ok]
    rw [vec_index_mut lens i hil]
    simp only [bind_tc_ok, Function.uncurry_def]
    rw [usize_add_ok i 1#usize (by change i.val + 1 < 2 ^ 32; omega)]
    rfl
  · refine ⟨?_, ?_, ?_, ?_, ?_⟩
    · rw [hstarts, List.length_append, List.length_singleton, h.starts_length, hi']
    · simpa [Vec.set] using h.lens_length
    · intro j hj
      rw [hstarts]
      by_cases he : j = i.val
      · subst j
        rw [List.getElem!_append_right _ _ _ (by rw [h.starts_length]), h.starts_length]
        simp only [Nat.sub_self, List.getElem!_cons_zero]
        exact h.total_value
      · have hjlt : j < i.val := by omega
        rw [List.getElem!_append_left _ _ _ (by rw [h.starts_length]; exact hjlt)]
        exact h.starts_values j hjlt
    · intro j hj
      change (lens.val.set i.val 0#u32)[j]!.val = _
      by_cases he : j = i.val
      · subst j
        rw [List.getElem!_set _ _ _ hil, if_pos (by omega)]
        rfl
      · rw [List.getElem!_set_ne _ _ _ _ (by omega), h.lens_values j hj]
        rw [hi']
        by_cases hjlt : j < i.val
        · simp only [hjlt, show j < i.val + 1 by omega, if_true]
        · simp only [hjlt, show ¬ j < i.val + 1 by omega, if_false]
    · change total.val + lens.val[i.val].val = _
      rw [hs, hi']

theorem prefix_loop_refines (starts lens : Vec U32) (total : U32) (i lists : Usize)
    (capacity : ℕ → ℕ) (h : PrefixState starts lens total i.val lists.val capacity)
    (hi : i.val ≤ lists.val) (hn : lists.val < 2 ^ 32)
    (ht : prefixSum capacity lists.val < 2 ^ 32) :
    ∃ starts' lens' total',
      buckets.Buckets.fill_loop1 starts lens lists total i = ok (starts', lens', total') ∧
      PrefixState starts' lens' total' lists.val lists.val capacity := by
  induction he : lists.val - i.val generalizing starts lens total i with
  | zero =>
    have hv : i.val = lists.val := by omega
    refine ⟨starts, lens, total, ?_, hv ▸ h⟩
    rw [buckets.Buckets.fill_loop1, loop.eq_1]
    simp [buckets.Buckets.fill_loop1.body, show ¬ i < lists from by simp only [UScalar.lt_equiv]; omega]
  | succ n ih =>
    obtain ⟨starts', lens', total', i', hstep, hi', hstate⟩ :=
      prefix_step starts lens total i lists capacity h (by omega) hn ht
    obtain ⟨outStarts, outLens, outTotal, hloop, hout⟩ :=
      ih starts' lens' total' i' hstate (by omega) (by omega)
    refine ⟨outStarts, outLens, outTotal, ?_, hout⟩
    rw [buckets.Buckets.fill_loop1, loop.eq_1]
    simpa only [hstep] using hloop

theorem prefix_initial (self : buckets.Buckets) (n : ℕ) (contents : BucketLists)
    (h : Counts self n contents) :
    PrefixState (Vec.new U32) self.lens 0#u32 0 n (fun i => (contents i).length) := by
  refine ⟨rfl, h.length, ?_, ?_, rfl⟩
  · intro j hj; omega
  · intro j hj
    simpa only [Nat.not_lt_zero, if_false] using h.values j hj

theorem prefix_from_counts (self : buckets.Buckets) (lists : Usize) (contents : BucketLists)
    (h : Counts self lists.val contents) (hn : lists.val < 2 ^ 32)
    (ht : prefixSum (fun i => (contents i).length) lists.val < 2 ^ 32) :
    ∃ starts lens total,
      buckets.Buckets.fill_loop1 (Vec.new U32) self.lens lists 0#u32 0#usize =
        ok (starts, lens, total) ∧
      PrefixState starts lens total lists.val lists.val (fun i => (contents i).length) := by
  exact prefix_loop_refines _ _ _ _ _ _ (prefix_initial self lists.val contents h)
    (by change 0 ≤ lists.val; omega) hn ht

theorem prefix_packed_empty (self : buckets.Buckets) (n : ℕ) (capacity : ℕ → ℕ)
    (total : U32) (h : PrefixState self.starts self.lens total n n capacity)
    (hrefs : self.refs.val.length = total.val) :
    Packed self n (prefixSum capacity) capacity (fun _ => []) := by
  refine ⟨⟨h.lens_length, ?_⟩, h.starts_length, h.starts_values, ?_, ?_, ?_, ?_⟩
  · intro j hj
    simpa only [hj, if_true, List.length_nil] using h.lens_values j hj
  · rw [hrefs]
    exact total.hBounds
  · intro j hj
    rw [hrefs, h.total_value]
    exact prefix_mono capacity (show j + 1 ≤ n by omega)
  · intro j _
    exact Nat.zero_le _
  · intro _ _ j hj
    simp only [List.length_nil] at hj
    omega

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

def bucketSlice (state : buckets.Buckets) (i : ℕ) : List U32 :=
  (state.refs.val.drop state.starts.val[i]!.val).take state.lens.val[i]!.val

theorem packed_recovers (self : buckets.Buckets) (n : ℕ) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (h : Packed self n base capacity contents) (i : ℕ) (hi : i < n) :
    bucketSlice self i = contents i := by
  unfold bucketSlice
  rw [h.starts_values i hi, h.counts.values i hi]
  have hr : base i + (contents i).length ≤ self.refs.val.length :=
    le_trans (Nat.add_le_add_left (h.capacity_bound i hi) _) (h.regions i hi)
  apply List.ext_getElem
  · simp only [List.length_take, List.length_drop]
    omega
  · intro j hj hj'
    rw [← getElem!_pos ((self.refs.val.drop (base i)).take (contents i).length) j hj,
      ← getElem!_pos (contents i) j hj']
    rw [List.getElem!_take_of_lt _ _ _ hj', List.getElem!_drop]
    simpa only [Nat.add_comm] using h.entries i hi j hj'

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

structure Event where
  window : Usize
  magnitude : Usize
  reference : U32

def eventIndex (width : Usize) (event : Event) : ℕ :=
  listIndex width.val event.window.val event.magnitude.val

def collectOne (width : Usize) (contents : BucketLists) (event : Event) : BucketLists :=
  if event.magnitude = 0#usize then contents
  else appendReference contents (eventIndex width event) event.reference

def collect (width : Usize) (contents : BucketLists) (events : List Event) : BucketLists :=
  events.foldl (collectOne width) contents

def eventReferences (width : Usize) : List Event → ℕ → List U32
  | [], _ => []
  | event :: rest, i =>
    (if event.magnitude ≠ 0#usize ∧ eventIndex width event = i then [event.reference] else []) ++
      eventReferences width rest i

theorem collectOne_at (width : Usize) (contents : BucketLists) (event : Event) (i : ℕ) :
    collectOne width contents event i = contents i ++
      (if event.magnitude ≠ 0#usize ∧ eventIndex width event = i then [event.reference] else []) := by
  by_cases hm : event.magnitude = 0#usize
  · simp [collectOne, hm]
  · by_cases hi : eventIndex width event = i
    · subst i
      simp [collectOne, hm, appendReference]
    · simp [collectOne, hm, appendReference, hi, Ne.symm hi]

theorem collect_at (width : Usize) (contents : BucketLists) (events : List Event) (i : ℕ) :
    collect width contents events i = contents i ++ eventReferences width events i := by
  induction events generalizing contents with
  | nil => simp [collect, eventReferences]
  | cons event rest ih =>
    change collect width (collectOne width contents event) rest i = _
    rw [ih, collectOne_at]
    simp only [eventReferences, List.append_assoc]

def countEvents : List Event → buckets.Buckets → Result buckets.Buckets
  | [], state => ok state
  | event :: rest, state => do
    let next ← state.count event.window event.magnitude
    countEvents rest next

def placeEvents : List Event → buckets.Buckets → Result buckets.Buckets
  | [], state => ok state
  | event :: rest, state => do
    let next ← state.place event.window event.magnitude event.reference
    placeEvents rest next

def Fits (width windows : Usize) (event : Event) : Prop :=
  event.window.val < windows.val ∧ event.magnitude.val ≤ 2 ^ (width.val - 1)

theorem event_index_refines (state : buckets.Buckets) (event : Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hfit : Fits state.window_bits state.windows event)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hm : event.magnitude ≠ 0#usize) :
    ∃ i, state.list event.window event.magnitude = ok i ∧
      i.val = eventIndex state.window_bits event ∧
      i.val < state.windows.val * 2 ^ (state.window_bits.val - 1) := by
  have hmag : 1 ≤ event.magnitude.val := by
    have : event.magnitude.val ≠ 0 := by
      intro hz
      apply hm
      exact UScalar.eq_of_val_eq hz
    omega
  have hbound : (event.window.val + 1) * 2 ^ (state.window_bits.val - 1) < 2 ^ 32 :=
    lt_of_le_of_lt (Nat.mul_le_mul_right _ (by have := hfit.1; omega)) hn
  obtain ⟨i, hi, hiv⟩ := list_refines state event.window event.magnitude hwl hwh hmag hfit.2 hbound
  refine ⟨i, hi, hiv, ?_⟩
  rw [hiv, listIndex]
  have hw : (event.window.val + 1) * 2 ^ (state.window_bits.val - 1) ≤
      state.windows.val * 2 ^ (state.window_bits.val - 1) :=
    Nat.mul_le_mul_right _ (by have := hfit.1; omega)
  rw [Nat.add_mul, Nat.one_mul] at hw
  have := hfit.2
  omega

theorem countEvents_refines (state : buckets.Buckets) (contents : BucketLists) (events : List Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hfits : ∀ event ∈ events, Fits state.window_bits state.windows event)
    (h : Counts state (state.windows.val * 2 ^ (state.window_bits.val - 1)) contents)
    (hb : ∀ i < state.windows.val * 2 ^ (state.window_bits.val - 1),
      (contents i).length + events.length < 2 ^ 32) :
    ∃ next, countEvents events state = ok next ∧
      Counts next (state.windows.val * 2 ^ (state.window_bits.val - 1))
        (collect state.window_bits contents events) ∧
      next.window_bits = state.window_bits ∧ next.windows = state.windows ∧
      next.refs = state.refs ∧ next.starts = state.starts := by
  induction events generalizing state contents with
  | nil => exact ⟨state, rfl, h, rfl, rfl, rfl, rfl⟩
  | cons event rest ih =>
    have hfit := hfits event (by simp)
    by_cases hm : event.magnitude = 0#usize
    · obtain ⟨out, hout, hc, hw, hn', hr, hs⟩ := ih state contents hwl hwh hn
        (by intro e he; exact hfits e (by simp [he])) h (by
          intro i hi
          have := hb i hi
          simp only [List.length_cons] at this
          omega)
      refine ⟨out, ?_, ?_, hw, hn', hr, hs⟩
      · simp only [countEvents, hm, count_zero, bind_tc_ok, hout]
      · simpa only [collect, List.foldl_cons, collectOne, hm, if_true] using hc
    · obtain ⟨i, hlist, hiv, hi⟩ := event_index_refines state event hwl hwh hfit hn hm
      obtain ⟨next, hcount, hc, hw, hn', hr, hs⟩ := count_preserves state _ contents h
        event.window event.magnitude i event.reference hm hlist hi (by
          have := hb i.val hi
          simp only [List.length_cons] at this
          omega)
      have hc' : Counts next (next.windows.val * 2 ^ (next.window_bits.val - 1))
          (collectOne state.window_bits contents event) := by
        simpa only [hw, hn', collectOne, hm, if_false, hiv] using hc
      have hb' : ∀ k < next.windows.val * 2 ^ (next.window_bits.val - 1),
          (collectOne state.window_bits contents event k).length + rest.length < 2 ^ 32 := by
        intro k hk
        have hk' : k < state.windows.val * 2 ^ (state.window_bits.val - 1) := by simpa only [hw, hn'] using hk
        have hb := hb k hk'
        simp only [List.length_cons] at hb
        rw [collectOne_at, List.length_append]
        split_ifs <;> simp only [List.length_singleton, List.length_nil] <;> omega
      obtain ⟨out, hout, hcout, hwout, hnout, hrout, hsout⟩ := ih next
        (collectOne state.window_bits contents event) (hw.symm ▸ hwl) (hw.symm ▸ hwh)
        (by simpa only [hw, hn'] using hn)
        (by intro e he; simpa only [hw, hn'] using hfits e (by simp [he])) hc' hb'
      refine ⟨out, ?_, ?_, hwout.trans hw, hnout.trans hn', hrout.trans hr, hsout.trans hs⟩
      · simp only [countEvents, hcount, bind_tc_ok, hout]
      · simpa only [hw, hn', collect, List.foldl_cons] using hcout

theorem placeEvents_refines (state : buckets.Buckets) (base capacity : ℕ → ℕ)
    (contents : BucketLists) (events : List Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hfits : ∀ event ∈ events, Fits state.window_bits state.windows event)
    (h : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (hd : DisjointRegions (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity)
    (hspace : ∀ i < state.windows.val * 2 ^ (state.window_bits.val - 1),
      (contents i).length + (eventReferences state.window_bits events i).length ≤ capacity i) :
    ∃ next, placeEvents events state = ok next ∧
      Packed next (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity
        (collect state.window_bits contents events) ∧
      next.window_bits = state.window_bits ∧ next.windows = state.windows ∧ next.starts = state.starts := by
  induction events generalizing state contents with
  | nil => exact ⟨state, rfl, h, rfl, rfl, rfl⟩
  | cons event rest ih =>
    have hfit := hfits event (by simp)
    by_cases hm : event.magnitude = 0#usize
    · obtain ⟨out, hout, hc, hw, hn', hs⟩ := ih state contents hwl hwh hn
        (by intro e he; exact hfits e (by simp [he])) h hd (by
          intro i hi
          simpa only [eventReferences, hm, ne_eq, not_true_eq_false, false_and, if_false,
            List.nil_append] using hspace i hi)
      refine ⟨out, ?_, ?_, hw, hn', hs⟩
      · simp only [placeEvents, hm, place_zero, bind_tc_ok, hout]
      · simpa only [collect, List.foldl_cons, collectOne, hm, if_true] using hc
    · obtain ⟨i, hlist, hiv, hi⟩ := event_index_refines state event hwl hwh hfit hn hm
      have hroom : (contents i.val).length < capacity i.val := by
        have hb := hspace i.val hi
        rw [eventReferences, if_pos ⟨hm, hiv.symm⟩] at hb
        simp only [List.length_append, List.length_singleton] at hb
        omega
      obtain ⟨next, hplace, hc, hw, hn', hs⟩ := place_preserves state _ base capacity contents h hd
        event.window event.magnitude i event.reference hm hlist hi hroom
      have hc' : Packed next (next.windows.val * 2 ^ (next.window_bits.val - 1)) base capacity
          (collectOne state.window_bits contents event) := by
        simpa only [hw, hn', collectOne, hm, if_false, hiv] using hc
      have hspace' : ∀ k < next.windows.val * 2 ^ (next.window_bits.val - 1),
          (collectOne state.window_bits contents event k).length +
          (eventReferences next.window_bits rest k).length ≤ capacity k := by
        intro k hk
        have hk' : k < state.windows.val * 2 ^ (state.window_bits.val - 1) := by simpa only [hw, hn'] using hk
        have hb := hspace k hk'
        simp only [eventReferences, List.length_append] at hb
        rw [collectOne_at, List.length_append, hw]
        omega
      obtain ⟨out, hout, hcout, hwout, hnout, hsout⟩ := ih next
        (collectOne state.window_bits contents event) (hw.symm ▸ hwl) (hw.symm ▸ hwh)
        (by simpa only [hw, hn'] using hn)
        (by intro e he; simpa only [hw, hn'] using hfits e (by simp [he])) hc'
        (by simpa only [hw, hn'] using hd) hspace'
      refine ⟨out, ?_, ?_, hwout.trans hw, hnout.trans hn', hsout.trans hs⟩
      · simp only [placeEvents, hplace, bind_tc_ok, hout]
      · simpa only [hw, hn', collect, List.foldl_cons] using hcout

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8 alloc.vec

theorem prefixSum_appendReference (contents : BucketLists) (i n : ℕ) (reference : U32) :
    prefixSum (fun k => (appendReference contents i reference k).length) n =
      prefixSum (fun k => (contents k).length) n + if i < n then 1 else 0 := by
  induction n with
  | zero => simp [prefixSum]
  | succ n ih =>
    simp only [prefixSum, ih]
    by_cases he : n = i
    · subst n
      simp [appendReference]
      omega
    · simp only [appendReference, Function.update_of_ne he]
      by_cases hi : i < n
      · simp only [hi, show i < n + 1 by omega, if_true]
        omega
      · simp only [hi, show ¬ i < n + 1 by omega, if_false]
        omega

theorem prefixSum_collect_bound (width : Usize) (contents : BucketLists) (events : List Event) (n : ℕ) :
    prefixSum (fun k => (collect width contents events k).length) n ≤
      prefixSum (fun k => (contents k).length) n + events.length := by
  induction events generalizing contents with
  | nil => simp [collect]
  | cons event rest ih =>
    change prefixSum (fun k => (collect width (collectOne width contents event) rest k).length) n ≤ _
    have hh := ih (collectOne width contents event)
    by_cases hm : event.magnitude = 0#usize
    · simp only [collectOne, hm, if_true] at hh ⊢
      simp only [List.length_cons]
      omega
    · simp only [collectOne, hm, if_false] at hh ⊢
      rw [prefixSum_appendReference] at hh
      simp only [List.length_cons]
      split_ifs at hh <;> omega

theorem prefixSum_zero (n : ℕ) : prefixSum (fun _ => 0) n = 0 := by
  induction n with
  | zero => rfl
  | succ n ih => simp only [prefixSum, ih, Nat.add_zero]

theorem eventReferences_total_bound (width : Usize) (events : List Event) (n : ℕ) :
    prefixSum (fun k => (eventReferences width events k).length) n ≤ events.length := by
  have h := prefixSum_collect_bound width (fun _ => []) events n
  simpa only [collect_at, List.nil_append, List.length_nil, prefixSum_zero, Nat.zero_add] using h

theorem eventReferences_length_bound (width : Usize) (events : List Event) (i : ℕ) :
    (eventReferences width events i).length ≤ events.length := by
  induction events with
  | nil => simp [eventReferences]
  | cons event rest ih =>
    simp only [eventReferences, List.length_append, List.length_cons]
    split_ifs <;> simp only [List.length_singleton, List.length_nil] <;> omega

theorem countEvents_empty (state : buckets.Buckets) (events : List Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hfits : ∀ event ∈ events, Fits state.window_bits state.windows event)
    (h : Counts state (state.windows.val * 2 ^ (state.window_bits.val - 1)) (fun _ => []))
    (hb : events.length < 2 ^ 32) :
    ∃ next, countEvents events state = ok next ∧
      Counts next (state.windows.val * 2 ^ (state.window_bits.val - 1))
        (eventReferences state.window_bits events) ∧
      next.window_bits = state.window_bits ∧ next.windows = state.windows ∧
      next.refs = state.refs ∧ next.starts = state.starts := by
  obtain ⟨next, hs, hc, hw, hn', hr, hst⟩ := countEvents_refines state (fun _ => []) events
    hwl hwh hn hfits h (by intro i hi; simpa only [List.length_nil, Nat.zero_add] using hb)
  refine ⟨next, hs, ?_, hw, hn', hr, hst⟩
  have he : collect state.window_bits (fun _ => []) events = eventReferences state.window_bits events := by
    funext i
    simp only [collect_at, List.nil_append]
  exact he ▸ hc

theorem placeEvents_recovers (state : buckets.Buckets) (events : List Event)
    (hwl : 1 ≤ state.window_bits.val) (hwh : state.window_bits.val ≤ 8)
    (hn : state.windows.val * 2 ^ (state.window_bits.val - 1) < 2 ^ 32)
    (hfits : ∀ event ∈ events, Fits state.window_bits state.windows event)
    (h : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1))
      (prefixSum (fun i => (eventReferences state.window_bits events i).length))
      (fun i => (eventReferences state.window_bits events i).length) (fun _ => [])) :
    ∃ next, placeEvents events state = ok next ∧
      (∀ i < state.windows.val * 2 ^ (state.window_bits.val - 1),
        bucketSlice next i = eventReferences state.window_bits events i) ∧
      next.window_bits = state.window_bits ∧ next.windows = state.windows ∧ next.starts = state.starts := by
  obtain ⟨next, hs, hp, hw, hn', hst⟩ := placeEvents_refines state _ _ (fun _ => []) events hwl hwh hn hfits h
    (prefix_disjoint _ _) (by intro i hi; simp only [List.length_nil, Nat.zero_add, le_refl])
  refine ⟨next, hs, ?_, hw, hn', hst⟩
  intro i hi
  have hh := packed_recovers next _ _ _ _ hp i hi
  simpa only [collect_at, List.nil_append] using hh

end LeanBlsSimd.BucketsRefines
namespace LeanBlsSimd.BucketsRefines
open silver_crypto_simd.bls.msm8

def signedReference (i : Usize) (negative : Bool) : U32 :=
  UScalar.cast .U32 i ||| (if negative then 2147483648#u32 else 0#u32)

theorem signedReference_refines (i : Usize) (negative : Bool) :
    (do
      let bit ← lift (UScalar.cast_fromBool .U32 negative)
      let mask ← pairs.NEGATED
      let sign ← bit * mask
      let index ← lift (UScalar.cast .U32 i)
      lift (index ||| sign)) = ok (signedReference i negative) := by
  have hmask : pairs.NEGATED = ok 2147483648#u32 := by unfold pairs.NEGATED; rfl
  cases negative <;>
    simp only [signedReference, Bool.false_eq_true, if_false, if_true, lift,
      bind_tc_ok, hmask, UScalar.cast_fromBool] <;> rfl

theorem signedReference_value (i : Usize) (negative : Bool) (hi : i.val < 2 ^ 31) :
    (signedReference i negative).val = i.val + if negative then 2 ^ 31 else 0 := by
  have hic : (UScalar.cast .U32 i).val = i.val := by
    rw [UScalar.cast_val_eq]
    exact Nat.mod_eq_of_lt (by change i.val < 2 ^ 32; omega)
  have hor : ∀ a b : U32, (a ||| b).val = a.val ||| b.val := by
    intro a b
    exact BitVec.toNat_or a.bv b.bv
  cases negative with
  | false => simp only [signedReference, Bool.false_eq_true, if_false, hor, hic,
      show (0#u32).val = 0 from rfl, Nat.or_zero, Nat.add_zero]
  | true =>
    simp only [signedReference, if_true, hor, hic, show (2147483648#u32).val = 2 ^ 31 from rfl]
    have hh := Nat.two_pow_add_eq_or_of_lt hi 1
    simpa only [Nat.mul_one, Nat.or_comm, Nat.add_comm] using hh.symm

theorem signedReference_index (i : Usize) (negative : Bool) (hi : i.val < 2 ^ 31) :
    (signedReference i negative).val % 2 ^ 31 = i.val := by
  rw [signedReference_value i negative hi]
  cases negative <;> simp <;> omega

theorem signedReference_sign (i : Usize) (negative : Bool) (hi : i.val < 2 ^ 31) :
    (signedReference i negative).val / 2 ^ 31 = if negative then 1 else 0 := by
  rw [signedReference_value i negative hi]
  cases negative <;> simp <;> omega

end LeanBlsSimd.BucketsRefines
