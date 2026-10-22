import LeanBlsSimd.Msm8.Initialise
import LeanBlsSimd.Msm8.PairRounds

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls BucketsRefines QueueRefines BatchedRefines PairRoundsRefines

private theorem signedReferenceValue_eq_referencePoint (values : ℕ → G1Spec.E.Point) :
    signedReferenceValue values = referencePoint values := by
  funext r
  rw [signedReferenceValue_eq_sign]
  have hr : r.val < 2 ^ 32 := r.hBounds
  have hs : (2 ^ 31 ≤ r.val) ↔ r.val / 2 ^ 31 = 1 := by omega
  simp only [referencePoint, hs]

private theorem bucketContributions_congr (width windows : ℕ)
    (values values' : ℕ → G1Spec.E.Point) (contents contents' : BucketLists)
    (h : ∀ i < windows * 2 ^ (width - 1),
      ((contents i).map (referencePoint values)).sum =
        ((contents' i).map (referencePoint values')).sum) :
    bucketContributions width windows values contents =
      bucketContributions width windows values' contents' := by
  unfold bucketContributions
  apply Finset.sum_congr rfl
  intro w hw
  congr 1
  apply Finset.sum_congr rfl
  intro b hb
  rw [h _ (WindowSums.listIndex_lt _ _ _ _ (Finset.mem_range.mp hw) (by omega)
    (by have := Finset.mem_range.mp hb; omega))]

private theorem member_bucketChunks (n : ℕ) (contents : BucketLists) (i : ℕ) (hi : i < n)
    (r : U32) (hr : r ∈ contents i) : r ∈ (bucketChunks n contents).flatten := by
  exact List.mem_flatten.mpr ⟨contents i,
    List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩, hr⟩

private theorem initial_limits (state : msm8.Msm8) (n : ℕ) (values : ℕ → G1Spec.E.Point)
    (capacity : ℕ → ℕ) (contents : BucketLists) (contribution : G1Spec.E.Point)
    (h : Initialised state n values capacity contents contribution) :
    Limits state.store.len.val
      (state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1))
      (2 * n * state.buckets.windows.val) state.store.rows.val.length (prefixSum capacity) capacity := by
  have hhalf : 2 * n * state.buckets.windows.val / 2 = n * state.buckets.windows.val := by
    rw [Nat.mul_assoc, Nat.mul_div_right _ (by decide)]
  refine ⟨?_, ?_, ?_, h.disjoint⟩
  · have hi := h.resources.independence31
    omega
  · rw [h.store_len, hhalf]
    exact h.store_capacity
  · rw [h.store_len]
    exact h.resources.independence31

def finish (self : msm8.Msm8) : Result (msm8.Msm8 × g1x8.G1x8) := do
  let (flag, next) ← self.pair_rounds self.store.len
  let buckets ← if flag then ok next.buckets else
    next.buckets.fill (alloc.vec.Vec.deref next.halves) 127#usize
  let out ← buckets.sum next.store
  ok ({next with buckets}, out)

theorem finish_correct (state : msm8.Msm8) (n : ℕ) (values : ℕ → G1Spec.E.Point)
    (capacity : ℕ → ℕ) (contents : BucketLists) (contribution : G1Spec.E.Point)
    (hn : 1 ≤ n) (h : Initialised state n values capacity contents contribution) :
    ∃ next out, finish state = ok (next, toG1x8 out) ∧ out.PointRep 0 contribution := by
  let ctx : Context := {
    originals := state.store.len
    total := state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1)
    maximum := 2 * n * state.buckets.windows.val
    rows := state.store.rows.val.length
    base := prefixSum capacity
    capacity := capacity
    limits := initial_limits state n values capacity contents contribution h
    window_bits := state.buckets.window_bits
    windows := state.buckets.windows
    target := fun i => ((contents i).map (signedReferenceValue values)).sum
    originalValues := values
  }
  have hactive : chunksActive (bucketChunks ctx.total contents) ≤ ctx.maximum := by
    rw [chunksActive_capacity contents capacity ctx.total (fun i _ => h.content_lengths i)]
    exact h.references_bound
  have hlive : ∀ r ∈ (bucketChunks ctx.total contents).flatten, pointIndex r < ctx.originals.val := by
    intro r hr
    obtain ⟨rs, hrs, hr⟩ := List.mem_flatten.mp hr
    obtain ⟨i, hi, rfl⟩ := List.mem_map.mp hrs
    rw [pointIndex_mod]
    change r.val % 2 ^ 31 < state.store.len.val
    rw [h.store_len]
    exact h.reference_indices i (List.mem_range.mp hi) r hr
  have hframe : Frame ctx (state.store, state.buckets, state.adds) := by
    refine ⟨?_, rfl, rfl, rfl⟩
    intro p hp
    apply h.original_rows p
    change p < state.store.len.val at hp
    rwa [h.store_len] at hp
  obtain ⟨flag, next, hround, houtcome, _, _, hhalves, _, _⟩ :=
    pair_rounds_initial ctx state contents h.packed rfl rfl hactive hlive hframe (by intros; rfl)
  change state.pair_rounds state.store.len = ok (flag, next) at hround
  cases hf : flag with
  | true =>
    simp only [hf, if_true] at houtcome
    obtain ⟨⟨afterContents, afterValues, hc⟩, _⟩ := houtcome
    have hbits : next.buckets.window_bits = state.buckets.window_bits := hc.frame.bits
    have hwindows : next.buckets.windows = state.buckets.windows := hc.frame.windows
    have htotal : next.buckets.windows.val * 2 ^ (next.buckets.window_bits.val - 1) = ctx.total := by
      simp only [hbits, hwindows, ctx]
    have hp : Packed next.buckets
        (next.buckets.windows.val * 2 ^ (next.buckets.window_bits.val - 1))
        (prefixSum capacity) capacity afterContents := by
      rw [htotal]
      exact hc.layout.packed
    have hshape : WindowSums.BucketShape next.buckets :=
      WindowSums.packed_shape next.buckets _ _ afterContents hp
        (by rw [hbits]; exact h.shape.width_lower)
        (by rw [hbits]; exact h.shape.width_upper)
        (by rw [hbits, hwindows]; exact h.shape.total_bound)
    have hwin : 1 ≤ next.buckets.windows.val := by rw [hwindows]; exact h.windows_positive
    have hzero : 1 < next.store.rows.val.length := by
      have hcap := h.store_capacity
      have hrows := hc.frame.rows_length
      change next.store.rows.val.length = state.store.rows.val.length at hrows
      omega
    have href : ∀ i, i < next.buckets.windows.val * 2 ^ (next.buckets.window_bits.val - 1) →
        ∀ r ∈ afterContents i, 2 * (r.val % 2 ^ 31) + 1 < next.store.rows.val.length := by
      intro i hi r hr
      rw [htotal] at hi
      have hl := hc.layout.live r (member_bucketChunks ctx.total afterContents i hi r hr)
      have hu := hc.layout.upper
      have ha := ctx.limits.allocate
      have hrlen := hc.layout.rows_length
      change next.store.rows.val.length = ctx.rows at hrlen
      change pointIndex r < next.store.len.val at hl
      rw [pointIndex_mod] at hl
      change next.store.len.val ≤ ctx.originals.val + ctx.maximum / 2 at hu
      omega
    have hrows : ∀ i, i < next.buckets.windows.val * 2 ^ (next.buckets.window_bits.val - 1) →
        ∀ r ∈ afterContents i,
          RowRep (pointRows next.store) (r.val % 2 ^ 31) (afterValues (r.val % 2 ^ 31)) := by
      intro i hi r hr
      rw [htotal] at hi
      simpa only [pointIndex_mod] using hc.refs r (member_bucketChunks ctx.total afterContents i hi r hr)
    obtain ⟨out, hsum, hrep⟩ := packed_sum_contribution next.buckets next.store
      (prefixSum capacity) capacity afterContents hp hshape hwin afterValues hzero href hrows
    have heq : bucketContributions next.buckets.window_bits.val next.buckets.windows.val
        afterValues (bucketSlice next.buckets) = contribution := by
      rw [hbits, hwindows]
      trans bucketContributions state.buckets.window_bits.val state.buckets.windows.val
        values (bucketSlice state.buckets)
      · apply bucketContributions_congr
        intro i hi
        rw [packed_recovers next.buckets _ _ _ _ hc.layout.packed i hi,
          packed_recovers state.buckets _ _ _ _ h.packed i hi]
        simpa only [ctx, signedReferenceValue_eq_referencePoint] using hc.sums i hi
      · exact h.bucket_sum
    refine ⟨next, out, ?_, ?_⟩
    · simp only [finish, hround, hf, bind_tc_ok, Function.uncurry_apply_pair, if_true, hsum]
    · rwa [heq] at hrep
  | false =>
    simp only [hf, Bool.false_eq_true, if_false] at houtcome
    have hrefsize : state.halves.val.length *
        (windows127 (selectedWidth state.halves.val.length)).val < 2 ^ 32 := by
      rw [h.halves_length]
      have hw : state.buckets.windows.val = (windows127 (selectedWidth (2 * n))).val :=
        congrArg UScalar.val h.selected_windows
      simpa only [hw] using h.resources.references32
    obtain ⟨b, cap, lists, hfill, _, _, hpacked, _, hshape, hwin, _, _, hsum, href⟩ :=
      fill127_ready next.buckets (alloc.vec.Vec.deref next.halves)
        (fun i => Kzg.limbs state.halves.val[i]!.val) values
        (by simpa only [alloc.vec.Vec.deref, hhalves] using hrefsize)
        (by simpa only [alloc.vec.Vec.deref, hhalves, h.halves_length] using h.resources.originals31)
        (by
          intro j hj
          change SignedDigits.value next.halves.val[j] = _
          rw [digit_value_eq_limbs, ← getElem!_pos next.halves.val j hj, hhalves])
        (by intro j hj; exact h.halves_bound j (by simpa only [alloc.vec.Vec.deref, hhalves] using hj))
    have hzero : 1 < next.store.rows.val.length := by
      have hcap := h.store_capacity
      have hrows := houtcome.rows_length
      change next.store.rows.val.length = state.store.rows.val.length at hrows
      omega
    have hirows : ∀ i, i < b.windows.val * 2 ^ (b.window_bits.val - 1) →
        ∀ r ∈ lists i, 2 * (r.val % 2 ^ 31) + 1 < next.store.rows.val.length := by
      intro i hi r hr
      have hh := href i hi r hr
      change r.val % 2 ^ 31 < next.halves.val.length at hh
      rw [hhalves, h.halves_length] at hh
      have hcap := h.store_capacity
      have hrows := houtcome.rows_length
      change next.store.rows.val.length = state.store.rows.val.length at hrows
      omega
    have hrepRows : ∀ i, i < b.windows.val * 2 ^ (b.window_bits.val - 1) →
        ∀ r ∈ lists i, RowRep (pointRows next.store) (r.val % 2 ^ 31) (values (r.val % 2 ^ 31)) := by
      intro i hi r hr
      apply houtcome.originals
      have hh := href i hi r hr
      change r.val % 2 ^ 31 < next.halves.val.length at hh
      change r.val % 2 ^ 31 < state.store.len.val
      rw [hhalves, h.halves_length] at hh
      rwa [h.store_len]
    obtain ⟨out, hout, hrep⟩ := packed_sum_contribution b next.store (prefixSum cap) cap lists
      hpacked hshape hwin values hzero hirows hrepRows
    have heq : bucketContributions b.window_bits.val b.windows.val values (bucketSlice b) = contribution := by
      rw [hsum]
      simpa only [alloc.vec.Vec.deref, hhalves] using h.scalar_sum
    refine ⟨{next with buckets := b}, out, ?_, ?_⟩
    · simp only [finish, hround, hf, bind_tc_ok, Function.uncurry_apply_pair, Bool.false_eq_true, if_false, hfill, hout]
    · rwa [heq] at hrep

end LeanBlsSimd.Msm8
