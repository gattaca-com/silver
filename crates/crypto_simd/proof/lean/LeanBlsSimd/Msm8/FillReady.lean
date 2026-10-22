import LeanBlsSimd.Msm8.SumBridge
import LeanBlsSimd.Msm8.Queue

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.BucketsRefines

theorem fill127_ready (state : msm8.buckets.Buckets)
    (scalars : Slice (Array U64 4#usize)) (values : ℕ → ℕ) (points : ℕ → G1Spec.E.Point)
    (hsize : scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32)
    (hlen : scalars.val.length < 2 ^ 31)
    (hv : ∀ j (hj : j < scalars.val.length), SignedDigits.value scalars.val[j] = values j)
    (hb : ∀ j, j < scalars.val.length → values j < 2 ^ 127) :
    ∃ (out : msm8.buckets.Buckets) (capacity : ℕ → ℕ) (contents : BucketLists),
      state.fill scalars 127#usize = ok out ∧
      out.window_bits = selectedWidth scalars.val.length ∧
      out.windows = windows127 (selectedWidth scalars.val.length) ∧
      Packed out (out.windows.val * 2 ^ (out.window_bits.val - 1))
        (prefixSum capacity) capacity contents ∧
      DisjointRegions (out.windows.val * 2 ^ (out.window_bits.val - 1)) (prefixSum capacity) capacity ∧
      WindowSums.BucketShape out ∧ 1 ≤ out.windows.val ∧
      prefixSum capacity (out.windows.val * 2 ^ (out.window_bits.val - 1)) ≤
        scalars.val.length * out.windows.val ∧
      (∀ i, (contents i).length = capacity i) ∧
      bucketContributions out.window_bits.val out.windows.val points (bucketSlice out) =
        ∑ j ∈ Finset.range scalars.val.length, values j • points j ∧
      ∀ i, i < out.windows.val * 2 ^ (out.window_bits.val - 1) →
        ∀ r ∈ contents i, r.val % 2 ^ 31 < scalars.val.length := by
  obtain ⟨events, out, _, hcall, hevents, hw, hn, hp⟩ := fill127_packed state scalars hsize
  obtain ⟨other, hother, hsum, href⟩ := fill127_contribution state scalars values points hsize hlen hv hb
  have heq : other = out := Result.ok.inj (hother.symm.trans hcall)
  subst other
  let contents := eventReferences (selectedWidth scalars.val.length) events
  let capacity := fun i => (contents i).length
  have hwidth := selectedWidth_bounds scalars.val.length
  have hshape := WindowSums.packed_shape out (prefixSum capacity) capacity contents hp
    (by rw [hw]; exact hwidth.1) (by rw [hw]; exact hwidth.2)
    (by rw [hw, hn]; exact listCount127_bound _ hwidth.2)
  refine ⟨out, capacity, contents, hcall, hw, hn, hp,
    prefix_disjoint _ _, hshape, ?_, ?_, (by intro i; rfl), hsum, ?_⟩
  · rw [hn]
    change 1 ≤ (127 / (selectedWidth scalars.val.length).val : ℕ) + 1
    exact Nat.le_add_left 1 _
  · have h := eventReferences_total_bound (selectedWidth scalars.val.length) events
      (out.windows.val * 2 ^ (out.window_bits.val - 1))
    rw [hevents, ← hn] at h
    exact h
  · intro i hi r hr
    apply href i hi r
    rw [packed_recovers out _ (prefixSum capacity) capacity contents hp i hi]
    exact hr

theorem chunksActive_range (contents : BucketLists) (n : ℕ) :
    QueueRefines.chunksActive ((List.range n).map contents) =
      prefixSum (fun i => (contents i).length) n := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [List.range_succ, List.map_append, List.map_cons, List.map_nil,
      QueueRefines.chunksActive, List.sum_append, List.sum_cons, List.sum_nil,
      Nat.add_zero, prefixSum]
    exact congrArg (fun k => k + (contents n).length) ih

end LeanBlsSimd.BucketsRefines
