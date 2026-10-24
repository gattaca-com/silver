import LeanBlsSimd.Portable.Msm.Buckets
import LeanBlsSimd.Msm8.Bounds

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Buckets
open BucketsRefines

theorem fill127_ready (state : portable.msm.buckets.Buckets)
    (scalars : Slice (Array U64 4#usize)) (values : ℕ → ℕ) (points : ℕ → G1Spec.E.Point)
    (hsize : scalars.val.length * (windows127 (selectedWidth scalars.val.length)).val < 2 ^ 32)
    (hlen : scalars.val.length < 2 ^ 31)
    (hv : ∀ j (hj : j < scalars.val.length), SignedDigits.value scalars.val[j] = values j)
    (hb : ∀ j, j < scalars.val.length → values j < 2 ^ 127) :
    ∃ (out : portable.msm.buckets.Buckets) (capacity : ℕ → ℕ) (contents : BucketLists),
      state.fill scalars 127#usize = ok out ∧
      out.window_bits = selectedWidth scalars.val.length ∧
      out.windows = windows127 (selectedWidth scalars.val.length) ∧
      Packed (toLane out) (out.windows.val * 2 ^ (out.window_bits.val - 1))
        (prefixSum capacity) capacity contents ∧
      DisjointRegions (out.windows.val * 2 ^ (out.window_bits.val - 1)) (prefixSum capacity) capacity ∧
      WindowSums.BucketShape (toLane out) ∧ 1 ≤ out.windows.val ∧
      prefixSum capacity (out.windows.val * 2 ^ (out.window_bits.val - 1)) ≤
        scalars.val.length * out.windows.val ∧
      (∀ i, (contents i).length = capacity i) ∧
      bucketContributions out.window_bits.val out.windows.val points (bucketSlice (toLane out)) =
        ∑ j ∈ Finset.range scalars.val.length, values j • points j ∧
      ∀ i, i < out.windows.val * 2 ^ (out.window_bits.val - 1) →
        ∀ r ∈ contents i, r.val % 2 ^ 31 < scalars.val.length := by
  obtain ⟨out, capacity, contents, hcall, hrest⟩ :=
    BucketsRefines.fill127_ready (toLane state) scalars values points hsize hlen hv hb
  refine ⟨fromLane out, capacity, contents, ?_, hrest⟩
  rw [fill_eq, hcall]
  rfl

theorem chunk_resources (n : ℕ) (hn : n ≤ portable.msm.CHUNK.val) :
    MsmBounds.Resources n (windows127 (selectedWidth (2*n))).val := by
  unfold portable.msm.CHUNK at hn
  apply MsmBounds.selected_resources n
  change n ≤ 4096 at hn
  omega

theorem chunk_reference_bounds (n : ℕ) (hn : n ≤ portable.msm.CHUNK.val) :
    2 * 32 * n < 2^31 ∧ (2+32)*n < 2^31 := by
  unfold portable.msm.CHUNK at hn
  change n ≤ 4096 at hn
  omega

theorem fill_chunk_bounds (state : portable.msm.buckets.Buckets) (scalars : Slice (Array U64 4#usize))
    (n : ℕ) (hscalars : scalars.val.length = 2*n) (hn : n ≤ portable.msm.CHUNK.val) :
    ∃ out, state.fill scalars 127#usize = ok out ∧
      out.window_bits = selectedWidth (2*n) ∧ out.windows = windows127 (selectedWidth (2*n)) ∧
      MsmBounds.Resources n out.windows.val ∧
      (∀ i < out.windows.val * 2^(out.window_bits.val-1),
        (bucketSlice (toLane out) i).length ≤ 2*n) ∧
      out.refs.val.length ≤ 2*n*out.windows.val := by
  have hb : n ≤ 2^24 := by unfold portable.msm.CHUNK at hn; change n ≤ 4096 at hn; omega
  obtain ⟨out,he,hrest⟩ := MsmBounds.fill_chunk_bounds (toLane state) scalars n hscalars hb
  refine ⟨fromLane out,?_,hrest⟩
  rw [fill_eq,he]
  rfl

end LeanBlsSimd.Portable.Msm.Buckets
