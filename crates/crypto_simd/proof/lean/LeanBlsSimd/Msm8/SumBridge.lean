import LeanBlsSimd.Msm8.FillSum
import LeanBlsSimd.Msm8.Flatten

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.BucketsRefines

theorem signedPoint_eq (points : ℕ → G1Spec.E.Point) (reference : U32) :
    WindowSums.signedPoint points reference = referencePoint points reference := by
  have hbound : reference.val < 2 ^ 32 := reference.hBounds
  have hsign : (2 ^ 31 ≤ reference.val) ↔ reference.val / 2 ^ 31 = 1 := by omega
  simp only [WindowSums.signedPoint, referencePoint, hsign]

theorem bucketGroup_eq (points : ℕ → G1Spec.E.Point) (refs : List U32) :
    WindowSums.bucketGroup points refs = (refs.map (referencePoint points)).sum := by
  have h : WindowSums.signedPoint points = referencePoint points := funext (signedPoint_eq points)
  rw [WindowSums.bucketGroup, h]

theorem packed_sum_contribution (state : msm8.buckets.Buckets) (store : msm8.store.PointStore)
    (base capacity : ℕ → ℕ) (contents : BucketLists)
    (hp : Packed state (state.windows.val * 2 ^ (state.window_bits.val - 1)) base capacity contents)
    (hshape : WindowSums.BucketShape state) (hwin : 1 ≤ state.windows.val)
    (points : ℕ → G1Spec.E.Point) (hzero : 1 < store.rows.val.length)
    (href : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
      ∀ r ∈ contents i, 2 * (r.val % 2 ^ 31) + 1 < store.rows.val.length)
    (hrow : ∀ i, i < state.windows.val * 2 ^ (state.window_bits.val - 1) →
      ∀ r ∈ contents i, Msm8.RowRep (pointRows store) (r.val % 2 ^ 31) (points (r.val % 2 ^ 31))) :
    ∃ out, state.sum store = ok (toG1x8 out) ∧
      out.PointRep 0 (bucketContributions state.window_bits.val state.windows.val points (bucketSlice state)) := by
  obtain ⟨out, hout, hrep⟩ := WindowSums.packed_sum_correct state store base capacity contents hp
    hshape hwin points hzero href hrow
  refine ⟨out, hout, ?_⟩
  simpa only [bucketGroup_eq, bucketContributions] using hrep

end LeanBlsSimd.BucketsRefines
