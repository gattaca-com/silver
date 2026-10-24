import LeanBlsSimd.Msm8.BatchValues
import LeanBlsSimd.Msm8.FillSum
import LeanBlsSimd.Msm8.WindowSum

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.BatchedRefines
open BucketsRefines QueueRefines

theorem signedReferenceValue_eq_referencePoint (values : ℕ → G1Spec.E.Point) :
    signedReferenceValue values = referencePoint values := by
  funext r
  rw [signedReferenceValue_eq_sign]
  have hr : r.val < 2 ^ 32 := r.hBounds
  have hs : (2 ^ 31 ≤ r.val) ↔ r.val / 2 ^ 31 = 1 := by omega
  simp only [referencePoint, hs]

theorem bucketContributions_congr (width windows : ℕ)
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

theorem member_bucketChunks (n : ℕ) (contents : BucketLists) (i : ℕ) (hi : i < n)
    (r : U32) (hr : r ∈ contents i) : r ∈ (bucketChunks n contents).flatten := by
  exact List.mem_flatten.mpr ⟨contents i,
    List.mem_map.mpr ⟨i, List.mem_range.mpr hi, rfl⟩, hr⟩

end LeanBlsSimd.BatchedRefines
