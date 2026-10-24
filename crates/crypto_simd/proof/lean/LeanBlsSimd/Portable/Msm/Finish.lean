import LeanBlsSimd.Portable.Msm.Initialise
import LeanBlsSimd.Portable.Msm.PairRounds
import LeanBlsSimd.Portable.Msm.Sum

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm
open BucketsRefines QueueRefines BatchedRefines Rounds
open PairRoundsRefines (chunksActive_capacity)

private theorem initial_limits (state : portable.msm.Msm) (n : ℕ) (values : ℕ → G1Spec.E.Point)
    (capacity : ℕ → ℕ) (contents : BucketLists) (contribution : G1Spec.E.Point)
    (h : Initialised state n values capacity contents contribution) :
    Limits state.store.len.val (state.buckets.windows.val*2^(state.buckets.window_bits.val-1))
      (2*n*state.buckets.windows.val) state.store.points.val.length (prefixSum capacity) capacity := by
  have hhalf : 2*n*state.buckets.windows.val/2 = n*state.buckets.windows.val := by
    rw [Nat.mul_assoc,Nat.mul_div_right _ (by decide)]
  refine ⟨?_,?_,?_,h.disjoint⟩
  · have := h.resources.independence31; omega
  · rw [h.store_len,hhalf]; exact h.store_capacity
  · rw [h.store_len]; exact h.resources.independence31

def finish [RuntimeFeatures] (state : portable.msm.Msm) : Result (portable.msm.Msm × portable.g1.G1) := do
  let (flag,next) ← state.pair_rounds state.store.len
  let buckets ← if flag then ok next.buckets else
    next.buckets.fill (alloc.vec.Vec.deref next.halves) 127#usize
  let out ← buckets.sum next.store
  ok ({next with buckets},out)

/-- Both round outcomes reach the same sum; rejection refills from the preserved inputs. -/
theorem finish_correct [RuntimeFeatures] (state : portable.msm.Msm) (n : ℕ)
    (values : ℕ → G1Spec.E.Point) (capacity : ℕ → ℕ) (contents : BucketLists)
    (contribution : G1Spec.E.Point) (h : Initialised state n values capacity contents contribution) :
    ∃ next out, finish state = ok (next,out) ∧ Group.PointRep out contribution := by
  let ctx : Context := {
    originals := state.store.len
    total := state.buckets.windows.val*2^(state.buckets.window_bits.val-1)
    maximum := 2*n*state.buckets.windows.val
    slots := state.store.points.val.length
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
    obtain ⟨rs,hrs,hr⟩ := List.mem_flatten.mp hr
    obtain ⟨i,hi,rfl⟩ := List.mem_map.mp hrs
    rw [pointIndex_mod]
    change r.val%2^31 < state.store.len.val
    rw [h.store_len]
    exact h.reference_indices i (List.mem_range.mp hi) r hr
  have hframe : Frame ctx (state.store,state.buckets,state.adds) := by
    refine ⟨?_,rfl,rfl,rfl⟩
    intro p hp
    apply h.original_points p
    change p < state.store.len.val at hp
    rwa [h.store_len] at hp
  obtain ⟨flag,next,hround,houtcome,_,_,hhalves,_,_⟩ :=
    pair_rounds_initial ctx state contents h.packed rfl rfl hactive hlive hframe (by intros; rfl)
  change state.pair_rounds state.store.len = ok (flag,next) at hround
  cases hf : flag with
  | true =>
    simp only [hf,if_true] at houtcome
    obtain ⟨⟨afterContents,afterValues,hc⟩,_⟩ := houtcome
    have hbits : next.buckets.window_bits = state.buckets.window_bits := hc.frame.bits
    have hwindows : next.buckets.windows = state.buckets.windows := hc.frame.windows
    have htotal : next.buckets.windows.val*2^(next.buckets.window_bits.val-1) = ctx.total := by
      simp only [hbits,hwindows,ctx]
    have hp : Queue.Packed next.buckets (next.buckets.windows.val*2^(next.buckets.window_bits.val-1))
        (prefixSum capacity) capacity afterContents := by
      rw [htotal]; exact hc.layout.packed
    have hlo : 1 ≤ next.buckets.window_bits.val := by rw [hbits]; exact h.shape.width_lower
    have hhi : next.buckets.window_bits.val ≤ 8 := by rw [hbits]; exact h.shape.width_upper
    have hb : next.buckets.windows.val*2^(next.buckets.window_bits.val-1) < 2^32 := by
      rw [hbits,hwindows]; exact h.shape.total_bound
    have hshape := WindowSums.packed_shape (Buckets.toLane next.buckets) _ _ afterContents hp hlo hhi hb
    have hwin : 1 ≤ next.buckets.windows.val := by rw [hwindows]; exact h.windows_positive
    have hpoints : ∀ i < next.buckets.windows.val*2^(next.buckets.window_bits.val-1),
        ∀ r ∈ afterContents i, Store.PointRep next.store (pointIndex r) (afterValues (pointIndex r)) := by
      intro i hi r hr
      rw [htotal] at hi
      exact hc.refs r (member_bucketChunks ctx.total afterContents i hi r hr)
    obtain ⟨out,hsum,hrep⟩ := Sums.packed_sum_contribution next.buckets next.store
      (prefixSum capacity) capacity afterContents afterValues hp hshape hwin hpoints
    have heq : bucketContributions next.buckets.window_bits.val next.buckets.windows.val
        afterValues (BucketsRefines.bucketSlice (Buckets.toLane next.buckets)) = contribution := by
      rw [hbits,hwindows]
      trans bucketContributions state.buckets.window_bits.val state.buckets.windows.val
        values (BucketsRefines.bucketSlice (Buckets.toLane state.buckets))
      · apply bucketContributions_congr
        intro i hi
        rw [BucketsRefines.packed_recovers (Buckets.toLane next.buckets) _ _ _ _ hc.layout.packed i hi,
          BucketsRefines.packed_recovers (Buckets.toLane state.buckets) _ _ _ _ h.packed i hi]
        simpa only [ctx,signedReferenceValue_eq_referencePoint] using hc.sums i hi
      · exact h.bucket_sum
    refine ⟨next,out,?_,?_⟩
    · simp only [finish,hround,hf,bind_tc_ok,Function.uncurry_apply_pair,if_true,hsum]
    · rwa [heq] at hrep
  | false =>
    simp only [hf,Bool.false_eq_true,if_false] at houtcome
    have hrefsize : state.halves.val.length*(windows127 (selectedWidth state.halves.val.length)).val < 2^32 := by
      rw [h.halves_length]
      have hw : state.buckets.windows.val = (windows127 (selectedWidth (2*n))).val :=
        congrArg UScalar.val h.selected_windows
      simpa only [hw] using h.resources.references32
    obtain ⟨b,cap,lists,hfill,_,_,hpacked,_,hshape,hwin,_,_,hsum,href⟩ :=
      Buckets.fill127_ready next.buckets (alloc.vec.Vec.deref next.halves)
        (fun i => Kzg.limbs state.halves.val[i]!.val) values
        (by simpa only [alloc.vec.Vec.deref,hhalves] using hrefsize)
        (by simpa only [alloc.vec.Vec.deref,hhalves,h.halves_length] using h.resources.originals31)
        (by
          intro j hj
          change SignedDigits.value next.halves.val[j] = _
          rw [Msm8.digit_value_eq_limbs,←getElem!_pos next.halves.val j hj,hhalves])
        (by intro j hj; exact h.halves_bound j (by simpa only [alloc.vec.Vec.deref,hhalves] using hj))
    have hpoints : ∀ i < b.windows.val*2^(b.window_bits.val-1),
        ∀ r ∈ lists i, Store.PointRep next.store (pointIndex r) (values (pointIndex r)) := by
      intro i hi r hr
      apply houtcome.originals
      have hh := href i hi r hr
      change r.val%2^31 < next.halves.val.length at hh
      change pointIndex r < state.store.len.val
      rw [hhalves,h.halves_length] at hh
      rwa [pointIndex_mod,h.store_len]
    obtain ⟨out,hout,hrep⟩ := Sums.packed_sum_contribution b next.store (prefixSum cap) cap lists values
      hpacked hshape hwin hpoints
    have heq : bucketContributions b.window_bits.val b.windows.val values
        (BucketsRefines.bucketSlice (Buckets.toLane b)) = contribution := by
      rw [hsum]
      simpa only [alloc.vec.Vec.deref,hhalves] using h.scalar_sum
    refine ⟨{next with buckets := b},out,?_,?_⟩
    · simp only [finish,hround,hf,bind_tc_ok,Function.uncurry_apply_pair,Bool.false_eq_true,if_false,hfill,hout]
    · rwa [heq] at hrep

end LeanBlsSimd.Portable.Msm
