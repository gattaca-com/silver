import LeanBlsSimd.Portable.Msm.FillReady
import LeanBlsSimd.Portable.Msm.Split
import LeanBlsSimd.Portable.Msm.Prepare

open Aeneas Aeneas.Std Result
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm
open LeanBlsSimd.Msm8 BucketsRefines
local instance : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem split_points_rep (points : List blst.blst_p1_affine) (fs ss : List Bool)
    (store : portable.msm.store.PointStore)
    (hf : ∀ i < points.length, Store.PointRep store i (transformedPoint points[i]! false fs[i]!))
    (hs : ∀ i < points.length, Store.PointRep store (points.length+i)
      (transformedPoint points[i]! true ss[i]!)) :
    ∀ i < 2*points.length, Store.PointRep store i (splitPoint points fs ss i) := by
  intro i hi
  by_cases h : i < points.length
  · rw [splitPoint_first _ _ _ _ h]
    exact hf i h
  · have he : i = points.length+(i-points.length) := by omega
    rw [he,splitPoint_second]
    exact hs _ (by omega)

def initialise [RuntimeFeatures] (self : portable.msm.Msm) : Result portable.msm.Msm := do
  let split ← self.split_scalars
  let buckets ← split.buckets.fill (alloc.vec.Vec.deref split.halves) 127#usize
  let store ← Store.prepareStore split.store (alloc.vec.Vec.deref split.finite_points)
    (alloc.vec.Vec.deref split.first_signs) (alloc.vec.Vec.deref split.second_signs) buckets.windows
  ok {split with buckets, store}

structure Initialised (state : portable.msm.Msm) (n : ℕ) (values : ℕ → G1Spec.E.Point)
    (capacity : ℕ → ℕ) (contents : BucketLists) (contribution : G1Spec.E.Point) : Prop where
  store_len : state.store.len.val = 2 * n
  store_capacity : 2 * n + n * state.buckets.windows.val ≤ state.store.points.val.length
  resources : MsmBounds.Resources n state.buckets.windows.val
  shape : WindowSums.BucketShape (Buckets.toLane state.buckets)
  windows_positive : 1 ≤ state.buckets.windows.val
  selected_windows : state.buckets.windows = windows127 (selectedWidth (2 * n))
  packed : Packed (Buckets.toLane state.buckets) (state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1))
    (prefixSum capacity) capacity contents
  disjoint : DisjointRegions (state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1))
    (prefixSum capacity) capacity
  references_bound : prefixSum capacity
    (state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1)) ≤ 2 * n * state.buckets.windows.val
  content_lengths : ∀ i, (contents i).length = capacity i
  bucket_lengths : ∀ i, i < state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1) →
    (contents i).length ≤ 2 * n
  reference_indices : ∀ i, i < state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1) →
    ∀ r ∈ contents i, r.val % 2 ^ 31 < 2 * n
  original_points : ∀ i, i < 2 * n → Store.PointRep state.store i (values i)
  halves_length : state.halves.val.length = 2 * n
  halves_bound : ∀ i, i < state.halves.val.length → Kzg.limbs state.halves.val[i]!.val < 2 ^ 127
  scalar_sum : (∑ i ∈ Finset.range state.halves.val.length,
    Kzg.limbs state.halves.val[i]!.val • values i) = contribution
  bucket_sum : bucketContributions state.buckets.window_bits.val state.buckets.windows.val values
    (bucketSlice (Buckets.toLane state.buckets)) = contribution

theorem initialise_correct [RuntimeFeatures] (self : portable.msm.Msm)
    (halign : self.finite_points.val.length = self.finite_scalars.val.length)
    (hn : 1 ≤ self.finite_scalars.val.length) (hchunk : self.finite_scalars.val.length ≤ portable.msm.CHUNK.val)
    (hp : ∀ i, i < self.finite_points.val.length → Kzg.G1AffineValid self.finite_points.val[i]!)
    (hfinite : ∀ i, i < self.finite_points.val.length →
      (Kzg.g1ReadAffine self.finite_points.val[i]!).isInfinity ≠ true)
    (hscalar : ∀ i, i < self.finite_scalars.val.length → Kzg.limbs self.finite_scalars.val[i]!.val < 2 ^ 255) :
    ∃ (out : portable.msm.Msm) (values : ℕ → G1Spec.E.Point) (capacity : ℕ → ℕ) (contents : BucketLists),
      initialise self = ok out ∧
      out.finite_points = self.finite_points ∧ out.finite_scalars = self.finite_scalars ∧
      out.adds = self.adds ∧
      Initialised out self.finite_scalars.val.length values capacity contents
        (∑ i ∈ Finset.range self.finite_scalars.val.length,
          inputContribution (self.finite_points.val[i]!, self.finite_scalars.val[i]!)) := by
  let n := self.finite_scalars.val.length
  have hres := Buckets.chunk_resources n hchunk
  obtain ⟨first, second, halves, fs, ss, hsplit, hinv, hhalf⟩ := Split.split_scalars_refines self
    (lt_trans hres.originals31 (by have := two_pow_32_le_usize; norm_num at *; omega))
    (by
      intro j
      rw [glv_value_eq_limbs]
      have h := hscalar j.val j.isLt
      rw [getElem!_pos self.finite_scalars.val j.val j.isLt] at h
      exact_mod_cast h)
  let values := splitPoint self.finite_points.val fs.val ss.val
  have hb : ∀ i, i < 2 * n → Kzg.limbs halves.val[i]!.val < 2 ^ 127 :=
    split_values_bound hinv (fun j => ⟨(hhalf j).2.2.1, (hhalf j).2.2.2⟩)
  have hsize : (alloc.vec.Vec.deref halves).val.length *
      (windows127 (selectedWidth (alloc.vec.Vec.deref halves).val.length)).val < 2 ^ 32 := by
    change halves.val.length * (windows127 (selectedWidth halves.val.length)).val < 2 ^ 32
    rw [hinv.1]
    exact hres.references32
  obtain ⟨b, capacity, contents, hfill, hw, hwin, hpacked, hdisjoint, hshape, hpositive,
    hbudget, hlengths, hsum, href⟩ := Buckets.fill127_ready self.buckets (alloc.vec.Vec.deref halves)
      (fun i => Kzg.limbs halves.val[i]!.val) values hsize (by
        change halves.val.length < 2 ^ 31
        rw [hinv.1]
        exact hres.originals31)
      (by
        intro j hj
        change SignedDigits.value halves.val[j] = _
        rw [digit_value_eq_limbs]
        change Kzg.limbs halves.val[j].val = Kzg.limbs halves.val[j]!.val
        rw [getElem!_pos halves.val j hj])
      (by
        intro j hj
        exact hb j (by change j < halves.val.length at hj; rwa [hinv.1] at hj))
  obtain ⟨b', hfill', _, _, hresources, hbucket, _⟩ :=
    Buckets.fill_chunk_bounds self.buckets (alloc.vec.Vec.deref halves) n hinv.1 hchunk
  have heq : b' = b := Result.ok.inj (hfill'.symm.trans hfill)
  subst b'
  obtain ⟨store, hstore, hstorelen, _, hcapacity, hfirst, hsecond⟩ :=
    Store.prepare_store_correct self.store (alloc.vec.Vec.deref self.finite_points)
      (alloc.vec.Vec.deref fs) (alloc.vec.Vec.deref ss) b.windows
      (by change fs.val.length = self.finite_points.val.length; rw [hinv.2.1, halign])
      (by change ss.val.length = self.finite_points.val.length; rw [hinv.2.2.1, halign])
      hp hfinite (by
        change 2*self.finite_points.val.length+b.windows.val*self.finite_points.val.length < 2^32
        have hh := hresources.capacity31
        dsimp only [n] at hh
        simp only [halign,Nat.mul_comm b.windows.val]
        omega)
  let out : portable.msm.Msm := {self with halves, first_signs := fs, second_signs := ss, buckets := b, store}
  have hscalarSum := split_sum_contribution self.finite_points.val self.finite_scalars.val halign
    first second halves fs ss hinv hp (fun j => (hhalf j).1) (fun j => (hhalf j).2.1)
  refine ⟨out, values, capacity, contents, ?_, rfl, rfl, rfl, ?_⟩
  · simp only [initialise, hsplit, bind_tc_ok]
    change (do
      let b ← self.buckets.fill (alloc.vec.Vec.deref halves) 127#usize
      let store ← Store.prepareStore self.store (alloc.vec.Vec.deref self.finite_points)
        (alloc.vec.Vec.deref fs) (alloc.vec.Vec.deref ss) b.windows
      ok ({self with halves, first_signs := fs, second_signs := ss, buckets := b, store} : portable.msm.Msm)) = _
    rw [hfill]
    simp only [bind_tc_ok, hstore]
    rfl
  · refine {
      store_len := by simpa only [alloc.vec.Vec.deref, halign, out] using hstorelen
      store_capacity := by simpa only [alloc.vec.Vec.deref, halign, Nat.mul_comm b.windows.val, out] using hcapacity
      resources := hresources
      shape := hshape
      windows_positive := hpositive
      selected_windows := by simpa only [alloc.vec.Vec.deref, hinv.1, out] using hwin
      packed := hpacked
      disjoint := hdisjoint
      references_bound := by simpa only [alloc.vec.Vec.deref, hinv.1, out] using hbudget
      content_lengths := hlengths
      bucket_lengths := ?_
      reference_indices := ?_
      original_points := ?_
      halves_length := hinv.1
      halves_bound := ?_
      scalar_sum := hscalarSum
      bucket_sum := hsum.trans hscalarSum
    }
    · intro i hi
      rw [← packed_recovers (Buckets.toLane b) _ (prefixSum capacity) capacity contents hpacked i hi]
      exact hbucket i hi
    · simpa only [alloc.vec.Vec.deref, hinv.1, out] using href
    · have h := split_points_rep self.finite_points.val fs.val ss.val store hfirst hsecond
      simpa only [halign] using h
    · intro i hi
      exact hb i (by change i < halves.val.length at hi; rwa [hinv.1] at hi)


end LeanBlsSimd.Portable.Msm
