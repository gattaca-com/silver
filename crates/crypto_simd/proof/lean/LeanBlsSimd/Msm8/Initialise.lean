import LeanBlsSimd.Msm8.FillReady
import LeanBlsSimd.Msm8.SplitGroup
import LeanBlsSimd.Msm8.Bounds

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls BucketsRefines
local instance initialiseAffineInhabited0 : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

def initialise (self : msm8.Msm8) : Result msm8.Msm8 := do
  let split ← self.split_scalars
  let buckets ← split.buckets.fill (alloc.vec.Vec.deref split.halves) 127#usize
  let store ← prepareStore split.store (alloc.vec.Vec.deref split.finite_points)
    (alloc.vec.Vec.deref split.first_signs) (alloc.vec.Vec.deref split.second_signs) buckets.windows
  ok {split with buckets, store}

structure Initialised (state : msm8.Msm8) (n : ℕ) (values : ℕ → G1Spec.E.Point)
    (capacity : ℕ → ℕ) (contents : BucketLists) (contribution : G1Spec.E.Point) : Prop where
  store_len : state.store.len.val = 2 * n
  store_capacity : 2 * n + n * state.buckets.windows.val ≤ state.store.rows.val.length / 2
  resources : MsmBounds.Resources n state.buckets.windows.val
  shape : WindowSums.BucketShape state.buckets
  windows_positive : 1 ≤ state.buckets.windows.val
  selected_windows : state.buckets.windows = windows127 (selectedWidth (2 * n))
  packed : Packed state.buckets (state.buckets.windows.val * 2 ^ (state.buckets.window_bits.val - 1))
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
  original_rows : ∀ i, i < 2 * n → RowRep (pointRows state.store) i (values i)
  halves_length : state.halves.val.length = 2 * n
  halves_bound : ∀ i, i < state.halves.val.length → Kzg.limbs state.halves.val[i]!.val < 2 ^ 127
  scalar_sum : (∑ i ∈ Finset.range state.halves.val.length,
    Kzg.limbs state.halves.val[i]!.val • values i) = contribution
  bucket_sum : bucketContributions state.buckets.window_bits.val state.buckets.windows.val values
    (bucketSlice state.buckets) = contribution

theorem initialise_correct (self : msm8.Msm8)
    (halign : self.finite_points.val.length = self.finite_scalars.val.length)
    (hn : 1 ≤ self.finite_scalars.val.length) (hchunk : self.finite_scalars.val.length ≤ 2 ^ 24)
    (hp : ∀ i, i < self.finite_points.val.length → Kzg.G1AffineValid self.finite_points.val[i]!)
    (hfinite : ∀ i, i < self.finite_points.val.length →
      (Kzg.g1ReadAffine self.finite_points.val[i]!).isInfinity ≠ true)
    (hscalar : ∀ i, i < self.finite_scalars.val.length → Kzg.limbs self.finite_scalars.val[i]!.val < 2 ^ 255) :
    ∃ (out : msm8.Msm8) (values : ℕ → G1Spec.E.Point) (capacity : ℕ → ℕ) (contents : BucketLists),
      initialise self = ok out ∧
      out.finite_points = self.finite_points ∧ out.finite_scalars = self.finite_scalars ∧
      out.adds = self.adds ∧
      Initialised out self.finite_scalars.val.length values capacity contents
        (∑ i ∈ Finset.range self.finite_scalars.val.length,
          inputContribution (self.finite_points.val[i]!, self.finite_scalars.val[i]!)) := by
  let n := self.finite_scalars.val.length
  have hres := MsmBounds.selected_resources n hchunk
  obtain ⟨first, second, halves, fs, ss, hsplit, hinv, hhalf⟩ := split_scalars_refines self
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
    hbudget, hlengths, hsum, href⟩ := fill127_ready self.buckets (alloc.vec.Vec.deref halves)
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
    MsmBounds.fill_chunk_bounds self.buckets (alloc.vec.Vec.deref halves) n hinv.1 hchunk
  have heq : b' = b := Result.ok.inj (hfill'.symm.trans hfill)
  subst b'
  obtain ⟨store, hstore, hstorelen, _, hcapacity, hfirst, hsecond, _, _⟩ :=
    prepare_store_correct self.store (alloc.vec.Vec.deref self.finite_points)
      (alloc.vec.Vec.deref fs) (alloc.vec.Vec.deref ss) b.windows
      (by change fs.val.length = self.finite_points.val.length; rw [hinv.2.1, halign])
      (by change ss.val.length = self.finite_points.val.length; rw [hinv.2.2.1, halign])
      hp hfinite (by change 1 ≤ self.finite_points.val.length; omega)
      (by
        change 2 * (2 * self.finite_points.val.length + b.windows.val * self.finite_points.val.length) < 2 ^ 32
        simpa only [halign, Nat.mul_comm b.windows.val] using hresources.rows32)
  let out : msm8.Msm8 := {self with halves, first_signs := fs, second_signs := ss, buckets := b, store}
  have hscalarSum := split_sum_contribution self.finite_points.val self.finite_scalars.val halign
    first second halves fs ss hinv hp (fun j => (hhalf j).1) (fun j => (hhalf j).2.1)
  refine ⟨out, values, capacity, contents, ?_, rfl, rfl, rfl, ?_⟩
  · simp only [initialise, hsplit, bind_tc_ok]
    change (do
      let b ← self.buckets.fill (alloc.vec.Vec.deref halves) 127#usize
      let store ← prepareStore self.store (alloc.vec.Vec.deref self.finite_points)
        (alloc.vec.Vec.deref fs) (alloc.vec.Vec.deref ss) b.windows
      ok ({self with halves, first_signs := fs, second_signs := ss, buckets := b, store} : msm8.Msm8)) = _
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
      original_rows := ?_
      halves_length := hinv.1
      halves_bound := ?_
      scalar_sum := hscalarSum
      bucket_sum := hsum.trans hscalarSum
    }
    · intro i hi
      rw [← packed_recovers b _ (prefixSum capacity) capacity contents hpacked i hi]
      exact hbucket i hi
    · simpa only [alloc.vec.Vec.deref, hinv.1, out] using href
    · have h := split_points_rep self.finite_points.val fs.val ss.val (pointRows store) hfirst hsecond
      simpa only [halign] using h
    · intro i hi
      exact hb i (by change i < halves.val.length at hi; rwa [hinv.1] at hi)

end LeanBlsSimd.Msm8
