import LeanBlsSimd.Msm8.FiniteCore

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section
namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls

private theorem bind_success {α β : Type} (r : Result α) (f : α → Result β) (v : β) :
    (do let x ← r; f x) = ok v ↔ ∃ x, r = ok x ∧ f x = ok v := by
  cases r <;> simp

private theorem split_points (self next : msm8.Msm8)
    (h : self.split_scalars = ok next) : next.finite_points = self.finite_points := by
  simp only [msm8.Msm8.split_scalars, bind_success] at h
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, h⟩ := h
  cases h
  rfl

private def generatedAfterFilter (self : msm8.Msm8) : Result (g1x8.G1x8 × msm8.Msm8) := do
  let n := alloc.vec.Vec.len self.finite_points
  if n = 0#usize
  then let gx ← bls.g1x8.G1x8.infinity
       ok (gx, self)
  else
    let self2 ← bls.msm8.Msm8.split_scalars self
    let s := alloc.vec.Vec.deref self2.halves
    let b ←
      bls.msm8.buckets.Buckets.fill self2.buckets s
        bls.msm8.glv.HALF_SCALAR_BITS
    let i ← 2#usize * n
    let i1 ← bls.msm8.buckets.Buckets.impl.windows b
    let i2 ← i1 * n
    let i3 ← i + i2
    let ps ← bls.msm8.store.PointStore.reset self2.store i3
    let s1 := alloc.vec.Vec.deref self2.finite_points
    let s2 := alloc.vec.Vec.deref self2.first_signs
    let ps1 ← bls.msm8.store.PointStore.push_blst ps s1 s2 false
    let s3 := alloc.vec.Vec.deref self2.finite_points
    let s4 := alloc.vec.Vec.deref self2.second_signs
    let ps2 ← bls.msm8.store.PointStore.push_blst ps1 s3 s4 true
    let (b1, self3) ←
      bls.msm8.Msm8.pair_rounds { self2 with store := ps2, buckets := b } i
    let self4 ←
      if b1
      then ok self3
      else
        do
        let s5 := alloc.vec.Vec.deref self3.halves
        let b2 ←
          bls.msm8.buckets.Buckets.fill self3.buckets s5
            bls.msm8.glv.HALF_SCALAR_BITS
        ok { self3 with buckets := b2 }
    let gx ← bls.msm8.buckets.Buckets.sum self4.buckets self4.store
    ok (gx, self4)

private theorem chunk_sum_eq_afterFilter (self : msm8.Msm8)
    (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length) :
    self.chunk_sum points scalars = (do
      let filtered ← filterPrefix self points scalars
      generatedAfterFilter filtered) := by
  have he : Slice.len points = Slice.len scalars := by
    apply UScalar.eq_of_val_eq
    exact halign
  simp only [msm8.Msm8.chunk_sum, filterPrefix, he, massert, if_true,
    generatedAfterFilter, bind_assoc_eq, bind_tc_ok]

private theorem afterFilter_of_initialise (self prepared : msm8.Msm8)
    (hn : alloc.vec.Vec.len self.finite_points ≠ 0#usize)
    (hinit : initialise self = ok prepared)
    (hlen : prepared.store.len.val = 2 * self.finite_points.val.length) :
    generatedAfterFilter self = (do
      let (next, out) ← finish prepared
      ok (out, next)) := by
  simp only [initialise, bind_success] at hinit
  obtain ⟨split, hsplit, buckets, hfill, store, hprep, he⟩ := hinit
  cases he
  have hp := split_points self split hsplit
  have hmul : 2#usize * alloc.vec.Vec.len self.finite_points = ok store.len := by
    rw [mul_ok _ _ (by change 2 * self.finite_points.val.length < _; rw [← hlen]; exact store.len.hBounds)]
    congr 1
    apply UScalar.eq_of_val_eq
    exact hlen.symm
  simp only [prepareStore, hp] at hprep
  change (do
    let count ← 2#usize * alloc.vec.Vec.len self.finite_points
    let extra ← buckets.windows * alloc.vec.Vec.len self.finite_points
    let capacity ← count + extra
    let reset ← msm8.store.PointStore.reset split.store capacity
    let first ← reset.push_blst (alloc.vec.Vec.deref self.finite_points)
      (alloc.vec.Vec.deref split.first_signs) false
    first.push_blst (alloc.vec.Vec.deref self.finite_points)
      (alloc.vec.Vec.deref split.second_signs) true) = ok store at hprep
  rw [hmul] at hprep
  simp only [bind_tc_ok, bind_success] at hprep
  obtain ⟨extra, hextra, capacity, hcapacity, reset, hreset, first, hfirst, hsecond⟩ := hprep
  simp only [generatedAfterFilter, hn, if_false, hsplit, bind_tc_ok,
    msm8.glv.HALF_SCALAR_BITS, hfill, hmul, msm8.buckets.Buckets.impl.windows,
    hextra, hcapacity, hreset, hp, hfirst, hsecond]
  simp only [finish, bind_assoc_eq]
  apply (bind_eq_iff _ _ _).mpr
  intro result _
  rcases result with ⟨flag, next⟩
  cases flag <;> simp

local instance chunkRefinesAffineInhabited : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

theorem chunk_sum_eq_finiteCore
    (state : msm8.Msm8) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hchunk : points.val.length ≤ 2 ^ 24) :
    state.chunk_sum points scalars = (do
      let (next, out) ← finiteCore state points scalars
      ok (out, next)) := by
  obtain ⟨ps, ss, hfilter, _, haligned, hlength, _, hpoints, hscalars⟩ :=
    filter_prefix_correct state points scalars halign hp hs (by omega)
  let filtered : msm8.Msm8 := {state with finite_points := ps, finite_scalars := ss}
  rw [chunk_sum_eq_afterFilter state points scalars halign]
  simp only [finiteCore, hfilter, bind_tc_ok]
  by_cases hz : ps.val.length = 0
  · have hn : alloc.vec.Vec.len ps = 0#usize := by
      apply UScalar.eq_of_val_eq
      exact hz
    simp only [generatedAfterFilter, hn, if_true, bind_assoc_eq, bind_tc_ok]
    rfl
  · have hn : alloc.vec.Vec.len ps ≠ 0#usize := by
      intro he
      exact hz (congrArg UScalar.val he)
    have hpositive : 1 ≤ filtered.finite_scalars.val.length := by
      change 1 ≤ ss.val.length
      omega
    have hbound : filtered.finite_scalars.val.length ≤ 2 ^ 24 := by
      change ss.val.length ≤ 2 ^ 24
      omega
    obtain ⟨prepared, values, capacity, contents, hinit, _, _, _, hinitialised⟩ :=
      initialise_correct filtered haligned hpositive hbound
        (by
          intro i hi
          change Kzg.G1AffineValid ps.val[i]!
          rw [getElem!_pos ps.val i hi]
          exact (hpoints _ (List.getElem_mem hi)).1)
        (by
          intro i hi
          change (Kzg.g1ReadAffine ps.val[i]!).isInfinity ≠ true
          rw [getElem!_pos ps.val i hi, (hpoints _ (List.getElem_mem hi)).2]
          decide)
        (by
          intro i hi
          change Kzg.limbs ss.val[i]!.val < 2 ^ 255
          rw [getElem!_pos ss.val i hi]
          exact hscalars _ (List.getElem_mem hi))
    simp only [hn, if_false, bind_assoc_eq]
    change generatedAfterFilter filtered = (do
      let prepared ← initialise filtered
      let (next, out) ← finish prepared
      ok (out, next))
    rw [hinit]
    apply afterFilter_of_initialise filtered prepared hn hinit
    have h := hinitialised.store_len
    simpa only [filtered, haligned] using h

theorem chunk_sum_refinement
    (state : msm8.Msm8) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs255 : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hchunk : points.val.length ≤ 2 ^ 24) :
    ∃ next out, state.chunk_sum points scalars = ok (toG1x8 out, next) ∧
      out.PointRep 0 (((points.val.zip scalars.val).map inputContribution).sum) := by
  obtain ⟨next, out, hcore, hrep⟩ := finiteCore_correct state points scalars halign hp hs255 hchunk
  refine ⟨next, out, ?_, hrep⟩
  rw [chunk_sum_eq_finiteCore state points scalars halign hp hs255 hchunk, hcore]
  rfl

end LeanBlsSimd.Msm8
