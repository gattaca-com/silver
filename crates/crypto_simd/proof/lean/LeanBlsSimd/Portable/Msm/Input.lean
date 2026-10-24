import LeanBlsSimd.Msm8.Filter

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd
open EthLib.Cryptography Bls

namespace LeanBlsSimd.Portable.Msm.Input
open LeanBlsSimd.Msm8

theorem is_infinity_eq (point : blst.blst_p1_affine) :
    portable.msm.is_infinity point = bls.msm8.is_infinity point := rfl

theorem is_infinity_correct (point : blst.blst_p1_affine) (hp : Kzg.G1AffineValid point) :
    portable.msm.is_infinity point = ok (Kzg.g1ReadAffine point).isInfinity := by
  rw [is_infinity_eq]
  exact Msm8.is_infinity_correct point hp

theorem keep_if_finite_refines (self : portable.msm.Msm)
    (point : blst.blst_p1_affine) (scalar : FilterScalar)
    (hs : Kzg.limbs scalar.val < 2 ^ 255)
    (hp : Kzg.G1AffineValid point)
    (hpl : self.finite_points.val.length < Usize.max)
    (hsl : self.finite_scalars.val.length < Usize.max) :
    ∃ (ps : alloc.vec.Vec blst.blst_p1_affine) (ss : alloc.vec.Vec FilterScalar),
      portable.msm.Msm.keep_if_finite self point scalar =
        ok { self with finite_points := ps, finite_scalars := ss } ∧
      ps.val = self.finite_points.val ++
        (if (Kzg.g1ReadAffine point).isInfinity then [] else [point]) ∧
      ss.val = self.finite_scalars.val ++
        (if (Kzg.g1ReadAffine point).isInfinity then [] else [scalar]) := by
  have hcall : portable.msm.Msm.keep_if_finite self point scalar = (do
      let b ← portable.msm.is_infinity point
      if b then ok self else do
        let ps ← alloc.vec.Vec.push self.finite_points point
        let ss ← alloc.vec.Vec.push self.finite_scalars scalar
        ok { self with finite_points := ps, finite_scalars := ss }) := by
    rw [portable.msm.Msm.keep_if_finite, index_usize_eq scalar 3#usize (by decide)]
    simp only [bind_tc_ok, UScalar.ofNatCore_val_eq, scalar_high_bit scalar hs]
    rfl
  rw [hcall, is_infinity_correct point hp]
  simp only [bind_tc_ok]
  by_cases hz : (Kzg.g1ReadAffine point).isInfinity = true
  · simp only [hz, if_true, List.append_nil]
    exact ⟨self.finite_points, self.finite_scalars, rfl, rfl, rfl⟩
  · simp only [hz, Bool.false_eq_true, if_false]
    obtain ⟨ps, hps, hpsval⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.push_spec self.finite_points point hpl)
    obtain ⟨ss, hss, hssval⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.push_spec self.finite_scalars scalar hsl)
    refine ⟨ps, ss, ?_, hpsval, hssval⟩
    rw [hps]
    simp only [bind_tc_ok, hss]


theorem filter_loop_refines (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine)
    (scalars : Slice FilterScalar) (i : Usize)
    (halign : points.val.length = scalars.val.length) (hi : i.val ≤ points.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hpr : state.finite_points.val.length + (points.val.length - i.val) ≤ Usize.max)
    (hsr : state.finite_scalars.val.length + (points.val.length - i.val) ≤ Usize.max) :
    ∃ ps ss, portable.msm.Msm.chunk_sum_loop state points scalars i =
        ok {state with finite_points := ps, finite_scalars := ss} ∧
      ps.val = state.finite_points.val ++ (filteredSuffix points scalars i.val).map Prod.fst ∧
      ss.val = state.finite_scalars.val ++ (filteredSuffix points scalars i.val).map Prod.snd := by
  induction hrem : points.val.length - i.val generalizing state i with
  | zero =>
    have he : i.val = points.val.length := by omega
    refine ⟨state.finite_points, state.finite_scalars, ?_, ?_, ?_⟩
    · unfold portable.msm.Msm.chunk_sum_loop
      rw [loop.eq_1]
      simp only [portable.msm.Msm.chunk_sum_loop.body, UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq,
        he, Nat.lt_irrefl, if_false]
    · simp only [filteredSuffix_done points scalars i.val (by omega), List.map_nil, List.append_nil]
    · simp only [filteredSuffix_done points scalars i.val (by omega), List.map_nil, List.append_nil]
  | succ remaining ih =>
    have hil : i.val < points.val.length := by omega
    have his : i.val < scalars.val.length := by omega
    have hpoint := hp points.val[i.val] (List.getElem_mem hil)
    have hscalar := hs scalars.val[i.val] (List.getElem_mem his)
    obtain ⟨ps, ss, hkeep, hps, hss⟩ := keep_if_finite_refines state points.val[i.val] scalars.val[i.val]
      hscalar hpoint (by omega) (by omega)
    have hpslen : ps.val.length ≤ state.finite_points.val.length + 1 := by rw [hps]; split <;> simp
    have hsslen : ss.val.length ≤ state.finite_scalars.val.length + 1 := by rw [hss]; split <;> simp
    have hsize : points.val.length < 2 ^ UScalarTy.Usize.numBits := by
      have h := points.property
      simp only [Usize.max_def, Usize.numBits_def] at h
      change points.val.length ≤ 2 ^ UScalarTy.Usize.numBits - 1 at h
      have := two_pow_32_le_usize
      omega
    have hadd : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by omega
    let next : Usize := UScalar.ofNatCore (i.val + 1) hadd
    have hn : next.val = i.val + 1 := rfl
    let mid := {state with finite_points := ps, finite_scalars := ss}
    have hbody : portable.msm.Msm.chunk_sum_loop.body points scalars state i = ok (cont (mid, next)) := by
      simp only [portable.msm.Msm.chunk_sum_loop.body, UScalar.lt_equiv, Slice.len, Usize.ofNatCore_val_eq,
        hil, if_true]
      have hix {A : Type} (xs : Slice A) (hx : i.val < xs.val.length) :
          Slice.index_usize xs i = ok xs.val[i.val] := by simp [Slice.index_usize, hx]
      rw [hix points hil]
      simp only [bind_tc_ok]
      rw [hix scalars his]
      simp only [bind_tc_ok, hkeep]
      rw [add_ok _ _ hadd]
      rfl
    obtain ⟨ps', ss', hloop, hps', hss'⟩ := ih mid next (by omega) (by dsimp [mid]; omega)
      (by dsimp [mid]; omega) (by omega)
    refine ⟨ps', ss', ?_, ?_, ?_⟩
    · unfold portable.msm.Msm.chunk_sum_loop
      change loop (fun p => portable.msm.Msm.chunk_sum_loop.body points scalars p.1 p.2) _ = _
      rw [loop.eq_1, hbody]
      exact hloop
    · rw [hps', filteredSuffix_step points scalars i.val halign hil]
      dsimp only [mid]
      rw [hps]
      simp only [List.map_append, List.append_assoc, hn]
      split <;> simp
    · rw [hss', filteredSuffix_step points scalars i.val halign hil]
      dsimp only [mid]
      rw [hss]
      simp only [List.map_append, List.append_assoc, hn]
      split <;> simp


/-- The generated clearing-and-filtering prefix, ending immediately after the loop. -/
def filterPrefix (self : portable.msm.Msm) (points : Slice blst.blst_p1_affine)
    (scalars : Slice FilterScalar) : Result portable.msm.Msm := do
  let v ← alloc.vec.Vec.clear Global self.finite_points
  let v1 ← alloc.vec.Vec.clear Global self.finite_scalars
  let self1 ← portable.msm.Msm.chunk_sum_loop
    {self with finite_points := v, finite_scalars := v1} points scalars 0#usize
  ok self1

theorem filter_prefix_refines (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine)
    (scalars : Slice FilterScalar)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hn : points.val.length < 2 ^ 32) :
    ∃ ps ss, filterPrefix state points scalars =
        ok {state with finite_points := ps, finite_scalars := ss} ∧
      ps.val = (filteredSuffix points scalars 0).map Prod.fst ∧
      ss.val = (filteredSuffix points scalars 0).map Prod.snd := by
  let emptyP : alloc.vec.Vec blst.blst_p1_affine := ⟨[], by simp⟩
  let emptyS : alloc.vec.Vec FilterScalar := ⟨[], by simp⟩
  have hroom : points.val.length ≤ Usize.max := by
    have := two_pow_32_le_usize
    simp only [Usize.max_def, Usize.numBits_def]
    omega
  obtain ⟨ps, ss, hloop, hps, hss⟩ := filter_loop_refines
    {state with finite_points := emptyP, finite_scalars := emptyS} points scalars 0#usize
    halign (by simp) hp hs (by simpa [emptyP] using hroom) (by simpa [emptyS] using hroom)
  refine ⟨ps, ss, ?_, ?_, ?_⟩
  · simp only [filterPrefix, bind_tc_ok, alloc.vec.Vec.clear]
    rw [hloop]
    rfl
  · simpa only [emptyP, List.nil_append] using hps
  · simpa only [emptyS, List.nil_append] using hss


theorem filter_prefix_correct (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine)
    (scalars : Slice FilterScalar)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hn : points.val.length < 2 ^ 32) :
    ∃ ps ss, filterPrefix state points scalars =
        ok {state with finite_points := ps, finite_scalars := ss} ∧
      ps.val.zip ss.val = (points.val.zip scalars.val).filter finiteInput ∧
      ps.val.length = ss.val.length ∧ ps.val.length ≤ points.val.length ∧
      ps.val.length < 2 ^ 32 ∧
      (∀ p ∈ ps.val, Kzg.G1AffineValid p ∧ (Kzg.g1ReadAffine p).isInfinity = false) ∧
      (∀ s ∈ ss.val, Kzg.limbs s.val < 2 ^ 255) := by
  obtain ⟨ps, ss, hprefix, hps, hss⟩ := filter_prefix_refines state points scalars halign hp hs hn
  have hlen := filteredSuffix_length points scalars 0
  refine ⟨ps, ss, hprefix, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hps, hss, paired_projections]
    rfl
  · rw [hps, hss]
    simp only [List.length_map]
  · rw [hps, List.length_map]
    simpa only [Nat.sub_zero] using hlen
  · rw [hps, List.length_map]
    omega
  · intro p h
    rw [hps] at h
    obtain ⟨⟨p', s⟩, hm, he⟩ := List.mem_map.mp h
    dsimp only at he
    subst p'
    obtain ⟨hm, _, hf⟩ := filteredSuffix_mem points scalars 0 p s hm
    exact ⟨hp p hm, hf⟩
  · intro s h
    rw [hss] at h
    obtain ⟨⟨p, s'⟩, hm, he⟩ := List.mem_map.mp h
    dsimp only at he
    subst s'
    exact hs s (filteredSuffix_mem points scalars 0 p s hm).2.1


end LeanBlsSimd.Portable.Msm.Input
