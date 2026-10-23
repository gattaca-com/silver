import LeanBlsSimd.Msm8.Refines
import LeanBlsSimd.Msm8.PlainWords
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.Routes

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Kzg

private def Msm8Correct : Prop :=
  ∀ (state : msm8.Msm8) (ps : Slice blst.blst_p1_affine)
    (words : Slice (Aeneas.Std.Array U64 4#usize)),
    ps.val.length = words.val.length → (∀ p ∈ ps.val, G1AffineValid p) →
    (∀ w ∈ words.val, limbs w.val < Fr.modulus) →
    ∃ point state', state.msm ps words = ok (point, state') ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray
        (words.val.map (fun w => Fr.ofNat (limbs w.val))).toArray)

private theorem msm8_correct : Msm8Correct := by
  intro state ps words hlen hpv hwords
  exact LeanBlsSimd.Msm8.msm_refinement state ps words hlen hpv hwords

private theorem lincomb_sum_kernel [e : KzgExternals] (hmsm : Msm8Correct)
    (self : verify.Lincomb) (state : msm8.Msm8) (hstate : self.msm = some state)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  obtain ⟨words, hwords, hwlen, hwval⟩ := PlainWords.plain_words_correct fs self.words hfv
  have hwbound : ∀ w ∈ words.val, limbs w.val < Fr.modulus := by
    intro w hw
    have hmem : limbs w.val ∈ words.val.map (fun w => limbs w.val) := List.mem_map.mpr ⟨w, hw, rfl⟩
    rw [hwval] at hmem
    obtain ⟨f, _, heq⟩ := List.mem_map.mp hmem
    rw [← heq]
    exact (frRead f).isLt
  obtain ⟨point, next, hcall, hrep⟩ := hmsm state ps (alloc.vec.Vec.deref words)
    (by simpa only [alloc.vec.Vec.deref, hwlen] using hlen) hpv hwbound
  have hvalues : words.val.map (fun w => Fr.ofNat (limbs w.val)) = fs.val.map frRead := by
    have hof (x : Fr) : Fr.ofNat x.val = x := by
      apply Fin.ext
      exact Nat.mod_eq_of_lt x.isLt
    have h := congrArg (List.map Fr.ofNat) hwval
    simpa only [List.map_map, Function.comp_def, hof] using h
  refine ⟨point, {self with msm := some next, words := words}, ?_, ?_⟩
  · simp only [verify.Lincomb.sum, hstate, hwords, bind_tc_ok, hcall]
    rfl
  · simpa only [alloc.vec.Vec.deref, hvalues] using hrep

private theorem lincomb_sum_scalar [e : KzgExternals] (hblst : BlstCorrect e)
    (self : verify.Lincomb) (hstate : self.msm = none)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  obtain ⟨point, next, hcall, hrep⟩ := hblst.lincomb ps fs self.scratch hlen hpv hfv
  refine ⟨point, {self with scratch := next}, ?_, hrep⟩
  simp only [verify.Lincomb.sum, hstate, blst_ops.g1_lincomb, hcall, bind_tc_ok]
  rfl

private theorem lincomb_sum_raw [e : KzgExternals] (hmsm : Msm8Correct) (hblst : BlstCorrect e)
    (self : verify.Lincomb) (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  cases hstate : self.msm with
  | none => exact lincomb_sum_scalar hblst self hstate ps fs hlen hpv hfv
  | some state => exact lincomb_sum_kernel hmsm self state hstate ps fs hlen hpv hfv

private theorem lincomb_encoded [KzgExternals]
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.Lincomb)
    (hsum : ps.val.length = fs.val.length →
      (∀ p ∈ ps.val, G1AffineValid p) → (∀ f ∈ fs.val, FrReduced f) →
      ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs) =
        ok (point, scratch') ∧
        G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray)) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) := by
  have hlen : (alloc.vec.Vec.deref ps).val.length = (alloc.vec.Vec.deref fs).val.length := by
    simp only [alloc.vec.Vec.deref, hps, hfs, List.length_map, _root_.Array.length_toList, hsize]
  have hpv : ∀ p ∈ (alloc.vec.Vec.deref ps).val, G1AffineValid p := by
    intro p hp
    simp only [alloc.vec.Vec.deref, hps] at hp
    obtain ⟨q, hq, rfl⟩ := List.mem_map.mp hp
    exact g1Affine_valid (hvalid q (_root_.Array.mem_toList_iff.mp hq))
  have hfv : ∀ f ∈ (alloc.vec.Vec.deref fs).val, FrReduced f := by
    intro f hf
    simp only [alloc.vec.Vec.deref, hfs] at hf
    obtain ⟨q, _, rfl⟩ := List.mem_map.mp hf
    exact frEncode_reduced q
  obtain ⟨point, scratch', hcall, hrep⟩ := hsum hlen hpv hfv
  have hreadp : (ps.val.map g1ReadAffine).toArray =
      points.map (fun p => g1ReadAffine (g1Affine p)) := by
    simp only [hps, List.map_map, ← List.map_toArray,
      _root_.Array.toArray_toList, Function.comp_def]
  have hreadf : (fs.val.map frRead).toArray = scalars := by
    simp only [hfs, List.map_map, Function.comp_def, frRead_frEncode,
      List.map_id', _root_.Array.toArray_toList]
  rw [hreadp, hreadf] at hrep
  have hvj : ∀ j, j < points.size → G1Valid points[j]! := by
    intro j hj
    rw [getElem!_pos points j hj]
    exact hvalid _ (_root_.Array.getElem_mem hj)
  have hget : ∀ j (hj : j < points.size),
      (points.map (fun p => g1ReadAffine (g1Affine p)))[j]! =
        g1ReadAffine (g1Affine points[j]!) := by
    intro j hj
    rw [getElem!_pos _ j (by simpa using hj), _root_.Array.getElem_map,
      getElem!_pos points j hj]
  have hn : (if points.size ≤ scalars.size then points.size else scalars.size) ≤
      points.size := by split <;> omega
  obtain ⟨_, _, hinf, haff⟩ := g1_msm_congr points
    (points.map (fun p => g1ReadAffine (g1Affine p))) scalars (by simp)
    (fun j hj => hvj j (Nat.lt_of_lt_of_le hj hn))
    (fun j hj => by
      have hjp := Nat.lt_of_lt_of_le hj hn
      rw [hget j hjp]
      exact (g1ReadAffine_g1Affine_matches (hvj j hjp)).1.symm)
    (fun j hj => by
      have hjp := Nat.lt_of_lt_of_le hj hn
      rw [hget j hjp]
      exact (g1ReadAffine_g1Affine_matches (hvj j hjp)).2.symm)
  exact ⟨point, scratch', hcall, g1Rep_trans hrep hinf.symm haff.symm⟩

private theorem lincomb_sum_encoded [e : KzgExternals] (hmsm : Msm8Correct) (h : ExternalsCorrect e)
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.Lincomb) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) := by
  exact lincomb_encoded ps fs points scalars hps hfs hsize hvalid scratch
    (lincomb_sum_raw hmsm h.blst scratch (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs))

private theorem msm8_default_ok : ∃ state, msm8.Msm8.Insts.CoreDefaultDefault.default = ok state := by
  simp only [msm8.Msm8.Insts.CoreDefaultDefault.default,
    msm8.store.PointStore.Insts.CoreDefaultDefault.default, msm8.store.PointStore.new,
    msm8.buckets.Buckets.Insts.CoreDefaultDefault.default,
    msm8.pairs.BatchedAdds.Insts.CoreDefaultDefault.default,
    alloc.vec.Vec.Insts.CoreDefaultDefault.default, bind_tc_ok]
  exact ⟨_, rfl⟩

theorem lincomb_new_route [e : KzgExternals] :
    ∃ self, verify.Lincomb.new = ok self ∧ self.msm.isSome = e.simdAvailable := by
  obtain ⟨state, hs⟩ := msm8_default_ok
  cases hsimd : e.simdAvailable <;>
    simp only [verify.Lincomb.new, blst_ops.LincombScratch.new, ifma_available, hsimd,
      bind_tc_ok, Bool.false_eq_true, if_false, if_true, hs] <;>
    exact ⟨_, rfl, rfl⟩

theorem lincomb_new_ok [e : KzgExternals] : ∃ self, verify.Lincomb.new = ok self := by
  obtain ⟨self, hnew, _⟩ := lincomb_new_route (e := e)
  exact ⟨self, hnew⟩

theorem lincomb_new_isSome [e : KzgExternals] (self : verify.Lincomb)
    (hnew : verify.Lincomb.new = ok self) : self.msm.isSome = e.simdAvailable := by
  obtain ⟨created, hcreated, hroute⟩ := lincomb_new_route (e := e)
  have he : created = self := Result.ok.inj (hcreated.symm.trans hnew)
  exact he ▸ hroute

theorem lincomb_sum_route [e : KzgExternals] (self next : verify.Lincomb)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : self.sum ps fs = ok (point, next)) : next.msm.isSome = self.msm.isSome := by
  exact Routes.lincomb_sum_route self next ps fs point hcall

theorem lincomb_sum_kernel_external_independent (e e' : KzgExternals)
    (self : verify.Lincomb) (state : msm8.Msm8) (hstate : self.msm = some state)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr) :
    @verify.Lincomb.sum e self ps fs = @verify.Lincomb.sum e' self ps fs := by
  simp only [verify.Lincomb.sum, hstate]

private theorem lincomb_sum_kernel_preserves [e : KzgExternals] (hmsm : Msm8Correct)
    (self : verify.Lincomb) (state : msm8.Msm8) (hstate : self.msm = some state)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧ next.msm.isSome = true ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  obtain ⟨point, next, hcall, hrep⟩ := lincomb_sum_kernel hmsm self state hstate ps fs hlen hpv hfv
  refine ⟨point, next, hcall, ?_, hrep⟩
  simpa only [hstate, Option.isSome_some] using lincomb_sum_route self next ps fs point hcall

private theorem lincomb_kernel_encoded [e : KzgExternals] (hmsm : Msm8Correct)
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.Lincomb) (state : msm8.Msm8) (hroute : scratch.msm = some state) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) ∧ scratch'.msm.isSome = true := by
  obtain ⟨point, scratch', hcall, hrep⟩ :=
    lincomb_encoded ps fs points scalars hps hfs hsize hvalid scratch
      (lincomb_sum_kernel hmsm scratch state hroute
        (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs))
  refine ⟨point, scratch', hcall, hrep, ?_⟩
  simpa only [hroute, Option.isSome_some] using
    lincomb_sum_route scratch scratch' _ _ point hcall


theorem verify_lincomb_raw_refinement [e : KzgExternals] (hblst : BlstCorrect e)
    (self : verify.Lincomb) (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  exact lincomb_sum_raw msm8_correct hblst self ps fs hlen hpv hfv

theorem verify_lincomb_refinement [e : KzgExternals] (h : ExternalsCorrect e)
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.Lincomb) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) := by
  exact lincomb_sum_encoded msm8_correct h ps fs points scalars hps hfs hsize hvalid scratch

theorem verify_lincomb_raw_kernel_refinement [e : KzgExternals]
    (self : verify.Lincomb) (state : msm8.Msm8) (hstate : self.msm = some state)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧ next.msm.isSome = true ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  exact lincomb_sum_kernel_preserves msm8_correct self state hstate ps fs hlen hpv hfv

theorem verify_lincomb_kernel_refinement [e : KzgExternals]
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.Lincomb) (state : msm8.Msm8) (hroute : scratch.msm = some state) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) ∧ scratch'.msm.isSome = true := by
  exact lincomb_kernel_encoded msm8_correct ps fs points scalars hps hfs hsize hvalid scratch state hroute

end LeanBlsSimd.Kzg
