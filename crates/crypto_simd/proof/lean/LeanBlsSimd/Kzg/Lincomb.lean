import LeanBlsSimd.Portable.Msm.Refines
import LeanBlsSimd.Kzg.Fr.ByteEncode
import LeanBlsSimd.Msm8.Refines
import LeanBlsSimd.Msm8.PlainWords
import LeanBlsSimd.Kzg.PairingRepresentation
import LeanBlsSimd.Kzg.CurveWorkState
import LeanBlsSimd.Kzg.PortableMsmContract
import LeanBlsSimd.Kzg.ScalarContracts

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls
open LeanBlsSimd.Portable.Msm (portable_msm_correct)
noncomputable section

namespace LeanBlsSimd.Kzg

open scoped EthLib.Cryptography.Bls.Fr

set_option maxHeartbeats 4000000
set_option exponentiation.threshold 512

private abbrev MsmWord := Aeneas.Std.Array U64 4#usize

private theorem words_four_injective (a b : MsmWord)
    (h : limbs a.val = limbs b.val) : a = b := by
  obtain ⟨a0, a1, a2, a3, ha⟩ := List.length_eq_four.mp a.property
  obtain ⟨b0, b1, b2, b3, hb⟩ := List.length_eq_four.mp b.property
  simp only [ha, hb, limbs, List.foldr_cons, List.foldr_nil] at h
  have ha0 := a0.hBounds; have ha1 := a1.hBounds
  have ha2 := a2.hBounds; have ha3 := a3.hBounds
  have hb0 := b0.hBounds; have hb1 := b1.hBounds
  have hb2 := b2.hBounds; have hb3 := b3.hBounds
  norm_num [UScalarTy.numBits] at ha0 ha1 ha2 ha3 hb0 hb1 hb2 hb3
  have h0 : a0.val = b0.val := by omega
  have h1 : a1.val = b1.val := by omega
  have h2 : a2.val = b2.val := by omega
  have h3 : a3.val = b3.val := by omega
  apply Subtype.ext
  rw [ha, hb, UScalar.eq_of_val_eq h0, UScalar.eq_of_val_eq h1,
    UScalar.eq_of_val_eq h2, UScalar.eq_of_val_eq h3]

private theorem frEncode_frRead (f : blst.blst_fr) (hf : FrReduced f) :
    frEncode (frRead f) = f := by
  have hm : Fr.ofNat ((frRead f).val * 2^256) = frRead f * Fr.ofNat (2^256) := by
    apply Fin.ext
    norm_num [Fr.ofNat, Fin.val_mul, Nat.mul_mod, Fr.modulus]
  have hprod : frRead f * Fr.ofNat (2^256) = Fr.ofNat (limbs f.l.val) := by
    unfold frRead
    have hc : (Fr.ofNat (2^256))⁻¹ * Fr.ofNat (2^256) = (1 : Fr) :=
      inv_mul_cancel₀ (by decide)
    rw [Fr.inverse_eq_inv, mul_assoc, hc]
    exact mul_one (Fr.ofNat (limbs f.l.val))
  have hn : ((frRead f).val * 2^256) % Fr.modulus = limbs f.l.val := by
    have hv := congrArg Fin.val (hm.trans hprod)
    change ((frRead f).val * 2^256) % Fr.modulus = limbs f.l.val % Fr.modulus at hv
    simpa only [Nat.mod_eq_of_lt hf] using hv
  cases f with
  | mk fw =>
    unfold frEncode
    congr 1
    apply words_four_injective
    rw [limbs_words_four _ (Nat.lt_trans (Nat.mod_lt _ Fr.modulus_pos) (by decide))]
    exact hn

private theorem portable_words_loop
    (fs : Slice blst.blst_fr) (ws : alloc.vec.Vec (MsmWord))
    (i : Usize) (hi : i.val ≤ fs.val.length)
    (hsize : ws.val.length = i.val) (hf : ∀ f ∈ fs.val, FrReduced f) :
    ∃ out, verify.CurveWork.sum_loop fs ws i = ok out ∧
      out.val = ws.val ++ (fs.val.drop i.val).map (fun f => words 4#usize (frRead f).val) := by
  induction hn : fs.val.length - i.val generalizing ws i with
  | zero =>
    have he : i.val = fs.val.length := by omega
    have hstop : ¬ i < Slice.len fs := by simp [he]
    refine ⟨ws, ?_, by simp [he]⟩
    rw [verify.CurveWork.sum_loop, loop.eq_1]
    simp only [verify.CurveWork.sum_loop.body, hstop, if_false]
  | succ n ih =>
    have hlt : i.val < fs.val.length := by omega
    have htest : i < Slice.len fs := by simpa using hlt
    let f := fs.val[i.val]'hlt
    have hindex : Slice.index_usize fs i = ok f := by simp [Slice.index_usize, hlt, f]
    have hcanon := frEncode_frRead f (hf f (List.getElem_mem hlt))
    have hword : fr.fr_to_words f = ok (words 4#usize (frRead f).val) := by
      rw [← hcanon]
      simpa only [frRead_frEncode] using FrScalar.fr_to_words_refines (frRead f)
    have hpushbound : ws.val.length < Usize.max := by
      have := fs.property
      omega
    obtain ⟨nextWords, hpush, hw⟩ := WP.spec_imp_exists
      (alloc.vec.Vec.push_spec ws (words 4#usize (frRead f).val) hpushbound)
    have hin : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have := (Slice.len fs).hBounds
      simp only [Slice.len_val, Slice.length] at this
      omega
    let i' : Usize := UScalar.ofNatCore (i.val + 1) hin
    have hi' : i'.val = i.val + 1 := rfl
    have hadd : i + 1#usize = ok i' := add_ok _ _ hin
    obtain ⟨out, hloop, hout⟩ := ih nextWords i' (by omega)
      (by simp [hw, hsize, hi']) (by omega)
    refine ⟨out, ?_, ?_⟩
    · rw [verify.CurveWork.sum_loop, loop.eq_1]
      simp only [verify.CurveWork.sum_loop.body, htest, if_true, hindex, bind_tc_ok,
        hword, hpush, hadd]
      exact hloop
    · rw [List.drop_eq_getElem_cons hlt]
      simpa only [List.map_cons, hw, hi', List.append_assoc, List.singleton_append] using hout

private theorem portable_words
    (fs : Slice blst.blst_fr) (ws : alloc.vec.Vec (MsmWord))
    (hf : ∀ f ∈ fs.val, FrReduced f) :
    ∃ out,
      (do let cleared ← alloc.vec.Vec.clear Global ws
          verify.CurveWork.sum_loop fs cleared 0#usize) = ok out ∧
      out.val.length = fs.val.length ∧
      out.val.map (fun w => limbs w.val) = fs.val.map (fun f => (frRead f).val) := by
  let empty := alloc.vec.Vec.new (MsmWord)
  obtain ⟨out, hloop, hout⟩ := portable_words_loop fs empty 0#usize (by simp) rfl hf
  refine ⟨out, ?_, ?_, ?_⟩
  · simpa only [alloc.vec.Vec.clear, bind_tc_ok] using hloop
  · simp [hout, empty]
  · simp only [hout, empty, List.nil_append, UScalar.ofNatCore_val_eq,
      List.drop_zero, List.map_map, Function.comp_def]
    congr 1
    funext f
    exact limbs_words_four _ (Nat.lt_trans (frRead f).isLt (by decide))

private def Msm8Correct : Prop :=
  ∀ (state : msm8.Msm8) (ps : Slice blst.blst_p1_affine)
    (ws : Slice (MsmWord)),
    ps.val.length = ws.val.length → (∀ p ∈ ps.val, G1AffineValid p) →
    (∀ w ∈ ws.val, limbs w.val < Fr.modulus) →
    ∃ point state', state.msm ps ws = ok (point, state') ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray
        (ws.val.map (fun w => Fr.ofNat (limbs w.val))).toArray)

private theorem msm8_correct : Msm8Correct := by
  intro state ps ws hlen hpv hwords
  exact LeanBlsSimd.Msm8.msm_refinement state ps ws hlen hpv hwords

private theorem word_values (fs : Slice blst.blst_fr)
    (ws : alloc.vec.Vec (MsmWord))
    (hval : ws.val.map (fun w => limbs w.val) = fs.val.map (fun f => (frRead f).val)) :
    (∀ w ∈ ws.val, limbs w.val < Fr.modulus) ∧
      ws.val.map (fun w => Fr.ofNat (limbs w.val)) = fs.val.map frRead := by
  constructor
  · intro w hw
    have hmem : limbs w.val ∈ ws.val.map (fun w => limbs w.val) := List.mem_map.mpr ⟨w, hw, rfl⟩
    rw [hval] at hmem
    obtain ⟨f, _, heq⟩ := List.mem_map.mp hmem
    rw [← heq]
    exact (frRead f).isLt
  · have hof (x : Fr) : Fr.ofNat x.val = x := by
      apply Fin.ext
      exact Nat.mod_eq_of_lt x.isLt
    have h := congrArg (List.map Fr.ofNat) hval
    simpa only [List.map_map, Function.comp_def, hof] using h

private theorem lincomb_sum_kernel [RuntimeFeatures]
    (state : msm8.Msm8) (scratch : alloc.vec.Vec (MsmWord))
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, (verify.CurveWork.Lanes state scratch).sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  obtain ⟨ws, hwords, hwlen, hwval⟩ := PlainWords.plain_words_correct fs scratch hfv
  obtain ⟨hwbound, hvalues⟩ := word_values fs ws hwval
  obtain ⟨point, next, hcall, hrep⟩ := msm8_correct state ps (alloc.vec.Vec.deref ws)
    (by simpa only [alloc.vec.Vec.deref, hwlen] using hlen) hpv hwbound
  refine ⟨point, .Lanes next ws, ?_, ?_⟩
  · simp only [verify.CurveWork.sum, hwords, bind_tc_ok, hcall]
    rfl
  · simpa only [alloc.vec.Vec.deref, hvalues] using hrep

private theorem lincomb_sum_portable [RuntimeFeatures]
    (state : portable.msm.Msm) (lines : portable.pairing.PairingLines)
    (scratch : alloc.vec.Vec (MsmWord))
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, (verify.CurveWork.Portable state lines scratch).sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  obtain ⟨ws, hwords, hwlen, hwval⟩ := portable_words fs scratch hfv
  obtain ⟨hwbound, hvalues⟩ := word_values fs ws hwval
  obtain ⟨point, next, hcall, hrep⟩ := portable_msm_correct.msm state ps (alloc.vec.Vec.deref ws)
    (by simpa only [alloc.vec.Vec.deref, hwlen] using hlen) hpv hwbound
  refine ⟨point, .Portable next lines ws, ?_, ?_⟩
  · simp only [alloc.vec.Vec.clear, bind_tc_ok] at hwords
    simp only [verify.CurveWork.sum, alloc.vec.Vec.clear, bind_tc_ok, hwords, hcall]
    rfl
  · simpa only [alloc.vec.Vec.deref, hvalues] using hrep

/-- Both routes refine MSM for all reusable workspaces and reduced input scalars. -/
theorem verify_lincomb_raw_refinement [RuntimeFeatures]
    (self : verify.CurveWork) (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  cases self with
  | Lanes state ws => exact lincomb_sum_kernel state ws ps fs hlen hpv hfv
  | Portable state lines ws => exact lincomb_sum_portable state lines ws ps fs hlen hpv hfv

/-- The MSM result and preservation of persistent workspace fields. -/
theorem curveWork_sum_raw [RuntimeFeatures]
    (self : verify.CurveWork) (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) ∧
      CurveWork.isLanes next = CurveWork.isLanes self ∧
      CurveWork.pairingLines next = CurveWork.pairingLines self := by
  obtain ⟨point, next, hcall, hrep⟩ := verify_lincomb_raw_refinement self ps fs hlen hpv hfv
  exact ⟨point, next, hcall, hrep, CurveWork.sum_frame self next ps fs point hcall⟩

private theorem lincomb_encoded [RuntimeFeatures]
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.CurveWork)
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

theorem verify_lincomb_refinement [RuntimeFeatures]
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.CurveWork) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) := by
  exact lincomb_encoded ps fs points scalars hps hfs hsize hvalid scratch
    (verify_lincomb_raw_refinement scratch
      (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs))

theorem verify_lincomb_raw_kernel_refinement [RuntimeFeatures]
    (self : verify.CurveWork) (hstate : CurveWork.isLanes self = true)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr)
    (hlen : ps.val.length = fs.val.length) (hpv : ∀ p ∈ ps.val, G1AffineValid p)
    (hfv : ∀ f ∈ fs.val, FrReduced f) :
    ∃ point next, self.sum ps fs = ok (point, next) ∧ CurveWork.isLanes next = true ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
  cases self with
  | Lanes state ws =>
    obtain ⟨point, next, hcall, hrep⟩ := lincomb_sum_kernel state ws ps fs hlen hpv hfv
    exact ⟨point, next, hcall, (CurveWork.sum_frame _ next ps fs point hcall).1, hrep⟩
  | Portable state lines ws => cases hstate

theorem verify_lincomb_kernel_refinement [RuntimeFeatures]
    (ps : alloc.vec.Vec blst.blst_p1_affine) (fs : alloc.vec.Vec blst.blst_fr)
    (points : _root_.Array G1) (scalars : _root_.Array Fr)
    (hps : ps.val = points.toList.map g1Affine) (hfs : fs.val = scalars.toList.map frEncode)
    (hsize : points.size = scalars.size) (hvalid : ∀ p ∈ points, G1Valid p)
    (scratch : verify.CurveWork) (hroute : CurveWork.isLanes scratch = true) :
    ∃ point scratch', scratch.sum (alloc.vec.Vec.deref ps)
      (alloc.vec.Vec.deref fs) = ok (point, scratch') ∧
      G1Rep point (G1.msm points scalars) ∧ CurveWork.isLanes scratch' = true := by
  have hsum : ps.val.length = fs.val.length →
      (∀ p ∈ ps.val, G1AffineValid p) → (∀ f ∈ fs.val, FrReduced f) → ∃ point next,
      scratch.sum (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs) = ok (point, next) ∧
      G1Rep point (G1.msm (ps.val.map g1ReadAffine).toArray (fs.val.map frRead).toArray) := by
    intro hlen hpv hfv
    obtain ⟨point, next, hcall, _, hrep⟩ := verify_lincomb_raw_kernel_refinement scratch hroute
      (alloc.vec.Vec.deref ps) (alloc.vec.Vec.deref fs) hlen hpv hfv
    exact ⟨point, next, hcall, hrep⟩
  obtain ⟨point, next, hcall, hrep⟩ := lincomb_encoded ps fs points scalars
    hps hfs hsize hvalid scratch hsum
  exact ⟨point, next, hcall, hrep, (CurveWork.sum_frame scratch next _ _ point hcall).1.trans hroute⟩

/-- A successful sum keeps the workspace route. -/
theorem lincomb_sum_route [RuntimeFeatures] (self next : verify.CurveWork)
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr) (point : blst.blst_p1)
    (hcall : self.sum ps fs = ok (point, next)) :
    CurveWork.isLanes next = CurveWork.isLanes self :=
  (CurveWork.sum_frame self next ps fs point hcall).1

/-- The lane route does not inspect CPU feature selection. -/
theorem lincomb_sum_kernel_runtime_independent (cpu cpu' : RuntimeFeatures)
    (state : msm8.Msm8) (scratch : alloc.vec.Vec (Aeneas.Std.Array U64 4#usize))
    (ps : Slice blst.blst_p1_affine) (fs : Slice blst.blst_fr) :
    @verify.CurveWork.sum cpu (.Lanes state scratch) ps fs =
      @verify.CurveWork.sum cpu' (.Lanes state scratch) ps fs := by
  rfl

end LeanBlsSimd.Kzg
