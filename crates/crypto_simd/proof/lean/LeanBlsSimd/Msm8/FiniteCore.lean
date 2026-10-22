import LeanBlsSimd.Msm8.Filter
import LeanBlsSimd.Msm8.Finish
import LeanBlsSimd.Msm8.InputOutput

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Msm8
open EthCryptographySpecs Bls BucketsRefines
local instance finiteCoreAffineInhabited : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

def finiteCore (self : msm8.Msm8) (points : Slice blst.blst_p1_affine)
    (scalars : Slice ScalarWords) : Result (msm8.Msm8 × g1x8.G1x8) := do
  let filtered ← filterPrefix self points scalars
  let n := alloc.vec.Vec.len filtered.finite_points
  if n = 0#usize then
    let out ← g1x8.G1x8.infinity
    ok (filtered, out)
  else
    let prepared ← initialise filtered
    finish prepared

theorem finiteCore_correct
    (state : msm8.Msm8) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hchunk : points.val.length ≤ 2 ^ 24) :
    ∃ next out, finiteCore state points scalars = ok (next, toG1x8 out) ∧
      out.PointRep 0 (((points.val.zip scalars.val).map inputContribution).sum) := by
  obtain ⟨ps, ss, hfilter, hzip, haligned, hlength, _, hpoints, hscalars⟩ :=
    filter_prefix_correct state points scalars halign hp hs (by omega)
  let filtered : msm8.Msm8 := {state with finite_points := ps, finite_scalars := ss}
  have hsum : ((ps.val.zip ss.val).map inputContribution).sum =
      ((points.val.zip scalars.val).map inputContribution).sum := by
    rw [hzip]
    exact filter_infinity_preserves_sum (points.val.zip scalars.val)
  by_cases hz : ps.val.length = 0
  · have hn : alloc.vec.Vec.len ps = 0#usize := by
      apply UScalar.eq_of_val_eq
      exact hz
    have hzero : ((points.val.zip scalars.val).map inputContribution).sum = 0 := by
      rw [← hsum, List.length_eq_zero_iff.mp hz]
      rfl
    refine ⟨filtered, G1x8.infinity, ?_, ?_⟩
    · simp only [finiteCore, hfilter, bind_tc_ok, hn, if_true, G1x8.infinity_refines]
      rfl
    · rw [hzero]
      exact WindowSums.infinity_pointRep 0
  · have hn : alloc.vec.Vec.len ps ≠ 0#usize := by
      intro he
      apply hz
      exact congrArg UScalar.val he
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
    obtain ⟨next, out, hfinishEq, hrep⟩ :=
      finish_correct prepared filtered.finite_scalars.val.length values capacity contents _ hpositive hinitialised
    refine ⟨next, out, ?_, ?_⟩
    · simp only [finiteCore, hfilter, bind_tc_ok, hn, if_false]
      change (do let prepared ← initialise filtered; finish prepared) = _
      rw [hinit]
      exact hfinishEq
    · have hcontribution := (inputContribution_range_eq_zip ps.val ss.val haligned).trans hsum
      change out.PointRep 0 (∑ i ∈ Finset.range ss.val.length, inputContribution (ps.val[i]!, ss.val[i]!)) at hrep
      rwa [hcontribution] at hrep

end LeanBlsSimd.Msm8
