import LeanBlsSimd.Portable.Msm.Input
import LeanBlsSimd.Portable.Msm.Finish
import LeanBlsSimd.Msm8.InputOutput

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section

namespace LeanBlsSimd.Portable.Msm
open EthLib.Cryptography Bls BucketsRefines
open LeanBlsSimd.Msm8
local instance finiteCoreAffineInhabited : Inhabited blst.blst_p1_affine := ⟨Kzg.g1Affine G1.zero⟩

def finiteCore [RuntimeFeatures] (self : portable.msm.Msm) (points : Slice blst.blst_p1_affine)
    (scalars : Slice ScalarWords) : Result (portable.msm.Msm × portable.g1.G1) := do
  let filtered ← Input.filterPrefix self points scalars
  let n := alloc.vec.Vec.len filtered.finite_points
  if n = 0#usize then
    ok (filtered, portable.g1.G1.INFINITY)
  else
    let prepared ← initialise filtered
    finish prepared

theorem finiteCore_correct [RuntimeFeatures]
    (state : portable.msm.Msm) (points : Slice blst.blst_p1_affine) (scalars : Slice ScalarWords)
    (halign : points.val.length = scalars.val.length)
    (hp : ∀ p ∈ points.val, Kzg.G1AffineValid p)
    (hs : ∀ s ∈ scalars.val, Kzg.limbs s.val < 2 ^ 255)
    (hchunk : points.val.length ≤ portable.msm.CHUNK.val) :
    ∃ next out, finiteCore state points scalars = ok (next, out) ∧
      Group.PointRep out (((points.val.zip scalars.val).map inputContribution).sum) := by
  obtain ⟨ps, ss, hfilter, hzip, haligned, hlength, _, hpoints, hscalars⟩ :=
    Input.filter_prefix_correct state points scalars halign hp hs (by unfold portable.msm.CHUNK at hchunk; change points.val.length ≤ 4096 at hchunk; omega)
  let filtered : portable.msm.Msm := {state with finite_points := ps, finite_scalars := ss}
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
    refine ⟨filtered, portable.g1.G1.INFINITY, ?_, ?_⟩
    · simp only [finiteCore, hfilter, bind_tc_ok, hn, if_true]
      rfl
    · rw [hzero]
      exact Group.infinity_rep
  · have hn : alloc.vec.Vec.len ps ≠ 0#usize := by
      intro he
      apply hz
      exact congrArg UScalar.val he
    have hpositive : 1 ≤ filtered.finite_scalars.val.length := by
      change 1 ≤ ss.val.length
      omega
    have hbound : filtered.finite_scalars.val.length ≤ portable.msm.CHUNK.val := by
      change ss.val.length ≤ portable.msm.CHUNK.val
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
      finish_correct prepared filtered.finite_scalars.val.length values capacity contents _ hinitialised
    refine ⟨next, out, ?_, ?_⟩
    · simp only [finiteCore, hfilter, bind_tc_ok, hn, if_false]
      change (do let prepared ← initialise filtered; finish prepared) = _
      rw [hinit]
      exact hfinishEq
    · have hcontribution := (inputContribution_range_eq_zip ps.val ss.val haligned).trans hsum
      change Group.PointRep out (∑ i ∈ Finset.range ss.val.length, inputContribution (ps.val[i]!, ss.val[i]!)) at hrep
      rwa [hcontribution] at hrep

end LeanBlsSimd.Portable.Msm
