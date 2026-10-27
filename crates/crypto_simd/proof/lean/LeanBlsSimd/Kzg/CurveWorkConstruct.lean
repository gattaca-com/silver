import LeanBlsSimd.Portable.Fp.Correct
import LeanBlsSimd.Kzg.PairingTable

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private theorem msm8_default_ok :
    ∃ state, msm8.Msm8.Insts.CoreDefaultDefault.default = ok state := by
  simp only [msm8.Msm8.Insts.CoreDefaultDefault.default,
    msm8.store.PointStore.Insts.CoreDefaultDefault.default, msm8.store.PointStore.new,
    msm8.buckets.Buckets.Insts.CoreDefaultDefault.default,
    msm8.pairs.BatchedAdds.Insts.CoreDefaultDefault.default,
    alloc.vec.Vec.Insts.CoreDefaultDefault.default, bind_tc_ok]
  exact ⟨_, rfl⟩

private theorem portableMsm_default_ok :
    ∃ state, portable.msm.Msm.Insts.CoreDefaultDefault.default = ok state := by
  simp only [portable.msm.Msm.Insts.CoreDefaultDefault.default,
    portable.msm.store.PointStore.Insts.CoreDefaultDefault.default,
    portable.msm.buckets.Buckets.Insts.CoreDefaultDefault.default,
    portable.msm.pairs.BatchedAdds.Insts.CoreDefaultDefault.default,
    alloc.vec.Vec.Insts.CoreDefaultDefault.default, bind_tc_ok]
  exact ⟨_, rfl⟩

theorem curveWork_scalar_refinement [RuntimeFeatures] :
    ∃ work, verify.CurveWork.scalar = ok work ∧ CurveWorkInvariant work ∧
      CurveWork.isLanes work = false := by
  obtain ⟨msm,hmsm⟩ := portableMsm_default_ok
  refine ⟨.Scalar msm (alloc.vec.Vec.new _), ?_, trivial, rfl⟩
  simp only [verify.CurveWork.scalar, hmsm, bind_tc_ok]

theorem curveWork_new_refinement [cpu : RuntimeFeatures] :
    ∃ work, verify.CurveWork.new = ok work ∧ CurveWorkInvariant work ∧
      CurveWork.isLanes work = cpu.simdAvailable := by
  cases hs : cpu.simdAvailable with
  | false =>
    obtain ⟨work,he,hi,hr⟩ := curveWork_scalar_refinement
    exact ⟨work, by simp only [verify.CurveWork.new, ifma_available, hs, bind_tc_ok,
      Bool.false_eq_true, if_false, he], hi, hr⟩
  | true =>
    obtain ⟨msm,he⟩ := msm8_default_ok
    refine ⟨.Lanes msm (alloc.vec.Vec.new _), ?_, trivial, rfl⟩
    simp only [verify.CurveWork.new, ifma_available, hs, bind_tc_ok, if_true, he]

end LeanBlsSimd.Kzg
