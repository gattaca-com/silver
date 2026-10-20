import LeanBlsSimd.Refines.Basic

open Aeneas Aeneas.Std Result
open silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.PipelineControls

private def firstWithStride (stride n half : Usize) : Result Usize := do
  let i ← stride * n
  let mask ← half - 1#usize
  let j ← lift (n &&& mask)
  i - j

example : firstWithStride 2#usize = fft8.first_of_pair := rfl

private theorem firstWithStride_eval (stride n expected : Usize)
    (hmul : stride.val * n.val < 512)
    (hsub : n.val &&& 1 ≤ stride.val * n.val)
    (he : expected.val = stride.val * n.val - (n.val &&& 1)) :
    firstWithStride stride n 2#usize = ok expected := by
  rw [firstWithStride, LeanBlsSimd.mul_ok _ _ (by scalar_tac)]
  simp only [bind_tc_ok]
  rw [LeanBlsSimd.sub_ok _ _ (by decide)]
  simp only [bind_tc_ok, lift]
  rw [LeanBlsSimd.sub_ok _ _ (by simpa using hsub)]
  simp only [Result.ok.injEq]
  apply UScalar.eq_of_val_eq
  simpa using he.symm

private theorem baseline : fft8.first_of_pair 0#usize 2#usize = ok 0#usize ∧
    fft8.first_of_pair 1#usize 2#usize = ok 1#usize ∧
    fft8.first_of_pair 2#usize 2#usize = ok 4#usize := by
  refine ⟨?_, ?_, ?_⟩ <;>
    change firstWithStride 2#usize _ _ = _ <;>
    apply firstWithStride_eval <;> decide +kernel

-- The wrong stride aliases consecutive butterflies, so their operand storage overlaps.
theorem wrong_stride_aliases :
    firstWithStride 1#usize 0#usize 2#usize = ok 0#usize ∧
    firstWithStride 1#usize 1#usize 2#usize = ok 0#usize ∧
    firstWithStride 1#usize 1#usize 2#usize ≠ fft8.first_of_pair 1#usize 2#usize := by
  have first : firstWithStride 1#usize 0#usize 2#usize = ok 0#usize :=
    firstWithStride_eval _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)
  have next : firstWithStride 1#usize 1#usize 2#usize = ok 0#usize :=
    firstWithStride_eval _ _ _ (by decide +kernel) (by decide +kernel) (by decide +kernel)
  refine ⟨first, next, ?_⟩
  intro h
  rw [next, baseline.2.1] at h
  have he : (0#usize).val = (1#usize).val := congrArg UScalar.val (Result.ok.inj h)
  exact Nat.zero_ne_one he

example : True := by
  fail_if_success
    have : firstWithStride 1#usize 1#usize 2#usize =
        fft8.first_of_pair 1#usize 2#usize := by rfl
  trivial

#print axioms wrong_stride_aliases

end LeanBlsSimd.Kzg.Extender.PipelineControls
