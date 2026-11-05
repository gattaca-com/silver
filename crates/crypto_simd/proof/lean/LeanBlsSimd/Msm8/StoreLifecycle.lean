import LeanBlsSimd.Msm8.Store

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


namespace LeanBlsSimd

theorem pointStore_capacity_refines (s : msm8.store.PointStore) :
    msm8.store.PointStore.capacity s = ok
      (UScalar.ofNatCore (s.rows.val.length / 2)
        (lt_of_le_of_lt (Nat.div_le_self _ _) (vec_length_bound s.rows))) := by
  unfold msm8.store.PointStore.capacity
  rw [div_ok _ _ (by decide)]
  rfl


theorem clone_limbs_eq (row : Array U64 8#usize) :
    core.array.CloneArray.clone core.clone.CloneU64 row = ok row := by
  obtain ⟨a, ha, he⟩ := spec_imp_exists
    (core.array.CloneArray.clone_spec core.clone.CloneU64 row (by intro x hx; rfl))
  simpa only [← he] using ha

def zeroRow : Array U64 8#usize := Array.repeat 8#usize 0#u64

theorem pointStore_reset_raw (s : msm8.store.PointStore) (capacity : Usize)
    (hcap : 2 * capacity.val < 2 ^ UScalarTy.Usize.numBits) :
    ∃ out, msm8.store.PointStore.reset s capacity = ok out ∧
      out.rows.val = s.rows.val ++ List.replicate (2 * capacity.val - s.rows.val.length)
        zeroRow ∧ out.len = 0#usize := by
  let n : Usize := UScalar.ofNatCore (2 * capacity.val) hcap
  have hn : n.val = 2 * capacity.val := by simp [n]
  have hmul : (2#usize * capacity : Result Usize) = ok n := by
    rw [mul_ok (2#usize) capacity hcap]
    rfl
  by_cases h : s.rows.val.length < 2 * capacity.val
  · obtain ⟨v, hv, hval⟩ := spec_imp_exists (alloc.vec.Vec.resize_spec
      (core.clone.CloneArray 8#usize core.clone.CloneU64) s.rows n
      zeroRow (clone_limbs_eq _))
    refine ⟨{ rows := v, len := 0#usize }, ?_, ?_, rfl⟩
    · simp only [msm8.store.PointStore.reset, hmul, bind_ok, UScalar.lt_equiv,
        alloc.vec.Vec.len_val, hn, h, ite_true]
      change (do
        let rows ← alloc.vec.Vec.resize (core.clone.CloneArray 8#usize core.clone.CloneU64) s.rows n zeroRow
        ok ({ rows := rows, len := 0#usize } : msm8.store.PointStore)) = _
      rw [hv]
      (simp only [bind_tc_ok] )
    · rw [hval]
      simp [List.resize, hn, List.take_of_length_le (Nat.le_of_lt h)]
  · refine ⟨{ s with len := 0#usize }, ?_, ?_, rfl⟩
    · simp [msm8.store.PointStore.reset, hmul, hn, UScalar.lt_equiv, h]
    · simp [Nat.sub_eq_zero_of_le (Nat.le_of_not_gt h)]

end LeanBlsSimd
