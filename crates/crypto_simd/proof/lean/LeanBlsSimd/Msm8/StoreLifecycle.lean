import LeanBlsSimd.Msm8.Store

open Aeneas Aeneas.Std Result ControlFlow Error
open silver_crypto_simd silver_crypto_simd.bls
noncomputable section


namespace LeanBlsSimd

theorem pointStore_new_refines : msm8.store.PointStore.new =
    ok { rows := alloc.vec.Vec.new (Array U64 8#usize), len := 0#usize } := rfl

theorem pointStore_capacity_refines (s : msm8.store.PointStore) :
    msm8.store.PointStore.capacity s = ok
      (UScalar.ofNatCore (s.rows.val.length / 2)
        (lt_of_le_of_lt (Nat.div_le_self _ _) (vec_length_bound s.rows))) := by
  unfold msm8.store.PointStore.capacity
  rw [div_ok _ _ (by decide)]
  rfl

theorem pointStore_allocate_refines (s : msm8.store.PointStore)
    (hcap : s.len.val < s.rows.val.length / 2)
    (h32 : s.len.val < 2 ^ 32) :
    ∃ n : Usize, n.val = s.len.val + 1 ∧
      msm8.store.PointStore.allocate s =
        ok (UScalar.ofNatCore s.len.val h32, { s with len := n }) := by
  have hs := vec_length_bound s.rows
  have hsum : s.len.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    change s.len.val + 1 < _
    have := Nat.div_le_self s.rows.val.length 2
    omega
  let n : Usize := UScalar.ofNatCore (s.len.val + 1) hsum
  refine ⟨n, by simp [n], ?_⟩
  have hsub : n - 1#usize = ok s.len := by
    rw [sub_ok _ _ (by simp [n])]
    congr 1
  have hcast : UScalar.cast .U32 s.len = (UScalar.ofNatCore s.len.val h32 : U32) := by
    apply UScalar.eq_of_val_eq
    simp only [UScalar.cast_val_eq, UScalar.ofNatCore_val_eq]
    exact Nat.mod_eq_of_lt h32
  simp only [msm8.store.PointStore.allocate, pointStore_capacity_refines,
    bind_tc_ok, UScalar.lt_equiv, UScalar.ofNatCore_val_eq, hcap, massert]
  rw [add_ok _ _ hsum]
  change (do let i ← n - 1#usize; let j ← lift (UScalar.cast .U32 i); ok (j, { s with len := n })) = _
  rw [hsub]
  simp [hcast, lift]


theorem clone_limbs_eq (row : Array U64 8#usize) :
    core.array.CloneArray.clone core.clone.CloneU64 row = ok row := by
  obtain ⟨a, ha, he⟩ := WP.spec_imp_exists
    (core.array.CloneArray.clone_spec core.clone.CloneU64 row (by intro x hx; rfl))
  simpa only [← he] using ha

def resetRows (rows : List Limbs) (capacity : ℕ) : List Limbs :=
  rows ++ List.replicate (2 * capacity - rows.length) (Vector.replicate LIMBS 0)

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
  · obtain ⟨v, hv, hval⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
      (core.clone.CloneArray 8#usize core.clone.CloneU64) s.rows n
      zeroRow (clone_limbs_eq _))
    refine ⟨{ rows := v, len := 0#usize }, ?_, ?_, rfl⟩
    · simp only [msm8.store.PointStore.reset, hmul, bind_tc_ok, UScalar.lt_equiv,
        alloc.vec.Vec.len_val, hn, h, if_true]
      change (do
        let rows ← alloc.vec.Vec.resize (core.clone.CloneArray 8#usize core.clone.CloneU64) s.rows n zeroRow
        ok ({ rows := rows, len := 0#usize } : msm8.store.PointStore)) = _
      rw [hv]
      rfl
    · rw [hval]
      simp [List.resize, hn, List.take_of_length_le (Nat.le_of_lt h)]
  · refine ⟨{ s with len := 0#usize }, ?_, ?_, rfl⟩
    · simp [msm8.store.PointStore.reset, hmul, hn, UScalar.lt_equiv, h]
    · simp [Nat.sub_eq_zero_of_le (Nat.le_of_not_gt h)]

theorem pointStore_reset_refines (s : msm8.store.PointStore) (capacity : Usize)
    (hcap : 2 * capacity.val < 2 ^ UScalarTy.Usize.numBits) :
    ∃ out, msm8.store.PointStore.reset s capacity = ok out ∧
      pointRows out = resetRows (pointRows s) capacity.val ∧ out.len = 0#usize := by
  obtain ⟨out, ho, hr, hl⟩ := pointStore_reset_raw s capacity hcap
  refine ⟨out, ho, ?_, hl⟩
  have hz : ofArray ofU64 zeroRow = Vector.replicate LIMBS (0 : UInt64) := by
    apply Vector.ext
    intro i hi
    have hi8 : i < 8 := hi
    interval_cases i <;> simp [getElem_ofArray, zeroRow, Array.repeat, LIMBS] <;> rfl
  simp [pointRows, resetRows, hr, hz]

end LeanBlsSimd
