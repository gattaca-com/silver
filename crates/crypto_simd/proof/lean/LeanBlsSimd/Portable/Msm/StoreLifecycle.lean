import LeanBlsSimd.Portable.Msm.Store

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Msm.Store

open QueueRefines

theorem allocate_refines (s : portable.msm.store.PointStore)
    (hcap : s.len.val < s.points.val.length) (h32 : s.len.val < 2^32) :
    ∃ n : Usize, n.val = s.len.val + 1 ∧
      s.allocate = ok (UScalar.ofNatCore s.len.val h32, {s with len := n}) := by
  have hs := vec_length_bound s.points
  have hsum : s.len.val + (1#usize).val < 2 ^ UScalarTy.Usize.numBits := by
    change s.len.val + 1 < _
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
  simp only [portable.msm.store.PointStore.allocate, UScalar.lt_equiv,
    alloc.vec.Vec.len_val, hcap, massert]
  rw [add_ok _ _ hsum]
  change (do let i ← n - 1#usize; let j ← lift (UScalar.cast .U32 i); ok (j, {s with len := n})) = _
  rw [hsub]
  simp [hcast, lift]

theorem sum_slot_refines (reference : U32) (s : portable.msm.store.PointStore) (originals : Usize)
    (halloc : (clearSign reference).val < originals.val →
      s.len.val < s.points.val.length ∧ s.len.val < 2^32) :
    ∃ out, portable.msm.buckets.sum_slot reference s originals =
        ok ((slot originals.val s.len.val reference).1, out) ∧
      out.len.val = (slot originals.val s.len.val reference).2 ∧ out.points = s.points := by
  simp only [portable.msm.buckets.sum_slot, negative_mask, bind_tc_ok, lift,
    show (~~~2147483648#u32 : U32) = 2147483647#u32 from rfl,
    UScalar.lt_equiv, cast_Usize_val]
  change ∃ out, (if (clearSign reference).val < originals.val then s.allocate else ok (clearSign reference,s)) = _ ∧ _
  by_cases h : (clearSign reference).val < originals.val
  · obtain ⟨n, hn, ha⟩ := allocate_refines s (halloc h).1 (halloc h).2
    refine ⟨{s with len := n}, ?_, ?_, rfl⟩
    · simp only [h, if_true, ha, slot]
      congr 2
      apply UScalar.eq_of_val_eq
      exact (Nat.mod_eq_of_lt (halloc h).2).symm
    · simpa only [slot, h, if_true] using hn
  · exact ⟨s, by simp [h, slot], by simp [slot,h], rfl⟩

def zeroRow : Array portable.fp.Fp 2#usize := Array.repeat 2#usize portable.fp.Fp.ZERO

theorem reset_refines (s : portable.msm.store.PointStore) (capacity : Usize) :
    ∃ out, s.reset capacity = ok out ∧
      out.points.val = s.points.val ++ List.replicate (capacity.val - s.points.val.length) zeroRow ∧
      out.len = 0#usize := by
  by_cases h : s.points.val.length < capacity.val
  · have hc : core.array.CloneArray.clone portable.fp.Fp.Insts.CoreCloneClone zeroRow = ok zeroRow := by
      obtain ⟨row, he, hr⟩ := WP.spec_imp_exists
        (core.array.CloneArray.clone_spec portable.fp.Fp.Insts.CoreCloneClone zeroRow
          (by intro x hx; rfl))
      simpa only [←hr] using he
    obtain ⟨v,hv,hval⟩ := WP.spec_imp_exists (alloc.vec.Vec.resize_spec
      (core.clone.CloneArray 2#usize portable.fp.Fp.Insts.CoreCloneClone) s.points capacity zeroRow hc)
    refine ⟨{points := v, len := 0#usize}, ?_, ?_, rfl⟩
    · simp only [portable.msm.store.PointStore.reset, UScalar.lt_equiv, alloc.vec.Vec.len_val,
        h, if_true]
      change (do let points ← alloc.vec.Vec.resize _ s.points capacity zeroRow
                 ok ({points, len := 0#usize} : portable.msm.store.PointStore)) = _
      rw [hv]
      rfl
    · rw [hval]
      simp [List.resize, List.take_of_length_le (Nat.le_of_lt h)]
  · refine ⟨{s with len := 0#usize}, ?_, ?_, rfl⟩
    · simp [portable.msm.store.PointStore.reset, UScalar.lt_equiv,h]
    · simp [Nat.sub_eq_zero_of_le (Nat.le_of_not_gt h)]

end LeanBlsSimd.Portable.Msm.Store
