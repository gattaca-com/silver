import LeanBlsSimd.Kzg.InterpolationKernel.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Fr8

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg

def decodedCellElements (cells : List (Aeneas.Std.Array U8 2048#usize)) : List (Option Fr) :=
  cells.flatMap fun cell => (List.range 64).map fun j =>
    (bytesToBlsField ((arrayBytes cell).extract (32*j) (32*(j+1)))).toOption

namespace InterpolationKernel

private def canonical (cell : Aeneas.Std.Array U8 2048#usize) (j : Nat) : Prop :=
  Fr.bytesBEToNat ((arrayBytes cell).extract (32*j) (32*(j+1))) < Fr.modulus

private theorem canonical_iff (cell : Aeneas.Std.Array U8 2048#usize)
    (j : Nat) (hj : j < 64) :
    (bytesToBlsField ((arrayBytes cell).extract (32*j) (32*(j+1)))).toOption.isSome = true ↔
      canonical cell j := by
  have hsize : ((arrayBytes cell).extract (32*j) (32*(j+1))).size = 32 := by
    simp [arrayBytes, bytes, ByteArray.size, cell.property]
    omega
  by_cases h : canonical cell j <;>
    simp only [canonical] at h <;>
    simp [bytesToBlsField, hsize, EthLib.Cryptography.Kzg.Constants.BYTES_PER_FIELD_ELEMENT,
      Fr.fromBytesBE, canonical, h, Except.toOption]

private theorem tryMk_ok {ty : UScalarTy} (n : Nat) (hn : n < 2 ^ ty.numBits) :
    UScalar.tryMk ty n = ok (UScalar.ofNatCore n hn) := by
  simp [UScalar.tryMk, UScalar.tryMkOpt, hn, Result.ofOption]

private theorem add_ok (v : Usize) (hv : v.val + 1 < 2 ^ UScalarTy.Usize.numBits) :
    v + 1#usize = ok (UScalar.ofNatCore (v.val + 1) hv) := by
  exact tryMk_ok _ hv

private theorem check_cell_loop_refinement
    (cell : Aeneas.Std.Array U8 2048#usize) (v : Usize) (hv : v.val ≤ 8) :
    ∃ stop, interpolation_kernel.InterpolationKernel.check_cell_loop cell v = ok stop ∧
      (stop = 8#usize ↔ ∀ j, 8*v.val ≤ j → j < 64 → canonical cell j) := by
  induction hn : 8 - v.val generalizing v with
  | zero =>
    have he : v.val = 8 := by omega
    refine ⟨v, ?_, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.check_cell_loop, loop.eq_1]
      simp [interpolation_kernel.InterpolationKernel.check_cell_loop.body, vectors_per_cell_eq, he]
    · simp [UScalar.eq_equiv, he]
      omega
  | succ n ih =>
    have hlt : v.val < 8 := by omega
    let offset : Usize := UScalar.ofNatCore (v.val * 256) (by scalar_tac)
    have hmul : v * 256#usize = ok offset := by
      exact tryMk_ok _ _
    obtain ⟨out, mask, hfrom, _, hlanes, hmask⟩ :=
      Extender.Kernel.from_bytes_refinement (Array.to_slice cell) offset
        (by simp [offset, Array.to_slice, cell.property]; omega)
    have hmask' : mask = 255#u8 ↔
        ∀ j, 8*v.val ≤ j → j < 8*(v.val+1) → canonical cell j := by
      rw [hmask]
      simp_rw [(hlanes _).1]
      constructor
      · intro h j hlo hhi
        have hl : j - 8*v.val < 8 := by omega
        have he : j = 8*v.val + (j - 8*v.val) := by omega
        have hh := h ⟨j - 8*v.val, hl⟩
        simpa [canonical, offset, Array.to_slice, arrayBytes,
          show v.val*256 + 32*(j-8*v.val) = 32*j by omega,
          show v.val*256 + 32*(j-8*v.val+1) = 32*(j+1) by omega] using hh
      · intro h lane
        have hh := h (8*v.val + lane.val) (by omega) (by omega)
        simpa only [canonical, offset, Array.to_slice, arrayBytes, UScalar.ofNatCore_val_eq,
          show 32*(8*v.val+lane.val) = v.val*256+32*lane.val by omega,
          show 32*(8*v.val+lane.val+1) = v.val*256+32*(lane.val+1) by omega] using hh
    let v' : Usize := UScalar.ofNatCore (v.val + 1) (by scalar_tac)
    have hv' : v'.val = v.val + 1 := rfl
    have hbody : interpolation_kernel.InterpolationKernel.check_cell_loop.body cell v =
        if mask = 255#u8 then ok (cont v') else ok (done v) := by
      simp [interpolation_kernel.InterpolationKernel.check_cell_loop.body, vectors_per_cell_eq,
        bytes_per_vector_eq, hlt, hmul, lift, hfrom, add_ok v (by scalar_tac), v']
    by_cases hm : mask = 255#u8
    · obtain ⟨stop, hstop, hs⟩ := ih v' (by omega) (by omega)
      refine ⟨stop, ?_, ?_⟩
      · rw [interpolation_kernel.InterpolationKernel.check_cell_loop, loop.eq_1]
        simpa [hbody, hm] using hstop
      · rw [hs]
        have hc := hmask'.mp hm
        constructor
        · intro h j hj hj'
          by_cases hbefore : j < 8*(v.val+1)
          · exact hc j hj hbefore
          · exact h j (by omega) hj'
        · intro h j hj hj'
          exact h j (by omega) hj'
    · refine ⟨v, ?_, ?_⟩
      · rw [interpolation_kernel.InterpolationKernel.check_cell_loop, loop.eq_1]
        simp [hbody, hm]
      · have hvne : v ≠ 8#usize := by simpa [UScalar.eq_equiv] using (show v.val ≠ 8 by omega)
        simp only [hvne, false_iff]
        intro h
        apply hm
        apply hmask'.mpr
        intro j hj hj'
        exact h j hj (by omega)

theorem check_cell_refinement (kernel : interpolation_kernel.InterpolationKernel)
    (cell : Aeneas.Std.Array U8 2048#usize) :
    interpolation_kernel.InterpolationKernel.check_cell kernel cell =
      ok ((decodedCellElements [cell]).all Option.isSome) := by
  obtain ⟨stop, hstop, hs⟩ := check_cell_loop_refinement cell 0#usize (by decide)
  simp only [interpolation_kernel.InterpolationKernel.check_cell, hstop, bind_tc_ok, vectors_per_cell_eq]
  congr 1
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq, hs, UScalar.ofNatCore_val_eq, Nat.mul_zero, Nat.zero_le,
    forall_true_left, decodedCellElements, List.flatMap_cons, List.flatMap_nil,
    List.append_nil, List.all_eq_true, List.mem_map, List.mem_range]
  constructor
  · intro h x hx
    obtain ⟨j, hj, rfl⟩ := hx
    exact (canonical_iff cell j hj).mpr (h j hj)
  · intro h j hj
    exact (canonical_iff cell j hj).mp (h _ ⟨j, hj, rfl⟩)

private theorem check_loop_refinement (kernel : interpolation_kernel.InterpolationKernel)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize)) (k : Usize)
    (hk : k.val ≤ cells.val.length) :
    ∃ stop, interpolation_kernel.InterpolationKernel.check_loop kernel cells k = ok stop ∧
      decide (stop = Slice.len cells) =
        (decodedCellElements (cells.val.drop k.val)).all Option.isSome := by
  induction hn : cells.val.length - k.val generalizing k with
  | zero =>
    have he : k.val = cells.val.length := by omega
    refine ⟨k, ?_, ?_⟩
    · rw [interpolation_kernel.InterpolationKernel.check_loop, loop.eq_1]
      simp [interpolation_kernel.InterpolationKernel.check_loop.body, he]
    · simp [he, decodedCellElements, UScalar.eq_equiv]
  | succ n ih =>
    have hlt : k.val < cells.val.length := by omega
    have htest : k < Slice.len cells := by simpa using hlt
    have hkBound : k.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
      have hmax := (Slice.len cells).hBounds
      simp only [Slice.len_val, Slice.length] at hmax
      omega
    let k' : Usize := UScalar.ofNatCore (k.val + 1) hkBound
    have hk' : k'.val = k.val + 1 := rfl
    let cell := cells.val[k.val]'hlt
    have hindex : Slice.index_usize cells k = ok cell := by
      simp [Slice.index_usize, hlt, cell]
    have hdrop : decodedCellElements (cells.val.drop k.val) =
        decodedCellElements [cell] ++ decodedCellElements (cells.val.drop k'.val) := by
      rw [hk']
      unfold decodedCellElements
      rw [List.drop_eq_getElem_cons hlt]
      simp only [List.flatMap_cons, List.flatMap_nil, List.append_nil]
      rfl
    have hbody : interpolation_kernel.InterpolationKernel.check_loop.body kernel cells k =
        if (decodedCellElements [cell]).all Option.isSome then ok (cont k') else ok (done k) := by
      simp only [interpolation_kernel.InterpolationKernel.check_loop.body, htest, if_true,
        hindex, bind_tc_ok, check_cell_refinement, add_ok k hkBound, k']
    cases hsuccess : (decodedCellElements [cell]).all Option.isSome with
    | false =>
      refine ⟨k, ?_, ?_⟩
      · rw [interpolation_kernel.InterpolationKernel.check_loop, loop.eq_1]
        simp only [hbody, hsuccess, Bool.false_eq_true, if_false]
      · have hne : k ≠ Slice.len cells := by
          simpa [UScalar.eq_equiv] using (show k.val ≠ cells.val.length by omega)
        simp [hdrop, hsuccess, hne]
    | true =>
      obtain ⟨stop, hstop, hs⟩ := ih k' (by omega) (by omega)
      refine ⟨stop, ?_, ?_⟩
      · rw [interpolation_kernel.InterpolationKernel.check_loop, loop.eq_1]
        simp only [hbody, hsuccess, if_true]
        exact hstop
      · simpa [hdrop, hsuccess] using hs

theorem check_refinement (kernel : interpolation_kernel.InterpolationKernel)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize)) :
    interpolation_kernel.InterpolationKernel.check kernel cells =
      ok ((decodedCellElements cells.val).all Option.isSome) := by
  obtain ⟨stop, hstop, hs⟩ := check_loop_refinement kernel cells 0#usize (by simp)
  unfold interpolation_kernel.InterpolationKernel.check
  rw [hstop]
  simpa using congrArg (fun b => ok b) hs

end InterpolationKernel
end LeanBlsSimd.Kzg
