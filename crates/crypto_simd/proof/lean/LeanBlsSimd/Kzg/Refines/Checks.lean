import LeanBlsSimd.Kzg.Refines.Cosets

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg

private theorem check_succ (i : Usize) (stop : Usize) (h : i.val < stop.val) :
    ∃ j : Usize, i + 1#usize = ok j ∧ j.val = i.val + 1 := by
  have hb : i.val + 1 < 2 ^ UScalarTy.Usize.numBits := by
    have := stop.hBounds
    omega
  let j : Usize := UScalar.ofNatCore (i.val + 1) hb
  refine ⟨j, ?_, UScalar.ofNatCore_val_eq _⟩
  show UScalar.tryMk .Usize (i.val + (1#usize).val) = ok j
  have hb' : i.val + 1 < 2 ^ System.Platform.numBits := hb
  simp [UScalar.tryMk, UScalar.tryMkOpt, hb', Result.ofOption, j]

private theorem indices_loop (indices : Slice U64) (remaining before : List U64)
    (hs : indices.val = before ++ remaining) (i : Usize) (hi : i.val = before.length) :
    ∃ result,
      verify.CellBatchVerifier.verify_loop indices (Slice.len indices) i = ok result ∧
      result.val = i.val + remaining.findIdx (fun x => decide (128 ≤ x.val)) := by
  induction remaining generalizing before i with
  | nil =>
    have hend : ¬ i < Slice.len indices := by simp [hi, hs]
    refine ⟨i, ?_, by simp⟩
    rw [verify.CellBatchVerifier.verify_loop, loop.eq_1]
    simp only [verify.CellBatchVerifier.verify_loop.body, hend, if_false]
  | cons x remaining ih =>
    have hlt : i.val < indices.val.length := by simp [hi, hs]
    have htest : i < Slice.len indices := by simpa using hlt
    have hindex : Slice.index_usize indices i = ok x := by
      simp [Slice.index_usize, hs, hi, List.getElem_append_right]
    have hcast : UScalar.cast .U64 128#usize = 128#u64 := by
      apply UScalar.eq_of_val_eq
      simp
    by_cases hx : x.val < 128
    · have hx' : x < 128#u64 := by simpa using hx
      obtain ⟨i', hadd, hi'⟩ := check_succ i (Slice.len indices) (by simpa using hlt)
      obtain ⟨result, hloop, hval⟩ := ih (before ++ [x])
        (by simpa [List.append_assoc] using hs) i' (by simp [hi', hi])
      refine ⟨result, ?_, ?_⟩
      · have hbody : verify.CellBatchVerifier.verify_loop.body indices (Slice.len indices) i =
            ok (cont i') := by
          simp only [verify.CellBatchVerifier.verify_loop.body, htest, if_true,
            hindex, bind_tc_ok, cells_per_ext_blob_eq, lift, hcast, hx', hadd]
        rw [verify.CellBatchVerifier.verify_loop, loop.eq_1, hbody]
        exact hloop
      · simp only [List.findIdx_cons, show decide (128 ≤ x.val) = false by simp; omega,
          cond_false]
        omega
    · have hx' : ¬ x < 128#u64 := by simpa using hx
      refine ⟨i, ?_, ?_⟩
      · rw [verify.CellBatchVerifier.verify_loop, loop.eq_1]
        simp only [verify.CellBatchVerifier.verify_loop.body, htest, if_true,
          hindex, bind_tc_ok, cells_per_ext_blob_eq, lift, hcast, hx', if_false]
      · simp [List.findIdx_cons, show 128 ≤ x.val by omega]

theorem verify_indices_refinement (indices : Slice U64) :
    ∃ result,
      verify.CellBatchVerifier.verify_loop indices (Slice.len indices) 0#usize = ok result ∧
      result.val = indices.val.findIdx (fun x => decide (128 ≤ x.val)) := by
  simpa only [UScalar.ofNatCore_val_eq, Nat.zero_add] using
    indices_loop indices indices.val [] rfl 0#usize rfl

private theorem slice_lengths_ne {α β : Type} (a : Slice α) (b : Slice β) :
    (Slice.len a != Slice.len b) = decide (a.val.length ≠ b.val.length) := by
  by_cases h : a.val.length = b.val.length
  · have he : Slice.len a = Slice.len b := by
      apply UScalar.eq_of_val_eq
      exact h
    simp [he, h]
  · have he : Slice.len a ≠ Slice.len b := by
      intro he
      exact h (congrArg UScalar.val he)
    simp [he, h]

theorem verify_rejects_lengths [KzgExternals] (v : verify.CellBatchVerifier)
    (cs : Slice (Aeneas.Std.Array U8 48#usize)) (indices : Slice U64)
    (cells : Slice (Aeneas.Std.Array U8 2048#usize))
    (ps : Slice (Aeneas.Std.Array U8 48#usize))
    (h : indices.val.length ≠ cs.val.length ∨ cells.val.length ≠ cs.val.length ∨
      ps.val.length ≠ cs.val.length) :
    verify.CellBatchVerifier.verify v cs indices cells ps = ok (false, v) := by
  unfold verify.CellBatchVerifier.verify
  simp only [slice_lengths_ne]
  by_cases hi : indices.val.length = cs.val.length
  · simp only [hi, ne_self_iff_false, decide_false, Bool.false_eq_true, if_false]
    by_cases hc : cells.val.length = cs.val.length
    · have hp : ps.val.length ≠ cs.val.length := by tauto
      simp [hc, hp]
    · simp [hc]
  · simp [hi]

theorem model_rejects_lengths (setup : TrustedSetup)
    (cs : _root_.Array Bytes48) (indices : _root_.Array Nat)
    (cells : _root_.Array Cell) (ps : _root_.Array Bytes48)
    (h : indices.size ≠ cs.size ∨ cells.size ≠ cs.size ∨ ps.size ≠ cs.size) :
    Model.verify setup cs indices cells ps = false := by
  have hfront : ∃ err, Model.frontHalf cs indices cells ps = .error err := by
    by_cases hc : cells.size = cs.size
    · by_cases hp : ps.size = cs.size
      · have hi : indices.size ≠ cs.size := by tauto
        refine ⟨.inputLengthMismatch "cellIndices" cs.size indices.size, ?_⟩
        simp [Model.frontHalf, hc, hp, hi, Bind.bind, Except.bind]
        rfl
      · refine ⟨.inputLengthMismatch "proofsBytes" cs.size ps.size, ?_⟩
        simp [Model.frontHalf, hc, hp, Bind.bind, Except.bind]
        rfl
    · refine ⟨.inputLengthMismatch "cells" cs.size cells.size, ?_⟩
      simp [Model.frontHalf, hc, Bind.bind, Except.bind]
  obtain ⟨err, herr⟩ := hfront
  unfold Model.verify Model.verifyPure
  rw [herr]
  rfl

end LeanBlsSimd.Kzg
