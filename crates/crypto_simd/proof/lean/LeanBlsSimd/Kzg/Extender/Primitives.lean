import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Extender.Kernel.Refines
import LeanBlsSimd.Kzg.Refines.InverseRoots
import LeanBlsSimd.Kzg.Refines.Fft
import EthLib.Cryptography.Proofs.Kzg.Polynomials

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Extender

local instance extenderPrimitivesRawFrInhabited : Inhabited blst.blst_fr := ⟨frEncode 0⟩

-- Simplification descends through the 4096-element scratch vectors.
set_option maxRecDepth 16000 in
theorem new_dispatch_refinement [cpu : RuntimeFeatures] (hfr : FrCorrect) :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial ∧
      initial.kernel.isSome = cpu.simdAvailable := by
  obtain ⟨rs, hrs, hrsval⟩ := roots_refinement_of_blst hfr cell_extender.LOG_BLOB
    (by simp [cell_extender.LOG_BLOB])
  obtain ⟨ext, hext, hextval⟩ := roots_refinement_of_blst hfr cell_extender.LOG_EXT_BLOB
    (by simp [cell_extender.LOG_EXT_BLOB])
  simp only [cell_extender.LOG_BLOB, UScalar.ofNatCore_val_eq] at hrsval
  simp only [cell_extender.LOG_EXT_BLOB, UScalar.ofNatCore_val_eq] at hextval
  have hclone : blst.blst_fr.Insts.CoreCloneClone.clone (frEncode (Fr.ofNat 0)) =
      ok (frEncode (Fr.ofNat 0)) := rfl
  obtain ⟨shift, hshift, hshiftval⟩ := WP.spec_imp_exists
    (alloc.vec.Vec.resize_spec blst.blst_fr.Insts.CoreCloneClone ext
      FIELD_ELEMENTS_PER_BLOB (frEncode (Fr.ofNat 0)) hclone)
  let empty := alloc.vec.Vec.with_capacity blst.blst_fr FIELD_ELEMENTS_PER_BLOB
  obtain ⟨scratch, hscratch, hscratchval⟩ := WP.spec_imp_exists
    (alloc.vec.Vec.resize_spec blst.blst_fr.Insts.CoreCloneClone empty
      FIELD_ELEMENTS_PER_BLOB (frEncode (Fr.ofNat 0)) hclone)
  dsimp only [empty] at hscratch
  obtain ⟨inv, hinv, hinvval⟩ := Refinement.inverse_roots_refinement 4096#usize (by decide) (alloc.vec.Vec.deref rs)
    (Kzg.Model.roots 12) (by simp [Kzg.Model.roots]) hrsval
  have hshiftmodel : shift.val = ((Kzg.Model.roots 13).extract 0 4096).toList.map frEncode := by
    have hextlen : ext.val.length = 8192 := by simp [hextval, Kzg.Model.roots]
    rw [hshiftval]
    simp only [List.resize, FIELD_ELEMENTS_PER_BLOB, UScalar.ofNatCore_val_eq,
      Nat.zero_le, if_true, hextlen]
    simp only [show 4096 - 8192 = 0 by decide, List.replicate_zero, List.append_nil]
    rw [hextval, ← List.map_take]
    simp only [_root_.Array.toList_extract, List.extract_eq_take_drop, Nat.sub_zero, List.drop_zero]
  have hscratchlen : scratch.val.length = 4096 := by
    simp [hscratchval, empty, alloc.vec.Vec.with_capacity, List.resize, FIELD_ELEMENTS_PER_BLOB]
  let scalar : cell_extender.CellExtender :=
    ⟨rs, inv, frEncode (Fr.ofNat 4096).inverse, shift, scratch, scratch, none⟩
  have hscalar : StateInvariant scalar :=
    ⟨hrsval, hinvval, rfl, hshiftmodel, hscratchlen, hscratchlen, trivial⟩
  have hnew : cell_extender.CellExtender.new =
      (if cpu.simdAvailable then do
        let kernel ← extension_kernel.ExtensionKernel.new
          (alloc.vec.Vec.deref rs) (alloc.vec.Vec.deref inv)
          (alloc.vec.Vec.deref shift) (frEncode (Fr.ofNat 4096).inverse)
        ok { scalar with kernel := some kernel }
      else ok scalar) := by
    unfold cell_extender.CellExtender.new
    rw [hrs]
    simp only [bind_tc_ok, fr_zero_eq]
    rw [hext]
    simp only [bind_tc_ok, UScalar.ofNatCore_val_eq, hshift, hscratch, hinv, inverse_blob_size_eq]
    rfl
  cases hsimd : cpu.simdAvailable with
  | false =>
    exact ⟨scalar, by simp only [hnew, hsimd, Bool.false_eq_true, if_false],
      hscalar, rfl⟩
  | true =>
    obtain ⟨kernel, hkernel, hki, _⟩ := Kernel.new_refinement hfr
      (alloc.vec.Vec.deref rs) (alloc.vec.Vec.deref inv) (alloc.vec.Vec.deref shift)
      (frEncode (Fr.ofNat 4096).inverse) hrsval hinvval hshiftmodel rfl
    refine ⟨{ scalar with kernel := some kernel }, ?_, ?_, ?_⟩
    · simp only [hnew, hsimd, if_true, hkernel, bind_tc_ok]
    · exact ⟨hrsval, hinvval, rfl, hshiftmodel, hscratchlen, hscratchlen, hki⟩
    · rfl

theorem new_refinement [cpu : RuntimeFeatures] (hfr : FrCorrect) :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial := by
  obtain ⟨initial, hnew, hinvariant, _⟩ := new_dispatch_refinement hfr
  exact ⟨initial, hnew, hinvariant⟩

end LeanBlsSimd.Kzg.Extender
