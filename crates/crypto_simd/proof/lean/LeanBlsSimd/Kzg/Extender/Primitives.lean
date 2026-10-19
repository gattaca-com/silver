import LeanBlsSimd.Kzg.Extender.Basic
import LeanBlsSimd.Kzg.Refines.Roots
import LeanBlsSimd.Kzg.Refines.Fft
import EthCryptographySpecs.Proofs.Kzg.Polynomials

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg silver_crypto_simd.bls

namespace LeanBlsSimd.Kzg.Extender

local instance extenderPrimitivesRawFrInhabited : Inhabited blst.blst_fr := ⟨frEncode 0⟩

private theorem inverse_loop (roots : Slice blst.blst_fr) (target : List blst.blst_fr)
    (hrlen : roots.val.length = 4096) (htlen : target.length = 4096)
    (hlookup : ∀ j, 0 < j → j < 4096 → roots.val[4096-j]! = target[j]!)
    (acc : alloc.vec.Vec blst.blst_fr) (i : Usize) (hi : 0 < i.val ∧ i.val ≤ 4096)
    (ha : acc.val = target.take i.val) :
    ∃ out, domain.inverse_roots_loop roots 4096#usize acc i = ok out ∧ out.val = target := by
  induction hk : 4096 - i.val generalizing i acc with
  | zero =>
    have he : i.val = 4096 := by omega
    refine ⟨acc, ?_, ?_⟩
    · rw [domain.inverse_roots_loop, loop.eq_1]
      simp [domain.inverse_roots_loop.body, UScalar.lt_equiv, he]
    · simpa [he, ← htlen] using ha
  | succ k ih =>
    have hil : i.val < 4096 := by omega
    have hib : 4096 < 2^UScalarTy.Usize.numBits := by
      rcases System.Platform.numBits_eq with h | h <;> simp [UScalarTy.numBits, h]
    let j : Usize := UScalar.ofNatCore (4096 - i.val) (by omega)
    let i' : Usize := UScalar.ofNatCore (i.val + 1) (by omega)
    have hj : j.val = 4096 - i.val := UScalar.ofNatCore_val_eq _
    have hi' : i'.val = i.val + 1 := UScalar.ofNatCore_val_eq _
    have hsub : 4096#usize - i = ok j := by
      show UScalar.sub _ _ = _
      simp only [UScalar.sub, UScalar.ofNatCore_val_eq, Nat.not_lt.mpr hi.2, if_false,
        Result.ok.injEq]
      apply (UScalar.eq_equiv_bv_eq _ _).mpr
      exact (UScalar.ofNatCore_bv _ _).symm
    have hadd : i + 1#usize = ok i' := by
      show UScalar.tryMk .Usize (i.val + (1#usize).val) = _
      simp [UScalar.tryMk, UScalar.tryMkOpt, Result.ofOption, i',
        show i.val + 1 < 2^System.Platform.numBits by change i.val + 1 < 2^UScalarTy.Usize.numBits; omega]
    have hindex : Slice.index_usize roots j = ok target[i.val]! := by
      rw [← hlookup _ hi.1 hil]
      simp [Slice.index_usize, hj, hrlen, show 4096-i.val < 4096 by omega]
    have hsize : acc.val.length + 1 ≤ Usize.max := by
      rw [ha, List.length_take, htlen]
      scalar_tac
    let acc' : alloc.vec.Vec blst.blst_fr :=
      ⟨acc.val ++ [target[i.val]!], by simpa using hsize⟩
    have hpush : alloc.vec.Vec.push acc target[i.val]! = ok acc' := by
      simp [alloc.vec.Vec.push, hsize, acc']
    have ha' : acc'.val = target.take i'.val := by
      simp only [acc', ha, hi']
      rw [List.take_add_one, List.getElem?_eq_getElem (by omega : i.val < target.length)]
      simp only [getElem!_pos target i.val (by omega)]
      rfl
    obtain ⟨out, hout, hval⟩ := ih acc' i' (by omega) ha' (by omega)
    refine ⟨out, ?_, hval⟩
    rw [domain.inverse_roots_loop, loop.eq_1]
    simp only [domain.inverse_roots_loop.body, UScalar.lt_equiv, UScalar.ofNatCore_val_eq,
      hil, if_true, hsub, hindex, hpush, hadd, bind_tc_ok]
    exact hout

private theorem inverse_roots_refinement (roots : Slice blst.blst_fr)
    (values : _root_.Array Fr) (hv : values.size = 4096)
    (hr : roots.val = values.toList.map frEncode) :
    ∃ out, domain.inverse_roots roots = ok out ∧
      out.val = (Model.inverseRoots values).toList.map frEncode := by
  let target := (Model.inverseRoots values).toList.map frEncode
  have hlen : roots.val.length = 4096 := by simp [hr, hv]
  have htlen : target.length = 4096 := by simp only [target, List.length_map, _root_.Array.length_toList, Model.inverseRoots, _root_.Array.size_ofFn, hv]
  have htarget (j : Nat) (hj : j < 4096) :
      target[j]! = frEncode (if j = 0 then values[0]! else values[4096-j]!) := by
    have htb : j < target.length := by omega
    rw [getElem!_pos target j htb]
    simp only [target, List.getElem_map, _root_.Array.getElem_toList,
      Model.inverseRoots, _root_.Array.getElem_ofFn, hv]
  have hlookup (j : Nat) (hj : j < 4096) : roots.val[j]! = frEncode values[j]! := by
    rw [hr, getElem!_pos _ j (by simp [hv]; omega)]
    simp [getElem!_pos values j (by omega)]
  have hzero : roots.val[0]! = target[0]! := by rw [hlookup 0 (by decide), htarget 0 (by decide)]; rfl
  let initial : alloc.vec.Vec blst.blst_fr := ⟨[target[0]!], by simp; scalar_tac⟩
  have hinitial : initial.val = target.take (1#usize).val := by
    simp only [UScalar.ofNatCore_val_eq, initial]
    rw [show (1 : Nat) = 0 + 1 by rfl, List.take_add_one,
      List.getElem?_eq_getElem (by omega : 0 < target.length)]
    simp [getElem!_pos target 0 (by omega)]
  obtain ⟨out, hout, hval⟩ := inverse_loop roots target hlen htlen
    (by
      intro j hj hj4096
      rw [hlookup (4096-j) (by omega), htarget j hj4096, if_neg (by omega)])
    initial 1#usize (by decide) hinitial
  refine ⟨out, ?_, hval⟩
  have hn : Slice.len roots = 4096#usize := by apply UScalar.eq_of_val_eq; simpa using hlen
  have hindex : Slice.index_usize roots 0#usize = ok target[0]! := by
    rw [← hzero]
    simp [Slice.index_usize, hlen]
  have hpush : alloc.vec.Vec.push (alloc.vec.Vec.with_capacity blst.blst_fr 4096#usize)
      target[0]! = ok initial := by
    simp [alloc.vec.Vec.push, alloc.vec.Vec.with_capacity, initial, U32.max_eq]
  unfold domain.inverse_roots
  dsimp only
  simp only [hn, hindex, hpush, bind_tc_ok]
  exact hout

-- Simplification descends through the 4096-element scratch vectors.
set_option maxRecDepth 16000 in
theorem new_refinement [e : KzgExternals] (hblst : BlstCorrect e) :
    ∃ initial, cell_extender.CellExtender.new = ok initial ∧ StateInvariant initial := by
  obtain ⟨rs, hrs, hrsval⟩ := roots_refinement_of_blst hblst cell_extender.LOG_BLOB
    (by simp [cell_extender.LOG_BLOB])
  obtain ⟨ext, hext, hextval⟩ := roots_refinement_of_blst hblst cell_extender.LOG_EXT_BLOB
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
  obtain ⟨inv, hinv, hinvval⟩ := inverse_roots_refinement (alloc.vec.Vec.deref rs)
    (Kzg.Model.roots 12) (by simp [Kzg.Model.roots]) hrsval
  have hinverse := hblst.fr_inverse (Fr.ofNat 4096) (by decide)
  have hcast : UScalar.cast .U64 FIELD_ELEMENTS_PER_BLOB = 4096#u64 := by
    apply UScalar.eq_of_val_eq
    simp [FIELD_ELEMENTS_PER_BLOB]
  refine ⟨⟨rs, inv, frEncode (Fr.ofNat 4096).inverse, shift, scratch, scratch⟩, ?_, ?_⟩
  · unfold cell_extender.CellExtender.new
    rw [hrs]
    simp only [bind_tc_ok, blst_ops.fr_from_u64, hblst.fr_u64]
    rw [hext]
    simp only [bind_tc_ok, UScalar.ofNatCore_val_eq, hshift, hscratch, hinv, lift, hcast]
    simp only [bind_tc_ok, blst_ops.fr_inverse, hinverse]
  · refine ⟨hrsval, hinvval, rfl, ?_, ?_, ?_⟩
    · have hextlen : ext.val.length = 8192 := by simp [hextval, Kzg.Model.roots]
      rw [hshiftval]
      simp only [List.resize, FIELD_ELEMENTS_PER_BLOB, UScalar.ofNatCore_val_eq,
        Nat.zero_le, if_true, hextlen]
      simp only [show 4096 - 8192 = 0 by decide, List.replicate_zero, List.append_nil]
      rw [hextval, ← List.map_take]
      simp only [_root_.Array.toList_extract, List.extract_eq_take_drop, Nat.sub_zero, List.drop_zero]
    · simp [hscratchval, empty, alloc.vec.Vec.with_capacity, List.resize, FIELD_ELEMENTS_PER_BLOB]
    · simp [hscratchval, empty, alloc.vec.Vec.with_capacity, List.resize, FIELD_ELEMENTS_PER_BLOB]

end LeanBlsSimd.Kzg.Extender
