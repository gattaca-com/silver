import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Extender.Scale
import LeanBlsSimd.Kzg.Extender.Write
import LeanBlsSimd.Kzg.Refines.Fft
import LeanBlsSimd.Kzg.Extender.Kernel.Refines

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg Kzg.BitReversal
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

private theorem cells_per_extended_blob : CELLS_PER_EXT_BLOB = ok 128#usize := by
  simp only [CELLS_PER_EXT_BLOB, FIELD_ELEMENTS_PER_BLOB, FIELD_ELEMENTS_PER_CELL]
  rw [scalar_mul_ok 2#usize 4096#usize (by scalar_tac)]
  rfl

private theorem compute_scalar_core
    (houtput : ∀ (blob : Blob) (cells : Cells) (values : _root_.Array Fr)
      (v : cell_extender.CellExtender), values.size = 4096 →
      v.evaluations.val = values.toList.map frEncode →
      ∃ copied out,
        cell_extender.copy_blob_loop
          { start := 0#usize, «end» := 64#usize } blob cells = ok copied ∧
        cell_extender.CellExtender.write_extension v copied = ok out ∧
        cellBytes out = _root_.Array.ofFn (n := 128) (fun i =>
          if i.val < 64 then (arrayBytes blob).extract (i.val*2048) ((i.val+1)*2048)
          else cosetEvalsToCell ((bitReversalPermutation values).extract
            ((i.val-64)*64) (((i.val-64)*64)+64))))
    (v : cell_extender.CellExtender) (hv : StateInvariant v) (hkernel : v.kernel = none)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) ∧
      (verdict = false → out = cells) ∧ next.kernel = none := by
  obtain ⟨verdict, decoded, hdecode, hd, hframe, hr⟩ := decode_blob_refinement v hv blob
  cases hm : blobToPolynomial (arrayBytes blob) with
  | error err =>
    simp only [hm] at hr
    subst verdict
    refine ⟨false, decoded, cells, ?_, hd, ?_, (fun _ => rfl), ?_⟩
    · simp only [cell_extender.CellExtender.compute, hkernel, hdecode, bind_tc_ok,
        Function.uncurry_apply_pair, Bool.false_eq_true, if_false]
    · simp [Model.compute, Model.extend, hm]
    · rw [hframe]
      exact hkernel
  | ok values =>
    simp only [hm] at hr
    rcases hr with ⟨rfl, hvalues, hdecoded⟩
    let coefficients := Kzg.Model.inverseFft (bitReversalPermutation values)
      (Kzg.Model.inverseRoots (Kzg.Model.roots 12)) (Fr.ofNat 4096).inverse
    have hcoeffSize : coefficients.size = 4096 := by
      simp [coefficients, Kzg.Model.inverseFft, size_bitReversalPermutation, hvalues]
    obtain ⟨inverse, hinverse, hinverseVal⟩ := inverse_fft_refinement_of_blst 12
      (alloc.vec.Vec.deref decoded.coefficients) (alloc.vec.Vec.deref decoded.evaluations)
      (alloc.vec.Vec.deref decoded.inverse_roots)
      (bitReversalPermutation values) (Kzg.Model.inverseRoots (Kzg.Model.roots 12))
      (Fr.ofNat 4096).inverse
      hd.2.2.2.2.2.1 (by simpa [size_bitReversalPermutation] using hvalues)
      (by simp [Kzg.Model.inverseRoots, Kzg.Model.roots]) hdecoded hd.2.1
    let inverseVec : alloc.vec.Vec blst.blst_fr := ⟨inverse.val, inverse.property⟩
    obtain ⟨shifted, hshift, hshiftVal⟩ := shift_refinement inverseVec
      decoded.shift_powers coefficients hcoeffSize hinverseVal hd.2.2.2.1
    let shiftedValues := _root_.Array.ofFn (n := 4096) fun i =>
      coefficients[i.val]! * (Kzg.Model.roots 13)[i.val]!
    have hshiftSize : shiftedValues.size = 4096 := _root_.Array.size_ofFn
    obtain ⟨evaluations, hfft, hevaluations⟩ := fft_refinement_of_blst 12
      (alloc.vec.Vec.deref decoded.evaluations) (alloc.vec.Vec.deref shifted)
      (alloc.vec.Vec.deref decoded.roots) shiftedValues (Kzg.Model.roots 12)
      hd.2.2.2.2.1 hshiftSize (by simp [Kzg.Model.roots]) hshiftVal hd.1
    let next : cell_extender.CellExtender :=
      { decoded with
        coefficients := shifted
        evaluations := ⟨evaluations.val, evaluations.property⟩ }
    have hnextValues : next.evaluations.val = (Model.extension values).toList.map frEncode :=
      hevaluations
    have hextSize : (Model.extension values).size = 4096 := by
      simp [Model.extension]
    have hnext : StateInvariant next := by
      rcases hd with ⟨hroots, hinv, hsize, hshiftRoots, _, _, hkinvariant⟩
      refine ⟨hroots, hinv, hsize, hshiftRoots, ?_, ?_, hkinvariant⟩
      · simpa only [List.length_map, _root_.Array.length_toList, hextSize] using
          congrArg List.length hnextValues
      · simpa only [List.length_map, _root_.Array.length_toList, _root_.Array.size_ofFn]
          using congrArg List.length hshiftVal
    obtain ⟨copied, out, hcopy, hwrite, hout⟩ :=
      houtput blob cells (Model.extension values) next hextSize hnextValues
    refine ⟨true, next, out, ?_, hnext, ?_, (by simp), ?_⟩
    · have hhalf : 128#usize / 2#usize = ok 64#usize := by rfl
      have hinverse' : fft.inverse_fft (alloc.vec.Vec.deref decoded.coefficients)
          (alloc.vec.Vec.deref decoded.evaluations) (alloc.vec.Vec.deref decoded.inverse_roots)
          decoded.inverse_size = ok inverse := by
        rw [hd.2.2.1]
        exact hinverse
      simp only [cell_extender.CellExtender.compute, hkernel, hdecode, bind_tc_ok,
        Function.uncurry_apply_pair, if_true, cell_extender.copy_blob, cells_per_extended_blob, hhalf, hcopy]
      simp only [alloc.vec.Vec.deref_mut, lift, bind_tc_ok, Function.uncurry_apply_pair]
      simp only [alloc.vec.Vec.deref] at hinverse'
      simp only [alloc.vec.Vec.deref]
      rw [hinverse']
      simp only [bind_tc_ok]
      change (do
        let shifted ← cell_extender.CellExtender.compute_loop
          { start := 0#usize, «end» := FIELD_ELEMENTS_PER_BLOB }
          decoded.shift_powers inverseVec
        let evaluations ← fft.fft (alloc.vec.Vec.deref decoded.evaluations)
          (alloc.vec.Vec.deref shifted) (alloc.vec.Vec.deref decoded.roots)
        let out ← cell_extender.CellExtender.write_extension
          { decoded with
            coefficients := shifted
            evaluations := ⟨evaluations.val, evaluations.property⟩ } copied
        ok (true, { decoded with
          coefficients := shifted
          evaluations := ⟨evaluations.val, evaluations.property⟩ }, out)) = _
      simp only [hshift, bind_tc_ok, hfft]
      change (do
        let result ← cell_extender.CellExtender.write_extension next copied
        ok (true, next, result)) = _
      simp only [hwrite, bind_tc_ok]
    · simp only [Model.compute, Model.extend, hm]
      change (true, cellBytes out) = (true, _)
      rw [hout]
    · change decoded.kernel = none
      rw [hframe]
      exact hkernel

private theorem compute_core
    (houtput : ∀ (blob : Blob) (cells : Cells) (values : _root_.Array Fr)
      (v : cell_extender.CellExtender), values.size = 4096 →
      v.evaluations.val = values.toList.map frEncode →
      ∃ copied out,
        cell_extender.copy_blob_loop
          { start := 0#usize, «end» := 64#usize } blob cells = ok copied ∧
        cell_extender.CellExtender.write_extension v copied = ok out ∧
        cellBytes out = _root_.Array.ofFn (n := 128) (fun i =>
          if i.val < 64 then (arrayBytes blob).extract (i.val*2048) ((i.val+1)*2048)
          else cosetEvalsToCell ((bitReversalPermutation values).extract
            ((i.val-64)*64) (((i.val-64)*64)+64))))
    (v : cell_extender.CellExtender) (hv : StateInvariant v)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) ∧
      (verdict = false → out = cells) := by
  cases hkernel : v.kernel with
  | none =>
    obtain ⟨verdict, next, out, hcompute, hinvariant, hmodel, hrejected, _⟩ :=
      compute_scalar_core houtput v hv hkernel blob cells
    exact ⟨verdict, next, out, hcompute, hinvariant, hmodel, hrejected⟩
  | some kernel =>
    obtain ⟨verdict, next, out, hcompute, hinvariant, hmodel, hrejected, _⟩ :=
      Kernel.compute_refinement v hv kernel hkernel blob cells
    exact ⟨verdict, next, out, hcompute, hinvariant, hmodel, hrejected⟩

theorem compute_refinement_with_rejection
    (v : cell_extender.CellExtender) (hv : StateInvariant v)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) ∧
      (verdict = false → out = cells) := by
  exact compute_core (output_refinement) v hv blob cells

theorem compute_refinement
    (v : cell_extender.CellExtender) (hv : StateInvariant v)
    (blob : Blob) (cells : Cells) :
    ∃ (verdict : Bool) (next : cell_extender.CellExtender) (out : Cells),
      cell_extender.CellExtender.compute v blob cells = ok (verdict, next, out) ∧
      StateInvariant next ∧
      (verdict, cellBytes out) = Model.compute (arrayBytes blob) (cellBytes cells) := by
  obtain ⟨verdict, next, out, hr, hi, hm, _⟩ :=
    compute_refinement_with_rejection v hv blob cells
  exact ⟨verdict, next, out, hr, hi, hm⟩

end LeanBlsSimd.Kzg.Extender
