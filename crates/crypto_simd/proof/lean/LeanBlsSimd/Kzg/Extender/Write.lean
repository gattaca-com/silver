import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Extender.WriteBytes
import LeanBlsSimd.Kzg.Extender.SpecBytes
import LeanBlsSimd.Kzg.Refines.Loop

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg Kzg.BitReversal
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

abbrev CellArray := Aeneas.Std.Array U8 2048#usize

theorem cellBytes_get (cells : Cells) (k : Nat) (hk : k < 128) :
    (cellBytes cells)[k]! = arrayBytes cells.val[k]! := by
  have hl : k < cells.val.length := by simpa [cells.property] using hk
  simp [cellBytes, List.getElem?_eq_getElem hl]

def blobCell (blob : Blob) (k : Nat) (hk : k < 64) : CellArray :=
  ⟨blob.val.slice (k*2048) ((k+1)*2048), by
    simp [List.slice, blob.property]
    omega⟩

theorem blobCell_bytes (blob : Blob) (k : Nat) (hk : k < 64) :
    arrayBytes (blobCell blob k hk) = (arrayBytes blob).extract (k*2048) ((k+1)*2048) := by
  apply ByteArray.ext
  rw [ByteArray.data_extract]
  apply _root_.Array.toList_inj.mp
  simp only [arrayBytes, bytes, blobCell, List.toList_toArray, _root_.Array.toList_extract]
  simp [List.extract_eq_take_drop, List.slice, List.map_take, List.map_drop]

theorem copy_cell_body (blob : Blob) (cells : Cells)
    (iter iter' : core.ops.range.Range Usize) (hk : iter.start.val < 64)
    (hn : core.iter.range.IteratorRange.next core.iter.range.StepUsize iter =
      ok (some iter.start, iter')) :
    cell_extender.CellExtender.compute_loop0.body blob iter cells =
      ok (cont (iter', cells.set iter.start (blobCell blob iter.start.val hk))) := by
  let k := iter.start
  have hk' : k.val < 64 := hk
  let k' : Usize := UScalar.ofNatCore (k.val+1) (by scalar_tac)
  let start : Usize := UScalar.ofNatCore (k.val*2048) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore ((k.val+1)*2048) (by scalar_tac)
  have hadd : k + 1#usize = ok k' := scalar_add_ok k 1#usize (by scalar_tac)
  have hstart : k * 2048#usize = ok start := scalar_mul_ok k 2048#usize (by scalar_tac)
  have hstop : k' * 2048#usize = ok stop := scalar_mul_ok k' 2048#usize (by scalar_tac)
  let chunk := blobCell blob k.val hk
  let src := Array.to_slice chunk
  have hklen : k.val < cells.val.length := by rw [cells.property]; exact Nat.lt_trans hk' (by decide)
  have hindex : Array.index_mut_usize cells k = ok (cells.val[k.val]!, cells.set k) := by
    simp [Array.index_mut_usize, Array.index_usize, List.getElem?_eq_getElem hklen]
  have hsrc : core.array.Array.index
      (core.ops.index.IndexSlice (core.slice.index.SliceIndexRangeUsizeSlice U8)) blob
      { start, «end» := stop } = ok src := by
    have hstopn : (k.val+1)*2048 ≤ 131072 := by omega
    simp [core.array.Array.index, core.ops.index.IndexSlice, core.slice.index.Slice.index,
      core.slice.index.SliceIndexRangeUsizeSlice.index, start, stop,
      src, chunk, blobCell, Array.to_slice, hstopn]
  have hcopy : core.slice.Slice.copy_from_slice core.marker.CopyU8
      (Array.to_slice cells.val[k.val]!) src = ok src := by
    simp [core.slice.Slice.copy_from_slice, UScalar.eq_equiv, src, Array.to_slice,
      chunk.property]
  have hback : Array.from_slice cells.val[k.val]! src = chunk := by
    apply Subtype.ext
    simp [src, Array.to_slice, chunk.property]
  have hbytes : BYTES_PER_CELL = ok 2048#usize := by
    unfold BYTES_PER_CELL
    simp only [FIELD_ELEMENTS_PER_CELL, BYTES_PER_FIELD_ELEMENT]
    rw [scalar_mul_ok 64#usize 32#usize (by scalar_tac)]
    congr 1
  dsimp only [k] at hindex hadd hstart hcopy hback
  simp only [cell_extender.CellExtender.compute_loop0.body, hn, bind_tc_ok,
    Function.uncurry_apply_pair, hindex, Array.to_slice_mut, lift, hbytes,
    hstart, hadd, hstop, hsrc, hcopy, hback]
  rfl

theorem copy_cells_loop (blob : Blob) (cells : Cells)
    (iter : core.ops.range.Range Usize) (he : iter.end.val = 64)
    (hs : iter.start.val ≤ 64)
    (hc : ∀ k, k < iter.start.val → arrayBytes cells.val[k]! =
      (arrayBytes blob).extract (k*2048) ((k+1)*2048)) :
    ∃ out, cell_extender.CellExtender.compute_loop0 iter blob cells = ok out ∧
      ∀ k, k < 64 → arrayBytes out.val[k]! =
        (arrayBytes blob).extract (k*2048) ((k+1)*2048) := by
  induction hrem : 64-iter.start.val generalizing cells iter with
  | zero =>
    have hs' : iter.start.val = 64 := by omega
    refine ⟨cells, ?_, by simpa [hs'] using hc⟩
    rw [cell_extender.CellExtender.compute_loop0, loop.eq_1]
    simp only [cell_extender.CellExtender.compute_loop0.body,
      Refinement.next_ge iter (by omega), bind_tc_ok, Function.uncurry_apply_pair]
  | succ rem ih =>
    have hk : iter.start.val < 64 := by omega
    obtain ⟨iter', hs', he', hn⟩ := Refinement.next_lt iter (by omega)
    let cells' := cells.set iter.start (blobCell blob iter.start.val hk)
    have hc' : ∀ k, k < iter'.start.val → arrayBytes cells'.val[k]! =
        (arrayBytes blob).extract (k*2048) ((k+1)*2048) := by
      intro k hkl
      by_cases hke : k = iter.start.val
      · subst k
        change arrayBytes ((cells.val.set iter.start.val _)[iter.start.val]!) = _
        rw [List.getElem!_set]
        · exact blobCell_bytes blob iter.start.val hk
        · rw [cells.property]; exact Nat.lt_trans hk (by decide)
      · simpa [cells', Array.set, List.getElem!_set_ne, Ne.symm hke] using hc k (by omega)
    obtain ⟨out, ho, hp⟩ := ih cells' iter' (by simp [he', he]) (by omega) hc' (by omega)
    refine ⟨out, ?_, hp⟩
    rw [cell_extender.CellExtender.compute_loop0, loop.eq_1]
    simpa only [copy_cell_body blob cells iter iter' hk hn] using ho

theorem copy_first_half (blob : Blob) (cells : Cells) :
    ∃ out, cell_extender.CellExtender.compute_loop0
        { start := 0#usize, «end» := 64#usize } blob cells = ok out ∧
      ∀ k, k < 64 → (cellBytes out)[k]! =
        (arrayBytes blob).extract (k*2048) ((k+1)*2048) := by
  obtain ⟨out, ho, hp⟩ := copy_cells_loop blob cells
    { start := 0#usize, «end» := 64#usize } rfl (by decide) (by simp)
  exact ⟨out, ho, fun k hk => (cellBytes_get out k (by omega)).trans (hp k hk)⟩

theorem write_cells_loop [e : KzgExternals] (hbytes : FrToBytesCorrect e)
    (v : cell_extender.CellExtender) (values : _root_.Array Fr)
    (hsize : values.size = 4096) (hvals : v.evaluations.val = values.toList.map frEncode)
    (initial cells : Cells) (iter : core.ops.range.Range Usize)
    (he : iter.end.val = 4096) (hs : iter.start.val ≤ 4096)
    (hw : Written values initial iter.start.val cells) :
    ∃ out, cell_extender.CellExtender.write_extension_loop iter v cells = ok out ∧
      Written values initial 4096 out := by
  induction hrem : 4096-iter.start.val generalizing cells iter with
  | zero =>
    have hs' : iter.start.val = 4096 := by omega
    refine ⟨cells, ?_, by simpa [hs'] using hw⟩
    rw [cell_extender.CellExtender.write_extension_loop, loop.eq_1]
    simp only [cell_extender.CellExtender.write_extension_loop.body,
      Refinement.next_ge iter (by omega), bind_tc_ok, Function.uncurry_apply_pair]
  | succ rem ih =>
    have hj : iter.start.val < 4096 := by omega
    obtain ⟨iter', hs', he', hn⟩ := Refinement.next_lt iter (by omega)
    obtain ⟨bs, hbs, hb⟩ := write_chunk_body hbytes v values hsize hvals cells iter iter' hj hn
    have hw' := Written.step values initial cells iter.start.val hj hw bs hbs
    obtain ⟨out, ho, hp⟩ := ih (storeChunk cells iter.start.val bs) iter'
      (by simp [he', he]) (by omega) (by simpa only [hs'] using hw') (by omega)
    refine ⟨out, ?_, hp⟩
    rw [cell_extender.CellExtender.write_extension_loop, loop.eq_1]
    simpa only [hb] using ho

theorem written_cell (values : _root_.Array Fr) (hsize : values.size = 4096)
    (initial cells : Cells) (hw : Written values initial 4096 cells)
    (k : Nat) (hk : k < 128) (hkl : 64 ≤ k) :
    arrayBytes cells.val[k]! = cosetEvalsToCell
      ((bitReversalPermutation values).extract ((k-64)*64) ((k-64)*64+64)) := by
  apply ByteArray.ext
  apply _root_.Array.ext
  · simp only [ByteArray.size_data, arrayBytes_size, cosetEvalsToCell_size,
      UScalar.ofNatCore_val_eq]
  · intro b hb hc
    have hb' : b < 2048 := by
      simpa only [ByteArray.size_data, arrayBytes_size, UScalar.ofNatCore_val_eq] using hb
    have hj : (k-64)*64+b/32 < 4096 := by omega
    have hh := hw.2 ((k-64)*64+b/32) hj (b%32) (by omega)
    have hdiv : 64+((k-64)*64+b/32)/64 = k := by omega
    have hat : (((k-64)*64+b/32)%64)*32+b%32 = b := by omega
    rw [hdiv, hat] at hh
    have htarget := extension_cell_get values hsize (k-64) b (by omega) hb'
    rw [getElem!_pos (arrayBytes cells.val[k]!) b (by rw [arrayBytes_size]; exact hb')] at hh
    rw [getElem!_pos (cosetEvalsToCell
      ((bitReversalPermutation values).extract ((k-64)*64) ((k-64)*64+64))) b
      (by rw [cosetEvalsToCell_size]; exact hb')] at htarget
    simp only [rev, ByteArray.getElem_eq_getElem_data] at hh htarget
    exact hh.trans htarget.symm

theorem write_extension_refinement [e : KzgExternals] (hbytes : FrToBytesCorrect e)
    (v : cell_extender.CellExtender) (values : _root_.Array Fr)
    (hsize : values.size = 4096) (hvals : v.evaluations.val = values.toList.map frEncode)
    (cells : Cells) :
    ∃ out, cell_extender.CellExtender.write_extension v cells = ok out ∧
      cellBytes out = _root_.Array.ofFn (n := 128) (fun i =>
        if i.val < 64 then (cellBytes cells)[i.val]!
        else cosetEvalsToCell ((bitReversalPermutation values).extract
          ((i.val-64)*64) ((i.val-64)*64+64))) := by
  obtain ⟨out, ho, hp⟩ := write_cells_loop hbytes v values hsize hvals cells cells
    { start := 0#usize, «end» := FIELD_ELEMENTS_PER_BLOB }
    (by simp [FIELD_ELEMENTS_PER_BLOB]) (by decide)
    ⟨fun _ _ => rfl, by simp⟩
  refine ⟨out, ho, ?_⟩
  apply _root_.Array.ext
  · simp only [cellBytes, List.size_toArray, List.length_map, out.property,
      _root_.Array.size_ofFn, UScalar.ofNatCore_val_eq]
  · intro k hk ht
    have hk' : k < 128 := by simpa only [_root_.Array.size_ofFn] using ht
    have hg := cellBytes_get out k hk'
    rw [getElem!_pos (cellBytes out) k hk] at hg
    rw [hg, _root_.Array.getElem_ofFn]
    by_cases hkl : k < 64
    · simp only [hkl, if_true, hp.1 k hkl, cellBytes_get cells k hk']
    · simp only [hkl, if_false]
      exact written_cell values hsize cells out hp k hk' (by omega)

theorem output_refinement [e : KzgExternals] (hbytes : FrToBytesCorrect e)
    (blob : Blob) (cells : Cells) (values : _root_.Array Fr)
    (v : cell_extender.CellExtender) (hsize : values.size = 4096)
    (hvals : v.evaluations.val = values.toList.map frEncode) :
    ∃ copied out, cell_extender.CellExtender.compute_loop0
        { start := 0#usize, «end» := 64#usize } blob cells = ok copied ∧
      cell_extender.CellExtender.write_extension v copied = ok out ∧
      cellBytes out = _root_.Array.ofFn (n := 128) (fun i =>
        if i.val < 64 then (arrayBytes blob).extract (i.val*2048) ((i.val+1)*2048)
        else cosetEvalsToCell ((bitReversalPermutation values).extract
          ((i.val-64)*64) ((i.val-64)*64+64))) := by
  obtain ⟨copied, hc, hp⟩ := copy_first_half blob cells
  obtain ⟨out, ho, hv⟩ := write_extension_refinement hbytes v values hsize hvals copied
  refine ⟨copied, out, hc, ho, hv.trans ?_⟩
  apply congrArg _root_.Array.ofFn
  funext i
  split
  · exact hp i.val (by assumption)
  · rfl

end LeanBlsSimd.Kzg.Extender
