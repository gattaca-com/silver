import LeanBlsSimd.Kzg.Extender.Kernel.Fr8
import LeanBlsSimd.Kzg.Extender.Write

open Aeneas Aeneas.Std Result ControlFlow
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Kernel

set_option maxHeartbeats 2000000

def extensionCells (cells : Cells) (values : _root_.Array Fr) : _root_.Array Cell :=
  _root_.Array.ofFn (n := 128) fun i =>
    if i.val < 64 then (cellBytes cells)[i.val]!
    else cosetEvalsToCell (values.extract ((i.val - 64) * 64) ((i.val - 64) * 64 + 64))

private def Encoded (values : _root_.Array Fr) (initial : Cells) (n : Nat)
    (cells : Cells) : Prop :=
  (∀ k, k < 64 → cells.val[k]! = initial.val[k]!) ∧
  ∀ j, j < 8*n → ∀ b, b < 32 →
    (arrayBytes cells.val[64+j/64]!)[(j%64)*32+b]! =
      (blsFieldToBytes values[j]!)[b]!

private theorem extract_get (a b : ByteArray) (start stop i : Nat)
    (he : a.extract start stop = b) (hi : i < b.size) :
    a[start+i]! = b[i]! := by
  have hx : i < (a.extract start stop).size := by rw [he]; exact hi
  have ha : start+i < a.size := ByteArray.getElem_extract_aux hx
  rw [getElem!_pos a (start+i) ha, getElem!_pos b i hi,
    ← ByteArray.getElem_extract hx]
  have hh := congrArg (fun x : ByteArray => x[i]!) he
  simpa only [getElem!_pos (a.extract start stop) i hx, getElem!_pos b i hi] using hh

private theorem encoded_step (values : _root_.Array Fr) (initial cells : Cells)
    (n : Nat) (hn : n < 512) (hw : Encoded values initial n cells)
    (out : Slice U8) (hlen : out.val.length = 2048)
    (hbytes : ∀ lane : Fin 8,
      (bytes out.val).extract ((n%8)*256+32*lane.val) ((n%8)*256+32*(lane.val+1)) =
        blsFieldToBytes values[8*n+lane.val]!)
    (hframe : ∀ i : Fin 2048, i.val < (n%8)*256 ∨ (n%8)*256+256 ≤ i.val →
      out.val[i.val]? = cells.val[64+n/8]!.val[i.val]?) :
    Encoded values initial (n+1)
      (cells.set (UScalar.ofNatCore (64+n/8) (by scalar_tac)) ⟨out.val, hlen⟩) := by
  let written : CellArray := ⟨out.val, hlen⟩
  have hc : 64+n/8 < cells.val.length := by
    simp only [cells.property, UScalar.ofNatCore_val_eq]; omega
  constructor
  · intro k hk
    change (cells.val.set (64+n/8) written)[k]! = _
    exact (List.getElem!_set_ne _ _ _ _ (by omega)).trans (hw.1 k hk)
  · intro j hj b hb
    by_cases hjn : j < 8*n
    · by_cases he : j/64 = n/8
      · change (arrayBytes ((cells.val.set (64+n/8) written)[64+j/64]!))[_]! = _
        rw [he, List.getElem!_set _ _ _ hc]
        have hat : (j%64)*32+b < 2048 := by omega
        have hlt : (j%64)*32+b < (n%8)*256 := by omega
        have hf := hframe ⟨(j%64)*32+b, hat⟩ (Or.inl hlt)
        have hg : out.val[(j%64)*32+b]! = cells.val[64+n/8]!.val[(j%64)*32+b]! := by
          simpa only [List.getElem!_eq_getElem?_getD] using
            congrArg (fun x : Option U8 => x.getD default) hf
        have hprev := hw.2 j hjn b hb
        rw [he, arrayBytes_get cells.val[64+n/8]! _ hat] at hprev
        rw [arrayBytes_get written _ hat]
        exact (congrArg (fun x : U8 => UInt8.ofBitVec x.bv) hg).trans hprev
      · change (arrayBytes ((cells.val.set (64+n/8) written)[64+j/64]!))[_]! = _
        rw [List.getElem!_set_ne _ _ _ _ (by omega)]
        exact hw.2 j hjn b hb
    · have hl : j-8*n < 8 := by omega
      have he : j = 8*n+(j-8*n) := by omega
      have hcell : 64+j/64 = 64+n/8 := by omega
      have hat : (j%64)*32+b = (n%8)*256+32*(j-8*n)+b := by omega
      change (arrayBytes ((cells.val.set (64+n/8) written)[64+j/64]!))[_]! = _
      rw [hcell, List.getElem!_set _ _ _ hc, hat]
      exact (extract_get (bytes out.val) _ _ _ b (hbytes ⟨j-8*n, hl⟩)
        (by rw [field_bytes_size]; exact hb)).trans (by rw [← he])

private theorem encoded_cell (values : _root_.Array Fr) (hsize : values.size = 4096)
    (initial cells : Cells) (hw : Encoded values initial 512 cells)
    (k : Nat) (hk : k < 128) (hkl : 64 ≤ k) :
    arrayBytes cells.val[k]! = cosetEvalsToCell
      (values.extract ((k-64)*64) ((k-64)*64+64)) := by
  apply ByteArray.ext
  apply _root_.Array.ext
  · simp only [ByteArray.size_data, arrayBytes_size, cosetEvalsToCell_size,
      UScalar.ofNatCore_val_eq]
  · intro b hb hc
    have hb' : b < 2048 := by
      simpa only [ByteArray.size_data, arrayBytes_size, UScalar.ofNatCore_val_eq] using hb
    have hj : (k-64)*64+b/32 < 8*512 := by omega
    have hh := hw.2 ((k-64)*64+b/32) hj (b%32) (by omega)
    have hdiv : 64+((k-64)*64+b/32)/64 = k := by omega
    have hat : (((k-64)*64+b/32)%64)*32+b%32 = b := by omega
    rw [hdiv, hat] at hh
    have htarget := cosetEvalsToCell_get
      (values.extract ((k-64)*64) ((k-64)*64+64)) b hb'
    have hchunk : b/32 < (values.extract ((k-64)*64) ((k-64)*64+64)).size := by
      simp only [_root_.Array.size_extract, hsize]; omega
    have hvalue : (values.extract ((k-64)*64) ((k-64)*64+64))[b/32]! =
        values[(k-64)*64+b/32]! := by
      rw [getElem!_pos (values.extract ((k-64)*64) ((k-64)*64+64)) (b/32) hchunk,
        _root_.Array.getElem_extract]
      exact (getElem!_pos values ((k-64)*64+b/32) (by omega)).symm
    have htarget' := htarget.trans
      (congrArg (fun f : Fr => (blsFieldToBytes f)[b%32]!) hvalue)
    rw [getElem!_pos (arrayBytes cells.val[k]!) b (by rw [arrayBytes_size]; exact hb')] at hh
    rw [getElem!_pos (cosetEvalsToCell
      (values.extract ((k-64)*64) ((k-64)*64+64))) b
      (by rw [cosetEvalsToCell_size]; exact hb')] at htarget'
    simp only [ByteArray.getElem_eq_getElem_data] at hh htarget'
    exact hh.trans htarget'.symm

private theorem encode_loop (data : alloc.vec.Vec fr8.Fr8) (values : _root_.Array Fr)
    (hlen : data.val.length = 512) (hdata : DataRep (alloc.vec.Vec.deref data) values)
    (initial cells : Cells) (i : Usize) (hi : i.val ≤ 512)
    (hw : Encoded values initial i.val cells) :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop1 data cells i = ok out ∧
      Encoded values initial 512 out := by
  induction hrem : 512-i.val generalizing cells i with
  | zero =>
    have he : i.val = 512 := by omega
    refine ⟨cells, ?_, by simpa only [he] using hw⟩
    rw [extension_kernel.ExtensionKernel.extend_loop1, loop.eq_1]
    simp [extension_kernel.ExtensionKernel.extend_loop1.body, alloc.vec.Vec.len,
      UScalar.lt_equiv, hlen, he]
  | succ rem ih =>
    have hit : i.val < 512 := by omega
    have hil : i.val < data.val.length := by omega
    have hp : Represents data.val[i.val]! (fun lane => values[8*i.val+lane.val]!) := by
      simpa only [getElem!_pos data.val i.val hil] using hdata.2 ⟨i.val, hil⟩
    let cell : Usize := UScalar.ofNatCore (64+i.val/8) (by scalar_tac)
    let offset : Usize := UScalar.ofNatCore ((i.val%8)*256) (by scalar_tac)
    have hc : cell.val = 64+i.val/8 := UScalar.ofNatCore_val_eq _
    have ho : offset.val = (i.val%8)*256 := UScalar.ofNatCore_val_eq _
    have hcell : cell.val < cells.val.length := by
      simp only [cells.property, UScalar.ofNatCore_val_eq, hc]; omega
    have hsize : offset.val+256 ≤ (Array.to_slice cells.val[cell.val]!).val.length := by
      simp only [Array.to_slice, cells.val[cell.val]!.property, UScalar.ofNatCore_val_eq, ho]
      omega
    obtain ⟨serialized, hs, hslen, hsbytes, hsframe⟩ :=
      to_bytes_refinement data.val[i.val]! hp.1 (Array.to_slice cells.val[cell.val]!) offset hsize
    have hslen' : serialized.val.length = 2048 := by
      simpa only [Array.to_slice, cells.val[cell.val]!.property, UScalar.ofNatCore_val_eq] using hslen
    let written : CellArray := ⟨serialized.val, hslen'⟩
    let next := cells.set cell written
    have hw' : Encoded values initial (i.val+1) next := by
      apply encoded_step values initial cells i.val hit hw serialized hslen'
      · intro lane
        simpa only [ho, hp.2 lane] using hsbytes lane
      · intro b hb
        have hbl : b.val < (Array.to_slice cells.val[cell.val]!).val.length := by
          simpa only [Array.to_slice, cells.val[cell.val]!.property, UScalar.ofNatCore_val_eq]
            using b.isLt
        simpa only [Array.to_slice, hc] using hsframe ⟨b.val, hbl⟩ (by simpa only [ho] using hb)
    let i' : Usize := UScalar.ofNatCore (i.val+1) (by scalar_tac)
    have hi' : i'.val = i.val+1 := UScalar.ofNatCore_val_eq _
    obtain ⟨out, hout, hwout⟩ := ih next i' (by omega)
      (by simpa only [hi'] using hw') (by omega)
    refine ⟨out, ?_, hwout⟩
    have hadd : i+1#usize = ok i' := scalar_add_ok i 1#usize (by scalar_tac)
    have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice fr8.Fr8)
        data i = ok data.val[i.val]! := by
      simp [alloc.vec.Vec.index_usize, List.getElem?_eq_getElem hil]
    have hmut : Array.index_mut_usize cells cell = ok (cells.val[cell.val]!, cells.set cell) := by
      simp [Array.index_mut_usize, Array.index_usize, List.getElem?_eq_getElem hcell]
    have hback : Array.from_slice cells.val[cell.val]! serialized = written := by
      apply Subtype.ext
      simp only [Array.from_slice, hslen', UScalar.ofNatCore_val_eq, ↓reduceDIte, written]
    have hvectors : extension_kernel.VECTORS_PER_CELL = ok 8#usize := by
      unfold extension_kernel.VECTORS_PER_CELL
      simp only [FIELD_ELEMENTS_PER_CELL, fr8.LANES]
      rfl
    obtain ⟨quot, hquot, hq⟩ := UScalar.div_spec i (y := 8#usize) (by decide)
    obtain ⟨rest, hrest, hr⟩ := WP.spec_imp_exists (UScalar.rem_spec i (y := 8#usize) (by decide))
    have hq' : quot.val = i.val/8 := hq
    have hr' : rest.val = i.val%8 := hr
    have hcelladd : 64#usize + quot = ok cell := by
      simpa only [hq', cell] using scalar_add_ok 64#usize quot (by scalar_tac)
    let block : Usize := UScalar.ofNatCore ((i.val%8)*8) (by scalar_tac)
    have hblock : rest*fr8.LANES = ok block := by
      simpa only [fr8.LANES, hr', block] using scalar_mul_ok rest 8#usize (by scalar_tac)
    have hoffset : block*BYTES_PER_FIELD_ELEMENT = ok offset := by
      simpa only [BYTES_PER_FIELD_ELEMENT, block, UScalar.ofNatCore_val_eq,
        Nat.mul_assoc, offset] using scalar_mul_ok block 32#usize (by scalar_tac)
    have hhalf : 128#usize / 2#usize = ok 64#usize := rfl
    have hlt : i < alloc.vec.Vec.len data := by
      simpa only [UScalar.lt_equiv, alloc.vec.Vec.len, UScalar.ofNatCore_val_eq] using hil
    have hbody : extension_kernel.ExtensionKernel.extend_loop1.body data cells i =
        ok (cont (next, i')) := by
      simp only [extension_kernel.ExtensionKernel.extend_loop1.body, hlt, if_true,
        cells_per_ext_blob_eq, bind_tc_ok, hhalf, hvectors, hquot, hcelladd, hrest,
        hblock, hoffset, hindex, hmut, Array.to_slice_mut, lift, Function.uncurry_apply_pair]
      simp only [hs, bind_tc_ok, hadd, hback, next]
    rw [extension_kernel.ExtensionKernel.extend_loop1, loop.eq_1]
    simpa only [hbody] using hout

theorem encode_refinement (data : alloc.vec.Vec fr8.Fr8) (values : _root_.Array Fr)
    (hsize : values.size = 4096) (hdata : DataRep (alloc.vec.Vec.deref data) values)
    (cells : Cells) :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop1 data cells 0#usize = ok out ∧
      cellBytes out = extensionCells cells values ∧
      ∀ i : Fin 64, out.val[i.val]? = cells.val[i.val]? := by
  have hlen : data.val.length = 512 := by
    have hh := hdata.1
    change values.size = 8*data.val.length at hh
    omega
  obtain ⟨out, hout, hw⟩ := encode_loop data values hlen hdata cells cells 0#usize
    (by decide) ⟨fun _ _ => rfl, by simp⟩
  refine ⟨out, hout, ?_, ?_⟩
  · unfold extensionCells
    apply _root_.Array.ext
    · simp only [cellBytes, List.size_toArray, List.length_map, out.property,
        _root_.Array.size_ofFn, UScalar.ofNatCore_val_eq]
    · intro k hk ht
      have hk' : k < 128 := by simpa only [_root_.Array.size_ofFn] using ht
      have hg := cellBytes_get out k hk'
      rw [getElem!_pos (cellBytes out) k hk] at hg
      rw [hg, _root_.Array.getElem_ofFn]
      by_cases hkl : k < 64
      · simp only [hkl, if_true, hw.1 k hkl, cellBytes_get cells k hk']
      · simp only [hkl, if_false]
        exact encoded_cell values hsize cells out hw k hk' (by omega)
  · intro i
    have ho : i.val < out.val.length := by simp only [out.property, UScalar.ofNatCore_val_eq]; omega
    have hc : i.val < cells.val.length := by simp only [cells.property, UScalar.ofNatCore_val_eq]; omega
    simpa only [List.getElem?_eq_getElem ho, List.getElem?_eq_getElem hc,
      getElem!_pos out.val i.val ho, getElem!_pos cells.val i.val hc]
      using congrArg some (hw.1 i.val i.isLt)

end LeanBlsSimd.Kzg.Extender.Kernel
