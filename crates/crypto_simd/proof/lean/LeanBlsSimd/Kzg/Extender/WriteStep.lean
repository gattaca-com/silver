import LeanBlsSimd.Kzg.Fr.ByteEncode
import LeanBlsSimd.Kzg.Extender.Decode
import LeanBlsSimd.Kzg.Refines.Cosets

open Aeneas Aeneas.Std Result ControlFlow
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender

local instance extenderWriteRawFrInhabited : Inhabited blst.blst_fr := ⟨frEncode 0⟩

def storeChunk (cells : Cells) (j : Nat) (bs : Aeneas.Std.Array U8 32#usize) : Cells :=
  ⟨cells.val.set (64+j/64)
    (Aeneas.Std.Array.setSlice! cells.val[64+j/64]! ((j%64)*32) bs.val), by simp [cells.property]⟩

theorem write_chunk_body
    (v : cell_extender.CellExtender) (values : _root_.Array Fr)
    (hsize : values.size = 4096) (hvals : v.evaluations.val = values.toList.map frEncode)
    (cells : Cells) (iter iter' : core.ops.range.Range Usize)
    (hj : iter.start.val < 4096)
    (hn : core.iter.range.IteratorRange.next core.iter.range.StepUsize iter =
      ok (some iter.start, iter')) :
    ∃ bs, arrayBytes bs = blsFieldToBytes values[rev iter.start.val]! ∧
      cell_extender.CellExtender.write_extension_loop.body v iter cells =
        ok (cont (iter', storeChunk cells iter.start.val bs)) := by
  obtain ⟨bs, hserialize, hbs⟩ := FrScalar.fr_to_bytes_refines values[rev iter.start.val]!
  refine ⟨bs, hbs, ?_⟩
  have hindex : alloc.vec.Vec.index (core.slice.index.SliceIndexUsizeSlice blst.blst_fr)
      v.evaluations (UScalar.ofNatCore (rev iter.start.val) (by have := rev_lt iter.start.val; scalar_tac)) =
      ok (frEncode values[rev iter.start.val]!) := by
    have hi : rev iter.start.val < values.size := by rw [hsize]; exact rev_lt _
    simp [alloc.vec.Vec.index_usize, hvals, hi]
  obtain ⟨half, hhalf, hhalfval⟩ := UScalar.div_spec 128#usize (y := 2#usize) (by simp)
  have hhalfeq : half = 64#usize := UScalar.eq_of_val_eq (by simpa using hhalfval)
  subst half
  obtain ⟨quot, hquot, hquotval⟩ := UScalar.div_spec iter.start
    (y := FIELD_ELEMENTS_PER_CELL) (by simp [FIELD_ELEMENTS_PER_CELL])
  have hquotval' : quot.val = iter.start.val / 64 := by simpa [FIELD_ELEMENTS_PER_CELL] using hquotval
  obtain ⟨rem, hrem, hremval⟩ := WP.spec_imp_exists (UScalar.rem_spec iter.start
    (y := FIELD_ELEMENTS_PER_CELL) (by simp [FIELD_ELEMENTS_PER_CELL]))
  have hremval' : rem.val = iter.start.val % 64 := by simpa [FIELD_ELEMENTS_PER_CELL] using hremval
  let cell : Usize := UScalar.ofNatCore (64 + iter.start.val / 64) (by scalar_tac)
  let atByte : Usize := UScalar.ofNatCore ((iter.start.val % 64)*32) (by scalar_tac)
  let stop : Usize := UScalar.ofNatCore ((iter.start.val % 64)*32 + 32) (by scalar_tac)
  have haddCell : 64#usize + quot = ok cell := by
    simpa [hquotval', cell] using scalar_add_ok 64#usize quot (by scalar_tac)
  have hmul : rem * BYTES_PER_FIELD_ELEMENT = ok atByte := by
    simpa [BYTES_PER_FIELD_ELEMENT, hremval', atByte] using
      scalar_mul_ok rem 32#usize (by scalar_tac)
  have haddStop : atByte + BYTES_PER_FIELD_ELEMENT = ok stop := by
    simpa [BYTES_PER_FIELD_ELEMENT, atByte, stop] using
      scalar_add_ok atByte 32#usize (by scalar_tac)
  have hcell : 64 + iter.start.val / 64 < cells.val.length := by simp [cells.property]; omega
  let old := cells.val[64 + iter.start.val / 64]!
  have hcellIndex : Array.index_mut_usize cells cell = ok (old, Aeneas.Std.Array.set cells cell) := by
    simp [Array.index_mut_usize, Array.index_usize, cell, old,
      List.getElem?_eq_getElem hcell, getElem!_pos cells.val (64 + iter.start.val / 64) hcell]
  have hbounds : (iter.start.val % 64) * 32 + 32 ≤ 2048 := by omega
  have hroom : 32 ≤ 2048 - (iter.start.val % 64) * 32 := by omega
  simp only [cell_extender.CellExtender.write_extension_loop.body, hn, bind_tc_ok,
    Function.uncurry_apply_pair, reverse_bits_blob, hindex,
    hserialize, cells_per_ext_blob_eq, hhalf, hquot, haddCell, hrem, hmul,
    hcellIndex, haddStop]
  simp [core.array.Array.index_mut, core.ops.index.IndexMutSlice,
    core.slice.index.Slice.index_mut, core.slice.index.SliceIndexRangeUsizeSlice.index_mut,
    atByte, stop, Array.to_slice, Slice.length, UScalar.le_equiv, hbounds,
    core.slice.Slice.copy_from_slice, Slice.len, List.slice, bs.property,
    Array.from_slice, Aeneas.Std.Array.set, Aeneas.Std.Array.setSlice!, storeChunk, cell, old,
    lift, bind_tc_ok, Nat.min_eq_left hroom]

end LeanBlsSimd.Kzg.Extender
