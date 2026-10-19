import LeanBlsSimd.Kzg.Extender.Statements

open Aeneas Aeneas.Std Result
open EthCryptographySpecs Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls

@[irreducible] def layoutBlob (b : U8) : Blob :=
  ⟨List.replicate 131072 b, by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

def layoutChunk (b : U8) : Aeneas.Std.Array U8 32#usize :=
  ⟨List.replicate 32 b, by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

@[irreducible] def layoutCell (b : U8) : CellArray :=
  ⟨List.replicate 2048 b, by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

@[irreducible] def layoutCells (b : U8) : Cells :=
  ⟨List.replicate 128 (layoutCell b), by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

private theorem layout_blob_chunk (b : U8) (i : Nat) (hi : i < 4096) :
    blobChunk (layoutBlob b) i hi = layoutChunk b := by
  apply Subtype.ext
  simp [-List.reduceReplicate, blobChunk, layoutBlob, layoutChunk, List.slice]
  omega

private theorem layout_cell_byte (b : U8) :
    ((cellBytes (layoutCells b))[0]!)[0]! = UInt8.ofBitVec b.bv := by
  rw [cellBytes_get _ 0 (by decide), arrayBytes_get _ 0 (by decide)]
  simp [-List.reduceReplicate, layoutCells, layoutCell]

theorem layout_zero_blob_canonical : Canonical (layoutBlob 0#u8) := by
  intro i
  have hchunk := blobChunk_bytes (layoutBlob 0#u8) i.val i.isLt
  rw [layout_blob_chunk] at hchunk
  rw [show i.val * 32 = 32 * i.val by omega,
    show (i.val+1)*32 = 32*(i.val+1) by omega, ← hchunk]
  decide +kernel

theorem layout_ff_blob_noncanonical : ¬ Canonical (layoutBlob 255#u8) := by
  intro h
  have hc := h ⟨0, by decide⟩
  have hchunk := blobChunk_bytes (layoutBlob 255#u8) 0 (by decide)
  rw [layout_blob_chunk] at hchunk
  change Fr.bytesBEToNat ((arrayBytes (layoutBlob 255#u8)).extract 0 32) < Fr.modulus at hc
  rw [← hchunk] at hc
  exact (by decide +kernel : ¬ Fr.bytesBEToNat (arrayBytes (layoutChunk 255#u8)) < Fr.modulus) hc

theorem decode_ff_blob_rejects :
    ∃ initial next,
      @cell_extender.CellExtender.new specExternals = ok initial ∧
      @cell_extender.CellExtender.decode_blob specExternals initial (layoutBlob 255#u8) =
        ok (false, next) ∧ StateInvariant next := by
  obtain ⟨initial, hnew, hinitial⟩ :=
    @new_returns_ok specExternals specExternals_correct.1
  obtain ⟨verdict, next, hdecode, hnext, _, hresult⟩ :=
    @decode_blob_refinement specExternals specExternals_correct.1 initial hinitial
      (layoutBlob 255#u8)
  have hfalse : verdict = false := by
    cases hd : blobToPolynomial (arrayBytes (layoutBlob 255#u8)) with
    | error err => simpa only [hd] using hresult
    | ok values =>
      exact False.elim (layout_ff_blob_noncanonical
        ((blob_decode_exists_iff _).mp ⟨values, hd⟩))
  subst verdict
  exact ⟨initial, next, hnew, hdecode, hnext⟩

private theorem blob_first_cell_byte (blob : Blob) :
    ((arrayBytes blob).extract 0 2048)[0]! = (arrayBytes blob)[0]! := by
  rw [getElem!_pos ((arrayBytes blob).extract 0 2048) 0 (by
    simp only [ByteArray.size_extract, blob_bytes_size]; decide), ByteArray.getElem_extract,
    getElem!_pos (arrayBytes blob) 0 (by rw [blob_bytes_size]; decide)]

private theorem layout_blob_byte (b : U8) :
    (arrayBytes (layoutBlob b))[0]! = UInt8.ofBitVec b.bv := by
  rw [arrayBytes_get _ 0 (by decide)]
  simp [-List.reduceReplicate, layoutBlob]

def omitFirstHalfCopy (_blob : Blob) (cells : Cells) : Result Cells := ok cells

private theorem copy_changes_first_byte (blob : Blob) (cells : Cells)
    (hdiff : ((cellBytes cells)[0]!)[0]! ≠ (arrayBytes blob)[0]!) :
    cell_extender.copy_blob_loop
      { start := 0#usize, «end» := 64#usize } blob cells ≠ omitFirstHalfCopy blob cells := by
  obtain ⟨out, hout, hfirst⟩ := copy_first_half blob cells
  intro he
  rw [hout] at he
  have heq : out = cells := Result.ok.inj he
  have hbyte := congrArg (fun b : ByteArray => b[0]!) (hfirst 0 (by decide))
  dsimp only at hbyte
  rw [heq, blob_first_cell_byte] at hbyte
  exact hdiff hbyte

theorem omitFirstHalfCopy_rejected :
    cell_extender.copy_blob_loop
      { start := 0#usize, «end» := 64#usize } (layoutBlob 0#u8) (layoutCells 255#u8) ≠
      omitFirstHalfCopy (layoutBlob 0#u8) (layoutCells 255#u8) := by
  apply copy_changes_first_byte
  rw [layout_cell_byte, layout_blob_byte]
  decide

private theorem noncanonical_extension (blob : Blob) (hc : ¬ Canonical blob) :
    ∃ err, Model.extend (arrayBytes blob) = .error err := by
  cases hm : Model.extend (arrayBytes blob) with
  | error err => exact ⟨err, rfl⟩
  | ok result =>
    exact False.elim (hc ((model_accepts_iff _).mp (by simp [hm, Except.isOk, Except.toBool])))

private theorem layout_invalid_extension :
    ∃ err, Model.extend (arrayBytes (layoutBlob 255#u8)) = .error err :=
  noncanonical_extension (layoutBlob 255#u8) layout_ff_blob_noncanonical

def acceptNoncanonicalBlob (blob : ByteArray) (cells : _root_.Array Cell) :
    Bool × _root_.Array Cell :=
  match Model.extend blob with
  | .error _ => (true, cells)
  | .ok out => (true, out)

theorem acceptNoncanonicalBlob_rejected :
    acceptNoncanonicalBlob (arrayBytes (layoutBlob 255#u8)) (cellBytes (layoutCells 255#u8)) ≠
      Model.compute (arrayBytes (layoutBlob 255#u8)) (cellBytes (layoutCells 255#u8)) := by
  obtain ⟨err, hm⟩ := layout_invalid_extension
  have hmut (blob : ByteArray) (cells : _root_.Array Cell) (err : KzgError)
      (hm : Model.extend blob = .error err) : acceptNoncanonicalBlob blob cells ≠ Model.compute blob cells := by
    simp [acceptNoncanonicalBlob, Model.compute, hm]
  exact hmut _ _ err hm

def clearCellsOnRejection (blob : ByteArray) (_cells : _root_.Array Cell) :
    Bool × _root_.Array Cell :=
  match Model.extend blob with
  | .error _ => (false, cellBytes (layoutCells 0#u8))
  | .ok out => (true, out)

theorem clearCellsOnRejection_rejected :
    clearCellsOnRejection (arrayBytes (layoutBlob 255#u8)) (cellBytes (layoutCells 255#u8)) ≠
      Model.compute (arrayBytes (layoutBlob 255#u8)) (cellBytes (layoutCells 255#u8)) := by
  obtain ⟨err, hm⟩ := layout_invalid_extension
  have hmut (blob : ByteArray) (cells : _root_.Array Cell) (err : KzgError)
      (hm : Model.extend blob = .error err) (hne : cellBytes (layoutCells 0#u8) ≠ cells) :
      clearCellsOnRejection blob cells ≠ Model.compute blob cells := by
    simp only [clearCellsOnRejection, Model.compute, hm, ne_eq, Prod.mk.injEq, true_and]
    exact hne
  apply hmut _ _ err hm
  intro he
  have hc := congrArg (fun cells : _root_.Array Cell => (cells[0]!)[0]!) he
  dsimp only at hc
  rw [layout_cell_byte, layout_cell_byte] at hc
  exact (by decide : (0 : UInt8) ≠ 255) hc

def omitExtensionOffset (cells : Cells) (j : Nat) (bs : Aeneas.Std.Array U8 32#usize) : Cells :=
  ⟨cells.val.set (j/64)
    (Aeneas.Std.Array.setSlice! cells.val[j/64]! ((j%64)*32) bs.val), by simp [cells.property]⟩

theorem omitExtensionOffset_rejected :
    omitExtensionOffset (layoutCells 0#u8) 0 (specFrBytes 1) ≠
      storeChunk (layoutCells 0#u8) 0 (specFrBytes 1) := by
  intro he
  have hc := congrArg (fun cells : Cells => (arrayBytes cells.val[0]!)[31]!) he
  dsimp only at hc
  rw [storeChunk_first _ _ 0 _ (by decide)] at hc
  have hleft :
      (arrayBytes (omitExtensionOffset (layoutCells 0#u8) 0 (specFrBytes 1)).val[0]!)[31]! =
        1 := by
    simp only [omitExtensionOffset, Nat.zero_div, Nat.zero_mod, Nat.zero_mul]
    rw [List.getElem!_set _ _ _ (by simp [-List.reduceReplicate, layoutCells]), arrayBytes_get _ 31 (by decide)]
    change UInt8.ofBitVec
      (((layoutCells 0#u8).val[0]!.val.setSlice! 0 (specFrBytes 1).val)[31]!).bv = 1
    rw [List.getElem!_setSlice!_middle _ _ 0 31 (by
      simp only [(specFrBytes 1).property, ((layoutCells 0#u8).val[0]!).property,
        UScalar.ofNatCore_val_eq]
      decide)]
    decide +kernel
  rw [hleft, arrayBytes_get _ 31 (by decide)] at hc
  simp [-List.reduceReplicate, layoutCells, layoutCell] at hc
  exact (by decide : (1 : UInt8) ≠ 0) hc

end LeanBlsSimd.Kzg.Extender.Controls

#print axioms LeanBlsSimd.Kzg.Extender.Controls.layout_zero_blob_canonical
#print axioms LeanBlsSimd.Kzg.Extender.Controls.layout_ff_blob_noncanonical
#print axioms LeanBlsSimd.Kzg.Extender.Controls.decode_ff_blob_rejects
#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitFirstHalfCopy_rejected
#print axioms LeanBlsSimd.Kzg.Extender.Controls.acceptNoncanonicalBlob_rejected
#print axioms LeanBlsSimd.Kzg.Extender.Controls.clearCellsOnRejection_rejected
#print axioms LeanBlsSimd.Kzg.Extender.Controls.omitExtensionOffset_rejected
