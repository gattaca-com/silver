import LeanBlsSimd.Kzg.Extender.Kernel.Encode

open Aeneas Aeneas.Std Result
open EthLib.Cryptography Bls Kzg
open silver_crypto_simd silver_crypto_simd.kzg

namespace LeanBlsSimd.Kzg.Extender.Controls.KernelBytes

open Kernel Kernel.BytePacking

set_option maxHeartbeats 2000000
set_option exponentiation.threshold 1000

private def splat (limbs : FrModel.Limbs) : fr8.Fr8 :=
  FrModel.toFr8 (.ofLanes (.replicate 8 limbs))

private theorem splat_lane (limbs : FrModel.Limbs) (lane : Fin 8) :
    (FrModel.ofFr8 (splat limbs)).lane lane = limbs := by
  simp only [splat, FrModel.ofFr8_toFr8, FrModel.Fr8.lane_ofLanes,
    Fin.getElem_fin, Vector.getElem_replicate]

private theorem splat_bounded (limbs : FrModel.Limbs)
    (hn : ∀ j : Fin 5, limbs[j].toNat < 2^52) (hb : FrModel.val limbs < 2*Fr.modulus) :
    Bounded (splat limbs) := by
  apply (bounded_iff_model _).mpr
  intro lane
  rw [splat_lane]
  exact ⟨hn, hb⟩

def modulusBatch : fr8.Fr8 := splat (.ofList FrModel.P)

theorem modulusBatch_bounded : Bounded modulusBatch :=
  splat_bounded _ FrModel.normal_ofList_P (by rw [FrModel.val_ofList_P]; decide)

theorem modulusBatch_nat (lane : Fin 8) : laneNat modulusBatch lane = Fr.modulus := by
  rw [laneNat_eq_val, modulusBatch, splat_lane, FrModel.val_ofList_P]

private theorem modulusBatch_value (lane : Fin 8) : laneValue modulusBatch lane = 0 := by
  unfold laneValue
  rw [modulusBatch_nat]
  rfl

def oneBatch : fr8.Fr8 := splat (.ofList [1, 0, 0, 0, 0])

private theorem one_limbs_nat : FrModel.val (.ofList [1, 0, 0, 0, 0]) = 1 := by decide +kernel

theorem oneBatch_bounded : Bounded oneBatch :=
  splat_bounded _ (by decide) (by rw [one_limbs_nat]; decide)

theorem oneBatch_nat (lane : Fin 8) : laneNat oneBatch lane = 1 := by
  rw [laneNat_eq_val, oneBatch, splat_lane, one_limbs_nat]

private theorem oneBatch_value (lane : Fin 8) : laneValue oneBatch lane = 1 := by
  unfold laneValue
  rw [oneBatch_nat]
  rfl

@[irreducible] def byteBuffer : Slice U8 :=
  ⟨List.replicate 256 0#u8, by simp only [List.length_replicate]; scalar_tac⟩

private theorem byteBuffer_length : byteBuffer.val.length = 256 := by
  simp only [byteBuffer, List.length_replicate]

/-- The generated output body with its call to `canonical` omitted. -/
def withoutCanonical (a : fr8.Fr8) (input : Slice U8) : Result (Slice U8) := do
  let words ← fr8.u256x8.U256x8.from_limbs a
  fr8.u256x8.U256x8.to_bytes words input 0#usize

example (a : fr8.Fr8) (input : Slice U8) :
    fr8.Fr8.to_bytes a input 0#usize = (do
      let canonical ← fr8.Fr8.canonical a
      withoutCanonical canonical input) := by rfl

private def rawChunks (a : fr8.Fr8) (lane : Nat) : List U8 :=
  wordsBytes (pack (store (ofArray id a))[lane]!)

private def rawEncoding (a : fr8.Fr8) (input : Slice U8) : Slice U8 :=
  writeBlocks 8 32 0 (rawChunks a) input

private theorem withoutCanonical_refines (a : fr8.Fr8) (hn : Normalized a) (input : Slice U8)
    (hlen : 256 ≤ input.val.length) :
    withoutCanonical a input = ok (rawEncoding a input) := by
  have hnormal : ∀ j : Fin 5, ∀ lane : Fin 8, (ofArray id a)[j][lane].toNat < 2^52 := by
    intro j lane
    have h := (normalized_iff_model a).mp hn lane j
    change ((ofArray id a).map (fun x => x[lane]))[j.val].toNat < 2^52 at h
    rw [Vector.getElem_map] at h
    exact h
  have hpack := vectorPack_refines (ofArray id a) hnormal
  rw [toArray_ofArray (f := id) (g := id) (m := 5) (fun _ => rfl) a rfl rfl] at hpack
  unfold withoutCanonical
  rw [hpack]
  simp only [bind_tc_ok]
  rw [vector_to_bytes_refines _ input 0#usize hlen]
  apply congrArg ok
  unfold rawEncoding writeBlocks
  apply congrArg (fun f => (List.finRange 8).foldl f input)
  funext state k
  apply congrArg (fun xs => state.setSlice! (0 + 32*k.val) xs)
  dsimp only [rawChunks]
  rw [getElem!_pos (store (ofArray id a)) k.val k.isLt]
  change wordsBytes (wordLane (vectorPack (ofArray id a)) ⟨k.val%8, _⟩) =
    wordsBytes (pack (store (ofArray id a))[k])
  rw [getElem_store]
  apply congrArg wordsBytes
  ext j hj
  simp [wordLane, vectorPack, laneOf, Nat.mod_eq_of_lt k.isLt]

private theorem rawEncoding_first (a : fr8.Fr8) (input : Slice U8)
    (hlen : 256 ≤ input.val.length) :
    (bytes (rawEncoding a input).val).extract 0 32 = bytes (rawChunks a 0) := by
  have hs := writeBlocks_spec 8 32 0 (rawChunks a) input
    (by intro; simp [rawChunks]) hlen
  apply extract_eq_bytes _ _ 0 32 (by simp [rawChunks])
  · change 0+32 ≤ (writeBlocks 8 32 0 (rawChunks a) input).val.length
    rw [hs.1]
    omega
  · intro i hi
    simpa only [Nat.mul_zero, Nat.zero_add] using hs.2.1 0 (by decide) i hi

theorem omitting_canonicalization_changes_generated_bytes :
    fr8.Fr8.to_bytes modulusBatch byteBuffer 0#usize ≠ withoutCanonical modulusBatch byteBuffer := by
  obtain ⟨out, hout, _, hb, _⟩ := to_bytes_refinement modulusBatch modulusBatch_bounded
    byteBuffer 0#usize (by rw [byteBuffer_length]; decide)
  rw [hout, withoutCanonical_refines _ modulusBatch_bounded.1 _ (by rw [byteBuffer_length])]
  intro he
  have heq := Result.ok.inj he
  have hfirst := hb ⟨0, by decide⟩
  change (bytes out.val).extract 0 32 = blsFieldToBytes (laneValue modulusBatch ⟨0, by decide⟩) at hfirst
  rw [heq, modulusBatch_value, rawEncoding_first _ _ (by rw [byteBuffer_length])] at hfirst
  have hraw : Fr.bytesBEToNat (bytes (rawChunks modulusBatch 0)) = Fr.modulus := by
    rw [bytesBEToNat_eq_bytesVal]
    change bytesVal ((rawChunks modulusBatch 0).map ofU8) = Fr.modulus
    unfold rawChunks
    rw [getElem!_pos (store (ofArray id modulusBatch)) 0 (by decide), wordsBytes_value]
    exact (packed_store_value modulusBatch modulusBatch_bounded.1 ⟨0, by decide⟩
      (by rw [modulusBatch_nat]; decide)).trans (modulusBatch_nat _)
  have hz : Fr.bytesBEToNat (blsFieldToBytes (0 : Fr)) = 0 := by decide +kernel
  have hm := hraw.symm.trans ((congrArg Fr.bytesBEToNat hfirst).trans hz)
  exact (by decide : Fr.modulus ≠ 0) hm

def reverseEncodedBytes (a : fr8.Fr8) (input : Slice U8) : Slice U8 :=
  writeBlocks 8 32 0
    (fun lane => (blsFieldToBytes (laneValue a ⟨lane%8, Nat.mod_lt _ (by decide)⟩)).data.toList.reverse.map toU8)
    input

theorem reversing_byte_order_changes_generated_bytes :
    fr8.Fr8.to_bytes oneBatch byteBuffer 0#usize ≠ ok (reverseEncodedBytes oneBatch byteBuffer) := by
  obtain ⟨out, hout, _, hb, _⟩ := to_bytes_refinement oneBatch oneBatch_bounded
    byteBuffer 0#usize (by rw [byteBuffer_length]; decide)
  rw [hout]
  intro he
  have heq := Result.ok.inj he
  have hfirst := hb ⟨0, by decide⟩
  change (bytes out.val).extract 0 32 = blsFieldToBytes (laneValue oneBatch ⟨0, by decide⟩) at hfirst
  have hs := writeBlocks_spec 8 32 0
    (fun lane => (blsFieldToBytes (laneValue oneBatch ⟨lane%8, Nat.mod_lt _ (by decide)⟩)).data.toList.reverse.map toU8)
    byteBuffer (by intro j _; simp only [List.length_map, List.length_reverse,
      _root_.Array.length_toList, ByteArray.size_data, field_bytes_size])
    (by rw [byteBuffer_length])
  have hrev : (bytes (reverseEncodedBytes oneBatch byteBuffer).val).extract 0 32 =
      bytes ((blsFieldToBytes (1 : Fr)).data.toList.reverse.map toU8) := by
    apply extract_eq_bytes _ _ 0 32
    · simp only [List.length_map, List.length_reverse, _root_.Array.length_toList,
        ByteArray.size_data, field_bytes_size]
    · change 32 ≤ (writeBlocks 8 32 0 _ byteBuffer).val.length
      rw [hs.1, byteBuffer_length]; decide
    · intro i hi
      have hv := hs.2.1 0 (by decide) i hi
      simp only [Nat.mul_zero, Nat.zero_add] at hv
      change (reverseEncodedBytes oneBatch byteBuffer).val[i]! =
        ((blsFieldToBytes (laneValue oneBatch ⟨0, by decide⟩)).data.toList.reverse.map toU8)[i]! at hv
      rw [oneBatch_value] at hv
      simpa only [Nat.zero_add] using hv
  rw [heq, oneBatch_value, hrev] at hfirst
  have hbyte := congrArg (fun bs : ByteArray => bs[0]!) hfirst
  exact (by decide +kernel :
    (bytes ((blsFieldToBytes (1 : Fr)).data.toList.reverse.map toU8))[0]! ≠
      (blsFieldToBytes (1 : Fr))[0]!) hbyte

@[irreducible] def filledCell (b : U8) : CellArray :=
  ⟨List.replicate 2048 b, by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

@[irreducible] def filledCells (b : U8) : Cells :=
  ⟨List.replicate 128 (filledCell b), by simp only [List.length_replicate, UScalar.ofNatCore_val_eq]⟩

private theorem filledCells_byte (b : U8) (i : Nat) (hi : i < 2048) :
    ((cellBytes (filledCells b))[0]!)[i]! = ofU8 b := by
  rw [cellBytes_get _ 0 (by decide), arrayBytes_get (filledCells b).val[0]! i hi]
  simp [-List.reduceReplicate, filledCells, filledCell, ofU8, hi]

@[irreducible] def oneData : alloc.vec.Vec fr8.Fr8 :=
  ⟨List.replicate 512 oneBatch, by simp only [List.length_replicate]; scalar_tac⟩

def oneValues : _root_.Array Fr := _root_.Array.replicate 4096 1

private theorem oneValues_size : oneValues.size = 4096 := by simp only [oneValues, _root_.Array.size_replicate]

theorem oneData_represents : DataRep (alloc.vec.Vec.deref oneData) oneValues := by
  constructor
  · simp only [alloc.vec.Vec.deref, oneData, oneValues, _root_.Array.size_replicate,
      List.length_replicate]
  · intro v
    have hv : v.val < 512 := by
      simpa only [alloc.vec.Vec.deref, oneData, List.length_replicate] using v.isLt
    simp only [alloc.vec.Vec.deref, oneData, List.getElem_replicate]
    refine ⟨oneBatch_bounded, ?_⟩
    intro lane
    change laneValue oneBatch lane = oneValues[8*v.val+lane.val]!
    rw [oneBatch_value, getElem!_pos oneValues (8*v.val+lane.val)
      (by rw [oneValues_size]; omega)]
    simp only [oneValues, _root_.Array.getElem_replicate]

private theorem extensionCells_first (cells : Cells) (values : _root_.Array Fr) :
    (extensionCells cells values)[0]! = (cellBytes cells)[0]! := by
  simp [extensionCells]

def omitOutputOffset (cells : Cells) (values : _root_.Array Fr) : _root_.Array Cell :=
  _root_.Array.ofFn (n := 128) fun i =>
    if i.val < 64 then cosetEvalsToCell (values.extract (i.val*64) (i.val*64+64))
    else (cellBytes cells)[i.val]!

private theorem omitOutputOffset_first (cells : Cells) :
    ((omitOutputOffset cells oneValues)[0]!)[31]! = 1 := by
  have hfirst : (omitOutputOffset cells oneValues)[0]! =
      cosetEvalsToCell (oneValues.extract 0 64) := by simp [omitOutputOffset]
  rw [hfirst, cosetEvalsToCell_get _ 31 (by decide)]
  have hvalue : (oneValues.extract 0 64)[0]! = (1 : Fr) := by
    rw [getElem!_pos (oneValues.extract 0 64) 0
      (by simp only [_root_.Array.size_extract, oneValues_size]; decide), _root_.Array.getElem_extract]
    simp only [oneValues, _root_.Array.getElem_replicate]
  rw [show 31/32 = 0 by decide, hvalue]
  decide +kernel

theorem omitting_output_offset_changes_generated_cells :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop1 oneData (filledCells 0#u8) 0#usize = ok out ∧
      cellBytes out ≠ omitOutputOffset (filledCells 0#u8) oneValues := by
  obtain ⟨out, hout, hb, _⟩ := encode_refinement oneData oneValues oneValues_size
    oneData_represents (filledCells 0#u8)
  refine ⟨out, hout, ?_⟩
  intro he
  have hbyte := congrArg (fun xs : _root_.Array Cell => (xs[0]!)[31]!) (hb.symm.trans he)
  dsimp only at hbyte
  rw [extensionCells_first, filledCells_byte _ 31 (by decide), omitOutputOffset_first] at hbyte
  exact (by decide : (0 : UInt8) ≠ 1) hbyte

def clearFirstHalf (cells : Cells) (values : _root_.Array Fr) : _root_.Array Cell :=
  _root_.Array.ofFn (n := 128) fun i =>
    if i.val < 64 then arrayBytes (filledCell 0#u8)
    else (extensionCells cells values)[i.val]!

theorem clearing_first_half_changes_generated_cells :
    ∃ out, extension_kernel.ExtensionKernel.extend_loop1 oneData (filledCells 255#u8) 0#usize = ok out ∧
      cellBytes out ≠ clearFirstHalf (filledCells 255#u8) oneValues := by
  obtain ⟨out, hout, hb, _⟩ := encode_refinement oneData oneValues oneValues_size
    oneData_represents (filledCells 255#u8)
  refine ⟨out, hout, ?_⟩
  intro he
  have hbyte := congrArg (fun xs : _root_.Array Cell => (xs[0]!)[0]!) (hb.symm.trans he)
  dsimp only at hbyte
  have hclear : (clearFirstHalf (filledCells 255#u8) oneValues)[0]! =
      arrayBytes (filledCell 0#u8) := by simp [clearFirstHalf]
  rw [extensionCells_first, filledCells_byte _ 0 (by decide), hclear,
    arrayBytes_get _ 0 (by decide)] at hbyte
  simp only [filledCell] at hbyte
  exact (by decide : (255 : UInt8) ≠ 0) hbyte

def addWithoutReduction (a b : fr8.Fr8) : fr8.Fr8 :=
  FrModel.toFr8 ⟨FrModel.Simd.add_limbs (FrModel.ofFr8 a).limbs (FrModel.ofFr8 b).limbs⟩

private theorem addWithoutReduction_modulus_nat :
    laneNat (addWithoutReduction modulusBatch modulusBatch) ⟨0, by decide⟩ = 2*Fr.modulus := by
  rw [laneNat_eq_val]
  simp only [addWithoutReduction, FrModel.ofFr8_toFr8, FrModel.Fr8.lane_mk,
    FrModel.Simd.add_limbs_lane, ← FrModel.Fr8.lane_eq, modulusBatch, splat_lane]
  exact FrModel.val_two_p

theorem omitting_twice_modulus_reduction_changes_generated_add :
    fr8.Fr8.add modulusBatch modulusBatch ≠ ok (addWithoutReduction modulusBatch modulusBatch) := by
  obtain ⟨out, hout, hbound, _⟩ := add_refinement modulusBatch modulusBatch
    modulusBatch_bounded modulusBatch_bounded
  rw [hout]
  intro he
  have hb := hbound.2 ⟨0, by decide⟩
  rw [Result.ok.inj he, addWithoutReduction_modulus_nat] at hb
  exact Nat.lt_irrefl _ hb

end LeanBlsSimd.Kzg.Extender.Controls.KernelBytes

#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBytes.omitting_canonicalization_changes_generated_bytes
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBytes.reversing_byte_order_changes_generated_bytes
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBytes.omitting_output_offset_changes_generated_cells
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBytes.clearing_first_half_changes_generated_cells
#print axioms LeanBlsSimd.Kzg.Extender.Controls.KernelBytes.omitting_twice_modulus_reduction_changes_generated_add
