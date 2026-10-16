import LeanBlsSimd.Refines.DecompressG2
import LeanBlsSimd.Proofs.Mmask8

open Aeneas Aeneas.Std Result ControlFlow
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG2

open DecompressG2

def paddedInputs (inputs : Slice (Array U8 96#usize)) : Vector (Array U8 96#usize) 8 :=
  .ofFn fun lane => inputs.val[min lane.val (inputs.val.length - 1)]!

theorem padding_refines (inputs : Slice (Array U8 96#usize)) (hne : 0 < inputs.val.length)
    (initial : Array (Array U8 96#usize) 8#usize) :
    decompress_g2_chunk_loop0 { start := 0#usize, «end» := LANES } inputs initial =
      ok (toArray id (paddedInputs inputs)) := by
  unfold decompress_g2_chunk_loop0
  have hinit : toArray (n := 8#usize) id (ofArray (m := 8) id initial) = initial :=
    toArray_ofArray (fun _ => rfl) initial rfl rfl
  rw [← hinit]
  apply loop_range (n := 8) _ LANES (by simp [LANES]) (toArray id)
    (fun v j => v.set j (paddedInputs inputs)[j]) (toArray id)
    (ofArray (m := 8) id initial) (toArray id (paddedInputs inputs))
  · intro r v he hs hn
    simp only [decompress_g2_chunk_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  · intro r r' v j he hs he' hs' hn
    have hj : r.start.val < 8 := by omega
    let k : Usize := UScalar.ofNatCore (min r.start.val (inputs.val.length - 1))
      (lt_of_le_of_lt (min_le_right _ _) (by have := (Slice.len inputs).hBounds; change inputs.val.length < 2 ^ UScalarTy.Usize.numBits at this; omega))
    have hk : k.val = min r.start.val (inputs.val.length - 1) := by simp [k]
    have hki : k.val < inputs.val.length := by omega
    have hselect : (if r.start < Slice.len inputs then ok r.start
        else Slice.len inputs - 1#usize) = ok k := by
      by_cases h : r.start.val < inputs.val.length
      · rw [if_pos (by simpa using h)]
        congr 1
        apply UScalar.eq_of_val_eq
        simp only [hk]
        omega
      · rw [if_neg (by simpa using h), sub_ok _ _ (by simpa using hne)]
        congr 1
        apply UScalar.eq_of_val_eq
        simp only [UScalar.ofNatCore_val_eq, Slice.len_val, Slice.length, hk]
        omega
    simp only [decompress_g2_chunk_loop0.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rw [hselect]
    simp only [bind_tc_ok]
    rw [show Slice.index_usize inputs k = ok inputs.val[k.val]! by
      simp [Slice.index_usize, hki]]
    simp only [bind_tc_ok]
    rw [update_eq _ _ _ hj]
    simp only [bind_tc_ok]
    congr 3
    apply toArray_set_of_eq id v rfl r.start j.val j.isLt _ _ hs
    simp [paddedInputs, hk, hs]
  · rw [foldl_set_ofFn]
    congr 1

def chunkBatch (inputs : Slice (Array U8 96#usize)) : Batch :=
  decompress (ofArray (ofArray ofU8) (toArray (n := 8#usize) id (paddedInputs inputs)))

def chunkOutput [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (i : Fin inputs.val.length) : Option blst.blst_p2_affine :=
  let b := chunkBatch inputs
  if b.undecided.toNat.testBit i then BlsExternals.uncompressG2 inputs.val[i]
  else if b.valid.toNat.testBit i then some (toBlstP2Affine b.points[i.val]!) else none

private theorem mask_bit (m : UInt8) (l : Fin 8) :
    (toU8 m &&& toU8 (1 <<< l.val.toUInt8) != 0#u8) = m.toNat.testBit l := by
  rw [Bool.eq_iff_iff]
  simp only [bne_iff_ne, toU8_and]
  change (toU8 (m &&& (1 <<< l.val.toUInt8)) ≠ toU8 0 ↔ _)
  simp only [ne_eq, toU8_inj]
  exact Mmask8.and_one_shiftLeft_ne_zero m l

private def vectorSlice {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max) : Slice α :=
  ⟨v.toList, by simpa using h⟩

private theorem slice_update_ok {α : Type} (s : Slice α) (i : Usize) (x : α)
    (h : i.val < s.val.length) : Slice.update s i x = ok (s.set i x) := by
  simp [Slice.update, h, Slice.set, Slice.setAtNat]

private theorem vectorSlice_set {α : Type} {n : ℕ} (v : Vector α n) (h : n ≤ Usize.max)
    (i : Usize) (hi : i.val < n) (x : α) :
    (vectorSlice v h).set i x = vectorSlice (v.set i.val x hi) h := by
  apply Subtype.ext
  simp [vectorSlice, Slice.set, Slice.setAtNat, Vector.toList_set]

theorem chunk_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (out : Slice (Option blst.blst_p2_affine)) (hlen : out.val.length = inputs.val.length)
    (hne : 0 < inputs.val.length) (hmax : inputs.val.length ≤ 8) :
    ∃ result, decompress_g2_chunk inputs out = ok result ∧
      result.val = (Vector.ofFn (chunkOutput inputs)).toList := by
  let b := chunkBatch inputs
  let target := Vector.ofFn (chunkOutput inputs)
  let enc := fun v : Vector (Option blst.blst_p2_affine) inputs.val.length =>
    vectorSlice v inputs.property
  have ho : enc (ofSlice id out hlen) = out := by
    apply Subtype.ext
    simp [enc, vectorSlice]
  refine ⟨enc target, ?_, rfl⟩
  rw [decompress_g2_chunk, padding_refines inputs hne]
  simp only [bind_tc_ok]
  rw [decompress_refines]
  simp only [bind_tc_ok, decompress_g2_chunk_loop1]
  rw [← ho]
  apply loop_range (n := inputs.val.length) _ (Slice.len inputs) (by simp) enc
    (fun v j => v.set j (target[j])) enc (ofSlice id out hlen) (enc target)
  · intro r v he hs hn
    simp only [decompress_g2_chunk_loop1.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
  · intro r r' v j he hs he' hs' hn
    have hj : r.start.val < inputs.val.length := by omega
    have hj8 : r.start.val < 8 := by omega
    let l : Fin 8 := ⟨j.val, by omega⟩
    simp only [decompress_g2_chunk_loop1.body, hn, bind_tc_ok, Function.uncurry_apply_pair]
    rw [toU8_shiftLeft_one _ hj8]
    simp only [lift, bind_tc_ok, toBatch]
    rw [show r.start.val = l.val from hs, mask_bit]
    have ht : target[j] = if b.undecided.toNat.testBit l then
        BlsExternals.uncompressG2 inputs.val[j]
        else if b.valid.toNat.testBit l then some (toBlstP2Affine b.points[l]) else none := by
      simp [target, chunkOutput, b, l, show j.val < 8 by omega]
    rw [show decompress (ofArray (ofArray ofU8)
      (toArray (n := 8#usize) id (paddedInputs inputs))) = b from rfl]
    cases hu : b.undecided.toNat.testBit l
    · simp only [Bool.false_eq_true, ↓reduceIte]
      rw [mask_bit]
      cases hv : b.valid.toNat.testBit l
      · simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v inputs.property r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
      · simp only [↓reduceIte]
        rw [index_usize_toArray _ _ _ _ hj8]
        simp only [bind_tc_ok, Function.uncurry_apply_pair]
        rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v inputs.property r.start hj]
        simp only [bind_tc_ok, enc, ht, hu, hv, hs, Bool.false_eq_true, ↓reduceIte]
        rfl
    · simp only [↓reduceIte]
      rw [show Slice.index_usize inputs r.start = ok inputs.val[j] by
        simp [Slice.index_usize, hs]]
      simp only [uncompress_in_g2_blst, bind_tc_ok, Function.uncurry_apply_pair]
      rw [slice_update_ok _ _ _ (by simp [enc, vectorSlice, hs]), vectorSlice_set v inputs.property r.start hj]
      simp only [bind_tc_ok, enc, ht, hu, hs, ↓reduceIte]
  · rw [foldl_set_ofFn]
    congr 1
    ext i hi
    simp

end LeanBlsSimd.UncompressG2
