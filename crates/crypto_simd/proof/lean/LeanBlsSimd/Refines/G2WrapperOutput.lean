import LeanBlsSimd.Refines.G2WrapperModel
import LeanBlsSimd.Refines.G2WrapperChunk

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd.UncompressG2

open DecompressG2

def modelBlst [BlsExternals] (bytes : Encoding) : Option BlstP2Affine :=
  (BlsExternals.uncompressG2 (toArray toU8 bytes)).map ofBlstP2Affine

theorem modelBlst_roundtrip [BlsExternals] (a : Array U8 96#usize) :
    (modelBlst (ofArray ofU8 a)).map toBlstP2Affine = BlsExternals.uncompressG2 a := by
  simp [modelBlst, toArray_ofArray, Option.map_map, Function.comp_def]

def rawOutput [BlsExternals] (simd : Bool) (inputs : Slice (Array U8 96#usize)) :=
  (uncompress simd modelBlst (inputs.val.map (ofArray ofU8))).map (Option.map toBlstP2Affine)

@[simp] theorem rawOutput_length [BlsExternals] (simd : Bool) (inputs : Slice (Array U8 96#usize)) :
    (rawOutput simd inputs).length = inputs.val.length := by
  simp [rawOutput]

theorem rawOutput_scalar [BlsExternals] (simd : Bool) (inputs : Slice (Array U8 96#usize))
    (i : ℕ) (hi : i < inputs.val.length)
    (hscalar : simd = false ∨ chunkLength (inputs.val.map (ofArray ofU8)) i < 3) :
    (rawOutput simd inputs)[i]! = BlsExternals.uncompressG2 inputs.val[i]! := by
  rw [getElem!_pos _ _ (by simpa using hi)]
  simp only [rawOutput, List.getElem_map]
  rw [getElem_uncompress_scalar _ _ _ _ (by simpa using hi) hscalar]
  rw [getElem!_pos _ _ (by simpa using hi), List.getElem_map, modelBlst_roundtrip]
  rw [getElem!_pos inputs.val i hi]

theorem rawOutput_kernel [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (start : ℕ) (halign : start % 8 = 0) (hkernel : 3 ≤ min 8 (inputs.val.length - start))
    (lane : Fin 8) (hlane : lane.val < min 8 (inputs.val.length - start)) :
    (rawOutput true inputs)[start + lane.val]! =
      let b := decompress (chunkAt (inputs.val.map (ofArray ofU8)) start)
      if b.undecided.toNat.testBit lane then BlsExternals.uncompressG2 inputs.val[start + lane.val]!
      else if b.valid.toNat.testBit lane then some (toBlstP2Affine b.points[lane]) else none := by
  have hi : start + lane.val < inputs.val.length := by omega
  have hmod : (start + lane.val) % 8 = lane.val := by omega
  rw [getElem!_pos _ _ (by simpa using hi)]
  simp only [rawOutput, List.getElem_map]
  rw [getElem_uncompress true _ _ _ (by simpa using hi)]
  simp only [usesKernel, Bool.true_and, chunkLength_aligned _ start halign lane,
    List.length_map, hi, hkernel, and_self, decide_true, Bool.true_and,
    chunkAt_aligned _ start halign lane, hmod]
  split <;> simp_all [modelBlst_roundtrip]

theorem chunk_slice_refines [BlsExternals] (inputs : Slice (Array U8 96#usize))
    (start next : Usize) (hnext : next.val = start.val + min 8 (inputs.val.length - start.val))
    (halign : start.val % 8 = 0) (hstart : start.val < inputs.val.length)
    (hkernel : 3 ≤ min 8 (inputs.val.length - start.val))
    (c : Slice (Array U8 96#usize)) (hc : c.val = inputs.val.slice start.val next.val)
    (out : Slice (Option blst.blst_p2_affine)) (hout : out.val.length = c.val.length) :
    ∃ result, decompress_g2_chunk c out = ok result ∧
      result.val = (rawOutput true inputs).slice start.val next.val := by
  have hbound : next.val ≤ inputs.val.length := by omega
  have hlen : c.val.length = min 8 (inputs.val.length - start.val) := by
    rw [hc, List.slice_length]
    omega
  have hne : 0 < c.val.length := by omega
  obtain ⟨result, hr, hv⟩ := chunk_refines c out hout hne (by omega)
  refine ⟨result, hr, hv.trans ?_⟩
  have hcmodel : ofArray (ofArray ofU8) (toArray (n := 8#usize) id (paddedInputs c)) =
      chunkAt (inputs.val.map (ofArray ofU8)) start.val := by
    apply Vector.ext
    intro lane hlane
    have hpad : min lane (c.val.length - 1) < c.val.length := by omega
    have hipad : start.val + min lane (c.val.length - 1) < inputs.val.length := by omega
    rw [getElem_ofArray, chunkAt_getElem _ _ halign ⟨lane, hlane⟩]
    simp only [toArray_val, List.getElem_map, Vector.getElem_toList, id_eq,
      paddedInputs, Vector.getElem_ofFn, List.length_map]
    rw [show c.val[min lane (c.val.length - 1)]! = inputs.val[start.val + min lane (c.val.length - 1)]! by
      rw [hc, List.getElem!_slice _ _ _ _ (by rw [List.slice_length]; omega)]]
    rw [getElem!_pos inputs.val _ hipad, getElem!_pos (inputs.val.map (ofArray ofU8)) _ (by simp; omega), List.getElem_map]
    simp [hlen]
  apply List.ext_getElem
  · simp [List.slice_length, hlen]
    omega
  · intro lane hl hr
    have hlc : lane < c.val.length := by simpa using hl
    have hl8 : lane < 8 := by omega
    simp only [Vector.getElem_toList, Vector.getElem_ofFn]
    rw [← getElem!_pos ((rawOutput true inputs).slice start.val next.val) lane hr,
      List.getElem!_slice _ _ _ _ (by rw [rawOutput_length]; omega)]
    rw [rawOutput_kernel inputs start.val halign hkernel ⟨lane, hl8⟩ (by simpa only [Fin.val_mk, hlen] using hlc)]
    simp only [chunkOutput, chunkBatch, hcmodel]
    have hget : c.val[lane] = inputs.val[start.val + lane]! := by
      rw [← getElem!_pos c.val lane hlc, hc, List.getElem!_slice _ _ _ _ (by omega)]
    simp [hget, hl8]

end LeanBlsSimd.UncompressG2
