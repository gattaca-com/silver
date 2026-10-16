import LeanBlsSimd.Model.UncompressG2

namespace LeanBlsSimd.UncompressG2

open DecompressG2

@[simp] theorem length_uncompress (simd : Bool) (blst : Encoding → Option BlstP2Affine)
    (inputs : List Encoding) : (uncompress simd blst inputs).length = inputs.length := by
  simp [uncompress]

theorem getElem_uncompress (simd : Bool) (blst : Encoding → Option BlstP2Affine)
    (inputs : List Encoding) (i : ℕ) (hi : i < inputs.length) :
    (uncompress simd blst inputs)[i]'(by simpa using hi) =
      if usesKernel simd inputs i then
        let batch := decompress (chunkAt inputs i)
        if batch.valid.toNat.testBit (i % 8) then some batch.points[i % 8]! else none
      else blst inputs[i]! := by
  simp [uncompress]

theorem chunkLength_aligned (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (lane : Fin 8) : chunkLength inputs (start + lane.val) = min 8 (inputs.length - start) := by
  have hdiv : (start + lane.val) / 8 * 8 = start := by omega
  simp [chunkLength, hdiv]

theorem chunkAt_aligned (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (lane : Fin 8) : chunkAt inputs (start + lane.val) = chunkAt inputs start := by
  have hdiv : (start + lane.val) / 8 = start / 8 := by omega
  simp only [chunkAt, chunkLength, hdiv]

theorem chunkAt_getElem (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (lane : Fin 8) : (chunkAt inputs start)[lane.val] =
      inputs[start + min lane.val (min 8 (inputs.length - start) - 1)]! := by
  have halign : start / 8 * 8 = start := by omega
  simp [chunkAt, chunkLength, halign]

theorem getElem_uncompress_scalar (simd : Bool) (blst : Encoding → Option BlstP2Affine)
    (inputs : List Encoding) (i : ℕ) (hi : i < inputs.length)
    (hscalar : simd = false ∨ chunkLength inputs i < 3) :
    (uncompress simd blst inputs)[i]'(by simpa using hi) = blst inputs[i]! := by
  rw [getElem_uncompress simd blst inputs i hi]
  rcases hscalar with h | h
  · simp [usesKernel, h]
  · simp [usesKernel, show ¬ 3 ≤ chunkLength inputs i by omega]

end LeanBlsSimd.UncompressG2
