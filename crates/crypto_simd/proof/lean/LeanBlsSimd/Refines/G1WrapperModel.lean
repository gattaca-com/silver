import LeanBlsSimd.Model.UncompressG1

namespace LeanBlsSimd.UncompressG1

open DecompressG1

@[simp] theorem length_uncompress (simd : Bool) (blst : Encoding → Option BlstP1Affine)
    (inputs : List Encoding) : (uncompress simd blst inputs).length = inputs.length := by
  simp [uncompress]

theorem getElem_uncompress (simd : Bool) (blst : Encoding → Option BlstP1Affine)
    (inputs : List Encoding) (i : ℕ) (hi : i < inputs.length) :
    (uncompress simd blst inputs)[i]'(by simpa using hi) =
      if usesKernel simd inputs i then
        laneVerdict (decompress (chunkAt inputs i)) ⟨i % 8, Nat.mod_lt _ (by decide)⟩
      else blst inputs[i]! := by
  simp [uncompress]

theorem getElem_uncompress_scalar (simd : Bool) (blst : Encoding → Option BlstP1Affine)
    (inputs : List Encoding) (i : ℕ) (hi : i < inputs.length)
    (hscalar : simd = false ∨ inputs.length / 8 * 8 ≤ i) :
    (uncompress simd blst inputs)[i]'(by simpa using hi) = blst inputs[i]! := by
  rw [getElem_uncompress simd blst inputs i hi]
  rcases hscalar with h | h
  · simp [usesKernel, h]
  · simp [usesKernel, Nat.not_lt.mpr h]

theorem chunkAt_aligned (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (lane : Fin 8) : chunkAt inputs (start + lane.val) = chunkAt inputs start := by
  have hdiv : (start + lane.val) / 8 = start / 8 := by omega
  simp only [chunkAt, hdiv]

theorem chunkAt_getElem (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (lane : Fin 8) : (chunkAt inputs start)[lane.val] = inputs[start + lane.val]! := by
  have halign : start / 8 * 8 = start := by omega
  simp [chunkAt, halign]

theorem getElem_uncompress_chunk (blst : Encoding → Option BlstP1Affine)
    (inputs : List Encoding) (start : ℕ) (hstart : start % 8 = 0)
    (hfull : start + 8 ≤ inputs.length) (lane : Fin 8) :
    (uncompress true blst inputs)[start + lane.val]'(by simp; omega) =
      (chunk blst (chunkAt inputs start))[lane.val] := by
  have hbound : start + lane.val < inputs.length / 8 * 8 := by omega
  have hmod : (start + lane.val) % 8 = lane.val := by omega
  rw [getElem_uncompress true blst inputs (start + lane.val) (by omega)]
  simp only [usesKernel, Bool.true_and, hbound, decide_true, chunkAt_aligned inputs start hstart,
    hmod, chunk, Vector.getElem_ofFn]
  split <;> simp_all [chunkAt_getElem inputs start hstart lane]

end LeanBlsSimd.UncompressG1
