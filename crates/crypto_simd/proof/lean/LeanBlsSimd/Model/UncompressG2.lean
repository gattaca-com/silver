import LeanBlsSimd.Model.DecompressG2

namespace LeanBlsSimd.UncompressG2

open DecompressG2

abbrev Encoding := Vector UInt8 G2_COMPRESSED_LEN

def chunkLength (inputs : List Encoding) (i : ℕ) : ℕ :=
  min 8 (inputs.length - i / 8 * 8)

/-- The unused lanes repeat the last input in the chunk. -/
def chunkAt (inputs : List Encoding) (i : ℕ) : Vector Encoding 8 :=
  .ofFn fun lane => inputs[i / 8 * 8 + min lane.val (chunkLength inputs i - 1)]!

def usesKernel (simd : Bool) (inputs : List Encoding) (i : ℕ) : Bool :=
  simd && decide (i < inputs.length ∧ 3 ≤ chunkLength inputs i) &&
    !(decompress (chunkAt inputs i)).undecided.toNat.testBit (i % 8)

def uncompress (simd : Bool) (blst : Encoding → Option BlstP2Affine)
    (inputs : List Encoding) : List (Option BlstP2Affine) :=
  (List.range inputs.length).map fun i =>
    if usesKernel simd inputs i then
      let batch := decompress (chunkAt inputs i)
      if batch.valid.toNat.testBit (i % 8) then some batch.points[i % 8]! else none
    else blst inputs[i]!

end LeanBlsSimd.UncompressG2
