import LeanBlsSimd.Model.DecompressG1

namespace LeanBlsSimd.UncompressG1

open DecompressG1

def chunkAt (inputs : List Encoding) (i : ℕ) : Vector Encoding 8 :=
  .ofFn fun lane => inputs[i / 8 * 8 + lane.val]!

def usesKernel (simd : Bool) (inputs : List Encoding) (i : ℕ) : Bool :=
  simd && decide (i < inputs.length / 8 * 8) &&
    !(decompress (chunkAt inputs i)).undecided.toNat.testBit (i % 8)

def chunk (blst : Encoding → Option BlstP1Affine) (inputs : Vector Encoding 8) :
    Vector (Option BlstP1Affine) 8 :=
  let batch := decompress inputs
  .ofFn fun lane =>
    if batch.undecided.toNat.testBit lane then blst inputs[lane] else laneVerdict batch lane

def uncompress (simd : Bool) (blst : Encoding → Option BlstP1Affine)
    (inputs : List Encoding) : List (Option BlstP1Affine) :=
  (List.range inputs.length).map fun i =>
    if usesKernel simd inputs i then
      laneVerdict (decompress (chunkAt inputs i)) ⟨i % 8, Nat.mod_lt _ (by decide)⟩
    else blst inputs[i]!

end LeanBlsSimd.UncompressG1
