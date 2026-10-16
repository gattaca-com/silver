import LeanBlsSimd.Proofs.Kernel
import LeanBlsSimd.Spec.CubicHasse
import LeanBlsSimd.Spec.G2Encoding

namespace LeanBlsSimd.DecompressG2

/-- On a lane the kernel decides, its verdict is the wrapper's specification verdict. -/
theorem decompress_eq_verdict
    (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false) :
    (if (decompress inputs).valid.toNat.testBit l then some (decompress inputs).points[l]
      else none) = G2Spec.verdict inputs[l] := by
  sorry

end LeanBlsSimd.DecompressG2
