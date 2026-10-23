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
  rw [decompress_eq_spec scott_complete inputs l hu]
  unfold G2Spec.verdict
  cases hd : EthLib.Cryptography.Bls.G2.uncompress (toBytes inputs[l]) with
  | error e => rfl
  | ok P =>
    have hu' : Kernel.laneUndecided inputs[l] = false :=
      (decompress_lane inputs l).undecided.symm.trans hu
    have hz := ((Kernel.laneOnCurve_iff hu').2 P hd).1
    dsimp only
    rw [G2Spec.blstLimbs_eq_of_z_one hz]

end LeanBlsSimd.DecompressG2
