import LeanBlsSimd.Proofs.DecompressG2

namespace LeanBlsSimd.G2Spec

open EthCryptographySpecs.Bls DecompressG2

/-- Affine infinity uses zero coordinates, as in blst's affine representation. -/
def blstLimbs (P : G2) : BlstP2Affine :=
  let (x, y) := P.toAffine
  blstPoint (Fp2.toField x) (Fp2.toField y)

/-- A successful decode on a decided lane has z = 1, so the kernel's direct-coordinate
conversion agrees with the affine conversion. -/
theorem blstLimbs_eq_of_decided_uncompress
    (inputs : Vector (Vector UInt8 G2_COMPRESSED_LEN) 8) (l : Fin 8)
    (hu : (decompress inputs).undecided.toNat.testBit l = false)
    (P : G2) (hP : G2.uncompress (toBytes inputs[l]) = .ok P) :
    blstLimbs P = DecompressG2.blstLimbs P := by
  sorry

def verdict (bytes : Vector UInt8 G2_COMPRESSED_LEN) : Option BlstP2Affine :=
  match G2.uncompress (toBytes bytes) with
  | .error _ => none
  | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none

end LeanBlsSimd.G2Spec
