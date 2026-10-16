import LeanBlsSimd.Proofs.DecompressG2

namespace LeanBlsSimd.G2Spec

open EthCryptographySpecs.Bls DecompressG2

/-- Affine infinity uses zero coordinates, as in blst's affine representation. -/
def blstLimbs (P : G2) : BlstP2Affine :=
  let (x, y) := P.toAffine
  blstPoint (Fp2.toField x) (Fp2.toField y)

def verdict (bytes : Vector UInt8 G2_COMPRESSED_LEN) : Option BlstP2Affine :=
  match G2.uncompress (toBytes bytes) with
  | .error _ => none
  | .ok P => if G2.inSubgroup P then some (blstLimbs P) else none

end LeanBlsSimd.G2Spec
