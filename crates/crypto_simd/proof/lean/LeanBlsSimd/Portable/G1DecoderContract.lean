import LeanBlsSimd.Refines.DecompressG1
import LeanBlsSimd.Proofs.G1

open Aeneas Aeneas.Std Result
open silver_crypto_simd silver_crypto_simd.bls

namespace LeanBlsSimd

open DecompressG1

def UncompressG1.specVerdict (bytes : Array U8 48#usize) : Option g1_point.G1Point :=
  (G1Spec.verdict (ofArray ofU8 bytes)).map toBlstP1Affine

/-- The generated portable decoders agree with the specification on each input. -/
structure G1DecoderCorrect [RuntimeFeatures] : Prop where
  singleton : ∀ bytes : Array U8 48#usize,
    portable.decompress.uncompress_in_g1 bytes = ok (UncompressG1.specVerdict bytes)
  pair : ∀ a b : Array U8 48#usize,
    portable.decompress.uncompress_pair_in_g1 a b =
      ok (Array.make 2#usize [UncompressG1.specVerdict a, UncompressG1.specVerdict b] (by rfl))

end LeanBlsSimd
