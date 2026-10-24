import LeanBlsSimd.Portable.Decode.Pair
import LeanBlsSimd.Portable.G1DecoderContract

open Aeneas Aeneas.Std Result
open silver_crypto_simd

namespace LeanBlsSimd.Portable.Decode

theorem g1_decoder_correct [RuntimeFeatures] : G1DecoderCorrect where
  singleton := by
    intro bytes
    simpa only [toArray_ofArray (fun a => toU8_ofU8 a),
      show (48#usize).val = 48 from rfl,UncompressG1.specVerdict] using
      scalar_refines (ofArray (m := 48) ofU8 bytes)
  pair := by
    intro a b
    simpa only [toArray_ofArray (fun a => toU8_ofU8 a),
      show (48#usize).val = 48 from rfl,UncompressG1.specVerdict] using
      pair_refines (ofArray (m := 48) ofU8 a) (ofArray (m := 48) ofU8 b)

end LeanBlsSimd.Portable.Decode
